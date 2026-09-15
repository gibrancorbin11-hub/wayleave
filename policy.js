/**
 * Remote policy for an installed gate.
 *
 * THE LAW THIS FILE EXISTS TO OBEY: traffic fails open.
 *
 * Wayleave sits in front of somebody else's site. If our service is slow,
 * unreachable, misconfigured or returning nonsense, their users must not
 * notice. Nothing here is awaited in a request path, nothing here can throw
 * into one, and every failure mode ends in "enforce what we last knew, and if
 * we never knew anything, enforce nothing."
 *
 *   boot      -> disk cache, then network, then nothing
 *   every 5m  -> conditional GET, swap in memory on success
 *   decide    -> pure memory read, no I/O, no await
 *
 * Money is the opposite law and fails closed; that lives in x402.js.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';

const DEFAULT_ENDPOINT = 'https://meter.wayleave.dev';
const DEFAULT_REFRESH_MS = 5 * 60_000;
const FETCH_TIMEOUT_MS = 5_000;
const LANES = ['verified_agent', 'declared_agent', 'suspected_bot', 'human'];

/**
 * The meter's policy document, translated into the shapes the gate already
 * enforces. Anything unrecognised is dropped rather than guessed at: a rule we
 * cannot express is a rule we must not pretend to apply.
 */
export function compilePolicy(doc) {
  const rules = {}, rateLimits = {}, pricedPaths = {};
  const applied = [], skipped = [];
  if (!doc || !Array.isArray(doc.rules)) return { rules, rateLimits, pricedPaths, applied, skipped };

  for (const r of doc.rules) {
    const lanes = r.lane ? [r.lane] : LANES;
    const prefix = typeof r.route === 'string' && r.route.startsWith('/') ? r.route : '/';

    if (r.action === 'allow' || r.action === 'deny') {
      // Selectors the gate cannot evaluate at this layer. Applying such a rule
      // as if it matched everything would deny traffic the customer meant to
      // allow, which is exactly the outage this file exists to prevent.
      if (r.subject || r.operator || r.tool || r.method || r.verified !== undefined) {
        skipped.push({ id: r.id, why: 'selector not enforceable by the gate' });
        continue;
      }
      for (const lane of lanes) (rules[lane] ||= []).push([prefix, r.action === 'allow']);
      applied.push(r.id);
    } else if (r.action === 'quota') {
      // The gate's limiter is per-lane and per-window, not per-route, so a
      // route-scoped quota is not something it can honour faithfully.
      if (r.route) { skipped.push({ id: r.id, why: 'route-scoped quota needs the shared store' }); continue; }
      for (const lane of lanes) rateLimits[lane] = r.quota.limit;
      applied.push(r.id);
    } else if (r.action === 'pay') {
      if (!r.route) { skipped.push({ id: r.id, why: 'priced rule needs a route' }); continue; }
      // Integer micro-USD is the wire format; pricedPaths is decimal USD. The
      // division is exact for any price a person would write.
      pricedPaths[r.route] = r.priceMicros / 1_000_000;
      applied.push(r.id);
    } else {
      skipped.push({ id: r.id, why: `unsupported action ${r.action}` });
    }
  }
  return { rules, rateLimits, pricedPaths, applied, skipped };
}

export class RemotePolicy {
  /**
   * @param {object} o
   * @param {string} o.apiKey      the meter API key for this tenant
   * @param {string} [o.endpoint]  meter base URL
   * @param {number} [o.refreshMs] poll interval
   * @param {string} [o.cachePath] where the last good document is kept
   * @param {(e:object)=>void} [o.onEvent] observability; never throws into us
   */
  constructor({ apiKey, endpoint = DEFAULT_ENDPOINT, refreshMs = DEFAULT_REFRESH_MS,
                cachePath = null, onEvent = null, onChange = null, fetchImpl = null } = {}) {
    if (!apiKey) throw new Error('RemotePolicy requires the meter apiKey');
    this.apiKey = apiKey;
    this.url = endpoint.replace(/\/+$/, '') + '/v1/policy';
    this.refreshMs = refreshMs;
    this.cachePath = cachePath || defaultCachePath();
    this.onEvent = onEvent || (() => {});
    this._onChange = onChange || (() => {});
    this._fetch = fetchImpl || globalThis.fetch;
    this.document = null;   // last good policy, or null meaning enforce nothing
    this.etag = null;
    this.fetchedAt = null;
    this._timer = null;
  }

  /** Compiled form of whatever we currently know. Pure memory. */
  compiled() { return compilePolicy(this.document); }

  /**
   * Load whatever is on disk, then try the network once. Never rejects: a gate
   * that cannot start because our service is down is the failure this whole
   * design refuses.
   */
  async start() {
    await this._loadCache();
    await this.refresh();
    if (this.refreshMs > 0) {
      this._timer = setInterval(() => { this.refresh(); }, this.refreshMs);
      this._timer.unref?.();
    }
    return this;
  }

  stop() { if (this._timer) clearInterval(this._timer); this._timer = null; }

  /** One conditional GET. Swallows everything; reports through onEvent. */
  async refresh() {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await this._fetch(this.url, {
        signal: ac.signal,
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          ...(this.etag ? { 'if-none-match': this.etag } : {}),
        },
      });

      if (res.status === 304) { this._emit('policy.unchanged'); return this.document; }

      // 404 is "this tenant has set no policy", which is a real answer and
      // means enforce nothing -- not an error, and not a reason to keep
      // enforcing something the customer has since deleted.
      if (res.status === 404) {
        if (this.document) { this.document = null; this.etag = null; await this._writeCache(null); }
        this._emit('policy.none');
        this._changed();
        return null;
      }

      if (!res.ok) { this._emit('policy.error', { status: res.status }); return this.document; }

      const doc = await res.json();
      if (!isUsable(doc)) { this._emit('policy.rejected', { why: 'document not usable' }); return this.document; }

      this.document = doc;
      this.etag = res.headers.get?.('etag') ?? null;
      this.fetchedAt = Date.now();
      await this._writeCache(doc);
      const { applied, skipped } = compilePolicy(doc);
      this._emit('policy.applied', { version: doc.version, applied, skipped });
      this._changed();
      return doc;
    } catch (err) {
      // Unreachable, timed out, DNS gone, TLS wrong, body not JSON: all the
      // same answer. Keep the last good copy and say nothing to the request path.
      this._emit('policy.unreachable', { error: err?.message });
      return this.document;
    } finally { clearTimeout(timer); }
  }

  async _loadCache() {
    try {
      const raw = JSON.parse(await readFile(this.cachePath, 'utf8'));
      if (raw?.url === this.url && isUsable(raw.document)) {
        this.document = raw.document;
        this.etag = null;   // revalidate against the server, not against disk
        this._emit('policy.cache.loaded', { version: raw.document.version });
        this._changed();
      }
    } catch { /* no cache is the normal first-run state */ }
  }

  async _writeCache(document) {
    try {
      await mkdir(dirname(this.cachePath), { recursive: true });
      await writeFile(this.cachePath, JSON.stringify({ url: this.url, document, at: Date.now() }));
    } catch (err) { this._emit('policy.cache.unwritable', { error: err?.message }); }
  }

  _changed() { try { this._onChange(this.compiled()); } catch { /* never breaks a refresh */ } }

  _emit(type, data = {}) { try { this.onEvent({ type, ...data }); } catch { /* never our problem */ } }
}

/** A document we can act on: right shape, explicit default, sane rule count. */
function isUsable(doc) {
  return !!doc && Array.isArray(doc.rules) && doc.rules.length <= 100
      && (doc.default === 'allow' || doc.default === 'deny');
}

function defaultCachePath() {
  // Beside the install when that is writable, /tmp when it is not. A read-only
  // node_modules is normal in a container and must not cost us the cache.
  try { return join(process.cwd(), 'node_modules', '.cache', 'wayleave', 'policy.json'); }
  catch { return join(tmpdir(), 'wayleave-policy.json'); }
}
