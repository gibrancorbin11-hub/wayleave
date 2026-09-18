/**
 * The Wayleave registry: a signed, cached, fail-open directory of agent keys.
 *
 * Why this exists rather than more verification code: verification is
 * commoditizable — an edge provider could clone the gate in a quarter. A
 * directory that every install consults, whose value grows on both sides, can
 * only be accumulated. It is also the one position an edge provider
 * structurally cannot take, because a directory owned by one network is not a
 * neutral directory.
 *
 * WHAT v1 IS: a signed list of operators' public keys, each traced to the
 * endpoint that operator published it at.
 *
 * WHAT v1 IS NOT: reputation, scores, ranking, paid placement. Those are
 * separate decisions with their own specs, and each is only safe after
 * NEUTRALITY.md has held under pressure.
 *
 * THE FAIL-OPEN LAW, restated because it is the whole design:
 *   unreachable, expired past grace, or bad signature -> last cached copy
 *   no cache -> behave exactly as if no directory were configured
 * Unknown agents stay unknown. They do not become suspected, and nothing
 * about a customer's traffic changes because our CDN had a bad day.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { verify as edVerify, createPublicKey } from 'node:crypto';
import { canonical } from './policy.js';

export const DEFAULT_REGISTRY_URL = 'https://registry.wayleave.dev/v1/agents.json';
const DEFAULT_REFRESH_MS = 6 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 5_000;

/**
 * Root keys this package accepts, newest first.
 *
 * Shipping the public half INSIDE the package is what makes a CDN compromise
 * useless: a tampered document fails here, not at a server we also have to
 * trust. A key fetched from the same origin as the document proves nothing.
 *
 * Rotation is never a flag day. Publish a release that accepts both the new
 * and old key, then drop the old one a version later.
 *
 * EMPTY UNTIL A ROOT KEY EXISTS. With no key pinned, `wayleave:default`
 * verifies nothing and therefore resolves nothing — which is the correct
 * inert state, not a bypass. It must never be made to "accept anything when
 * unconfigured"; that would turn the registry into an open door.
 */
export const WAYLEAVE_ROOT_KEYS = [];

/** Verify the signed envelope. Returns rather than throws; see the header. */
export function verifyRegistry(envelope, rootKeys, { now = Date.now(), graceMs = 0 } = {}) {
  if (!envelope || typeof envelope !== 'object') return { ok: false, reason: 'not an object' };
  if (envelope.v !== 1) return { ok: false, reason: 'unsupported registry version' };
  if (!Array.isArray(envelope.agents)) return { ok: false, reason: 'no agents array' };
  if (typeof envelope.sig !== 'string' || !envelope.sig) return { ok: false, reason: 'missing signature' };
  if (!rootKeys?.length) return { ok: false, reason: 'no root key pinned in this build' };

  const { sig, ...body } = envelope;
  const bytes = Buffer.from(canonical(body), 'utf8');
  const signature = Buffer.from(sig, 'base64');
  const matched = rootKeys.some(k => {
    try { return edVerify(null, bytes, typeof k === 'string' ? createPublicKey(k) : k, signature); }
    catch { return false; }
  });
  if (!matched) return { ok: false, reason: 'signature does not match any pinned root key' };

  // After the signature, so a forged expiry cannot decide whether we check it.
  const expires = Date.parse(envelope.expires);
  if (!Number.isFinite(expires)) return { ok: false, reason: 'unreadable expiry' };
  if (now > expires + graceMs) return { ok: false, reason: 'expired past grace' };

  return { ok: true, agents: envelope.agents };
}

/**
 * Build the synchronous resolver verifySignature() expects.
 *
 * Keys are indexed by the operator's OWN published endpoint, because that is
 * what an agent's signature names. An entry with no `source` is dropped: a key
 * we cannot trace back to where the operator published it is a key we guessed,
 * and guessing is the one thing this list must never do.
 */
export function buildIndex(agents) {
  const byDirectory = new Map();
  for (const a of agents || []) {
    if (!a || typeof a.source !== 'string' || !a.source) continue;
    if (a.status && a.status !== 'listed') continue;
    const keys = byDirectory.get(a.source) || {};
    for (const k of a.keys || []) {
      if (!k || k.scheme !== 'ed25519' || k.status === 'revoked') continue;
      if (typeof k.keyid !== 'string' || typeof k.pubkey !== 'string') continue;
      keys[k.keyid] = k.pubkey;
    }
    if (Object.keys(keys).length) byDirectory.set(a.source, keys);
  }
  return byDirectory;
}

export class Registry {
  constructor({ url = DEFAULT_REGISTRY_URL, rootKeys = WAYLEAVE_ROOT_KEYS,
                refreshMs = DEFAULT_REFRESH_MS, graceMs = 0, cachePath = null,
                onEvent = null, fetchImpl = null } = {}) {
    this.url = url;
    this.rootKeys = rootKeys;
    this.refreshMs = refreshMs;
    this.graceMs = graceMs;
    this.cachePath = cachePath || defaultCachePath();
    this.onEvent = onEvent || (() => {});
    this._fetch = fetchImpl || globalThis.fetch;
    this.agents = null;
    this.index = new Map();
    this._timer = null;
  }

  /** Synchronous, memory-only. This runs on every signed request. */
  resolver() {
    return directoryUrl => this.index.get(directoryUrl);
  }

  /** How many operators and keys are live. For a dashboard, not a decision. */
  stats() {
    let keys = 0;
    for (const m of this.index.values()) keys += Object.keys(m).length;
    return { directories: this.index.size, keys, listed: this.agents?.length ?? 0 };
  }

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

  async refresh() {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await this._fetch(this.url, { signal: ac.signal });
      if (!res.ok) { this._emit('registry.error', { status: res.status }); return this.agents; }
      const envelope = await res.json();
      const v = verifyRegistry(envelope, this.rootKeys, { graceMs: this.graceMs });
      if (!v.ok) { this._emit('registry.rejected', { why: v.reason }); return this.agents; }
      this._adopt(v.agents);
      await this._writeCache(envelope);
      this._emit('registry.applied', this.stats());
      return this.agents;
    } catch (err) {
      this._emit('registry.unreachable', { error: err?.message });
      return this.agents;
    } finally { clearTimeout(timer); }
  }

  _adopt(agents) { this.agents = agents; this.index = buildIndex(agents); }

  async _loadCache() {
    try {
      const raw = JSON.parse(await readFile(this.cachePath, 'utf8'));
      if (raw?.url !== this.url) return;
      // The cache is re-verified, not trusted. A file on disk is not evidence.
      const v = verifyRegistry(raw.envelope, this.rootKeys, { graceMs: this.graceMs });
      if (!v.ok) { this._emit('registry.cache.rejected', { why: v.reason }); return; }
      this._adopt(v.agents);
      this._emit('registry.cache.loaded', this.stats());
    } catch { /* no cache is the normal first run */ }
  }

  async _writeCache(envelope) {
    try {
      await mkdir(dirname(this.cachePath), { recursive: true });
      await writeFile(this.cachePath, JSON.stringify({ url: this.url, envelope, at: Date.now() }));
    } catch (err) { this._emit('registry.cache.unwritable', { error: err?.message }); }
  }

  _emit(type, data = {}) { try { this.onEvent({ type, ...data }); } catch { /* never our problem */ } }
}

function defaultCachePath() {
  try { return join(process.cwd(), 'node_modules', '.cache', 'wayleave', 'registry.json'); }
  catch { return join(tmpdir(), 'wayleave-registry.json'); }
}
