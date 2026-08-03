/**
 * wayleave — charge AI agents for passage across your app.
 *
 * A wayleave is the fee paid for the right of passage across private
 * land. Utilities have paid them for 150 years. Agents are next.
 *
 * Every request is classified into a lane:
 *   verified_agent  — valid Ed25519 signature (Web Bot Auth profile)
 *                     against a key directory you trust
 *   declared_agent  — says it's a bot, no valid signature
 *   suspected_bot   — automation fingerprints without disclosure
 *   human           — browser-shaped traffic
 *
 * Then policy runs per lane: allow, deny, rate-limit — and on priced
 * routes, agents get 402 Payment Required with a price. Humans browse free.
 *
 * Zero dependencies. Node's native crypto only.
 */

import { createPublicKey, verify as edVerify, sign as edSign,
         createHash, randomUUID } from 'node:crypto';
// Same package, zero dependencies, ~9KB. Importing it unconditionally costs
// nothing measurable and makes `meter: { apiKey }` work without ceremony.
import { MeterSink } from './meter.js';

export const LANES = Object.freeze({
  VERIFIED: 'verified_agent',
  DECLARED: 'declared_agent',
  SUSPECT: 'suspected_bot',
  HUMAN: 'human',
});

// ── RFC 9421 profile (Web Bot Auth usage) ───────────────────────────────

/**
 * Parse an RFC 9421 `signature-input` value: `label=("a" "b");k=v;k2="v2"`.
 *
 * Parameters form a dictionary — order is NOT significant, and no
 * implementation is obliged to emit them in any particular sequence. The
 * label is arbitrary too (Cloudflare uses `sig2`, we emit `sig1`). Anything
 * that hardcodes either will reject legitimately signed traffic.
 *
 * Returns { label, components, params, paramsRaw } or null.
 * `paramsRaw` is preserved verbatim — the signature base must reproduce it
 * byte for byte or verification fails.
 */
function parseSignatureInput(raw) {
  const eq = raw.indexOf('=');
  if (eq < 1) return null;
  const label = raw.slice(0, eq).trim();
  if (!/^[A-Za-z0-9_-]+$/.test(label)) return null;

  const paramsRaw = raw.slice(eq + 1);
  const close = paramsRaw.indexOf(')');
  if (!paramsRaw.startsWith('(') || close < 0) return null;

  const components = (paramsRaw.slice(1, close).match(/"[^"]*"/g) || [])
    .map(s => s.slice(1, -1).toLowerCase());

  const params = {};
  const re = /;\s*([A-Za-z0-9_.-]+)=("[^"]*"|[^;]+)/g;
  let m;
  while ((m = re.exec(paramsRaw.slice(close + 1))) !== null) {
    const v = m[2].trim();
    params[m[1]] = v.startsWith('"') ? v.slice(1, -1) : v;
  }
  return { label, components, params, paramsRaw };
}

/** Structured-field strings arrive quoted; the directory URL itself is not. */
function unquote(s) {
  return s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s;
}

function headerValue(headers, name) {
  const v = headers[name];
  return Array.isArray(v) ? v.join(', ') : (v == null ? '' : String(v));
}

/**
 * Build the signature base from the components the signer actually declared,
 * not from a fixed list. An agent covering only ("@authority") is valid.
 */
function sigBase(components, ctx, paramsRaw) {
  const lines = components.map(c =>
    c === '@authority'
      ? `"@authority": ${ctx.authority}`
      : `"${c}": ${headerValue(ctx.headers, c)}`
  );
  lines.push(`"@signature-params": ${paramsRaw}`);
  return Buffer.from(lines.join('\n'));
}

export function buildParams(keyid, created, expires) {
  return `("@authority" "signature-agent");created=${created};` +
         `keyid="${keyid}";alg="ed25519";expires=${expires};tag="web-bot-auth"`;
}

/** What a legitimate agent operator's SDK does before sending. */
export function signRequest(headers, authority, privateKey, keyid, directoryUrl,
                            created = Math.floor(Date.now() / 1000),
                            expires = created + 300) {
  // Structured-field string: the value is sent quoted.
  headers['signature-agent'] = `"${directoryUrl}"`;
  const params = buildParams(keyid, created, expires);
  const base = sigBase(['@authority', 'signature-agent'],
                       { authority, headers }, params);
  const sig = edSign(null, base, privateKey);
  headers['signature-input'] = `sig1=${params}`;
  headers['signature'] = `sig1=:${sig.toString('base64')}:`;
  return headers;
}

/**
 * Key lookup, as a seam rather than an object read.
 *
 * `directories` may be the config object it has always been, or a function
 * `(directoryUrl) => { keyid: key }`. The function form is what makes rotation
 * possible without touching this file: point it at a cache your app refreshes
 * from a JWKS endpoint on a timer.
 *
 * It MUST be synchronous. This runs on every signed request, and awaiting a
 * network fetch per crossing would cost far more than the crossing earns —
 * the sub-millisecond claim in the README is a real constraint, not a boast.
 * Fetch on a schedule, resolve from memory.
 */
function asResolver(directories) {
  if (typeof directories === 'function') return directories;
  const d = directories || {};
  return (directoryUrl) => d[directoryUrl];
}

/**
 * directories: { [directoryUrl]: { [keyid]: publicKey (KeyObject|PEM|raw b64) } }
 *              or (directoryUrl) => { [keyid]: publicKey }
 * Returns { ok, agentId, reason, nonce, expires }
 *
 * `nonce` is set only when the signer supplied RFC 9421's `nonce` parameter,
 * and it is what makes a signature single-use. Do NOT substitute a hash of
 * the signature itself: Ed25519 is deterministic and the Web Bot Auth profile
 * covers only `@authority`, so one agent hitting two different paths in the
 * same second legitimately produces the SAME signature bytes. Treating that
 * as a replay would reject real traffic. Without a signer-supplied nonce,
 * replay is bounded by the expiry window and nothing tighter — see README.
 */
export function verifySignature(h, authority, directories,
                                now = Math.floor(Date.now() / 1000)) {
  const sigInput = headerValue(h, 'signature-input');
  const sigHeader = headerValue(h, 'signature');
  const rawAgent = headerValue(h, 'signature-agent');

  if (!sigInput || !sigHeader || !rawAgent)
    return { ok: false, agentId: null, reason: 'no signature presented' };

  const parsed = parseSignatureInput(sigInput);
  if (!parsed) return { ok: false, agentId: null, reason: 'malformed signature-input' };
  const { label, components, params, paramsRaw } = parsed;

  const directory = unquote(rawAgent);
  const keyid = params.keyid;
  const tag = params.tag;
  const created = Number(params.created);
  const expires = Number(params.expires);

  if (!keyid) return { ok: false, agentId: null, reason: 'signature-input missing keyid' };
  if (!Number.isFinite(created) || !Number.isFinite(expires))
    return { ok: false, agentId: null, reason: 'signature-input missing created/expires' };
  if (!components.includes('@authority'))
    return { ok: false, agentId: null, reason: '@authority not covered by signature' };
  // alg is mandatory in the Web Bot Auth profile; tolerate its absence for
  // signers that omit it, but reject anything that is not Ed25519.
  if (params.alg && params.alg.toLowerCase() !== 'ed25519')
    return { ok: false, agentId: null, reason: `unsupported alg "${params.alg}"` };
  if (tag !== 'web-bot-auth')
    return { ok: false, agentId: null, reason: `unexpected tag "${tag}"` };
  if (now < created - 30)
    return { ok: false, agentId: null, reason: 'signature created in the future' };
  if (now > expires)
    return { ok: false, agentId: null, reason: `signature expired ${now - expires}s ago` };
  if (expires - created > 3600)
    return { ok: false, agentId: null, reason: 'validity window too long (replay risk)' };

  const dir = asResolver(directories)(directory);
  if (!dir) return { ok: false, agentId: null, reason: `unknown key directory ${directory}` };
  let key = dir[keyid];
  if (!key) return { ok: false, agentId: null, reason: `keyid "${keyid}" not in directory` };
  if (typeof key === 'string') {
    key = key.includes('BEGIN')
      ? createPublicKey(key)
      : createPublicKey({ key: Buffer.concat([
          // raw 32-byte ed25519 pubkey -> SPKI DER prefix
          Buffer.from('302a300506032b6570032100', 'hex'),
          Buffer.from(key, 'base64')]), format: 'der', type: 'spki' });
    dir[keyid] = key; // cache the KeyObject
  }

  // Match the signature by the label the signer used, not a hardcoded "sig1".
  const sm = new RegExp(
    `(?:^|,)\\s*${label.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')}=:([A-Za-z0-9+/=]+):`
  ).exec(sigHeader);
  if (!sm) return { ok: false, agentId: null, reason: 'malformed signature header' };

  const valid = edVerify(null, sigBase(components, { authority, headers: h }, paramsRaw),
                         key, Buffer.from(sm[1], 'base64'));
  if (!valid)
    return { ok: false, agentId: null,
             reason: 'signature verification FAILED (forged or tampered)' };
  return { ok: true, agentId: `${directory}#${keyid}`, reason: 'valid signature',
           nonce: params.nonce
             ? createHash('sha256')
                 .update(`${directory}#${keyid}#${params.nonce}`).digest('base64')
             : null,
           expires };
}

// ── classification ──────────────────────────────────────────────────────

const AGENT_UA = [
  /gptbot/, /oai-searchbot/, /chatgpt-user/, /claude(?:bot|-user|-searchbot)?/,
  /perplexitybot/, /google-extended/, /bingbot/, /anthropic/, /openai/,
  /agent/, /autonomous/, /\bbot\b/,
];
const AUTOMATION_TELLS = [
  ['headlesschrome', 'headless browser UA'],
  ['python-requests', 'raw HTTP library UA'],
  ['curl/', 'curl UA'],
  ['selenium', 'browser automation UA'],
  ['phantomjs', 'headless UA'],
  ['undici', 'raw HTTP library UA'],
  ['node', 'raw HTTP client UA'],
  ['axios', 'raw HTTP library UA'],
  ['wget', 'wget UA'],
];

/**
 * A verifier that throws must not decide the lane. Treat the failure as
 * "could not check" rather than "is a forger" — a DNS timeout is not evidence
 * of fraud, and demoting real agents to the fraud lane because a lookup blipped
 * would be a self-inflicted outage on the traffic we most want to bill.
 */
function tryVerifyIP(verify, ip, ua) {
  try {
    const r = verify(ip, ua);
    return r === true ? true : r === false ? false : null;
  } catch { return null; }
}

export function classify(req, directories, now, opts = {}) {
  const h = req.headers, ua = (h['user-agent'] || '').toLowerCase();
  const v = verifySignature(h, req.authority, directories, now);
  if (v.ok) return { lane: LANES.VERIFIED, agentId: v.agentId,
                     evidence: [`crypto: ${v.reason}`],
                     nonce: v.nonce, sigExpires: v.expires };
  if (h['signature'] || h['signature-input'])
    return { lane: LANES.SUSPECT, agentId: null,
             evidence: [`crypto: ${v.reason}`, 'presented invalid signature'] };
  if (AGENT_UA.some(p => p.test(ua))) {
    // A UA naming a known operator is a claim, and claims are checkable when
    // the operator publishes its addresses. Claiming to be GPTBot from an
    // address OpenAI does not own is a stronger fraud signal than saying
    // nothing at all — so it lands in the fraud lane, exactly like a
    // signature that fails to verify. An unrecognised operator returns
    // null/undefined and stays merely declared: unknown is not guilty.
    const ipOk = opts.verifyAgentIP
      ? tryVerifyIP(opts.verifyAgentIP, opts.ip, ua)
      : null;
    if (ipOk === false)
      return { lane: LANES.SUSPECT, agentId: null,
               evidence: [`UA claims "${ua.slice(0, 40)}"`,
                          `but ${opts.ip || 'the client'} is not a published address for it`] };
    return { lane: LANES.DECLARED, agentId: null,
             evidence: [`self-identified in UA: "${ua.slice(0, 40)}"`,
                        ipOk === true ? 'source address matches published range'
                                      : 'no signature presented'] };
  }
  for (const [tell, why] of AUTOMATION_TELLS)
    if (ua.includes(tell))
      return { lane: LANES.SUSPECT, agentId: null, evidence: [why] };
  if (!ua) return { lane: LANES.SUSPECT, agentId: null, evidence: ['empty user-agent'] };
  if (!h['accept-language'] && ua.includes('mozilla'))
    return { lane: LANES.SUSPECT, agentId: null,
             evidence: ['browser UA without accept-language'] };
  return { lane: LANES.HUMAN, agentId: null, evidence: ['browser-shaped request'] };
}

// ── state ───────────────────────────────────────────────────────────────

/**
 * Rate-limit counters and consumed nonces, in this process's memory.
 *
 * This is the seam that a shared backend replaces. Implement the same four
 * methods against Redis or Postgres and pass it as `store` — the gate does not
 * know the difference. Two properties any replacement must preserve:
 *
 *   Synchronous. Called on every request. An awaited round trip per crossing
 *   is a worse tax than the crossing is worth; a distributed store belongs
 *   behind a local view that replicates asynchronously.
 *
 *   Bounded. `maxTracked` exists because an attacker who can mint identities
 *   can otherwise mint memory. Evicting the oldest keeps recent arrivals
 *   counted, which is the useful half.
 *
 * A distributed store trades exactness for reach, and the two uses differ in
 * how much they mind. Fixed-window rate limiting tolerates approximate counts.
 * Replay does NOT: a nonce that has not replicated yet is a nonce that can be
 * spent twice. Say which you chose in your deployment notes.
 */
export class MemoryStore {
  constructor({ maxTracked = 10000 } = {}) {
    this.maxTracked = maxTracked;
    this._hits = new Map();
    this._window = -1;
    this._seen = new Map();
  }

  /** Count this identity's requests in the current fixed window. */
  hit(identity, windowSeconds, now) {
    const w = Math.floor(now / windowSeconds);
    if (w !== this._window) {
      this._window = w;
      this._hits.clear();
      for (const [n, exp] of this._seen) if (exp <= now) this._seen.delete(n);
    }
    if (this._hits.size >= this.maxTracked && !this._hits.has(identity))
      this._hits.delete(this._hits.keys().next().value);
    const n = (this._hits.get(identity) || 0) + 1;
    this._hits.set(identity, n);
    return n;
  }

  hasNonce(nonce) { return this._seen.has(nonce); }

  rememberNonce(nonce, expiresAt) {
    if (this._seen.size >= this.maxTracked)
      this._seen.delete(this._seen.keys().next().value);
    this._seen.set(nonce, expiresAt);
  }
}

/**
 * Where metering events go. The default hands each one straight to `onEvent`
 * and swallows anything it throws, because serving must not depend on billing.
 *
 * That swallow is correct for uptime and lossy for revenue, which is the
 * trade a durable sink is meant to change: buffer locally, flush in batches,
 * retry on failure, and dedup on `idempotencyKey` at the far end. Implement
 * `emit(event)` and pass it as `sink`. Whatever you build, it must not throw
 * into the request path — this class is the last line that guarantees that.
 */
export class DirectSink {
  constructor(onEvent) { this.onEvent = onEvent || (() => {}); }
  emit(event) {
    try { this.onEvent(event); } catch { /* metering must never break serving */ }
  }
}

/**
 * Turn whatever a verifier returned into a verdict.
 *
 * A Promise reaching here means an async verifier was used on the synchronous
 * path. Reading `.ok` off a Promise yields undefined and denies silently —
 * which is precisely how the documented facilitator example failed from 0.1.5
 * to 0.2.1. It now says so instead.
 */
function normalizeVerdict(r) {
  if (r && typeof r.then === 'function')
    return { ok: false, reason:
      'verifyPayment returned a Promise — use gate.handleAsync() or gate.express(), ' +
      'which await it. The synchronous handle() cannot.' };
  if (r === true) return { ok: true, ref: null };
  if (r && r.ok === true) return { ok: true, ref: r.ref || null };
  return { ok: false, reason: (r && r.reason) || 'not settled' };
}

// ── the gate ────────────────────────────────────────────────────────────

export class Wayleave {
  /**
   * opts = {
   *   directories: { dirUrl: { keyid: publicKey } },
   *   rules: { [lane]: [ [pathPrefix, allow], ... ] },
   *   rateLimits: { [lane]: perWindow }, rateWindow: 60,
   *   pricedPaths: { pathPrefix: priceUsd },
   *   verifyPayment: (proof, ctx) => boolean | { ok, ref },
   *   strictPricedPaths: false,
   *   confirmHuman: (req) => boolean,
   *   trustProxy: false,
   *   replayProtection: true,
   *   maxTracked: 10000,
   *   onEvent: (logEntry) => {}   // metering/billing hook, async-safe
   * }
   */
  constructor(opts = {}) {
    this.directories = opts.directories || {};
    this.rules = opts.rules || {};
    this.rateLimits = opts.rateLimits || {};
    this.rateWindow = opts.rateWindow || 60;
    this.pricedPaths = opts.pricedPaths || {};
    this.onEvent = opts.onEvent || (() => {});

    // No payment verifier configured means no agent can ever buy passage.
    // Deny is the only safe default: a proof is a string the PAYER wrote, and
    // anything this library could check about it without a settlement network
    // is something the payer could equally have made up.
    this.verifyPayment = opts.verifyPayment || null;

    // The human lane is a fall-through: it means no automation tell was found,
    // not that a person is present. Since humans are never priced, that
    // asymmetry pays the spoofer — a browser User-Agent plus an
    // accept-language header is the whole bypass. Strict mode inverts the
    // burden on priced routes only: nothing crosses free without positive
    // evidence, which is a verified signature or confirmHuman saying yes.
    this.strictPricedPaths = opts.strictPricedPaths === true;
    this.confirmHuman = opts.confirmHuman || null;

    // x-forwarded-for is written by the client unless a proxy you control
    // overwrites it. Trusting it by default hands every attacker an unlimited
    // supply of fresh rate-limit buckets. Opt in only behind a real proxy.
    this.trustProxy = opts.trustProxy === true;

    this.replayProtection = opts.replayProtection !== false;
    this.maxTracked = opts.maxTracked || 10000;

    // Verifies that a UA claiming to be a known operator comes from that
    // operator's published addresses. Absent, a declared agent is taken at
    // its word — which is all "declared" ever meant.
    this.verifyAgentIP = opts.verifyAgentIP || null;

    // State and metering are interfaces, not implementations. Swap either for
    // a shared or durable one without the gate noticing. See MemoryStore.
    this.store = opts.store || new MemoryStore({ maxTracked: this.maxTracked });

    // `meter: { apiKey }` is shorthand for wiring a MeterSink yourself. It
    // exists because the two-line version of this was the most common thing
    // people got wrong: forgetting to drain on shutdown, or handing the sink
    // a callback that throws. Pass `sink` directly if you want control.
    this.sink = opts.sink
      || (opts.meter?.apiKey
            ? new MeterSink({
                endpoint: 'https://meter.wayleave.dev',
                ...opts.meter,
              })
            : null)
      || new DirectSink(this.onEvent);

    // Identifies events from this process so a retrying sink can dedup. A
    // counter alone would collide across instances; a timestamp alone would
    // collide within a millisecond.
    this._instance = randomUUID();
    this._seq = 0;
  }

  /** req: { method, path, authority, headers, ip } → decision */
  handle(req, now = Math.floor(Date.now() / 1000), paymentProof = '') {
    const c = classify(req, this.directories, now,
                       { verifyAgentIP: this.verifyAgentIP, ip: this._client(req) });
    const { lane, agentId, evidence } = c;
    const ident = agentId || `${lane}:${this._client(req)}`;
    const proof = paymentProof || headerValue(req.headers, 'x-payment-proof');
    const d = this._decide(req, lane, ident, now, proof, c);
    // v is the event schema version. A meter that outlives one release has to
    // know which shape it is reading; adding this after receipts exist in the
    // wild would mean reconciling two formats forever.
    const entry = { v: 1, idempotencyKey: `${this._instance}:${this._seq++}`,
                    t: now, path: req.path, lane, identity: ident,
                    status: d.status, why: d.why, evidence,
                    billedUsd: d.billed || 0 };
    if (d.paymentRef) entry.paymentRef = d.paymentRef;
    this.sink.emit(entry);
    return { lane, identity: ident, ...d, evidence };
  }

  /**
   * Async twin of handle(), for verifiers that talk to a network.
   *
   * Identical in every respect except that it can await your verifyPayment.
   * Use this whenever you actually sell something; the Express adapter does.
   */
  async handleAsync(req, now = Math.floor(Date.now() / 1000), paymentProof = '') {
    const c = classify(req, this.directories, now,
                       { verifyAgentIP: this.verifyAgentIP, ip: this._client(req) });
    const { lane, agentId, evidence } = c;
    const ident = agentId || `${lane}:${this._client(req)}`;
    const proof = paymentProof || headerValue(req.headers, 'x-payment-proof');
    const d = await this._decideAsync(req, lane, ident, now, proof, c);
    const entry = { v: 1, idempotencyKey: `${this._instance}:${this._seq++}`,
                    t: now, path: req.path, lane, identity: ident,
                    status: d.status, why: d.why, evidence,
                    billedUsd: d.billed || 0 };
    if (d.paymentRef) entry.paymentRef = d.paymentRef;
    this.sink.emit(entry);
    return { lane, identity: ident, ...d, evidence };
  }

  /**
   * Who to rate-limit. A cryptographic identity is authoritative; a network
   * address is at least expensive to rotate. A header is neither.
   */
  _client(req) {
    if (this.trustProxy) {
      const xff = headerValue(req.headers, 'x-forwarded-for');
      if (xff) return xff.split(',')[0].trim();
    }
    return req.ip || 'unknown';
  }


  /**
   * Positive evidence that a person is present, which only your application
   * holds — a signed-in session, a cookie you set, a challenge you passed.
   * Consulted only under strictPricedPaths, and fails closed: no callback, a
   * throw, or anything other than true means no free crossing of a priced
   * route. Deliberately not inferred from headers; every header a browser
   * sends, a bot can send too.
   */
  _confirmedHuman(req) {
    if (!this.confirmHuman) return false;
    // Hand back the framework's own request when an adapter supplied one, so
    // req.session and req.cookies are there to be checked.
    try { return this.confirmHuman(req.raw || req) === true; }
    catch { return false; }
  }

  /** Fixed-window counting, delegated to whichever store is configured. */
  _bump(ident, now) {
    return this.store.hit(ident, this.rateWindow, now);
  }

  /**
   * Everything up to the payment question.
   *
   * Split out so the sync and async paths share one copy of the policy,
   * replay, and rate-limit logic. Two copies of this would drift, and the
   * half that drifted would be the one nobody tested.
   *
   * Returns either a final decision, or a marker saying a priced route was
   * matched and a payment verdict is needed.
   */
  _preDecide(req, lane, ident, now, paymentProof, c) {
    for (const [prefix, allow] of this.rules[lane] || []) {
      if (req.path.startsWith(prefix)) {
        if (!allow) return { status: 403, why: `${lane} denied on ${prefix}` };
        break;
      }
    }
    // A valid signature replayed is still a replay. Checked before rate
    // limiting so a captured request cannot be farmed into N billed crossings.
    // Only signers that send a nonce can be held to single use; see
    // verifySignature for why a signature hash is not a safe substitute.
    if (this.replayProtection && c && c.nonce) {
      if (this.store.hasNonce(c.nonce))
        return { status: 403, why: 'signature already used (replay)' };
      this.store.rememberNonce(c.nonce, c.sigExpires || now + this.rateWindow);
    }
    const limit = this.rateLimits[lane];
    if (limit) {
      const n = this._bump(ident, now);
      if (n > limit) return { status: 429, why: `${n} req in window, limit ${limit}` };
    }
    // Who crosses a priced route without paying. Normally the human lane —
    // which anything browser-shaped reaches. Under strictPricedPaths only an
    // application-confirmed human does, so an unsigned request that merely
    // looks like a browser is asked to pay like the automation it may be.
    const freeOnPriced = this.strictPricedPaths
      ? this._confirmedHuman(req)
      : lane === LANES.HUMAN;
    if (!freeOnPriced) {
      for (const [prefix, price] of Object.entries(this.pricedPaths)) {
        if (req.path.startsWith(prefix)) {
          const challenge = { scheme: 'x402', price_usd: price, resource: prefix };
          if (!paymentProof) {
            const why = this.strictPricedPaths && lane === LANES.HUMAN
              ? 'payment required: no signature and no confirmed human'
              : 'payment required for agent access';
            return { status: 402, why, challenge };
          }
          // Hand back to the caller, which knows whether it can await.
          return { needsPayment: true, challenge, price,
                   ctx: { price, resource: prefix, identity: ident,
                          path: req.path, now } };
        }
      }
    }
    if (lane === LANES.SUSPECT && req.method !== 'GET')
      return { status: 403, why: 'write blocked for unverified automation' };
    return { status: 200, why: `${lane} allowed` };
  }

  /** Turn a payment verdict into the final decision. Shared by both paths. */
  _settleDecision(v, pre) {
    if (v.ok)
      return { status: 200, billed: pre.price, paymentRef: v.ref,
               why: `settled $${pre.price}` };
    return { status: 402, why: `payment proof rejected: ${v.reason}`,
             challenge: pre.challenge };
  }

  _decide(req, lane, ident, now, paymentProof, c) {
    const pre = this._preDecide(req, lane, ident, now, paymentProof, c);
    if (!pre.needsPayment) return pre;
    return this._settleDecision(this._checkPayment(paymentProof, pre.ctx), pre);
  }

  async _decideAsync(req, lane, ident, now, paymentProof, c) {
    const pre = this._preDecide(req, lane, ident, now, paymentProof, c);
    if (!pre.needsPayment) return pre;
    return this._settleDecision(
      await this._checkPaymentAsync(paymentProof, pre.ctx), pre);
  }

  /**
   * Settlement is somebody else's job — a facilitator that actually moved the
   * money. This asks yours and believes nothing else. A verifier that throws
   * is a verifier that did not say yes, so the answer is no.
   */
  _checkPayment(proof, ctx) {
    if (!this.verifyPayment)
      return { ok: false, reason: 'no verifyPayment configured' };
    let r;
    try { r = this.verifyPayment(proof, ctx); }
    catch (e) { return { ok: false, reason: `verifier threw: ${e.message}` }; }
    return normalizeVerdict(r);
  }

  /**
   * The async twin of _checkPayment.
   *
   * Every real facilitator is a network call, so a useful verifier returns a
   * Promise. The synchronous path cannot await one and refuses it loudly
   * rather than reading `.ok` off a Promise and silently denying — which is
   * what shipped from 0.1.5 to 0.2.1, and meant the documented way to sell
   * anything never worked.
   */
  async _checkPaymentAsync(proof, ctx) {
    if (!this.verifyPayment)
      return { ok: false, reason: 'no verifyPayment configured' };
    try {
      return normalizeVerdict(await this.verifyPayment(proof, ctx));
    } catch (e) {
      return { ok: false, reason: `verifier threw: ${e.message}` };
    }
  }

  /** Express/Connect adapter: app.use(wayleave.express()) */
  express() {
    return async (req, res, next) => {
      const r = await this.handleAsync({
        method: req.method, path: req.path || req.url,
        authority: req.headers.host || '',
        headers: req.headers,
        // The socket address, not a header. Express only populates req.ip
        // from x-forwarded-for when ITS trust proxy setting says to.
        ip: req.socket?.remoteAddress || req.connection?.remoteAddress,
        // confirmHuman needs the session and cookies your framework parsed,
        // none of which survive the projection above. Classification still
        // reads only the fields it declares; this is for your callback.
        raw: req,
      }, undefined, req.headers['x-payment-proof'] || '');
      req.wayleave = r;
      if (r.status === 200) return next();
      if (r.status === 402)
        return res.status(402)
                  .set('x-payment-challenge', JSON.stringify(r.challenge))
                  .json({ error: r.why, challenge: r.challenge });
      return res.status(r.status).json({ error: r.why });
    };
  }
}

export default Wayleave;
