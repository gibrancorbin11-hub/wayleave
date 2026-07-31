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

import { createPublicKey, verify as edVerify, sign as edSign } from 'node:crypto';

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
 * directories: { [directoryUrl]: { [keyid]: publicKey (KeyObject|PEM|raw b64) } }
 * Returns { ok, agentId, reason }
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

  const dir = directories[directory];
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
  return { ok: true, agentId: `${directory}#${keyid}`, reason: 'valid signature' };
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

export function classify(req, directories, now) {
  const h = req.headers, ua = (h['user-agent'] || '').toLowerCase();
  const v = verifySignature(h, req.authority, directories, now);
  if (v.ok) return { lane: LANES.VERIFIED, agentId: v.agentId,
                     evidence: [`crypto: ${v.reason}`] };
  if (h['signature'] || h['signature-input'])
    return { lane: LANES.SUSPECT, agentId: null,
             evidence: [`crypto: ${v.reason}`, 'presented invalid signature'] };
  if (AGENT_UA.some(p => p.test(ua)))
    return { lane: LANES.DECLARED, agentId: null,
             evidence: [`self-identified in UA: "${ua.slice(0, 40)}"`,
                        'no signature presented'] };
  for (const [tell, why] of AUTOMATION_TELLS)
    if (ua.includes(tell))
      return { lane: LANES.SUSPECT, agentId: null, evidence: [why] };
  if (!ua) return { lane: LANES.SUSPECT, agentId: null, evidence: ['empty user-agent'] };
  if (!h['accept-language'] && ua.includes('mozilla'))
    return { lane: LANES.SUSPECT, agentId: null,
             evidence: ['browser UA without accept-language'] };
  return { lane: LANES.HUMAN, agentId: null, evidence: ['browser-shaped request'] };
}

// ── the gate ────────────────────────────────────────────────────────────

export class Wayleave {
  /**
   * opts = {
   *   directories: { dirUrl: { keyid: publicKey } },
   *   rules: { [lane]: [ [pathPrefix, allow], ... ] },
   *   rateLimits: { [lane]: perWindow }, rateWindow: 60,
   *   pricedPaths: { pathPrefix: priceUsd },
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
    this._hits = new Map();
  }

  /** req: { method, path, authority, headers } → decision */
  handle(req, now = Math.floor(Date.now() / 1000), paymentProof = '') {
    const { lane, agentId, evidence } = classify(req, this.directories, now);
    const ident = agentId ||
      `${lane}:${req.headers['x-forwarded-for'] || 'unknown'}`;
    const d = this._decide(req, lane, ident, now, paymentProof);
    const entry = { t: now, path: req.path, lane, identity: ident,
                    status: d.status, why: d.why, evidence,
                    billedUsd: d.billed || 0 };
    try { this.onEvent(entry); } catch { /* metering must never break serving */ }
    return { lane, identity: ident, ...d, evidence };
  }

  _decide(req, lane, ident, now, paymentProof) {
    for (const [prefix, allow] of this.rules[lane] || []) {
      if (req.path.startsWith(prefix)) {
        if (!allow) return { status: 403, why: `${lane} denied on ${prefix}` };
        break;
      }
    }
    const limit = this.rateLimits[lane];
    if (limit) {
      const k = `${ident}|${Math.floor(now / this.rateWindow)}`;
      const n = (this._hits.get(k) || 0) + 1;
      this._hits.set(k, n);
      if (n > limit) return { status: 429, why: `${n} req in window, limit ${limit}` };
    }
    if (lane !== LANES.HUMAN) {
      for (const [prefix, price] of Object.entries(this.pricedPaths)) {
        if (req.path.startsWith(prefix)) {
          if (paymentProof === `paid:${prefix}:${price}`)
            return { status: 200, billed: price, why: `paid access $${price}` };
          return { status: 402, why: 'payment required for agent access',
                   challenge: { scheme: 'x402', price_usd: price, resource: prefix } };
        }
      }
    }
    if (lane === LANES.SUSPECT && req.method !== 'GET')
      return { status: 403, why: 'write blocked for unverified automation' };
    return { status: 200, why: `${lane} allowed` };
  }

  /** Express/Connect adapter: app.use(wayleave.express()) */
  express() {
    return (req, res, next) => {
      const r = this.handle({
        method: req.method, path: req.path || req.url,
        authority: req.headers.host || '',
        headers: req.headers,
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
