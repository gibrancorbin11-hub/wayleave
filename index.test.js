import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { Wayleave, LANES, signRequest } from './index.js';

const NOW = Math.floor(Date.now() / 1000);
const anthropic = generateKeyPairSync('ed25519');
const shopbot = generateKeyPairSync('ed25519');
const attacker = generateKeyPairSync('ed25519');

const DIRS = () => ({
  'https://agents.anthropic.example/keys': { 'claude-1': anthropic.publicKey },
  'https://shopbot.example/.well-known/keys': { 'sb-2026': shopbot.publicKey },
});

const OPTS = () => ({
  directories: DIRS(),
  rules: {
    [LANES.VERIFIED]: [['/api/admin', false], ['/api', true]],
    [LANES.DECLARED]: [['/api/admin', false], ['/api/bulk', false], ['/api', true]],
    [LANES.SUSPECT]: [['/api', false]],
    [LANES.HUMAN]: [['/api', true]],
  },
  rateLimits: { [LANES.VERIFIED]: 100, [LANES.DECLARED]: 10, [LANES.SUSPECT]: 3 },
  pricedPaths: { '/api/premium': 0.05 },
});

function req(path = '/api/listings', {
  method = 'GET', ua = 'Mozilla/5.0 (Macintosh) Safari/17',
  lang = 'en-US', extra = {} } = {}) {
  const headers = { 'user-agent': ua, ...extra };
  if (lang) headers['accept-language'] = lang;
  return { method, path, authority: 'app.example.com', headers };
}

function signed(r, key = anthropic.privateKey, keyid = 'claude-1',
                dir = 'https://agents.anthropic.example/keys',
                created = NOW, expires = NOW + 300) {
  signRequest(r.headers, r.authority, key, keyid, dir, created, expires);
  return r;
}

/** A signer that supplies RFC 9421's nonce — what makes single-use possible. */
function nonceSigned(r, nonce, created = NOW, expires = NOW + 300) {
  return foreignSign(r,
    `("@authority" "signature-agent");created=${created};keyid="claude-1";` +
    `alg="ed25519";expires=${expires};nonce="${nonce}";tag="web-bot-auth"`);
}

// ── lanes ───────────────────────────────────────────────────────────────

test('plain browser → human, 200', () => {
  const r = new Wayleave(OPTS()).handle(req(), NOW);
  assert.equal(r.lane, LANES.HUMAN); assert.equal(r.status, 200);
});

test('raw HTTP library → suspected bot', () => {
  const r = new Wayleave(OPTS()).handle(req('/api/x', { ua: 'python-requests/2.31' }), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('headless browser → suspected bot', () => {
  const r = new Wayleave(OPTS()).handle(req('/api/x', { ua: 'Mozilla/5.0 HeadlessChrome/120' }), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('browser UA without accept-language → suspected bot', () => {
  const r = new Wayleave(OPTS()).handle(req('/api/x', { ua: 'Mozilla/5.0', lang: null }), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('self-declared agent, no signature → declared lane', () => {
  const r = new Wayleave(OPTS()).handle(req('/api/x', { ua: 'ShopBot/2.0 (autonomous agent)' }), NOW);
  assert.equal(r.lane, LANES.DECLARED);
});

// ── crypto ──────────────────────────────────────────────────────────────

test('validly signed agent → verified, 200, directory#keyid identity', () => {
  const r = new Wayleave(OPTS()).handle(signed(req('/api/x', { ua: 'ClaudeBot/1.0' })), NOW);
  assert.equal(r.lane, LANES.VERIFIED); assert.equal(r.status, 200);
  assert.equal(r.identity, 'https://agents.anthropic.example/keys#claude-1');
});

test('FORGED signature (stolen keyid, attacker key) → suspect', () => {
  const r = new Wayleave(OPTS()).handle(
    signed(req('/api/x', { ua: 'ClaudeBot/1.0' }), attacker.privateKey), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('signature from untrusted directory → suspect', () => {
  const r = new Wayleave(OPTS()).handle(
    signed(req('/api/x', { ua: 'ShadyBot' }), attacker.privateKey, 'evil-1',
           'https://evil.example/keys'), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('TAMPERED request (authority changed after signing) → rejected', () => {
  const r0 = signed(req('/api/x', { ua: 'ClaudeBot/1.0' }));
  r0.authority = 'victim.example.com';
  const r = new Wayleave(OPTS()).handle(r0, NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('EXPIRED signature (replay) → rejected', () => {
  const r = new Wayleave(OPTS()).handle(
    signed(req('/api/x', { ua: 'ClaudeBot/1.0' }), anthropic.privateKey,
           'claude-1', 'https://agents.anthropic.example/keys',
           NOW - 1200, NOW - 900), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('24h validity window → rejected as replay risk', () => {
  const r = new Wayleave(OPTS()).handle(
    signed(req('/api/x', { ua: 'ClaudeBot/1.0' }), anthropic.privateKey,
           'claude-1', 'https://agents.anthropic.example/keys',
           NOW, NOW + 86400), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
});

test('raw base64 public key in directory also verifies', () => {
  const raw = anthropic.publicKey.export({ format: 'der', type: 'spki' })
    .subarray(-32).toString('base64');
  const opts = OPTS();
  opts.directories['https://agents.anthropic.example/keys']['claude-1'] = raw;
  const r = new Wayleave(opts).handle(signed(req('/api/x', { ua: 'ClaudeBot/1.0' })), NOW);
  assert.equal(r.lane, LANES.VERIFIED);
});

// ── policy ──────────────────────────────────────────────────────────────

test('verified agent on admin path → 403', () => {
  const r = new Wayleave(OPTS()).handle(signed(req('/api/admin/users', { ua: 'ClaudeBot/1.0' })), NOW);
  assert.equal(r.status, 403);
});

test('declared agent on bulk path → 403', () => {
  const r = new Wayleave(OPTS()).handle(req('/api/bulk/export', { ua: 'ShopBot agent' }), NOW);
  assert.equal(r.status, 403);
});

test('suspected bot write → 403', () => {
  const r = new Wayleave(OPTS()).handle(req('/api/listings', { method: 'POST', ua: 'curl/8.0' }), NOW);
  assert.equal(r.status, 403);
});

test('declared agent rate limit trips at request 11', () => {
  const g = new Wayleave(OPTS());
  const statuses = [];
  for (let i = 0; i < 12; i++)
    statuses.push(g.handle(req('/api/x', { ua: 'ShopBot agent',
      extra: { 'x-forwarded-for': '9.9.9.9' } }), NOW).status);
  assert.equal(statuses[9], 200); assert.equal(statuses[10], 429);
});

test('rotating x-forwarded-for does NOT mint fresh rate-limit buckets', () => {
  // The whole point of a rate limit is that the subject cannot choose its own
  // identity. x-forwarded-for is written by the client unless a proxy you own
  // overwrites it, so by default it must not be believed.
  const g = new Wayleave(OPTS());
  const statuses = [];
  for (let i = 0; i < 12; i++)
    statuses.push(g.handle({ ...req('/api/x', { ua: 'ShopBot agent',
      extra: { 'x-forwarded-for': `10.0.0.${i}` } }), ip: '203.0.113.7' }, NOW).status);
  assert.equal(statuses[10], 429, 'header rotation bought unlimited requests');
});

test('trustProxy:true honours the proxy-supplied client address', () => {
  const g = new Wayleave({ ...OPTS(), trustProxy: true });
  const statuses = [];
  for (let i = 0; i < 12; i++)
    statuses.push(g.handle(req('/api/x', { ua: 'ShopBot agent',
      extra: { 'x-forwarded-for': '9.9.9.9, 10.0.0.1' } }), NOW).status);
  assert.equal(statuses[10], 429);
});

test('distinct clients are still limited independently', () => {
  const g = new Wayleave(OPTS());
  for (let i = 0; i < 11; i++)
    g.handle({ ...req('/api/x', { ua: 'ShopBot agent' }), ip: '198.51.100.1' }, NOW);
  const other = g.handle({ ...req('/api/x', { ua: 'ShopBot agent' }), ip: '198.51.100.2' }, NOW);
  assert.equal(other.status, 200, 'one noisy client must not deny everyone else');
});

test('the hit table stays bounded under a flood of distinct clients', () => {
  const g = new Wayleave({ ...OPTS(), maxTracked: 50 });
  for (let i = 0; i < 5000; i++)
    g.handle({ ...req('/api/x', { ua: 'ShopBot agent' }), ip: `10.1.${i >> 8}.${i & 255}` }, NOW);
  assert.ok(g._hits.size <= 50, `tracked ${g._hits.size} identities, cap was 50`);
});

test('counters reset on window rollover instead of accumulating', () => {
  const g = new Wayleave(OPTS());
  for (let i = 0; i < 11; i++)
    g.handle({ ...req('/api/x', { ua: 'ShopBot agent' }), ip: '198.51.100.9' }, NOW);
  assert.equal(g.handle({ ...req('/api/x', { ua: 'ShopBot agent' }), ip: '198.51.100.9' },
                        NOW).status, 429);
  const next = g.handle({ ...req('/api/x', { ua: 'ShopBot agent' }), ip: '198.51.100.9' },
                        NOW + 61);
  assert.equal(next.status, 200);
  assert.ok(g._hits.size <= 1, 'stale window left entries behind');
});

// ── replay ──────────────────────────────────────────────────────────────

test('a captured nonce-bearing request cannot be replayed', () => {
  const g = new Wayleave({ ...OPTS(), verifyPayment: () => true });
  const captured = nonceSigned(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' }), 'n-001');
  const first = g.handle(captured, NOW, 'tx');
  const replay = g.handle(captured, NOW, 'tx');
  assert.equal(first.status, 200);
  assert.equal(replay.status, 403, 'one signature, one crossing');
  assert.match(replay.why, /replay/);
});

test('a fresh nonce from the same agent still passes', () => {
  const g = new Wayleave({ ...OPTS(), verifyPayment: () => true });
  g.handle(nonceSigned(req('/api/premium/a', { ua: 'ClaudeBot/1.0' }), 'n-1'), NOW, 'tx');
  const second = g.handle(nonceSigned(req('/api/premium/b', { ua: 'ClaudeBot/1.0' }), 'n-2'),
                          NOW, 'tx');
  assert.equal(second.status, 200);
});

test('a signer with no nonce is not falsely accused of replaying', () => {
  // Ed25519 is deterministic and the profile covers only @authority, so two
  // legitimate same-second requests carry byte-identical signatures.
  const g = new Wayleave(OPTS());
  const a = g.handle(signed(req('/api/one', { ua: 'ClaudeBot/1.0' })), NOW);
  const b = g.handle(signed(req('/api/two', { ua: 'ClaudeBot/1.0' })), NOW);
  assert.equal(a.status, 200);
  assert.equal(b.status, 200, 'rejected real traffic as a replay');
});

// ── monetization ────────────────────────────────────────────────────────

test('agent on priced path, unpaid → 402 with challenge', () => {
  const r = new Wayleave(OPTS()).handle(signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW);
  assert.equal(r.status, 402);
  assert.equal(r.challenge.price_usd, 0.05);
});

test('a settled payment, confirmed by the verifier → 200 and billed', () => {
  const opts = { ...OPTS(), verifyPayment: p => p === 'settled-tx-9f3' };
  const r = new Wayleave(opts).handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW,
    'settled-tx-9f3');
  assert.equal(r.status, 200); assert.equal(r.billed, 0.05);
});

// ── the payment path is adversarial: the proof is written by the payer ───

test('no verifyPayment configured → proof is worthless, still 402', () => {
  const r = new Wayleave(OPTS()).handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW,
    'paid:/api/premium:0.05');
  assert.equal(r.status, 402, 'default must be deny, never a string compare');
  assert.equal(r.billed, undefined);
});

test('an agent that echoes the challenge back is not paid', () => {
  // The 402 tells the agent the price and the resource. Anything derivable
  // from the challenge is something the agent can forge.
  const opts = { ...OPTS(), verifyPayment: p => p === 'settled-tx-9f3' };
  const g = new Wayleave(opts);
  const c = g.handle(signed(req('/api/premium/x', { ua: 'ClaudeBot/1.0' })), NOW).challenge;
  for (const guess of [`paid:${c.resource}:${c.price_usd}`, 'paid', 'true',
                       JSON.stringify(c), `${c.price_usd}`]) {
    const r = g.handle(signed(req('/api/premium/x', { ua: 'ClaudeBot/1.0' })), NOW, guess);
    assert.equal(r.status, 402, `guessed proof "${guess}" bought passage`);
  }
});

test('a rejected payment is never written to the ledger as billed', () => {
  const events = [];
  const opts = { ...OPTS(), onEvent: e => events.push(e),
                 verifyPayment: () => false };
  new Wayleave(opts).handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW, 'nice-try');
  assert.equal(events[0].status, 402);
  assert.equal(events[0].billedUsd, 0, 'unsettled money must never be booked');
});

test('a verifier that throws denies passage rather than granting it', () => {
  const opts = { ...OPTS(), verifyPayment: () => { throw new Error('rail down'); } };
  const r = new Wayleave(opts).handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW, 'x');
  assert.equal(r.status, 402);
  assert.match(r.why, /verifier threw/);
});

test('the verifier is told the price and resource it is confirming', () => {
  let ctx;
  const opts = { ...OPTS(), verifyPayment: (p, c) => { ctx = c; return true; } };
  new Wayleave(opts).handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW, 'tx');
  assert.equal(ctx.price, 0.05);
  assert.equal(ctx.resource, '/api/premium');
  assert.equal(ctx.identity, 'https://agents.anthropic.example/keys#claude-1');
});

test('settlement reference from the verifier reaches the ledger', () => {
  const events = [];
  const opts = { ...OPTS(), onEvent: e => events.push(e),
                 verifyPayment: () => ({ ok: true, ref: 'base-tx-0xabc' }) };
  new Wayleave(opts).handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW, 'tx');
  assert.equal(events[0].paymentRef, 'base-tx-0xabc');
  assert.equal(events[0].billedUsd, 0.05);
});

test('suspected bot on priced path → 402 (sneaky automation pays too)', () => {
  const opts = OPTS();
  opts.rules[LANES.SUSPECT] = [['/api', true]];  // let it reach the paywall
  const r = new Wayleave(opts).handle(req('/api/premium/comps', { ua: 'curl/8.0' }), NOW);
  assert.equal(r.lane, LANES.SUSPECT);
  assert.equal(r.status, 402);
});

test('human on priced path → free 200', () => {
  const r = new Wayleave(OPTS()).handle(req('/api/premium/comps'), NOW);
  assert.equal(r.status, 200); assert.equal(r.billed, undefined);
});

// ── strictPricedPaths ───────────────────────────────────────────────────
// The human lane is reached by failing to look like automation, so by default
// it is spoofable with two headers. That is a documented property, not a
// secret: the test below asserts the bypass works exactly as described, and
// the rest assert that strict mode is the answer to it.

test('DEFAULT: two headers buy free passage on a priced route', () => {
  const bot = req('/api/premium/comps', {
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/131.0.0.0',
    lang: 'en-US,en;q=0.9' });
  const r = new Wayleave(OPTS()).handle(bot, NOW);
  assert.equal(r.lane, LANES.HUMAN, 'a browser UA is all the lane requires');
  assert.equal(r.status, 200, 'this is the bypass the README discloses');
});

test('STRICT: the same spoofed request is asked to pay', () => {
  const opts = { ...OPTS(), strictPricedPaths: true };
  const bot = req('/api/premium/comps', {
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/131.0.0.0',
    lang: 'en-US,en;q=0.9' });
  const r = new Wayleave(opts).handle(bot, NOW);
  assert.equal(r.lane, LANES.HUMAN, 'classification is unchanged...');
  assert.equal(r.status, 402, '...but looking human no longer buys anything');
  assert.equal(r.challenge.price_usd, 0.05);
});

test('STRICT: confirmHuman lets a real session browse free', () => {
  const opts = { ...OPTS(), strictPricedPaths: true,
                 confirmHuman: r => r.headers.cookie === 'sid=real-session' };
  const w = new Wayleave(opts);
  const signedIn = w.handle(
    req('/api/premium/comps', { extra: { cookie: 'sid=real-session' } }), NOW);
  assert.equal(signedIn.status, 200);
  assert.equal(signedIn.billed, undefined, 'a person is not a billable crossing');
  const anon = w.handle(req('/api/premium/comps'), NOW);
  assert.equal(anon.status, 402);
});

test('STRICT: no confirmHuman configured → nobody crosses free', () => {
  const opts = { ...OPTS(), strictPricedPaths: true };
  const r = new Wayleave(opts).handle(req('/api/premium/comps'), NOW);
  assert.equal(r.status, 402, 'fail closed, same doctrine as verifyPayment');
});

test('STRICT: a throwing confirmHuman denies rather than admits', () => {
  const opts = { ...OPTS(), strictPricedPaths: true,
                 confirmHuman: () => { throw new Error('session store down'); } };
  const r = new Wayleave(opts).handle(req('/api/premium/comps'), NOW);
  assert.equal(r.status, 402, 'a broken check must never become an open door');
});

test('STRICT: confirmHuman must return true, not merely truthy', () => {
  const opts = { ...OPTS(), strictPricedPaths: true,
                 confirmHuman: () => 'yes' };
  const r = new Wayleave(opts).handle(req('/api/premium/comps'), NOW);
  assert.equal(r.status, 402);
});

test('STRICT: verified agents still pay the ordinary way', () => {
  const opts = { ...OPTS(), strictPricedPaths: true, verifyPayment: () => true };
  const w = new Wayleave(opts);
  const unpaid = w.handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW);
  assert.equal(unpaid.status, 402);
  const paid = w.handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW, 'tx-abc');
  assert.equal(paid.status, 200);
  assert.equal(paid.billed, 0.05);
});

test('STRICT: unpriced paths are untouched — humans still browse', () => {
  const opts = { ...OPTS(), strictPricedPaths: true };
  const r = new Wayleave(opts).handle(req('/api/listings'), NOW);
  assert.equal(r.status, 200, 'strict mode is scoped to priced routes only');
});

test('STRICT: confirmHuman sees the framework request under express()', () => {
  // The adapter projects the request down to headers/path/ip before
  // classifying. If that projection is all confirmHuman ever saw, every
  // signed-in visitor would be billed as a bot on a priced route.
  let sawSession = null;
  const gate = new Wayleave({ ...OPTS(), strictPricedPaths: true,
    confirmHuman: r => { sawSession = r.session; return Boolean(r.session?.userId); } });
  const expressReq = {
    method: 'GET', url: '/api/premium/comps', path: '/api/premium/comps',
    headers: { host: 'app.example.com', 'user-agent': 'Mozilla/5.0 Safari/17',
               'accept-language': 'en-US' },
    socket: { remoteAddress: '203.0.113.7' },
    session: { userId: 'u_42' },
  };
  let nexted = false;
  gate.express()(expressReq, { status: () => { throw new Error('paywalled a real user'); } },
                 () => { nexted = true; });
  assert.deepEqual(sawSession, { userId: 'u_42' }, 'callback got the express req');
  assert.ok(nexted, 'a signed-in human passes through');
  assert.equal(expressReq.wayleave.status, 200);
});

test('STRICT: the 402 says which check failed', () => {
  const opts = { ...OPTS(), strictPricedPaths: true };
  const r = new Wayleave(opts).handle(req('/api/premium/comps'), NOW);
  assert.match(r.why, /no signature and no confirmed human/);
});

test('onEvent metering hook fires with billed amount', () => {
  const events = [];
  const opts = { ...OPTS(), onEvent: e => events.push(e),
                 verifyPayment: () => true };
  new Wayleave(opts).handle(
    signed(req('/api/premium/comps', { ua: 'ClaudeBot/1.0' })), NOW,
    'settled-tx-9f3');
  assert.equal(events.length, 1);
  assert.equal(events[0].billedUsd, 0.05);
  assert.equal(events[0].identity, 'https://agents.anthropic.example/keys#claude-1');
});

test('a throwing metering hook never breaks serving', () => {
  const opts = { ...OPTS(), onEvent: () => { throw new Error('billing down'); } };
  const r = new Wayleave(opts).handle(req(), NOW);
  assert.equal(r.status, 200);
});

// ── throughput ──────────────────────────────────────────────────────────

test('verify+policy per signed request under 5ms', () => {
  const g = new Wayleave(OPTS());
  const N = 300;
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < N; i++)
    g.handle(signed(req('/api/x', { ua: 'ClaudeBot/1.0' })), NOW);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6 / N;
  console.log(`      per signed request: ${ms.toFixed(3)}ms`);
  assert.ok(ms < 5, `${ms}ms`);
});

// ── interop: signatures NOT produced by this library ─────────────────────
//
// Every test above signs with our own signRequest, so they all round-trip
// through one wire format and cannot catch a format mismatch. These sign at
// the byte level in other implementations' shapes. The first one is the exact
// parameter ordering and label from Cloudflare's Web Bot Auth documentation,
// which this library rejected as "malformed signature-input" before 0.1.4.

import { sign as edSign } from 'node:crypto';

/** Sign an arbitrary signature-input verbatim, the way a foreign SDK would. */
function foreignSign(r, paramsRaw, { label = 'sig1', key = anthropic.privateKey,
                                     dir = 'https://agents.anthropic.example/keys',
                                     components = ['@authority', 'signature-agent'] } = {}) {
  r.headers['signature-agent'] = `"${dir}"`;
  const lines = components.map(c =>
    c === '@authority' ? `"@authority": ${r.authority}`
                       : `"${c}": ${r.headers[c] ?? ''}`);
  lines.push(`"@signature-params": ${paramsRaw}`);
  const sig = edSign(null, Buffer.from(lines.join('\n')), key);
  r.headers['signature-input'] = `${label}=${paramsRaw}`;
  r.headers['signature'] = `${label}=:${sig.toString('base64')}:`;
  return r;
}

const CF = (created = NOW, expires = NOW + 300) =>
  `("@authority" "signature-agent");created=${created};keyid="claude-1";` +
  `alg="ed25519";expires=${expires};tag="web-bot-auth"`;

test('Cloudflare parameter order and sig2 label → verified', () => {
  const w = new Wayleave(OPTS());
  const d = w.handle(foreignSign(req(), CF(), { label: 'sig2' }), NOW);
  assert.equal(d.lane, LANES.VERIFIED);
  assert.equal(d.identity, 'https://agents.anthropic.example/keys#claude-1');
});

test('parameters in any order → verified (they are a dictionary)', () => {
  const w = new Wayleave(OPTS());
  const shuffled = `("@authority" "signature-agent");tag="web-bot-auth";` +
    `alg="ed25519";keyid="claude-1";expires=${NOW + 300};created=${NOW}`;
  assert.equal(w.handle(foreignSign(req(), shuffled), NOW).lane, LANES.VERIFIED);
});

test('an optional nonce does not break verification', () => {
  const w = new Wayleave(OPTS());
  const withNonce = `("@authority" "signature-agent");created=${NOW};` +
    `keyid="claude-1";alg="ed25519";expires=${NOW + 300};nonce="abc123";tag="web-bot-auth"`;
  assert.equal(w.handle(foreignSign(req(), withNonce), NOW).lane, LANES.VERIFIED);
});

test('covering only @authority → verified', () => {
  const w = new Wayleave(OPTS());
  const only = `("@authority");created=${NOW};keyid="claude-1";` +
    `alg="ed25519";expires=${NOW + 300};tag="web-bot-auth"`;
  const d = w.handle(foreignSign(req(), only, { components: ['@authority'] }), NOW);
  assert.equal(d.lane, LANES.VERIFIED);
});

test('a non-Ed25519 alg is refused, not silently trusted', () => {
  const w = new Wayleave(OPTS());
  const rsa = `("@authority" "signature-agent");created=${NOW};keyid="claude-1";` +
    `alg="rsa-pss-sha512";expires=${NOW + 300};tag="web-bot-auth"`;
  assert.equal(w.handle(foreignSign(req(), rsa), NOW).lane, LANES.SUSPECT);
});

test('a signature not covering @authority is refused', () => {
  const w = new Wayleave(OPTS());
  const noAuth = `("signature-agent");created=${NOW};keyid="claude-1";` +
    `alg="ed25519";expires=${NOW + 300};tag="web-bot-auth"`;
  const d = w.handle(foreignSign(req(), noAuth, { components: ['signature-agent'] }), NOW);
  assert.equal(d.lane, LANES.SUSPECT);
});

test('foreign-format tampering is still caught', () => {
  const w = new Wayleave(OPTS());
  const r = foreignSign(req(), CF(), { label: 'sig2' });
  r.authority = 'evil.example.com';           // changed after signing
  assert.equal(w.handle(r, NOW).lane, LANES.SUSPECT);
});

// ── the zero-dependency property ────────────────────────────────────────
//
// This is the differentiation, not a boast. Every comparable library pulls a
// tree (corri 3, x402 13, vestauth 8); the CDN and SaaS products can't run on
// your host at all. One `npm install --save` erases the only thing Wayleave
// has that nobody else does, and it would be erased silently. So it is a test.

test('the package declares zero runtime dependencies', async () => {
  const { readFile } = await import('node:fs/promises');
  const pkg = JSON.parse(await readFile(new URL('./package.json', import.meta.url)));
  assert.deepEqual(pkg.dependencies ?? {}, {},
    'a runtime dependency erases the whole differentiation — see launch/COMPETITIVE.md');
  assert.deepEqual(pkg.peerDependencies ?? {}, {}, 'a peer dep is still a dep to the installer');
});

test('nothing outside node: is imported at runtime', async () => {
  const { readFile } = await import('node:fs/promises');
  const src = await readFile(new URL('./index.js', import.meta.url), 'utf8');
  const imports = [...src.matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)].map(m => m[1]);
  const foreign = imports.filter(s => !s.startsWith('node:') && !s.startsWith('.'));
  assert.deepEqual(foreign, [], `non-builtin import(s): ${foreign.join(', ')}`);
});
