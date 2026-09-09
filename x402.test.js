import { generateKeyPairSync as generateCDPTestKey } from 'node:crypto';
const cdpTestSecret = generateCDPTestKey('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
import test from 'node:test';
import assert from 'node:assert/strict';
import { coinbaseFacilitator, toAtomicUnits } from './x402.js';
import Wayleave from './index.js';
import { MeterSink } from './meter.js';

const ok200 = (data) => async () => ({ ok: true, status: 200, json: async () => data });
const args = ['{"scheme":"exact","payload":{}}', { price: 0.05, resource: '/api/premium' }];

const fac = (fetchImpl, over = {}) => coinbaseFacilitator({
  apiKeyId: 'id', apiKeySecret: cdpTestSecret, receivingAddress: '0xCUSTOMER',
  fetch: fetchImpl, ...over,
});

test('money is converted exactly, never floated', () => {
  assert.equal(toAtomicUnits(0.05), '50000');
  assert.equal(toAtomicUnits(0.07), '70000');   // 0.07 * 1e6 floats to 70000.00000000001
  assert.equal(toAtomicUnits(1), '1000000');
  assert.throws(() => toAtomicUnits('0.0000001'), /finer/);
});

test('a settled payment returns ok with the transaction as ref', async () => {
  const f = fac(ok200({ success: true, transaction: '0xabc' }));
  const r = await f(...args);
  assert.equal(r.ok, true);
  assert.equal(r.ref, '0xabc');
});

test('HTTP 200 with success:false is a REJECTION', async () => {
  // The facilitator answers 200 for failed payments. Reading the status code
  // alone books every failure as revenue — the 0.1.4 bug, one layer down.
  const f = fac(ok200({ success: false, errorReason: 'insufficient_funds' }));
  const r = await f(...args);
  assert.equal(r.ok, false);
  assert.match(r.reason, /insufficient_funds/);
});

test('settlement with no transaction is refused — nothing to reference', async () => {
  const r = await fac(ok200({ success: true }))(...args);
  assert.equal(r.ok, false);
});

test('the customer address is what gets paid, in atomic units', async () => {
  let sent = null;
  const f = fac(async (url, init) => {
    sent = JSON.parse(init.body);
    return { ok: true, status: 200, json: async () => ({ success: true, transaction: '0x1' }) };
  });
  await f(...args);
  assert.equal(sent.paymentRequirements.payTo, '0xCUSTOMER');
  assert.equal(sent.paymentRequirements.maxAmountRequired, '50000');
  assert.equal(sent.x402Version, 1);
});

test('an outage denies rather than admits', async () => {
  const f = fac(async () => { throw new Error('ECONNREFUSED'); });
  const r = await f(...args);
  assert.equal(r.ok, false, 'an outage must never become free passage');
  assert.match(r.reason, /unreachable/);
});

test('garbage proof is refused, not thrown', async () => {
  const r = await fac(ok200({}))('not json at all', { price: 0.05 });
  assert.equal(r.ok, false);
});

test('a receiving address is required at construction, not at payment time', () => {
  // Failing here is far better than failing on a customer's first sale.
  assert.throws(() => coinbaseFacilitator({ apiKeyId: 'a', apiKeySecret: 'b' }),
                /receivingAddress/);
  assert.throws(() => coinbaseFacilitator({ receivingAddress: '0x1' }), /apiKeyId/);
});

test('it exposes no way to move money on its own', () => {
  const f = fac(ok200({}));
  for (const bad of ['transfer', 'send', 'payout', 'withdraw', 'balance'])
    assert.equal(typeof f[bad], 'undefined');
});

// ── the meter shorthand ─────────────────────────────────────────────────

test('meter: { apiKey } builds a MeterSink', async () => {
  const g = new Wayleave({ meter: { apiKey: 'k', endpoint: 'https://x.example' } });
  assert.ok(g.sink instanceof MeterSink);
  await g.sink.close();
});

test('an explicit sink still wins over the shorthand', async () => {
  const mine = { emit() {} };
  const g = new Wayleave({ sink: mine, meter: { apiKey: 'k' } });
  assert.equal(g.sink, mine);
});

test('no meter and no sink is still the swallow-and-continue default', () => {
  const g = new Wayleave({});
  assert.equal(g.sink.constructor.name, 'DirectSink');
});

test('a Promise on the SYNC path is refused loudly, not silently', async () => {
  // This is the bug that shipped from 0.1.5 to 0.2.1: an async verifier
  // returns a Promise, the sync path read .ok off it, got undefined, and
  // denied every payment forever without saying why.
  const g = new Wayleave({
    pricedPaths: { '/api/premium': 0.05 },
    verifyPayment: async () => ({ ok: true }),
  });
  const r = g.handle({ method: 'GET', path: '/api/premium/x', authority: 'a.example',
                       headers: { 'user-agent': 'GPTBot/1.0' }, ip: '1.2.3.4' },
                     1785600000, 'proof');
  assert.equal(r.status, 402);
  assert.match(r.why, /handleAsync|Promise/,
               'a silent denial here is how nobody gets paid and nobody knows');
});

test('the whole friendly path composes', async () => {
  // What the README now tells people to write.
  const sent = [];
  const g = new Wayleave({
    pricedPaths: { '/api/premium': 0.05 },
    strictPricedPaths: true,
    confirmHuman: () => false,
    verifyPayment: fac(ok200({ success: true, transaction: '0xdead' })),
    sink: { emit: e => sent.push(e) },
  });
  const req = { method: 'GET', path: '/api/premium/x', authority: 'a.example',
                headers: { 'user-agent': 'GPTBot/1.0' }, ip: '1.2.3.4' };
  const unpaid = await g.handleAsync(req, 1785600000);
  assert.equal(unpaid.status, 402, 'no proof must not pass');
  const paid = await g.handleAsync(req, 1785600000, '{"scheme":"exact","payload":{}}');
  assert.equal(paid.status, 200);
  assert.equal(paid.billed, 0.05);
  assert.equal(sent.at(-1).paymentRef, '0xdead');
});

// ── what the facilitator must send, learned the hard way ────────────────
//
// Both fields below were missing until 0.4.1, and each alone made settlement
// impossible in every default configuration. The failure was invisible here:
// the module built, these tests passed, and CDP returned 400 for reasons that
// never reached the customer. Proven against the live rail on base-sepolia.

/** Capture the body the facilitator actually puts on the wire. */
function capture(over = {}) {
  const box = {};
  const f = fac(async (_url, init) => {
    box.body = JSON.parse(init.body);
    return { ok: true, status: 200, json: async () => ({ isValid: true, success: true, transaction: '0xabc' }) };
  }, over);
  return { f, box };
}

test('the settlement asset is sent, because CDP rejects the call without it', async () => {
  const { f, box } = capture({ network: 'base' });
  await f(...args);
  assert.equal(box.body.paymentRequirements.asset,
    '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    "no asset sent — CDP answers 'x402V1PaymentRequirements requires asset' and nobody is paid");
});

test("the token's EIP-712 domain is sent, or the signature cannot be checked", async () => {
  const { f, box } = capture({ network: 'base' });
  await f(...args);
  assert.deepEqual(box.body.paymentRequirements.extra, { name: 'USD Coin', version: '2' },
    'without extra, CDP identifies the payer and then fails on the domain');
});

test('the EIP-712 name differs per network and is never guessed', async () => {
  const main = capture({ network: 'base' });
  await main.f(...args);
  const test_ = capture({ network: 'base-sepolia' });
  await test_.f(...args);
  assert.equal(main.box.body.paymentRequirements.extra.name, 'USD Coin');
  assert.equal(test_.box.body.paymentRequirements.extra.name, 'USDC',
    'Sepolia USDC reports a different name; the mainnet one is rejected on chain');
  assert.notEqual(main.box.body.paymentRequirements.asset,
                  test_.box.body.paymentRequirements.asset);
});

test('an unknown network refuses to build rather than denying every payment later', () => {
  assert.throws(() => coinbaseFacilitator({
    apiKeyId: 'id', apiKeySecret: cdpTestSecret, receivingAddress: '0xCUSTOMER',
    network: 'polygon',
  }), /no settlement asset known/);
});

test('an unknown network works when the caller supplies asset and domain', () => {
  assert.doesNotThrow(() => coinbaseFacilitator({
    apiKeyId: 'id', apiKeySecret: cdpTestSecret, receivingAddress: '0xCUSTOMER',
    network: 'polygon', asset: '0xtoken', extra: { name: 'USD Coin', version: '2' },
  }));
});
