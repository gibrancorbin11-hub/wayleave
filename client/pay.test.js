/**
 * The loop nothing had ever closed: a client that pays, against the gate
 * that charges.
 *
 * The gate could always issue a correct 402. Nothing in this repo could
 * answer one, so the priced path had never been walked end to end by
 * anything behaving like a stranger's agent. Two bugs lived there because of
 * it — the payment header read under a name x402 does not use, and the
 * payload required as raw JSON when the protocol sends base64.
 *
 * The challenge in these tests is not hand-written. It comes out of the
 * gate's own manifest code, so if the published shape changes these fail
 * rather than quietly testing a fiction.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { recoverTypedDataAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { buildManifest, paymentRequirementsFor } from '../manifest.js';
import Wayleave from '../index.js';
import { signPayment, encodePayment, payFetch } from './pay.js';

/* A throwaway key. Testnet-shaped and worth nothing: it signs structures in
   this file and has never held a balance on any chain. */
const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';
const AGENT = privateKeyToAccount(KEY).address;
const PAYTO = '0x50a39061ffcdde872f2f644fb1fc78a719c0f4ce';
const SEPOLIA_USDC = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

const manifest = () => buildManifest({
  pricedPaths: { '/api/premium': 0.05 },
  payment: { network: 'base-sepolia', payTo: PAYTO },
  origin: 'https://api.example.com',
});
const requirements = () => paymentRequirementsFor(manifest(), '/api/premium');

test('the gate publishes requirements a client can actually sign against', () => {
  const r = requirements();
  assert.equal(r.scheme, 'exact');
  assert.equal(r.network, 'base-sepolia');
  assert.equal(r.maxAmountRequired, '50000', '$0.05 in atomic USDC units');
  assert.equal(r.payTo, PAYTO);
  assert.equal(r.asset.toLowerCase(), SEPOLIA_USDC.toLowerCase());
});

test('the signature recovers to the agent that made it', async () => {
  /* The whole protocol rests on this. A payload whose signature recovers to
     someone else authorises nothing, and the failure is invisible until a
     facilitator refuses it. */
  const r = requirements();
  const p = await signPayment(r, { privateKey: KEY });
  const recovered = await recoverTypedDataAddress({
    domain: { name: 'USDC', version: '2', chainId: 84532, verifyingContract: SEPOLIA_USDC },
    types: { TransferWithAuthorization: [
      { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
    ] },
    primaryType: 'TransferWithAuthorization',
    message: {
      from: p.payload.authorization.from,
      to: p.payload.authorization.to,
      value: BigInt(p.payload.authorization.value),
      validAfter: BigInt(p.payload.authorization.validAfter),
      validBefore: BigInt(p.payload.authorization.validBefore),
      nonce: p.payload.authorization.nonce,
    },
    signature: p.payload.signature,
  });
  assert.equal(recovered.toLowerCase(), AGENT.toLowerCase());
});

test('it authorises the exact amount, to the exact payee, and no more', async () => {
  const p = await signPayment(requirements(), { privateKey: KEY });
  assert.equal(p.payload.authorization.value, '50000', 'not a cent more than asked');
  assert.equal(p.payload.authorization.to, PAYTO);
  assert.equal(p.payload.authorization.from, AGENT);
});

test('every payment gets a fresh nonce', async () => {
  /* An authorisation is single-use on-chain. Reusing a nonce means the
     second payment silently fails after the first succeeded. */
  const a = await signPayment(requirements(), { privateKey: KEY });
  const b = await signPayment(requirements(), { privateKey: KEY });
  assert.notEqual(a.payload.authorization.nonce, b.payload.authorization.nonce);
});

test('the header is base64, which is what x402 specifies', async () => {
  const p = await signPayment(requirements(), { privateKey: KEY });
  const header = encodePayment(p);
  assert.doesNotMatch(header, /[{}"]/, 'not raw JSON on the wire');
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64').toString('utf8')), p);
});

/* ── the loop ──────────────────────────────────────────────────────────── */

test('a 402 from the gate is answered, and the gate lets the agent through', async () => {
  /* Both of today's fixes, exercised together. Against the old code this
     fails twice over: the gate never reads X-PAYMENT, and the verifier
     cannot parse base64. */
  const seen = [];
  const gate = new Wayleave({
    pricedPaths: { '/api/premium': 0.05 },
    payment: { network: 'base-sepolia', payTo: PAYTO },
    origin: 'https://api.example.com',
    sink: { emit() {} },
    verifyPayment: (proof) => {
      // Exactly what the real facilitator does with the string first.
      const decoded = JSON.parse(Buffer.from(proof, 'base64').toString('utf8'));
      seen.push(decoded);
      return { ok: true, ref: '0xsettled' };
    },
  });

  const req = (headers) => ({ method: 'GET', path: '/api/premium/comps',
    url: '/api/premium/comps', headers: { 'user-agent': 'PayingAgent/1.0', ...headers } });

  const unpaid = gate.handle(req({}));
  assert.equal(unpaid.status, 402, 'an agent is asked to pay');

  const payload = await signPayment(requirements(), { privateKey: KEY });
  const paid = gate.handle(req({ 'x-payment': encodePayment(payload) }));

  assert.equal(paid.status, 200, 'and having paid, it is let through');
  assert.equal(paid.billed, 0.05, 'and billed what it was quoted');
  assert.equal(seen.length, 1, 'the verifier saw the payload');
  assert.equal(seen[0].payload.authorization.to, PAYTO, 'addressed to the site owner');
});

/* ── refusals ──────────────────────────────────────────────────────────── */

test('an unknown scheme is refused rather than signed blind', async () => {
  await assert.rejects(
    () => signPayment({ ...requirements(), scheme: 'upto' }, { privateKey: KEY }),
    /unsupported x402 scheme: upto/);
});

test('a challenge naming a different token is refused', async () => {
  /* Otherwise a server could collect a signature valid for real USDC by
     asking for something else. */
  await assert.rejects(
    () => signPayment({ ...requirements(), asset: '0x' + '9'.repeat(40) }, { privateKey: KEY }),
    /is not the base-sepolia USDC/);
});

test('an unknown network is refused — no domain means no valid signature', async () => {
  await assert.rejects(
    () => signPayment({ ...requirements(), network: 'polygon' }, { privateKey: KEY }),
    /no EIP-712 domain known/);
});

test('a 402 with no accepts is an error, not a silent pass', async () => {
  const fetchImpl = async () => new Response(JSON.stringify({ error: 'pay up' }),
    { status: 402, headers: { 'content-type': 'application/json' } });
  await assert.rejects(() => payFetch('https://x.dev/a', { privateKey: KEY, fetchImpl }),
    /nothing says what to pay/);
});

test('a non-402 is returned untouched and nothing is signed', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return new Response('ok', { status: 200 }); };
  const r = await payFetch('https://x.dev/a', { privateKey: KEY, fetchImpl });
  assert.equal(r.status, 200);
  assert.equal(calls, 1, 'no speculative second request');
});

test('payFetch pays once and only once', async () => {
  /* A second 402 means the payment was rejected. Paying again would
     authorise a second transfer to re-ask a question already answered. */
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    return new Response(JSON.stringify({ accepts: [requirements()] }),
      { status: 402, headers: { 'content-type': 'application/json' } });
  };
  const r = await payFetch('https://x.dev/a', { privateKey: KEY, fetchImpl });
  assert.equal(r.status, 402, 'the second refusal is surfaced, not paid again');
  assert.equal(calls, 2);
});
