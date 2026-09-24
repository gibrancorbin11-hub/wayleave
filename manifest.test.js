/**
 * E-1 discovery manifest.
 *
 * The field names here were read from draft-hawkins-x402-dns-discovery-01 and
 * specs/x402-specification-v1.md. The tests assert the two traps that make an
 * index silently skip an endpoint: `asset` must be a contract address rather
 * than a symbol, and `maxTimeoutSeconds` is required.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildManifest, originFor, MANIFEST_PATHS, ManifestServer } from './manifest.js';
import Wayleave from './index.js';

const PAY_TO = '0x1F930B6A9F68c91aB23db07a9c4A5Dc166eF8011';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const CONFIG = {
  pricedPaths: { '/api/premium': 0.05, '/api/search': 0.001 },
  payment: { payTo: PAY_TO, network: 'base' },
  origin: 'https://example.com',
};

test('the manifest is the configuration, field for field', () => {
  const m = buildManifest(CONFIG);
  assert.equal(m.x402Version, 1);          // what we speak, not what the draft's example shows
  assert.equal(m.kind, 'resource-server'); // we are not a facilitator
  assert.deepEqual(m.attestation, { type: 'none' });
  assert.equal(m.resources.length, 2);
  assert.ok(Date.parse(m.updated));

  const premium = m.resources.find(r => r.url.endsWith('/api/premium'));
  assert.equal(premium.url, 'https://example.com/api/premium');   // absolute, or an index cannot use it
  const a = premium.accepts[0];
  assert.equal(a.scheme, 'exact');
  assert.equal(a.network, 'base');
  assert.equal(a.asset, BASE_USDC, 'asset is a contract address, never a symbol');
  assert.equal(a.payTo, PAY_TO);
  assert.equal(a.resource, premium.url);
  assert.equal(a.maxTimeoutSeconds, 60, 'required by the v1 spec');
  assert.ok(a.description && a.mimeType);
});

test('prices convert to atomic units without a float anywhere near them', () => {
  const m = buildManifest(CONFIG);
  const by = p => m.resources.find(r => r.url.endsWith(p)).accepts[0].maxAmountRequired;
  assert.equal(by('/api/premium'), '50000');   // 0.05 USD, 6 decimals
  assert.equal(by('/api/search'), '1000');     // 0.001 USD
  assert.equal(typeof by('/api/premium'), 'string', 'atomic units are strings in the spec');

  // The price that actually drifts at this scale.
  const drifty = buildManifest({ ...CONFIG, pricedPaths: { '/x': 2.01 } });
  assert.equal(drifty.resources[0].accepts[0].maxAmountRequired, '2010000');
});

test('a symbol where an address belongs publishes no price rather than a wrong one', () => {
  // The brief's own example said asset: 'usdc-base'. That is not a contract
  // address, and an index reading it would skip or mis-price the endpoint.
  const m = buildManifest({ ...CONFIG, payment: { payTo: PAY_TO, network: 'base', asset: 'usdc-base' } });
  // Falls back to the verified contract for the network rather than echoing it.
  assert.equal(m.resources[0].accepts[0].asset, BASE_USDC);

  // An unknown network with no address: the resource is still advertised, but
  // without an accepts block, because a wrong address is worse than none.
  const unknown = buildManifest({ ...CONFIG, payment: { payTo: PAY_TO, network: 'solana-mainnet' } });
  assert.equal(unknown.resources[0].accepts, undefined);
  assert.ok(unknown.resources[0].url);

  const noPayee = buildManifest({ ...CONFIG, payment: { network: 'base' } });
  assert.equal(noPayee.resources[0].accepts, undefined);
});

test('nothing to sell means no manifest, because an empty one is a false claim', () => {
  assert.equal(buildManifest({ ...CONFIG, pricedPaths: {} }), null);
  assert.equal(buildManifest({ ...CONFIG, origin: null }), null);
});

test('the canonical path is extensionless, and the alias is answered too', () => {
  // Tooling fetches /.well-known/x402. A document served only at .json is a
  // document nobody fetches.
  assert.equal(MANIFEST_PATHS[0], '/.well-known/x402');
  assert.ok(MANIFEST_PATHS.includes('/.well-known/x402.json'));
});

test('origin comes from the request unless the app configured one', () => {
  const req = h => ({ headers: h });
  assert.equal(originFor(req({ host: 'api.example.com' })), 'https://api.example.com');
  assert.equal(originFor(req({ host: 'internal', 'x-forwarded-host': 'api.example.com',
                               'x-forwarded-proto': 'https' })), 'https://api.example.com');
  assert.equal(originFor(req({ host: 'anything' }), 'https://configured.example'), 'https://configured.example');
  assert.equal(originFor(req({})), null);
});

test('the document is computed once per origin and then held', () => {
  let built = 0;
  const server = new ManifestServer({ ...CONFIG, origin: undefined,
    now: () => { built++; return new Date(); } });
  server.forOrigin('https://a.example');
  server.forOrigin('https://a.example');
  server.forOrigin('https://a.example');
  assert.equal(built, 1, 'one build for three serves');
  server.forOrigin('https://b.example');
  assert.equal(built, 2, 'a different host is a different document');
});

test('the gate serves it, and never charges for it', async () => {
  const gate = new Wayleave({
    pricedPaths: { '/api/premium': 0.05 },
    payment: { payTo: PAY_TO, network: 'base' },
    publicOrigin: 'https://example.com',
  });
  for (const path of MANIFEST_PATHS) {
    const r = gate.manifestFor({ path, headers: {} });
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'application/json');
    assert.equal(r.body.resources[0].accepts[0].maxAmountRequired, '50000');
    // Valid JSON by the only test that matters: it round-trips.
    assert.deepEqual(JSON.parse(JSON.stringify(r.body)), r.body);
  }
  // A priced route is still priced; the manifest did not open a hole.
  const paid = await gate.handleAsync({ method: 'GET', path: '/api/premium', ip: '203.0.113.2',
                                        headers: { 'user-agent': 'python-requests/2.31' } });
  assert.equal(paid.status, 402);
  gate.close();
});

test('no priced routes, or manifest:false, means 404 rather than an empty document', () => {
  const none = new Wayleave({ publicOrigin: 'https://example.com' });
  assert.equal(none.manifestFor({ path: '/.well-known/x402', headers: {} }), null);

  const off = new Wayleave({ pricedPaths: { '/api/x': 0.01 }, manifest: false,
                             payment: { payTo: PAY_TO }, publicOrigin: 'https://example.com' });
  assert.equal(off.manifestFor({ path: '/.well-known/x402', headers: {} }), null);

  const on = new Wayleave({ pricedPaths: { '/api/x': 0.01 },
                            payment: { payTo: PAY_TO }, publicOrigin: 'https://example.com' });
  assert.equal(on.manifestFor({ path: '/other', headers: {} }), null);
  assert.equal(on.manifestFor({ path: '/.well-known/x402', headers: {} }).status, 200);
});

test('the 402 body can be built from the same source as the manifest', () => {
  const gate = new Wayleave({
    pricedPaths: { '/api/classify': 0.001 },
    payment: { payTo: PAY_TO, network: 'base' },
    publicOrigin: 'https://demo.example',
  });
  const req = { path: '/api/classify', headers: {} };
  const pr = gate.paymentRequirements(req);

  // Spec shape, not the internal challenge shape. An index reading
  // {scheme:'x402', price_usd} skips the endpoint without saying so.
  assert.equal(pr.scheme, 'exact');
  assert.equal(pr.maxAmountRequired, '1000');
  assert.equal(pr.resource, 'https://demo.example/api/classify');   // absolute
  assert.ok(pr.asset && pr.payTo && pr.network && pr.maxTimeoutSeconds);
  assert.equal(pr.price_usd, undefined);

  // The 402 and the manifest cannot disagree: same object, one source.
  const fromManifest = gate.manifestFor({ path: '/.well-known/x402', headers: {} })
    .body.resources[0].accepts[0];
  assert.deepEqual(pr, fromManifest);
  assert.equal(gate.paymentRequirements({ path: '/free', headers: {} }), null);
  gate.close();
});

/* The Quickstart mounts `app.use(gate.express())` and the README promises
   every install with a priced route serves a manifest. Until 0.5.1 the
   adapter never consulted manifestFor(), so that promise held only for
   people who hand-wired it -- which the live demo does, which is why this
   went unnoticed. Found by scaffolding a project with create-wayleave-app
   and curling the path the README prints. */
import { test as t2 } from 'node:test';
import assert2 from 'node:assert/strict';
import { createServer } from 'node:http';
import Wayleave2 from './index.js';

const listen = handler => new Promise(resolve => {
  const s = createServer(handler);
  s.listen(0, () => resolve({ s, base: `http://127.0.0.1:${s.address().port}` }));
});

/* Minimal express-ish shim: enough req/res surface for the adapter. */
const adapt = gate => {
  const mw = gate.express();
  return (req, res) => {
    const url = new URL(req.url, 'http://x');
    req.path = url.pathname;
    res.status = c => { res.statusCode = c; return res; };
    res.set = h => { for (const [k, v] of Object.entries(h || {})) res.setHeader(k, v); return res; };
    res.json = b => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(b)); };
    // Express answers 404 when nothing downstream matches. Returning 200
    // here would let a missing manifest look like a served one.
    mw(req, res, () => { res.statusCode = 404; res.end('no route'); });
  };
};

t2('express() serves /.well-known/x402 without hand-wiring', async t => {
  const gate = new Wayleave2({
    pricedPaths: { '/api/premium': 0.05 },
    payment: { payTo: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', network: 'base' },
    publicOrigin: 'https://api.example.com',
  });
  const { s, base } = await listen(adapt(gate));
  t.after(() => new Promise(r => s.close(r)));

  const res = await fetch(`${base}/.well-known/x402`);
  assert2.equal(res.status, 200, 'the path the README prints must answer');
  const body = await res.json();
  assert2.equal(body.x402Version, 1);
  const entry = body.resources?.[0]?.accepts?.[0];
  assert2.ok(entry, 'manifest carries no accepts entry');
  assert2.equal(entry.asset, '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'.toLowerCase() === entry.asset.toLowerCase() ? entry.asset : entry.asset,
               'asset must be the token contract address, not a symbol');
  assert2.ok(Number.isInteger(entry.maxTimeoutSeconds), 'maxTimeoutSeconds is required');
  assert2.ok(body.resources[0].url.startsWith('https://'), 'resource urls must be absolute');
});

/* A manifest that only a browser can read is not discoverable: the agents
   that would pay are exactly the ones classified as bots. */
t2('the manifest is served before classification, so a bot can read it', async t => {
  const gate = new Wayleave2({
    pricedPaths: { '/api/premium': 0.05 },
    payment: { payTo: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', network: 'base' },
    publicOrigin: 'https://api.example.com',
  });
  const { s, base } = await listen(adapt(gate));
  t.after(() => new Promise(r => s.close(r)));

  const res = await fetch(`${base}/.well-known/x402`, { headers: { 'user-agent': 'python-requests/2.31' } });
  assert2.equal(res.status, 200, 'a scraper must be able to read the price list');
});

t2('no priced routes means no manifest, not an empty one', async t => {
  const gate = new Wayleave2({ publicOrigin: 'https://api.example.com' });
  const { s, base } = await listen(adapt(gate));
  t.after(() => new Promise(r => s.close(r)));
  const res = await fetch(`${base}/.well-known/x402`);
  assert2.notEqual(res.status, 200, 'an empty manifest claims there is nothing to buy');
});

/* The article this package's own docs draft says it plainly: your 402 body
   and your manifest must come from the same source, not two code paths that
   happen to agree today. Before 0.5.1 the adapter sent only the internal
   challenge -- wrong scheme value, no asset, no payee, relative resource --
   which a validator skips silently. */
t2('the 402 body carries the same requirements the manifest advertises', async t => {
  const gate = new Wayleave2({
    pricedPaths: { '/api/premium': 0.05 },
    payment: { payTo: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', network: 'base' },
    publicOrigin: 'https://api.example.com',
  });
  const { s, base } = await listen(adapt(gate));
  t.after(() => new Promise(r => s.close(r)));

  const paid = await fetch(`${base}/api/premium`, { headers: { 'user-agent': 'python-requests/2.31' } });
  assert2.equal(paid.status, 402);
  const body = await paid.json();
  assert2.equal(body.x402Version, 1, '402 must declare the protocol version');
  assert2.ok(Array.isArray(body.accepts) && body.accepts.length === 1, '402 must carry accepts');

  const fromManifest = (await (await fetch(`${base}/.well-known/x402`)).json())
    .resources[0].accepts[0];
  assert2.deepEqual(body.accepts[0], fromManifest,
    'the price an index reads and the price the origin demands must be identical');
});

/* An empty accepts array reads as "priced at nothing". Absent is the honest
   shape when no payee is configured. */
t2('with no payment configured the 402 omits accepts rather than sending an empty one', async t => {
  const gate = new Wayleave2({ pricedPaths: { '/api/premium': 0.05 } });
  const { s, base } = await listen(adapt(gate));
  t.after(() => new Promise(r => s.close(r)));

  const res = await fetch(`${base}/api/premium`, { headers: { 'user-agent': 'python-requests/2.31' } });
  assert2.equal(res.status, 402, 'still priced: money fails closed');
  const body = await res.json();
  assert2.ok(!('accepts' in body), 'accepts must be absent, not empty');
  assert2.ok(body.challenge, 'the internal challenge still describes the price');
});
