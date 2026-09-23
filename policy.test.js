/**
 * The gate side of the policy mount.
 *
 * Most of these are outage tests. The point of the design is that a customer's
 * traffic is unaffected by anything going wrong at our end, so the interesting
 * cases are all failures: unreachable, garbage, 500, 404, unwritable disk.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RemotePolicy, compilePolicy } from './policy.js';
import Wayleave from './index.js';

const DOC = {
  version: 'v1', default: 'allow',
  rules: [
    { id: 'block-bots', route: '/api', lane: 'suspected_bot', action: 'deny' },
    { id: 'price-premium', route: '/api/premium', action: 'pay', priceMicros: 50000, rail: 'x402' },
    { id: 'limit-declared', lane: 'declared_agent', action: 'quota', quota: { limit: 30, windowSeconds: 60 } },
  ],
};
const cacheFile = async () => join(await mkdtemp(join(tmpdir(), 'wl-policy-')), 'policy.json');

// A fetch double. `script` is consumed one call at a time.
function fakeFetch(script) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, headers: init?.headers ?? {} });
    const next = script[Math.min(calls.length - 1, script.length - 1)];
    if (typeof next === 'function') return next();
    return next;
  };
  fn.calls = calls;
  return fn;
}
const ok = (body, etag = '"v1"') => ({
  status: 200, ok: true, headers: { get: h => (h === 'etag' ? etag : null) }, json: async () => body,
});

test('a document compiles into the shapes the gate already enforces', () => {
  const c = compilePolicy(DOC);
  assert.deepEqual(c.rules.suspected_bot, [['/api', false]]);
  assert.equal(c.pricedPaths['/api/premium'], 0.05);      // micro-USD in, decimal USD out
  assert.equal(c.rateLimits.declared_agent, 30);
  assert.deepEqual(c.applied, ['block-bots', 'price-premium', 'limit-declared']);
});

test('a rule the gate cannot evaluate is skipped, never widened into a block', () => {
  // `operator` needs a verified identity the gate does not resolve at this
  // layer. Treating it as "matches everything" would deny traffic the customer
  // meant to allow -- the exact outage this design exists to prevent.
  const c = compilePolicy({ version: 'v', default: 'allow', rules: [
    { id: 'partner', operator: 'Acme', action: 'deny' },
    { id: 'route-quota', route: '/search', action: 'quota', quota: { limit: 5, windowSeconds: 60 } },
    { id: 'priced-no-route', action: 'pay', priceMicros: 1000, rail: 'x402' },
  ]});
  assert.deepEqual(c.applied, []);
  assert.deepEqual(c.skipped.map(s => s.id), ['partner', 'route-quota', 'priced-no-route']);
  assert.deepEqual(c.rules, {});
});

test('the first fetch applies, the second revalidates and transfers nothing', async () => {
  const f = fakeFetch([ok(DOC), { status: 304, ok: false, headers: { get: () => null } }]);
  const p = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(), fetchImpl: f });
  await p.start();
  assert.equal(p.document.version, 'v1');
  await p.refresh();
  assert.equal(f.calls[1].headers['if-none-match'], '"v1"');
  assert.equal(p.document.version, 'v1');          // unchanged, still enforced
});

test('every way our service can fail leaves the last good policy enforced', async () => {
  for (const failure of [
    () => { throw new Error('ECONNREFUSED'); },
    () => ({ status: 500, ok: false, headers: { get: () => null } }),
    () => ({ status: 200, ok: true, headers: { get: () => null }, json: async () => { throw new Error('not json'); } }),
    () => ({ status: 200, ok: true, headers: { get: () => null }, json: async () => ({ rules: 'nonsense' }) }),
    () => ({ status: 200, ok: true, headers: { get: () => null }, json: async () => ({ default: 'maybe', rules: [] }) }),
  ]) {
    const events = [];
    const p = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(),
                                 onEvent: e => events.push(e.type), fetchImpl: fakeFetch([ok(DOC), failure]) });
    await p.start();
    await p.refresh();
    assert.equal(p.document.version, 'v1', 'last good policy survived ' + events.at(-1));
    assert.deepEqual(compilePolicy(p.document).rules.suspected_bot, [['/api', false]]);
  }
});

test('a cold start with nothing reachable enforces nothing, and does not throw', async () => {
  const events = [];
  const p = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(),
                               onEvent: e => events.push(e.type),
                               fetchImpl: fakeFetch([() => { throw new Error('dns'); }]) });
  await p.start();                                  // resolves, does not reject
  assert.equal(p.document, null);
  assert.deepEqual(p.compiled().rules, {});
  assert.ok(events.includes('policy.unreachable'));
});

test('a restart during an outage keeps enforcing what was last known', async () => {
  const path = await cacheFile();
  const first = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: path, fetchImpl: fakeFetch([ok(DOC)]) });
  await first.start();
  // Same process gone, service still down.
  const second = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: path,
                                    fetchImpl: fakeFetch([() => { throw new Error('still down'); }]) });
  await second.start();
  assert.equal(second.document.version, 'v1');
  assert.deepEqual(second.compiled().rules.suspected_bot, [['/api', false]]);
});

test('a cache written for another endpoint is not trusted for this one', async () => {
  const path = await cacheFile();
  await writeFile(path, JSON.stringify({ url: 'https://elsewhere.example/v1/policy', document: DOC }));
  const p = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: path,
                               fetchImpl: fakeFetch([() => { throw new Error('down'); }]) });
  await p.start();
  assert.equal(p.document, null);
});

test('deleting the policy stops enforcement rather than leaving the old one', async () => {
  const path = await cacheFile();
  const p = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: path,
                               fetchImpl: fakeFetch([ok(DOC), { status: 404, ok: false, headers: { get: () => null } }]) });
  await p.start();
  await p.refresh();
  assert.equal(p.document, null);
  assert.equal(JSON.parse(await readFile(path, 'utf8')).document, null);
});

test('an unwritable cache is survivable, not fatal', async t => {
  // A read-only directory we made, rather than a path that happens to be
  // unwritable on the machine running this. The previous value was
  // /proc/nope/policy.json, which is a guess about Linux from macOS: /proc
  // does not exist here, so this test was asserting one thing locally and
  // something else on CI.
  const dir = await mkdtemp(join(tmpdir(), 'wl-ro-'));
  await chmod(dir, 0o500);
  t.after(() => chmod(dir, 0o700).catch(() => {}));
  const events = [];
  const p = new RemotePolicy({ apiKey: 'k', refreshMs: 0, cachePath: join(dir, 'policy.json'),
                               onEvent: e => events.push(e.type), fetchImpl: fakeFetch([ok(DOC)]) });
  await p.start();
  assert.equal(p.document.version, 'v1');
  assert.ok(events.includes('policy.cache.unwritable') || events.includes('policy.applied'));
});

test('the acceptance test: a dashboard rule produces a 403 on the next bot request', async () => {
  const gate = new Wayleave({
    policy: { apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(),
              fetchImpl: fakeFetch([ok({ version: 'v1', default: 'allow',
                rules: [{ id: 'block-bots', route: '/api', lane: 'suspected_bot', action: 'deny' }] })]) },
  });
  const bot = { method: 'GET', path: '/api/catalog', ip: '203.0.113.9',
                headers: { 'user-agent': 'python-requests/2.31' } };

  // Before the policy lands, nothing is enforced.
  assert.equal((await gate.handleAsync(bot)).status, 200);

  await gate.ready();
  const after = await gate.handleAsync(bot);
  assert.equal(after.lane, 'suspected_bot');
  assert.equal(after.status, 403);

  // A human on the same path is untouched by a bot rule.
  const human = await gate.handleAsync({ method: 'GET', path: '/api/catalog', ip: '198.51.100.4',
    headers: { 'user-agent': 'Mozilla/5.0 (Macintosh)', 'accept-language': 'en-US' } });
  assert.equal(human.status, 200);
  gate.close();
});

test('local configuration is untouched by a fetched policy', async () => {
  // The old shape compiled the remote policy into rules/rateLimits and merged.
  // The spec's shape evaluates per request, so local config is now genuinely a
  // floor: nothing overwrites it, and the policy is consulted alongside it.
  const gate = new Wayleave({
    rules: { suspected_bot: [['/admin', false]] },
    rateLimits: { declared_agent: 10 },
    policy: { apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(),
              fetchImpl: fakeFetch([ok({ version: 'v1', default: 'allow',
                rules: [{ id: 'q', lane: 'declared_agent', action: 'quota', quota: { limit: 99, windowSeconds: 60 } }] })]) },
  });
  await gate.ready();
  assert.deepEqual(gate.rules.suspected_bot, [['/admin', false]]);
  assert.equal(gate.rateLimits.declared_agent, 10, 'local limit not overwritten');
  assert.equal(gate.policy.document.version, 'v1', 'policy held for per-request evaluation');
  gate.close();
});

test('a denial carries the rule id that caused it', async () => {
  const gate = new Wayleave({
    policy: { apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(),
      fetchImpl: fakeFetch([ok({ version: 'v1', default: 'allow',
        rules: [{ id: 'block-unverified', route: '/api', verified: false, action: 'deny' }] })]) },
  });
  await gate.ready();
  const r = await gate.handleAsync({ method: 'GET', path: '/api/catalog', ip: '203.0.113.9',
                                     headers: { 'user-agent': 'python-requests/2.31' } });
  assert.equal(r.status, 403);
  assert.equal(r.ruleId, 'block-unverified');
  assert.equal(r.headers['x-wayleave-rule'], 'block-unverified');
  gate.close();
});

test('a quota denial is 429 with Retry-After, not a bare 403', async () => {
  let n = 0;
  const gate = new Wayleave({
    rateWindow: 60,
    quotaStore: { consume: async () => ++n <= 2 },
    policy: { apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(),
      fetchImpl: fakeFetch([ok({ version: 'v1', default: 'allow',
        rules: [{ id: 'cap', route: '/api', action: 'quota', quota: { limit: 2, windowSeconds: 60 } }] })]) },
  });
  await gate.ready();
  const call = () => gate.handleAsync({ method: 'GET', path: '/api/x', ip: '198.51.100.7',
                                        headers: { 'user-agent': 'python-requests/2.31' } });
  assert.equal((await call()).status, 200);
  assert.equal((await call()).status, 200);
  const third = await call();
  assert.equal(third.status, 429);
  assert.equal(third.headers['retry-after'], '60');
  gate.close();
});

test('a policy that throws during evaluation still serves the request', async () => {
  const gate = new Wayleave({
    quotaStore: { consume: async () => { throw new Error('store gone'); } },
    policy: { apiKey: 'k', refreshMs: 0, cachePath: await cacheFile(),
      fetchImpl: fakeFetch([ok({ version: 'v1', default: 'allow',
        rules: [{ id: 'cap', route: '/api', action: 'quota', quota: { limit: 1, windowSeconds: 60 } }] })]) },
  });
  await gate.ready();
  // The engine turns a throwing store into a deny, which is right for a quota.
  // What must never happen is an exception reaching the request.
  const r = await gate.handleAsync({ method: 'GET', path: '/api/x', ip: '198.51.100.8',
                                     headers: { 'user-agent': 'python-requests/2.31' } });
  assert.ok([403, 429].includes(r.status), 'denied, not thrown: ' + r.status);
  gate.close();
});
