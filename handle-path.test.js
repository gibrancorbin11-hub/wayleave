/**
 * handle() outside Express.
 *
 * The docs say `gate.handle(req)` works "for any framework". It did not: it
 * read `req.path`, which is an Express property. Node's own server, Fastify,
 * Hono and anything handing you a raw request put the path on `req.url`, with
 * the query still attached. So `req.path` was undefined, no priced prefix
 * matched, no rule matched, and the answer was 200 — on a route the operator
 * had priced, with a receipt recording no path at all.
 *
 * A bypass that needs no attacker: the developer just isn't using Express.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { Wayleave, requestPath } from './index.js';

const AGENT = { 'user-agent': 'GPTBot/1.0' };
const priced = (over = {}) => new Wayleave({
  pricedPaths: { '/api/premium': 0.05 },
  onWarn: () => {},
  ...over,
});

test('a priced route answers 402 whether the caller passes path or url', () => {
  const gate = priced();
  for (const req of [
    { method: 'GET', path: '/api/premium', headers: AGENT },
    { method: 'GET', url: '/api/premium', headers: AGENT },
    { method: 'GET', url: '/api/premium?q=1', headers: AGENT },
    { method: 'GET', url: '/api/premium#frag', headers: AGENT },
    { method: 'GET', url: '/api/premium/deep?a=b', headers: AGENT },
  ]) {
    const d = gate.handle(req);
    assert.equal(d.status, 402, `${req.path ?? req.url} should have been asked to pay`);
  }
});

test('a rule denies by url too, not only by path', () => {
  const gate = new Wayleave({ rules: { declared_agent: [['/admin', false]] }, onWarn: () => {} });
  assert.equal(gate.handle({ method: 'GET', url: '/admin/users?page=2', headers: AGENT }).status, 403);
  assert.equal(gate.handle({ method: 'GET', path: '/admin/users', headers: AGENT }).status, 403);
});

test('a route that was never priced still passes, url or path', () => {
  const gate = priced();
  assert.equal(gate.handle({ method: 'GET', url: '/public?x=1', headers: AGENT }).status, 200);
});

test('the receipt records the path, with no query string in it', () => {
  const seen = [];
  const gate = priced({ sink: { emit: e => seen.push(e), flush: () => {} } });
  gate.handle({ method: 'GET', url: '/api/premium?token=secret&q=2', headers: AGENT });
  assert.equal(seen[0].path, '/api/premium',
    'a query string in a receipt is user data nobody asked us to store');
});

test('an Express request is untouched — the object it hands us is not modified', () => {
  const gate = priced();
  const req = { method: 'GET', path: '/api/premium', url: '/api/premium?q=1', headers: AGENT };
  const before = { ...req };
  gate.handle(req);
  assert.deepEqual({ ...req }, before, 'we must never write to the caller’s request');
});

test('handleAsync agrees with handle about what the path is', async () => {
  const gate = priced();
  const a = gate.handle({ method: 'GET', url: '/api/premium?x=1', headers: AGENT });
  const b = await gate.handleAsync({ method: 'GET', url: '/api/premium?x=1', headers: AGENT });
  assert.equal(a.status, 402);
  assert.equal(b.status, 402);
});

test('requestPath survives the shapes a request object actually arrives in', () => {
  assert.equal(requestPath({ path: '/a' }), '/a');
  assert.equal(requestPath({ url: '/a?b=c' }), '/a');
  assert.equal(requestPath({ url: '/a#f' }), '/a');
  assert.equal(requestPath({ path: '/a', url: '/zzz' }), '/a', 'path wins when both are present');
  assert.equal(requestPath({}), '/');
  assert.equal(requestPath({ url: '' }), '/');
  assert.equal(requestPath(null), '/');
  assert.equal(requestPath({ url: '?only=query' }), '/');
});

/* ── the other silent under-enforcement ──────────────────────────────────
   A remote policy is a signed document fetched over the network. handle() is
   synchronous, so it cannot evaluate one. That is inherent, not a bug — but
   an operator who configured a policy and calls handle() is running with no
   policy at all, and has no way to know. */

/* ── one policy, both paths ───────────────────────────────────────────────
   handle() used to skip policy evaluation entirely: the same signed document
   enforced through express() and was ignored through handle(), so one policy
   behaved as two. Everything that needs no I/O is decided on both paths now,
   and the one thing that cannot be — a quota rule, which means consulting a
   store over the network — refuses rather than passes. Passing it would let
   through exactly the traffic the operator metered. */

const withPolicy = (rules, over = {}) => {
  const gate = new Wayleave({ onWarn: over.onWarn || (() => {}), ...over });
  // Stand in for a fetched, verified document.
  gate.policy = { document: { version: 'v1', default: 'allow', rules }, tenant: 'self' };
  return gate;
};

test('a deny rule answers 403 on both paths, with the same rule id', async () => {
  const rules = [{ id: 'block-bots', lane: 'declared_agent', route: '/api', action: 'deny' }];
  const req = { method: 'GET', url: '/api/data', headers: AGENT };

  const sync = withPolicy(rules).handle(req);
  const async_ = await withPolicy(rules).handleAsync(req);

  assert.equal(sync.status, 403);
  assert.equal(async_.status, 403);
  assert.equal(sync.ruleId, 'block-bots');
  assert.equal(async_.ruleId, 'block-bots', 'the same document must name the same rule');
  assert.equal(sync.headers['x-wayleave-rule'], async_.headers['x-wayleave-rule']);
});

test('a pay rule answers 402 on both paths, with the same price', async () => {
  const rules = [{ id: 'priced', route: '/api', action: 'pay', priceMicros: 50_000, rail: 'x402' }];
  const req = { method: 'GET', url: '/api/data', headers: AGENT };

  const sync = withPolicy(rules).handle(req);
  const async_ = await withPolicy(rules).handleAsync(req);

  assert.equal(sync.status, 402);
  assert.equal(async_.status, 402);
  assert.equal(sync.challenge.price_usd, 0.05);
  assert.equal(async_.challenge.price_usd, 0.05);
  assert.equal(sync.ruleId, async_.ruleId);
});

test('the rule that decided reaches the meter from both paths', async () => {
  const rules = [{ id: 'block-bots', lane: 'declared_agent', route: '/api', action: 'deny' }];
  const req = { method: 'GET', url: '/api/data', headers: AGENT };

  const a = [], b = [];
  withPolicy(rules, { sink: { emit: e => a.push(e), flush: () => {} } }).handle(req);
  await withPolicy(rules, { sink: { emit: e => b.push(e), flush: () => {} } }).handleAsync(req);

  assert.equal(a[0].ruleId, 'block-bots');
  assert.equal(b[0].ruleId, 'block-bots',
    'a denial arriving at the meter with no rule on it cannot answer "which rule refused this?"');
});

test('a quota rule on the sync path refuses, and says which call to use', () => {
  const said = [];
  const gate = withPolicy(
    [{ id: 'per-agent', route: '/api', action: 'quota', quota: { limit: 10, windowSeconds: 60 } }],
    { onWarn: m => said.push(m) });

  const d = gate.handle({ method: 'GET', url: '/api/data', headers: AGENT });
  assert.equal(d.status, 403, 'passing a metered rule is worse than refusing it');
  assert.equal(d.why, 'quota rule requires handleAsync');
  assert.equal(d.ruleId, 'per-agent');
  assert.equal(said.length, 1);
  assert.match(said[0], /handleAsync/);

  gate.handle({ method: 'GET', url: '/api/data', headers: AGENT });
  assert.equal(said.length, 1, 'said once, not once per request');
});

test('a rule that does not match leaves the ordinary decision alone', () => {
  const gate = withPolicy([{ id: 'other', route: '/admin', action: 'deny' }]);
  assert.equal(gate.handle({ method: 'GET', url: '/api/data', headers: AGENT }).status, 200);
});

test('no policy document, no policy decision', () => {
  const gate = new Wayleave({ onWarn: () => {} });
  assert.equal(gate.handle({ method: 'GET', url: '/api/data', headers: AGENT }).status, 200);
});

test('no policy configured, no policy warning — the common case stays quiet', () => {
  const said = [];
  const gate = new Wayleave({
    pricedPaths: { '/api': 0.01 },
    confirmHuman: () => false,          // else the strict-mode warning fires, rightly
    onWarn: m => said.push(m),
  });
  gate.handle({ method: 'GET', url: '/api', headers: AGENT });
  assert.deepEqual(said, [], 'a gate with no remote policy has nothing to warn about');
});
