/**
 * The acceptance test PLATFORM-PLAN gates the platform on:
 *
 *   a stranger sets "deny unverified on /api/*", sees it enforced, sets
 *   allow, sees it enforced, blocks the policy URL, and traffic still flows.
 *
 * This drives the REAL meter over a real socket and the REAL gate fetching
 * over HTTP with a real Ed25519 signature. The only doubles are the database
 * and the clock. Skipped when the meter checkout is absent, so the package
 * suite still runs for anyone who only has the gate.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RemotePolicy } from './policy.js';

const METER = '/Users/gibrancorbin/Desktop/business domains/wayleave-meter';
/* The policy is SET by a human with a dashboard session and READ by a gate
   from the public signed URL. That separation is load-bearing, so the test
   uses each door the way the product does. */
const SESSION = 'session-token-for-the-stranger';

/* Both tables this path touches. Rows only, no query planner. */
function fakeSb() {
  const state = { policies: [], customer: { id: 'cust-A', policy_public_id: null } };
  const table = name => ({
    insert(v) { state.policies.push(v); return { error: null }; },
    update(patch) {
      let guardNull = false;
      const c = {
        eq: () => c,
        is: () => { guardNull = true; return c; },
        select: () => c,
        maybeSingle: async () => {
          if (guardNull && state.customer.policy_public_id !== null) return { data: null, error: null };
          Object.assign(state.customer, patch);
          return { data: { policy_public_id: state.customer.policy_public_id }, error: null };
        },
      };
      return c;
    },
    select() {
      let wantedPublicId;
      const c = {
        eq: (col, val) => { if (col === 'policy_public_id') wantedPublicId = val; return c; },
        order: () => c,
        limit: async () => {
          const newest = state.policies[state.policies.length - 1];
          return { data: newest ? [{ document: newest.document, version: newest.version }] : [], error: null };
        },
        maybeSingle: async () => {
          if (wantedPublicId !== undefined)
            return { data: state.customer.policy_public_id === wantedPublicId ? state.customer : null, error: null };
          return { data: state.customer, error: null };
        },
      };
      return c;
    },
  });
  return { state, from: table, async rpc() { return { data: true, error: null }; } };
}

const fakeDb = customer => ({
  sb: {},
  async customerByAuthUser(id) { return id === 'auth-user-1' ? customer : null; },
  touchKey() {},
});

const fakeAuth = () => ({
  auth: {
    async getUser(token) {
      return token === SESSION
        ? { data: { user: { id: 'auth-user-1', email: 'stranger@example.com' } }, error: null }
        : { data: null, error: { message: 'invalid session' } };
    },
  },
});

const denyOn = route => ({ version: 'ignored', default: 'allow',
  rules: [{ id: 'block', route, lane: 'suspected_bot', action: 'deny' }] });
const allowOn = route => ({ version: 'ignored', default: 'allow',
  rules: [{ id: 'block', route, lane: 'suspected_bot', action: 'allow' }] });

/** Does the compiled policy deny this lane on this path? */
function denies(policy, lane, path) {
  const rules = policy.compiled().rules[lane] || [];
  const hit = rules.filter(([prefix]) => path === prefix || path.startsWith(prefix.replace(/\/$/, '') + '/'));
  return hit.length > 0 && hit.every(([, allowed]) => allowed === false);
}

test('a policy is set, served signed, enforced, changed, and survives our outage', async t => {
  try { await access(METER); } catch { return t.skip('meter checkout not present'); }

  const { createApp } = await import(`${METER}/src/server.js`);
  const { PolicyStore } = await import(`${METER}/src/policy-store.js`);
  const { generateRootKeyPair } = await import(`${METER}/src/policy-signing.js`);
  const { createPrivateKey, createPublicKey } = await import('node:crypto');

  const { privateKeyPem, publicKeyPem } = generateRootKeyPair();
  const sb = fakeSb();
  const policies = new PolicyStore(sb);

  const server = createServer(createApp({
    db: fakeDb(sb.state.customer), facilitator: { name: 'none' }, policies,
    policyKey: createPrivateKey(privateKeyPem),
    sbAuth: fakeAuth(),
    publicUrl: 'http://policy.test',
  }));
  await new Promise(r => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => new Promise(r => server.close(r)));

  const put = body => fetch(`${base}/v1/account/policy`, {
    method: 'PUT',
    headers: { authorization: `Bearer ${SESSION}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

  // 1 — the stranger sets "deny suspected bots on /api".
  const first = await put(denyOn('/api'));
  assert.equal(first.status, 200, 'saving a policy must succeed');
  const { publicId } = await first.json();
  assert.ok(publicId, 'a saved policy must come with a public URL to fetch it from');

  // 2 — the gate fetches it, unauthenticated, and verifies the signature.
  const gate = new RemotePolicy({
    url: `${base}/v1/policy/public/${publicId}.json`,
    publicKey: createPublicKey(publicKeyPem),
    refreshMs: 0,
    cachePath: join(tmpdir(), `wl-accept-${process.pid}-${Date.now()}.json`),
  });
  await gate.start();
  assert.ok(gate.document, 'the gate must end up holding a verified document');
  assert.equal(denies(gate, 'suspected_bot', '/api/data'), true, 'the rule the stranger set must be enforced');
  assert.equal(denies(gate, 'human', '/api/data'), false, 'humans are never walled');

  // 3 — they change their mind. A new version, never a mutation of the old.
  const second = await put(allowOn('/api'));
  assert.equal(second.status, 200);
  const { publicId: again } = await second.json();
  assert.equal(again, publicId, 'the public URL must not rotate under an existing gate');
  await gate.refresh();
  assert.equal(denies(gate, 'suspected_bot', '/api/data'), false, 'the change must reach the gate');

  // 4 — we go down. Traffic must not.
  await new Promise(r => server.close(r));
  const lastKnown = gate.document;
  await gate.refresh();
  assert.deepEqual(gate.document, lastKnown, 'an outage of ours must not change what the gate enforces');
  assert.equal(denies(gate, 'human', '/api/data'), false, 'traffic still flows while we are unreachable');
  gate.stop();
});

/* Signing is the only reason the public document can be unauthenticated and
   cacheable. If a tampered document were accepted, anything on the path could
   rewrite a customer's policy. */
test('a tampered policy document is refused and the last good one is kept', async t => {
  try { await access(METER); } catch { return t.skip('meter checkout not present'); }
  const { generateRootKeyPair, signPolicyDocument } = await import(`${METER}/src/policy-signing.js`);
  const { createPublicKey } = await import('node:crypto');
  const { privateKeyPem, publicKeyPem } = generateRootKeyPair();
  const { createPrivateKey } = await import('node:crypto');

  const good = signPolicyDocument({
    tenant: 'pub', policy: denyOn('/api'), privateKey: createPrivateKey(privateKeyPem),
  });
  let serve = good;
  const server = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(serve));
  });
  await new Promise(r => server.listen(0, r));
  t.after(() => new Promise(r => server.close(r)));

  const gate = new RemotePolicy({
    url: `http://127.0.0.1:${server.address().port}/p.json`,
    publicKey: createPublicKey(publicKeyPem),
    refreshMs: 0,
    cachePath: join(tmpdir(), `wl-tamper-${process.pid}-${Date.now()}.json`),
  });
  await gate.start();
  assert.equal(denies(gate, 'suspected_bot', '/api/x'), true);

  // Flip the rule to allow, leaving the signature over the original bytes.
  serve = { ...good, policy: allowOn('/api') };
  await gate.refresh();
  assert.equal(denies(gate, 'suspected_bot', '/api/x'), true,
    'a forged policy must not take effect — the last verified one stands');
  gate.stop();
});
