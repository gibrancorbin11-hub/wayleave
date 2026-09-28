/**
 * The two holes fixed in 0.5.2.
 *
 * Both were live in 0.5.1, in the package that sits in a customer's request
 * path. Both are the kind that fail quietly: the gate kept answering, it just
 * answered about the wrong routes.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import Wayleave, { pathUnder } from './index.js';
import { RemotePolicy } from './policy.js';

const BOT = { 'user-agent': 'python-requests/2.31.0' };
const ask = (gate, path) =>
  gate.handle({ method: 'GET', path, authority: 'x.test', headers: BOT }).status;

// ── prefix boundaries ─────────────────────────────────────────────────────

test('a prefix matches at a path boundary, not as a string', () => {
  assert.equal(pathUnder('/api', '/api'), true);
  assert.equal(pathUnder('/api/search', '/api'), true);
  assert.equal(pathUnder('/api/search', '/api/'), true, 'a trailing slash changes nothing');
  assert.equal(pathUnder('/apiv2', '/api'), false);
  assert.equal(pathUnder('/api-internal', '/api'), false);
  assert.equal(pathUnder('/apis', '/api'), false);
  assert.equal(pathUnder('/anything', '/'), true, 'root covers everything');
});

test('pricing does not leak onto a neighbouring route', () => {
  const gate = new Wayleave({ pricedPaths: { '/api': 0.05 } });
  assert.equal(ask(gate, '/api'), 402);
  assert.equal(ask(gate, '/api/search'), 402);
  assert.equal(ask(gate, '/apiv2/free'), 200,
    'charging for a route the operator never priced is billing someone for nothing');
  assert.equal(ask(gate, '/api-internal/keys'), 200);
});

test('an ALLOW rule does not open a route beside it', () => {
  // The shape an operator writes: open one path, close the rest.
  const gate = new Wayleave({ rules: { suspected_bot: [['/public', true], ['/', false]] } });
  assert.equal(ask(gate, '/public'), 200);
  assert.equal(ask(gate, '/public/docs'), 200);
  assert.equal(ask(gate, '/public-admin'), 403,
    'an over-matching allow is a hole; an over-matching deny is only annoying');
  assert.equal(ask(gate, '/private'), 403);
});

test('a DENY rule does not spill onto a neighbouring route', () => {
  const gate = new Wayleave({ rules: { suspected_bot: [['/admin', false]] } });
  assert.equal(ask(gate, '/admin'), 403);
  assert.equal(ask(gate, '/admin/users'), 403);
  assert.equal(ask(gate, '/administrators'), 200);
});

// ── unsigned policy ───────────────────────────────────────────────────────

test('a remote policy with no signing key is refused', () => {
  assert.throws(
    () => new RemotePolicy({ url: 'https://policy.example.com/p.json' }),
    /publicKey/,
    'whoever can answer that URL would otherwise write the access rules');
});

test('unsigned is available, but has to be asked for', () => {
  assert.doesNotThrow(
    () => new RemotePolicy({ url: 'https://policy.example.com/p.json', allowUnsigned: true }));
});

test('the meter path is unaffected: its channel is already authenticated', () => {
  // apiKey fetches from the customer's own meter over TLS with their key.
  // The signature is defence in depth there; on a public URL it is the only
  // defence. Requiring it in both places would break every existing install
  // to fix a hole that only exists in one of them.
  assert.doesNotThrow(() => new RemotePolicy({ apiKey: 'wm_live_x' }));
});

test('a signing key is all it takes', () => {
  assert.doesNotThrow(
    () => new RemotePolicy({ url: 'https://policy.example.com/p.json', publicKey: 'x' }));
});

test('even with the field cleared afterwards, a fetch will not apply an unsigned document', async () => {
  const p = new RemotePolicy({ url: 'https://policy.example.com/p.json', publicKey: 'x' });
  p.publicKey = null;                       // simulate a caller clearing it
  const events = [];
  p.onEvent = (e) => events.push(e);
  p._fetch = async () => ({ ok: true, status: 200, headers: { get: () => null },
                            json: async () => ({ version: '1', rules: [] }) });
  const doc = await p.refresh();
  assert.equal(doc, null, 'nothing is applied');
  assert.ok(events.some(e => /rejected/.test(e.type || '')),
    'and it says why rather than failing silently');
});
