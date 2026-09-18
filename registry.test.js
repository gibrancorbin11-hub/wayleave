/**
 * Registry v1.
 *
 * Like the policy tests, most of these are outage tests, because the promise
 * is that a registry failure is invisible to a customer's users. The one that
 * matters most is the last: no cache and nothing reachable must behave exactly
 * as if no directory were configured.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { Registry, verifyRegistry, buildIndex } from './registry.js';
import { canonical } from './policy.js';
import Wayleave from './index.js';

const cacheFile = async () => join(await mkdtemp(join(tmpdir(), 'wl-reg-')), 'registry.json');

const root = generateKeyPairSync('ed25519');
const ROOT_PEM = root.publicKey.export({ type: 'spki', format: 'pem' });
const other = generateKeyPairSync('ed25519');

const AGENT_KEY = 'ZmFrZS1wdWJsaWMta2V5LWJ5dGVzLWZvci10ZXN0cw';
const AGENTS = [{
  id: 'agents.example.com/research',
  operator: 'Example Research',
  source: 'https://agents.example.com/.well-known/http-message-signatures-directory',
  listed: '2026-09-18',
  status: 'listed',
  keys: [{ keyid: 'k1', scheme: 'ed25519', pubkey: AGENT_KEY, status: 'active' }],
}];

function envelope({ agents = AGENTS, key = root.privateKey, ttlMs = 7 * 86400_000, now = Date.now() } = {}) {
  const body = { v: 1, issued: new Date(now).toISOString(),
                 expires: new Date(now + ttlMs).toISOString(), agents };
  return { ...body, sig: edSign(null, Buffer.from(canonical(body), 'utf8'), key).toString('base64') };
}
const ok = body => ({ status: 200, ok: true, json: async () => body });
const fakeFetch = script => {
  const calls = [];
  const fn = async () => {
    calls.push(1);
    const next = script[Math.min(calls.length - 1, script.length - 1)];
    return typeof next === 'function' ? next() : next;
  };
  fn.calls = calls;
  return fn;
};

test('a signed list verifies, and anything touched stops verifying', () => {
  const env = envelope();
  assert.equal(verifyRegistry(env, [ROOT_PEM]).ok, true);

  // A CDN serving something else is the threat the signature exists for.
  const injected = { ...env, agents: [{ ...AGENTS[0], keys: [{ keyid: 'k1', scheme: 'ed25519', pubkey: 'attacker', status: 'active' }] }] };
  assert.equal(verifyRegistry(injected, [ROOT_PEM]).ok, false);

  assert.match(verifyRegistry(env, [other.publicKey.export({ type: 'spki', format: 'pem' })]).reason,
               /does not match any pinned root key/);
  // Unconfigured must be inert, never permissive.
  assert.match(verifyRegistry(env, []).reason, /no root key pinned/);
});

test('rotation accepts both keys, which is what makes it not a flag day', () => {
  const env = envelope();
  const newKey = other.publicKey.export({ type: 'spki', format: 'pem' });
  assert.equal(verifyRegistry(env, [newKey, ROOT_PEM]).ok, true);   // newest first, old still accepted
  assert.equal(verifyRegistry(env, [newKey]).ok, false);            // a version later, old is gone
});

test('an expired list is refused, and expiry is checked after the signature', () => {
  const stale = envelope({ now: Date.now() - 14 * 86400_000, ttlMs: 7 * 86400_000 });
  assert.match(verifyRegistry(stale, [ROOT_PEM]).reason, /expired/);
  assert.equal(verifyRegistry(stale, [ROOT_PEM], { graceMs: 14 * 86400_000 }).ok, true);
  const forged = { ...stale, expires: new Date(Date.now() + 9e9).toISOString() };
  assert.match(verifyRegistry(forged, [ROOT_PEM]).reason, /signature does not match/);
});

test('a key with no source is dropped, because a key we cannot trace is a key we guessed', () => {
  const index = buildIndex([
    { id: 'a', source: 'https://a.example/.well-known/d', keys: [{ keyid: 'k', scheme: 'ed25519', pubkey: 'p' }] },
    { id: 'b', keys: [{ keyid: 'k2', scheme: 'ed25519', pubkey: 'p2' }] },                     // no source
    { id: 'c', source: 'https://c.example/.well-known/d', status: 'delisted',
      keys: [{ keyid: 'k3', scheme: 'ed25519', pubkey: 'p3' }] },                              // delisted
    { id: 'd', source: 'https://d.example/.well-known/d',
      keys: [{ keyid: 'k4', scheme: 'secp256k1', pubkey: 'p4' },                               // unsupported scheme
             { keyid: 'k5', scheme: 'ed25519', pubkey: 'p5', status: 'revoked' }] },           // revoked
  ]);
  assert.deepEqual([...index.keys()], ['https://a.example/.well-known/d']);
  assert.deepEqual(index.get('https://a.example/.well-known/d'), { k: 'p' });
});

test('a listed operator resolves by the endpoint it published at', async () => {
  const r = new Registry({ rootKeys: [ROOT_PEM], refreshMs: 0, cachePath: await cacheFile(),
                           fetchImpl: fakeFetch([ok(envelope())]) });
  await r.start();
  const resolve = r.resolver();
  assert.deepEqual(resolve(AGENTS[0].source), { k1: AGENT_KEY });
  assert.equal(resolve('https://unlisted.example/.well-known/d'), undefined);
  assert.deepEqual(r.stats(), { directories: 1, keys: 1, listed: 1 });
});

test('every failure keeps the last good list', async () => {
  for (const failure of [
    () => { throw new Error('ECONNREFUSED'); },
    () => ({ status: 500, ok: false }),
    () => ({ status: 200, ok: true, json: async () => { throw new Error('not json'); } }),
    () => ok(envelope({ key: other.privateKey })),          // signed by the wrong key
    () => ok({ ...envelope(), agents: 'nonsense' }),
  ]) {
    const r = new Registry({ rootKeys: [ROOT_PEM], refreshMs: 0, cachePath: await cacheFile(),
                             fetchImpl: fakeFetch([ok(envelope()), failure]) });
    await r.start();
    await r.refresh();
    assert.deepEqual(r.resolver()(AGENTS[0].source), { k1: AGENT_KEY }, 'last good list survived');
  }
});

test('a cache is re-verified, not trusted because it is on disk', async () => {
  const path = await cacheFile();
  // Someone edits the cache file to inject a key.
  await writeFile(path, JSON.stringify({ url: 'https://registry.wayleave.dev/v1/agents.json',
    envelope: { ...envelope(), agents: [{ ...AGENTS[0], keys: [{ keyid: 'evil', scheme: 'ed25519', pubkey: 'x', status: 'active' }] }] } }));
  const r = new Registry({ rootKeys: [ROOT_PEM], refreshMs: 0, cachePath: path,
                           fetchImpl: fakeFetch([() => { throw new Error('offline'); }]) });
  await r.start();
  assert.equal(r.resolver()(AGENTS[0].source), undefined, 'tampered cache rejected');
});

test('a restart during an outage keeps resolving what was last known', async () => {
  const path = await cacheFile();
  const first = new Registry({ rootKeys: [ROOT_PEM], refreshMs: 0, cachePath: path,
                               fetchImpl: fakeFetch([ok(envelope())]) });
  await first.start();
  const second = new Registry({ rootKeys: [ROOT_PEM], refreshMs: 0, cachePath: path,
                                fetchImpl: fakeFetch([() => { throw new Error('still down'); }]) });
  await second.start();
  assert.deepEqual(second.resolver()(AGENTS[0].source), { k1: AGENT_KEY });
});

test('cold start with nothing reachable behaves exactly as if no directory were configured', async () => {
  // If this one fails, nothing else counts.
  const withRegistry = new Wayleave({ directories: 'wayleave:default',
    registry: { rootKeys: [ROOT_PEM], refreshMs: 0, cachePath: await cacheFile(),
                fetchImpl: fakeFetch([() => { throw new Error('dns')} ]) } });
  await withRegistry.ready();
  const without = new Wayleave({});

  const req = { method: 'GET', path: '/api/data', ip: '203.0.113.5',
                headers: { 'user-agent': 'python-requests/2.31' } };
  const a = await withRegistry.handleAsync(req);
  const b = await without.handleAsync(req);
  assert.equal(a.status, b.status);
  assert.equal(a.lane, b.lane, 'an unknown agent stays unknown; it does not become suspected');
  withRegistry.close();
});

test('with no root key pinned, wayleave:default resolves nothing rather than everything', async () => {
  const r = new Registry({ refreshMs: 0, cachePath: await cacheFile(), fetchImpl: fakeFetch([ok(envelope())]) });
  await r.start();
  assert.equal(r.resolver()(AGENTS[0].source), undefined);
  assert.deepEqual(r.stats(), { directories: 0, keys: 0, listed: 0 });
});
