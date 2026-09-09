/**
 * Signer-side nonces, and the single-use guarantee they buy.
 *
 * Before this, `verifySignature` read a nonce it had no way to be sent:
 * nothing in the package could produce one, so `replayProtection` was
 * configuration with no effect. These tests fix that shape in place — a
 * signature with a nonce is good exactly once, and one without keeps the old
 * behaviour, because an agent that retries with held headers depends on it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import Wayleave, { signRequest, verifySignature, buildParams } from './index.js';

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const DIR = 'https://agent.example/keys';
const KEYID = 'k1';
const AUTH = 'example.test';
const dirs = { [DIR]: { [KEYID]: publicKey } };

const req = (headers) => ({
  method: 'GET', path: '/api/data', authority: AUTH, headers, ip: '203.0.113.9',
});

test('buildParams omits nonce entirely when there is none', () => {
  assert.ok(!buildParams(KEYID, 1, 2).includes('nonce'));
  assert.ok(buildParams(KEYID, 1, 2, 'abc').includes(';nonce="abc"'));
});

test('a signature carrying a nonce still verifies', () => {
  const h = signRequest({}, AUTH, privateKey, KEYID, DIR, undefined, undefined, true);
  const v = verifySignature(h, AUTH, dirs);
  assert.equal(v.ok, true, v.reason);
  assert.ok(v.nonce, 'the verifier reported no nonce to remember');
});

test('two signings produce two different nonces', () => {
  const a = signRequest({}, AUTH, privateKey, KEYID, DIR, undefined, undefined, true);
  const b = signRequest({}, AUTH, privateKey, KEYID, DIR, undefined, undefined, true);
  assert.notEqual(verifySignature(a, AUTH, dirs).nonce, verifySignature(b, AUTH, dirs).nonce);
});

test('a caller-supplied nonce is used verbatim', () => {
  const h = signRequest({}, AUTH, privateKey, KEYID, DIR, undefined, undefined, 'my-nonce-1');
  assert.ok(h['signature-input'].includes(';nonce="my-nonce-1"'));
  assert.equal(verifySignature(h, AUTH, dirs).ok, true);
});

test('a nonced signature crosses once and is refused the second time', () => {
  const gate = new Wayleave({ directories: dirs });
  const h = signRequest({}, AUTH, privateKey, KEYID, DIR, undefined, undefined, true);

  const first = gate.handle(req({ ...h }));
  assert.equal(first.status, 200, first.why);

  // The lane stays verified_agent on the replay, and should: the signature is
  // genuinely valid. It is the policy that refuses it, so the refusal shows up
  // as the status, not as a downgraded lane.
  const replay = gate.handle(req({ ...h }));
  assert.equal(replay.status, 403,
    'the same nonced signature was accepted twice — replay protection is inert');
  assert.match(replay.why, /replay/);
});

test('without a nonce the old behaviour is preserved, so retries still work', () => {
  const gate = new Wayleave({ directories: dirs });
  const h = signRequest({}, AUTH, privateKey, KEYID, DIR);
  assert.equal(gate.handle(req({ ...h })).status, 200);
  assert.equal(gate.handle(req({ ...h })).status, 200,
    'an unnonced retry was rejected — this would break agents that resend held headers');
});

test('one agent cannot burn another agent nonce value', () => {
  const other = crypto.generateKeyPairSync('ed25519');
  const OTHER_DIR = 'https://other.example/keys';
  const gate = new Wayleave({
    directories: { ...dirs, [OTHER_DIR]: { [KEYID]: other.publicKey } },
  });
  const a = signRequest({}, AUTH, privateKey, KEYID, DIR, undefined, undefined, 'same-value');
  const b = signRequest({}, AUTH, other.privateKey, KEYID, OTHER_DIR, undefined, undefined, 'same-value');
  assert.equal(gate.handle(req({ ...a })).status, 200);
  assert.equal(gate.handle(req({ ...b })).status, 200,
    'a nonce from one directory blocked an identical value from another');
});
