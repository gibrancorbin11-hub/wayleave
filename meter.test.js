import test from 'node:test';
import assert from 'node:assert/strict';
import { MeterSink } from './meter.js';
import { Wayleave, LANES } from './index.js';

const ev = (i) => ({ v: 1, idempotencyKey: `inst:${i}`, t: 1785600000, path: '/api/x',
                     lane: 'verified_agent', identity: 'dir#k', status: 200, billedUsd: 0.05 });

/** A fetch stand-in that records calls and replies however a test wants. */
function fakeFetch(handler) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body), headers: init.headers });
    return handler(calls.length, calls[calls.length - 1]);
  };
  f.calls = calls;
  return f;
}

const okRes = (body = {}) => ({
  ok: true, status: 200,
  json: async () => ({ accepted: 0, duplicates: 0, rejected: [], ...body }),
});
const errRes = (status, error = 'nope') => ({
  ok: false, status, json: async () => ({ error }),
});

const sink = (fetchImpl, over = {}) => new MeterSink({
  endpoint: 'https://meter.example', apiKey: 'k', fetch: fetchImpl,
  flushMs: 1e9, maxRetries: 2, ...over,
});

// ── the hot path must stay cold ─────────────────────────────────────────

test('emit never throws, even when everything underneath is broken', () => {
  const s = sink(() => { throw new Error('exploded'); });
  // No await, no try/catch at the call site — this is how the gate calls it.
  assert.doesNotThrow(() => s.emit(ev(1)));
});

test('emit does not block on the network', () => {
  let resolved = false;
  const s = sink(async () => { await new Promise(r => setTimeout(r, 50)); resolved = true; return okRes(); });
  s.emit(ev(1));
  // If emit awaited the flush, this would already be true.
  assert.equal(resolved, false, 'emit awaited I/O on the request path');
});

test('a sink that throws inside onError still cannot break serving', () => {
  const s = sink(async () => okRes(), {
    maxBuffer: 1, onError: () => { throw new Error('bad handler'); },
  });
  s.emit(ev(1));
  assert.doesNotThrow(() => s.emit(ev(2)), 'a broken error handler reached the request path');
});

// ── retries are safe because events carry idempotency keys ──────────────

test('a batch is retried after a 5xx, with the same keys', async () => {
  const f = fakeFetch(n => (n === 1 ? errRes(503) : okRes({ accepted: 2 })));
  const s = sink(f, { maxBatch: 10 });
  s.emit(ev(1)); s.emit(ev(2));
  await s.flush();

  assert.equal(f.calls.length, 2, 'batch was not retried');
  assert.deepEqual(
    f.calls[0].body.events.map(e => e.idempotencyKey),
    f.calls[1].body.events.map(e => e.idempotencyKey),
    'the retry sent different keys — the meter could not dedup it',
  );
});

test('duplicates reported by the meter are counted, not treated as failure', async () => {
  const s = sink(fakeFetch(() => okRes({ accepted: 0, duplicates: 3 })), { maxBatch: 10 });
  s.emit(ev(1));
  await s.flush();
  assert.equal(s.stats.duplicates, 3);
  assert.equal(s.stats.failedBatches, 0);
});

test('an unreachable meter requeues rather than discards', async () => {
  const s = sink(fakeFetch(() => errRes(503)), { maxBatch: 10 });
  s.emit(ev(1)); s.emit(ev(2));
  await s.flush();
  assert.equal(s._buffer.length, 2, 'events were lost while the meter was down');
  assert.equal(s.stats.failedBatches, 1);
});

test('a recovered meter drains what was buffered during the outage', async () => {
  let down = true;
  const s = sink(fakeFetch(() => (down ? errRes(503) : okRes({ accepted: 2 }))), { maxBatch: 10 });
  s.emit(ev(1)); s.emit(ev(2));
  await s.flush();
  assert.equal(s._buffer.length, 2);

  down = false;
  await s.flush();
  assert.equal(s._buffer.length, 0, 'buffered events were never delivered after recovery');
  assert.equal(s.stats.sent, 2);
});

// ── permanent failures must not wedge the buffer ────────────────────────

test('a 401 is not retried forever — it can never succeed', async () => {
  const f = fakeFetch(() => errRes(401, 'unknown key'));
  const s = sink(f, { maxBatch: 10 });
  s.emit(ev(1));
  await s.flush();

  assert.equal(f.calls.length, 1, 'a permanently-rejected batch was retried');
  assert.equal(s._buffer.length, 0, 'an unfixable batch stayed in the buffer forever');
  assert.equal(s.stats.dropped, 1);
});

test('a 429 IS retried — it is backpressure, not a bug', async () => {
  const f = fakeFetch(n => (n === 1 ? errRes(429) : okRes({ accepted: 1 })));
  const s = sink(f, { maxBatch: 10 });
  s.emit(ev(1));
  await s.flush();
  assert.equal(f.calls.length, 2);
});

test('events the meter rejects individually are reported, not retried', async () => {
  const errors = [];
  const s = sink(fakeFetch(() => okRes({ accepted: 1, rejected: [{ index: 1, error: 'bad lane' }] })),
                 { maxBatch: 10, onError: (e, i) => errors.push(i) });
  s.emit(ev(1)); s.emit(ev(2));
  await s.flush();
  assert.equal(s._buffer.length, 0);
  assert.equal(errors[0].rejected.length, 1);
});

// ── bounded memory ──────────────────────────────────────────────────────

test('the buffer is bounded, and every drop is counted and reported', () => {
  const reported = [];
  const s = sink(fakeFetch(() => okRes()), {
    maxBuffer: 3, maxBatch: 1000, onError: (e) => reported.push(e.message),
  });
  for (let i = 0; i < 10; i++) s.emit(ev(i));

  assert.equal(s._buffer.length, 3, 'buffer grew past its ceiling');
  assert.equal(s.stats.dropped, 7);
  assert.ok(reported.some(m => /buffer full/.test(m)), 'drops happened silently');
});

test('shedding keeps the newest events', () => {
  const s = sink(fakeFetch(() => okRes()), { maxBuffer: 2, maxBatch: 1000 });
  s.emit(ev(1)); s.emit(ev(2)); s.emit(ev(3));
  assert.deepEqual(s._buffer.map(e => e.idempotencyKey), ['inst:2', 'inst:3']);
});

// ── shutdown ────────────────────────────────────────────────────────────

test('close drains the buffer so a deploy does not cost you revenue', async () => {
  const f = fakeFetch(() => okRes({ accepted: 2 }));
  const s = sink(f, { maxBatch: 10 });
  s.emit(ev(1)); s.emit(ev(2));
  const stats = await s.close();
  assert.equal(f.calls.length, 1);
  assert.equal(stats.sent, 2);
});

test('emit after close is ignored rather than throwing', async () => {
  const s = sink(fakeFetch(() => okRes()));
  await s.close();
  assert.doesNotThrow(() => s.emit(ev(1)));
  assert.equal(s._buffer.length, 0);
});

// ── wiring ──────────────────────────────────────────────────────────────

test('the gate drives the sink end to end, with keys intact', async () => {
  const f = fakeFetch(() => okRes({ accepted: 3 }));
  const s = sink(f, { maxBatch: 100 });
  const gate = new Wayleave({
    rules: { [LANES.HUMAN]: [['/api', true]] },
    sink: s,
  });

  for (let i = 0; i < 3; i++)
    gate.handle({ method: 'GET', path: '/api/x', authority: 'a.example',
                  headers: { 'user-agent': 'Mozilla/5.0 Safari/17', 'accept-language': 'en' } },
                1785600000 + i);

  await s.flush();

  const sent = f.calls[0].body.events;
  assert.equal(sent.length, 3);
  assert.equal(new Set(sent.map(e => e.idempotencyKey)).size, 3,
               'the gate minted colliding keys — the meter would dedup real crossings away');
  for (const e of sent) {
    assert.equal(e.v, 1);
    assert.equal(e.lane, LANES.HUMAN);
    assert.ok(typeof e.identity === 'string' && e.identity.length > 0);
  }
});

test('the sink is sent with bearer auth and nothing else', async () => {
  const f = fakeFetch(() => okRes());
  const s = sink(f);
  s.emit(ev(1));
  await s.flush();
  assert.equal(f.calls[0].headers.authorization, 'Bearer k');
  assert.equal(f.calls[0].url, 'https://meter.example/v1/events');
});

test('endpoint and apiKey are required — a silently disabled meter is worse', () => {
  assert.throws(() => new MeterSink({ apiKey: 'k' }), /endpoint/);
  assert.throws(() => new MeterSink({ endpoint: 'https://x' }), /apiKey/);
});
