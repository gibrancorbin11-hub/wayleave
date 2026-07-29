/**
 * Wayleave live demo — the proof developers can verify from their own terminal.
 *
 *   node demo/server.js
 *
 * Then in another terminal:
 *
 *   curl -i http://localhost:4020/api/premium/comps
 *     → 402 Payment Required, with a price. You're an unsigned caller.
 *
 *   node demo/agent.js
 *     → signs a request like a legitimate agent and gets 200.
 *
 * Zero dependencies. This file IS the pitch.
 */

import { createServer } from 'node:http';
import { Wayleave, LANES } from '../index.js';

// ── a demo agent operator the server trusts ─────────────────────────────
import { demoAgent, DIRECTORY, KEYID } from './keys.js';

const gate = new Wayleave({
  directories: { [DIRECTORY]: { [KEYID]: demoAgent.publicKey } },
  rules: {
    [LANES.VERIFIED]: [['/api', true]],
    [LANES.DECLARED]: [['/api', true]],
    [LANES.SUSPECT]: [['/api', true]],   // demo: let them in far enough to see the paywall
    [LANES.HUMAN]: [['/api', true]],
  },
  pricedPaths: { '/api/premium': 0.05 },
  onEvent: e => console.log(
    `  [gate] ${e.lane.padEnd(15)} ${String(e.status).padEnd(4)} ${e.path}` +
    (e.billedUsd ? `  billed $${e.billedUsd}` : '')),
});

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const decision = gate.handle({
    method: req.method,
    path: url.pathname,
    authority: req.headers.host || '',
    headers: req.headers,
  }, undefined, req.headers['x-payment-proof'] || '');

  res.setHeader('content-type', 'application/json');

  if (url.pathname === '/') {
    res.end(JSON.stringify({
      wayleave: 'demo',
      you_are: decision.lane,
      try: [
        'curl -i http://localhost:4020/api/premium/comps   (unsigned → 402 with a price)',
        'node demo/agent.js                                (signed agent → 200)',
      ],
    }, null, 2));
    return;
  }

  if (decision.status === 402) {
    res.statusCode = 402;
    res.setHeader('x-payment-challenge', JSON.stringify(decision.challenge));
    res.end(JSON.stringify({
      error: 'Payment Required',
      message: 'Agents pay for passage here. Humans browse free.',
      challenge: decision.challenge,
      hint: `retry with header x-payment-proof: paid:${decision.challenge.resource}:${decision.challenge.price_usd}`,
    }, null, 2));
    return;
  }

  if (decision.status !== 200) {
    res.statusCode = decision.status;
    res.end(JSON.stringify({ error: decision.why }, null, 2));
    return;
  }

  res.end(JSON.stringify({
    ok: true,
    lane: decision.lane,
    identity: decision.identity,
    billed: decision.billed || 0,
    data: { comps: ['1201 Brickell Bay Dr', '1425 Brickell Ave'], asOf: '2026-07' },
  }, null, 2));
});

if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  server.listen(4020, () =>
    console.log('wayleave demo on http://localhost:4020\n' +
                '  curl -i http://localhost:4020/api/premium/comps\n'));
}

export { server, demoAgent, DIRECTORY, KEYID };
