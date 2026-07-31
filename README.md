# wayleave

[![Tests](https://github.com/gibrancorbin11-hub/wayleave/actions/workflows/test.yml/badge.svg)](https://github.com/gibrancorbin11-hub/wayleave/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/wayleave.svg)](https://www.npmjs.com/package/wayleave)
[![install size](https://img.shields.io/badge/dependencies-0-brightgreen)](https://www.npmjs.com/package/wayleave)

**Charge AI agents for passage across your app.**

A *wayleave* is the fee paid for the right of passage across private land — utility companies have paid them for 150 years to run cables through property. AI agents are about to cross your app millions of times for free. Charge them a wayleave.

Zero dependencies. Node's native crypto only. TypeScript declarations included.

## What it does

Every request gets classified into a lane:

- **verified_agent** — valid Ed25519 signature (Web Bot Auth profile, RFC 9421) against a key directory you trust
- **declared_agent** — identifies as a bot, no valid signature
- **suspected_bot** — automation fingerprints without disclosure (an *invalid* signature lands here too — faking verification is the strongest fraud signal there is)
- **human** — browser-shaped traffic

Then policy runs per lane: allow, deny, rate-limit — and on routes you price, agents get **402 Payment Required** with an x402-shaped challenge. Your human users never see a paywall.

## Quickstart

```js
import Wayleave from 'wayleave';

const gate = new Wayleave({
  directories: {
    'https://agents.anthropic.example/keys': { 'claude-1': publicKeyOrRawB64 },
  },
  rules: {
    verified_agent: [['/api/admin', false], ['/api', true]],
    suspected_bot:  [['/api', false]],
  },
  rateLimits: { declared_agent: 10 },
  pricedPaths: { '/api/premium': 0.05 },   // agents pay 5¢/call, humans free
  onEvent: e => queueForBilling(e),        // metering hook; never blocks serving
});

app.use(gate.express());
```

## Guarantees, honestly stated

- Signature verification is real Ed25519 over an RFC 9421 signature base (`@authority`, `signature-agent`) — forged keys, tampered requests, expired signatures, and replay-farming windows are all rejected. Tested adversarially.
- Sub-millisecond per request. Your latency budget won't notice.
- The metering hook can throw, crash, or hang your billing backend — serving continues. Your uptime never depends on ours.
- This is a **screening and pricing layer, not a guarantee**. Every decision returns its evidence and is loggable.

## Status

v0.1 — verification, lanes, policy, pricing, and the metering hook, all under test (22 scenarios, including forgery, tampering, and replay). Payment settlement network integration is in progress; today the 402 challenge and payment-proof check are pluggable.

## License

MIT
