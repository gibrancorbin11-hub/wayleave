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
- **human** — browser-shaped traffic, which means *nothing gave it away*, not that a person is there

Then policy runs per lane: allow, deny, rate-limit — and on routes you price, agents get **402 Payment Required** with an x402-shaped challenge. Your human users never see a paywall.

Only the first lane is cryptographic. The other three are read off what the client says about itself, so a bot willing to lie reaches the human lane — see [Guarantees](#guarantees-honestly-stated), and set `strictPricedPaths` on anything you charge for.

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
  verifyPayment: (proof, { price, resource }) =>
    facilitator.confirmSettled(proof, price, resource),  // REQUIRED to sell
  onEvent: e => queueForBilling(e),        // metering hook; never blocks serving
});

app.use(gate.express());
```

## Guarantees, honestly stated

- Signature verification is real Ed25519 over an RFC 9421 signature base — forged keys, tampered requests, expired signatures, and replay-farming windows are all rejected. Tested adversarially, and against other implementations' wire formats rather than only its own.
- Signature parameters are parsed as an RFC 9421 dictionary: order-independent, `alg` enforced as Ed25519, any signature label, and the signature base is built from whatever components the signer declared. Requests signed in Cloudflare's documented format verify.
- Sub-millisecond per request. Your latency budget won't notice.
- The metering hook can throw, crash, or hang your billing backend — serving continues. Your uptime never depends on ours.
- Key rotation has a seam but no implementation. `directories` accepts a resolver function you can point at a cache, but there is no JWKS fetcher in the box and the resolver must not block. Wiring that cache is still your job.
- **A bot that sends a browser `user-agent` and an `accept-language` header is classified `human` and crosses priced routes free.** Those two headers are the entire bypass. The `human` lane is a fall-through — it is reached by tripping none of the automation tells, which is absence of evidence, not evidence of a person. There is no TLS fingerprinting and no challenge here; that work belongs at your edge or CDN, and pretending otherwise would be the dishonest version of this list. (`verifyAgentIP` checks a *declared* operator against its published ranges — it does nothing about a request claiming to be a browser, which is this bypass.) `strictPricedPaths: true` inverts the burden on priced routes so that only a verified signature or your own `confirmHuman(req)` crosses. Recommended wherever there is a price.
- Wayleave prices **disclosure**; it does not detect **concealment**. It is a tollbooth, not a wall — it works on operators who want to be identifiable, which today is most of the ones worth billing.
- This is a **screening and pricing layer, not a guarantee**. Every decision returns its evidence and is loggable.

## Status

v0.2.0 — verification, lanes, policy, pricing, and the metering hook, all under test (70 scenarios, including forgery, tampering, replay, guessed payment proofs, spoofed rate-limit identities, spoofed browser headers, spoofed operator identity, and cross-implementation wire formats). Payment settlement network integration is in progress; the 402 challenge is built in and settlement confirmation is a function you supply.

0.1.5 closes a hole worth naming: before it, a priced route accepted a payment proof that any agent could derive from the 402 challenge it had just been sent — free passage, recorded as revenue. Settlement confirmation is now yours to supply and denies by default. If you shipped 0.1.4 or earlier on a priced route, upgrade.

0.1.6 addresses the other half of the same question. Payment could be faked; so could being human. `strictPricedPaths` lets a priced route demand positive evidence instead of accepting the absence of a bot signal as one.

0.2.0 turns three hardcoded strategies into seams — state, metering, and key lookup — so shared storage, durable billing, and key rotation become configuration rather than a rewrite. Defaults are unchanged; see [Extending it](#extending-it).

## How payment actually works

Pay-at-the-door, not IOUs. On a route you price:

1. An agent requests the route → Wayleave answers `402 Payment Required`
   with an x402-shaped challenge: the price and *your* receiving address.
2. A wallet-carrying agent signs payment and retries with proof attached.
3. The proof is verified and settlement executes on a licensed rail
   (x402 facilitator) — money moves to your account.
4. Only then: `200`. No settled payment, no passage. Data never moves
   on a promise.

Agents without wallets (most crawlers today) are simply turned away on
priced routes — you aren't paid by them, but you also never serve them
free. The ledger shows exactly how much turned-away demand is standing
at your gate.

Wayleave never holds funds. Agent money flows agent → facilitator → you.
The hosted meter (not built yet — see the waitlist) is what wires this
end-to-end; today the 402 challenge is built in and step 3 is a function
you supply.

**Step 3 is yours, and it defaults to no.** `verifyPayment(proof, ctx)` is
the only thing that can turn a 402 into a 200. Configure nothing and every
priced route stays 402 forever — deliberately. A payment proof is a string
written by the party who owes you money, so there is nothing this library
can check about it on its own that the payer could not have fabricated.
Point it at a facilitator that confirms settlement, and never at a
comparison against the challenge you just issued. A verifier that returns
anything but `true`/`{ok:true}` — or that throws — denies passage, and
nothing but a confirmed settlement is ever written to the ledger as billed.

## Security posture

- **`strictPricedPaths: true` is the recommended setting on any priced route.**
  Without it the free lane is whatever fails to look automated, so the cheapest
  strategy against a paywall is to look like a browser. With it, a priced route
  admits exactly two things: a verified signature that pays, and a request your
  own `confirmHuman(req)` vouches for. That callback fails closed — absent,
  throwing, or returning anything but `true` all mean pay or leave.

  ```js
  const gate = new Wayleave({
    pricedPaths: { '/api/premium': 0.05 },
    strictPricedPaths: true,
    confirmHuman: req => Boolean(req.session?.userId),   // your session, not a header
    verifyPayment: (proof, ctx) => facilitator.confirmSettled(proof, ctx),
  });
  ```

  Never infer humanity from headers inside this callback. Every header a
  browser sends, a bot can send too — that is the property strict mode exists
  to close, and re-deriving it from `user-agent` reopens it.
- **Rate limits key on the connection address, not `x-forwarded-for`.**
  The header is client-written unless a proxy you own overwrites it; believing
  it by default hands an attacker unlimited fresh buckets. Behind a real proxy,
  set `trustProxy: true`. Pass `req.ip` (the Express adapter does).
- **In-memory state is bounded** by `maxTracked` (default 10,000) and cleared
  each rate window, so a flood of distinct clients cannot exhaust memory.
- **Replay: single-use is enforced only for signers that send RFC 9421's
  `nonce`.** Signature bytes are not a usable substitute — Ed25519 is
  deterministic and the Web Bot Auth profile covers only `@authority`, so one
  agent hitting two paths in the same second produces byte-identical
  signatures. Rejecting those would break real traffic. Without a signer
  nonce, replay is bounded by the expiry window and nothing tighter.
- **State is per-process by default.** Rate limits and replay memory do not
  survive a restart and do not span instances. Pass a `store` implementing
  `hit` / `hasNonce` / `rememberNonce` to share them. Keep it synchronous —
  it runs on every request — so back a distributed store with a local view
  that replicates asynchronously. Note the two uses differ in how much they
  mind lag: fixed-window rate limiting tolerates approximate counts, replay
  does not, because a nonce that has not replicated yet can be spent twice.
- **Key rotation is possible but not built in.** `directories` accepts a
  resolver function, so point it at a cache you refresh from a JWKS endpoint
  on a timer. There is no fetcher in the box, and the resolver must not block.

## Extending it

Three seams, each defaulting to the behaviour above. Nothing here is required.

```js
new Wayleave({
  store: myRedisBackedStore,        // shared rate limits + replay across instances
  sink: myBufferedSink,             // emit() with batching, retry, dedup
  directories: url => keyCache[url],// rotatable keys, refreshed out of band
  verifyAgentIP: (ip, ua) => isPublishedRange(ip, ua),
});
```

Every metering event carries `v` (schema version) and `idempotencyKey`, so a
sink that retries can be deduplicated at the far end rather than double-billing.

`verifyAgentIP` is the one that changes a lane. A `user-agent` naming a known
operator is a claim; when that operator publishes its ranges the claim is
checkable. Returning `false` moves the request to `suspected_bot` — a false
claim of identity is a stronger signal than no claim, which is the same
reasoning that puts an invalid signature there. Return `null` for operators you
cannot check; that leaves the request `declared_agent`, because unknown is not
guilty. Throwing is treated as `null` for the same reason.

## License

MIT
