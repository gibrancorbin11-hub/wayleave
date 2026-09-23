# wayleave

[![Tests](https://github.com/gibrancorbin11-hub/wayleave/actions/workflows/test.yml/badge.svg)](https://github.com/gibrancorbin11-hub/wayleave/actions/workflows/test.yml)
[![npm](https://img.shields.io/npm/v/wayleave.svg)](https://www.npmjs.com/package/wayleave)
[![install size](https://img.shields.io/badge/dependencies-0-brightgreen)](https://www.npmjs.com/package/wayleave)

**Know which AI agents cross your API — verified by signature, not guessed from an IP.**

Wayleave is open-source middleware that classifies every request, verifies signed agents against a key
directory, applies the access rules you set, and prices the non-human traffic with HTTP 402. Humans are
never charged. The [hosted Meter](https://meter.wayleave.dev) records what crossed and what settled.

Zero dependencies. Node's native crypto only. TypeScript declarations included.

## What it does

Every request gets classified into a lane:

- **verified_agent** — valid Ed25519 HTTP Message Signature (RFC 9421, compatible with emerging Web Bot Auth) against a key directory you trust
- **declared_agent** — identifies as a bot, no valid signature
- **suspected_bot** — automation fingerprints without disclosure (an *invalid* signature lands here too — faking verification is the strongest fraud signal there is)
- **human** — browser-shaped traffic, which means *nothing gave it away*, not that a person is there

Then policy runs per lane: allow, deny, rate-limit — and on routes you price, agents get **402 Payment Required** with an x402-shaped challenge. Your human users never see a paywall.

Only the first lane is cryptographic. The other three are read off what the client says about itself, so a bot willing to lie reaches the human lane — see [Guarantees](#guarantees-honestly-stated), and set `strictPricedPaths` on anything you charge for.

## Two ways to use it

**1. The hosted Identity API — no install, any language.** Post a request's
signature headers and get back who signed it and which lane it belongs in.
Nothing is stored, and your traffic never routes through us.

```sh
curl -X POST https://wayleave-api-production.up.railway.app/v1/identify \
  -H "Authorization: Bearer $WAYLEAVE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","url":"https://api.yourapp.com/v1/data",
       "headers":{"user-agent":"...","signature":"...","signature-input":"..."},
       "client_ip":"203.0.113.7"}'
```

```json
{ "lane": "verified_agent", "verified": true,
  "identity": { "keyid": "k1", "operator": "Example Labs" },
  "signature": { "present": true, "valid": true, "reason": null } }
```

The same evaluator answers here and in the middleware, and a test asserts they
agree — if the two front doors disagreed about one request you would have no
way to know which to believe. (`api.wayleave.dev` is the intended hostname and
has no DNS record yet; the URL above is the one that answers today.)

**2. The middleware — in your own process.** Nothing leaves your server that
you do not send. This is the path if you want to price routes, enforce access
rules, or stay in-process. Start below.

## Quickstart: observe first

```sh
npm install wayleave
```

[Create a Meter account](https://meter.wayleave.dev/account.html), issue an API key,
and set `WAYLEAVE_METER_KEY` in your server environment. Signing in does not
start billing. The optional hosted Meter trial requires a card and becomes
$49/month after 3 days unless canceled; see your account for current terms.

In your existing Express app:

```js
import Wayleave from 'wayleave';

if (!process.env.WAYLEAVE_METER_KEY) {
  throw new Error('Set WAYLEAVE_METER_KEY before starting the app');
}
const gate = new Wayleave({
  meter: { apiKey: process.env.WAYLEAVE_METER_KEY },
});
app.use(gate.express()); // before the routes you want to observe
```

Send a request to your app, allow the buffer to flush, then open the
[Meter dashboard](https://meter.wayleave.dev/app.html). No pricing, blocking,
or rate limits are configured in this example. Drain `gate.sink.close()`
during your application's graceful shutdown. Keep the key server-side.

The middleware also works without an account: omit `meter` and use `onEvent`
to send events to your own backend. See [integration docs](https://meter.wayleave.dev/docs.html).

## Add access rules and payments

```js
import Wayleave from 'wayleave';
import { coinbaseFacilitator } from 'wayleave/x402';

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
  verifyPayment: coinbaseFacilitator({                   // REQUIRED to sell
    apiKeyId: process.env.CDP_API_KEY_ID,
    apiKeySecret: process.env.CDP_API_KEY_SECRET,
    receivingAddress: process.env.WAYLEAVE_RECEIVING_ADDRESS,
  }),
  onEvent: e => queueForBilling(e),        // metering hook; never blocks serving
});

app.use(gate.express());   // async: it awaits your verifier
```

**If you sell anything, use `gate.express()` or `gate.handleAsync()`.**
Confirming settlement is a network call, so a real `verifyPayment` returns a
Promise. The synchronous `handle()` cannot await one and will tell you so
rather than quietly denying every payment.

## Enforce rules you set elsewhere

> Requires 0.5.0. npm currently serves **0.4.1**, which has no `policy` option —
> installing from npm and pasting this will silently do nothing. Until 0.5.0 is
> published, install from source:
> `npm install github:gibrancorbin11-hub/wayleave`

A policy the gate fetches, rather than configuration compiled into your app:

```js
const gate = new Wayleave({
  policy: { url: 'https://meter.wayleave.dev/v1/policy/public/<id>.json',
            publicKey: WAYLEAVE_ROOT_KEY },
});
await gate.ready();
app.use(gate.express());
```

Fetched on a timer and evaluated from memory — never a network call inside a request. A denial
returns `403` with `x-wayleave-rule: <ruleId>`; a quota denial returns `429` with `Retry-After`.

The document is signed, which is the only reason the URL can be public. A CDN, or anyone on the
path, can serve whatever it likes and the gate refuses the bytes.

**If we are unreachable, your traffic is unaffected.** Last cached policy; with no cache, the gate
behaves exactly as if no policy were configured. That is tested five ways, and the cold-start case is
asserted by comparing against a gate constructed with no policy at all.

## Be found by the agents that can pay

A priced route nothing can discover earns nothing. Every install with `pricedPaths` serves a
manifest derived from your own configuration:

```js
new Wayleave({
  pricedPaths: { '/api/premium': 0.05 },
  payment: { payTo: '0xYourAddress', network: 'base' },
  publicOrigin: 'https://api.example.com',
});
```

```sh
curl https://api.example.com/.well-known/x402
```

No priced routes, or `manifest: false`, returns 404 — an empty manifest tells an index there is
nothing to buy here, which is a claim.

Use `gate.paymentRequirements(req)` to build your 402 body. It returns the same spec-shaped entry the
manifest advertises, so the two cannot disagree about the price.

Three details that decide whether an index reads you at all, all verified against the spec rather
than assumed: the path is `/.well-known/x402` (not `.json`), `asset` is the **token contract
address** rather than a symbol, and `maxTimeoutSeconds` is required. Note that the merged x402
specification has no well-known discovery document — this is a
[proposed extension](https://datatracker.ietf.org/doc/html/draft-hawkins-x402-dns-discovery-01)
that tooling in the wild does fetch.

## Guarantees, honestly stated

- Signature verification is real Ed25519 over an RFC 9421 signature base — forged keys, tampered requests, expired signatures, and replay-farming windows are all rejected. Tested adversarially, and against other implementations' wire formats rather than only its own.
- A signature is single-use only when the signer sends a nonce. `signRequest(..., nonce)` will issue one (`true` for random, or supply your own) and the gate then refuses a repeat. Without a nonce there is nothing to remember a request by, and a captured signature stays usable until it expires — on any path of the host, since the Web Bot Auth profile covers only `@authority`. Opt in when you sign per attempt; leave it off if your client retries by resending the same headers.
- Signature parameters are parsed as an RFC 9421 dictionary: order-independent, `alg` enforced as Ed25519, any signature label, and the signature base is built from whatever components the signer declared. Requests signed in Cloudflare's documented format verify.
- Local verification is benchmarked by the tests; latency depends on your hardware and configuration. Payment-provider network calls add latency.
- The metering hook can throw, crash, or hang your billing backend — serving continues. Your uptime never depends on ours.
- Key rotation has an implementation now: `directories: 'wayleave:default'` fetches a signed directory on a timer and resolves from memory, and you can still pass your own resolver function instead. The resolver must not block; that constraint has not moved. The bundled registry currently lists no operators — an empty directory resolves nothing rather than everything, so it changes no decision until it has entries.
- **A bot that sends a browser `user-agent` and an `accept-language` header is classified `human` and crosses priced routes free.** Those two headers are the entire bypass. The `human` lane is a fall-through — it is reached by tripping none of the automation tells, which is absence of evidence, not evidence of a person. There is no TLS fingerprinting and no challenge here; that work belongs at your edge or CDN, and pretending otherwise would be the dishonest version of this list. (`verifyAgentIP` checks a *declared* operator against its published ranges — it does nothing about a request claiming to be a browser, which is this bypass.) `strictPricedPaths: true` inverts the burden on priced routes so that only a verified signature or your own `confirmHuman(req)` crosses. Recommended wherever there is a price.
- Wayleave prices **disclosure**; it does not detect **concealment**. It is a tollbooth, not a wall — it works on operators who want to be identifiable, which today is most of the ones worth billing.
- This is a **screening and pricing layer, not a guarantee**. Every decision returns its evidence and is loggable.

## Status

v0.5.0 — 155 tests, zero dependencies. Published on npm: 0.4.1.

**0.5.0** does three things. Rules you set are now *enforced*: `policy: { url, publicKey }` fetches a
signed policy, verifies it, caches it, and evaluates per request — denials carry the rule id in
`x-wayleave-rule`, and a quota denial is 429 with `Retry-After`. `directories: 'wayleave:default'`
resolves agent keys from a signed directory. And every install with a priced route now serves
`/.well-known/x402`, so discovery indexes can find it.

The property worth testing for yourself: **a Wayleave outage cannot break your API.** Unreachable,
500, unparseable, wrong signature — each keeps the last good policy, and with no cache at all the
gate behaves exactly as if no policy were configured. Money is the opposite law and fails closed: an
unreachable rail is a 402, never free passage on a priced route.

That claim is not only unit-tested. `acceptance-policy.test.js` drives the real meter over a socket
and this gate fetching over HTTP with a real Ed25519 signature: a rule is set and enforced, changed
and re-enforced, a forged document is refused, and the service is then killed while traffic keeps
flowing. The same run against production on 2026-09-22 found a bug no local test had — the public
policy URL advertised an ETag and ignored `if-none-match`, so every poll re-sent and re-signed the
whole document. Fixed and covered.

**0.4.1** fixed a rail that could never settle. Two required fields were missing from every request
the x402 module made — `asset`, and the EIP-712 domain in `extra` — so the documented configuration
would have failed for anyone who tried it. Found by settling a real payment, not by reading the code.
If you were running the Coinbase rail before 0.4.1 and saw nothing settle, that is why.

**0.1.5** closed a hole worth naming: a priced route accepted a payment proof any agent could derive
from the 402 challenge it had just been sent — free passage, recorded as revenue. Settlement
confirmation is yours to supply and denies by default. If you shipped 0.1.4 or earlier on a priced
route, upgrade.

**0.1.6** addressed the other half: payment could be faked, and so could being human.
`strictPricedPaths` lets a priced route demand positive evidence rather than accepting the absence of
a bot signal as one.

## How payment actually works

Pay-at-the-door, not IOUs. On a route you price:

1. An agent requests the route → Wayleave answers `402 Payment Required`
   with an x402-shaped challenge: the price and *your* receiving address.
2. A wallet-carrying agent signs payment and retries with proof attached.
3. The proof is verified and settlement executes on a licensed rail
   (x402 facilitator) — money moves to your account.
4. Access can be released after payment verification. Your verifier must
   check the payment with the configured provider before returning success.

Agents without wallets (most crawlers today) are simply turned away on
priced routes — you aren't paid by them, but you also never serve them
free. The ledger shows exactly how much turned-away demand is standing
at your gate.

Wayleave never holds funds. Agent money flows agent → facilitator → you.
The [hosted Meter](https://meter.wayleave.dev) records crossings and confirmed
settlement activity. The 402 challenge is built in; payment verification is
a function you configure. A Meter account does not configure a payment rail.

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

A buffering, retrying sink ships in the box:

```js
import Wayleave from 'wayleave';
import { MeterSink } from 'wayleave/meter';

const sink = new MeterSink({
  endpoint: 'https://meter.wayleave.dev',
  apiKey: process.env.WAYLEAVE_METER_KEY,
  onError: (err, info) => log.warn({ err, info }, 'meter'),
});

const gate = new Wayleave({ pricedPaths: { '/api/premium': 0.05 }, sink });
process.on('SIGTERM', () => sink.close());   // drain, or lose what is buffered
```

`emit` is synchronous, non-throwing, and does no I/O — a billing backend
having a bad day must not become your customers having one. Retries are safe
because of the idempotency key: sending a batch twice costs a round trip, not
a double-billed customer. The buffer is bounded, and anything shed is counted
and reported rather than dropped quietly.

`verifyAgentIP` is the one that changes a lane. A `user-agent` naming a known
operator is a claim; when that operator publishes its ranges the claim is
checkable. Returning `false` moves the request to `suspected_bot` — a false
claim of identity is a stronger signal than no claim, which is the same
reasoning that puts an invalid signature there. Return `null` for operators you
cannot check; that leaves the request `declared_agent`, because unknown is not
guilty. Throwing is treated as `null` for the same reason.

## License

MIT
