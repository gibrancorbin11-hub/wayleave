# Changelog

## 0.5.1

### The manifest the README promised was never served through express()

`app.use(gate.express())` is the integration the Quickstart shows, and the
README says every install with a priced route serves `/.well-known/x402`.
The adapter never called `manifestFor()`, so for Express users that path
404'd. The live demo works because it hand-wires `gate.manifestFor(request)`
-- which is why nobody noticed.

Found by scaffolding a project with `create-wayleave-app`, following the
README exactly, and curling the path it prints.

The manifest is now answered inside `express()` before classification, rate
limiting or pricing. Two properties that matter and are now tested: a
scraper can read it (the agents who would pay are precisely the ones
classified as bots, so a manifest behind classification is invisible to its
audience), and no priced routes still means 404 rather than an empty
document, because an empty manifest is a claim that there is nothing to buy.

## 0.5.0

### Rules you set are enforced at your origin

Until now `policy` meant a builder that generated code you pasted somewhere.
The gate now fetches a policy the meter serves, verifies its signature, caches
it, and evaluates it per request. A denial returns the rule id in
`x-wayleave-rule`; a quota denial is 429 with `Retry-After` rather than a bare
403, because a caller who can usefully come back should be told when.

```js
const gate = new Wayleave({ policy: { url, publicKey } });
await gate.ready();
```

The context is built from this library's own verification result. Nothing in it
comes from a header or body the caller controls — the evaluator only honours
`subject` and `operator` selectors when `identity.verified` is true, and passing
a caller's claims through would defeat exactly that check.

### A Wayleave outage cannot break your API

This is the property the whole design exists for, so it is tested rather than
asserted. Unreachable, 500, unparseable, wrong signature, structurally wrong:
each keeps the last good policy. A restart mid-outage comes back enforcing what
it last knew, which is why the cache is on disk. And with no cache and nothing
reachable, the gate behaves exactly as if no policy were configured — compared
against a gate constructed with none, including that an unknown agent stays
unknown rather than becoming suspected.

Money is the opposite law and still fails closed. An unreachable rail is a 402,
never free passage on a priced route.

### `directories: 'wayleave:default'`

Resolves to a signed directory of agent operator keys, fetched on a timer and
read from memory — never a network call inside a request. Root keys are pinned
inside this package, which is what makes a compromised CDN harmless: a key you
fetch from the same place as the document proves nothing.

The pinned list is empty until a root key exists, and an empty list verifies
nothing rather than everything. Unconfigured is inert, never permissive.

### Discovery: `/.well-known/x402`

A priced route that nothing can find earns nothing. The gate serves a manifest
derived entirely from `pricedPaths` and `payment`, so an install advertises what
it sells. No priced routes, or `manifest: false`, is a 404 — an empty manifest
tells an index there is nothing to buy here, which is a claim.

Three corrections worth stating, because the obvious implementation gets them
wrong: the path is `/.well-known/x402`, not `.json`; `asset` is the token
contract address, not a symbol like `"usdc"`; and `maxTimeoutSeconds` is
required. Any of the three makes an index silently skip the endpoint, which is
indistinguishable from not publishing at all.

The merged x402 specification has no well-known discovery document — its
mechanism is the `bazaar` extension inside 402 responses. The manifest is a
proposed extension that tooling in the wild does fetch. Worth serving; not a
standard, and `manifest.js` says so.

### Also

`policy-engine.js` ships, so evaluation happens in-process with zero
dependencies, as everything here does. A test asserts it has not drifted from
the meter's copy: a rule the dashboard accepts and the origin ignores looks
exactly like the product working.

152 tests.

## 0.4.1

### The Coinbase rail could not settle a payment in any default configuration

Two required fields were missing from every request this module made, and
either one alone was fatal. Both were found by settling a real payment on
base-sepolia rather than by reading the code, because locally nothing looked
wrong: the module built, its tests passed, and the failures were 400s from
someone else's API that never reached the customer.

`asset` was omitted whenever the caller did not pass one, which was the
default. CDP rejects that outright — "x402V1PaymentRequirements requires
'asset'". The settlement asset is now defaulted per network and the
facilitator refuses to construct for a network it has no default for, rather
than building cleanly and denying every payment at runtime.

`extra` was never sent at all. It carries the EIP-712 domain the agent signed
its EIP-3009 authorization against, and without it the facilitator gets far
enough to identify the payer and then fails with "missing EIP-712 domain
parameters". It cannot be guessed: Base mainnet USDC calls itself "USD Coin"
and the Sepolia token calls itself "USDC", so a single hardcoded value is
wrong on one of the two chains. Both were read from the contracts and checked
against each one's own DOMAIN_SEPARATOR.

With both fixed, a real payment settles: 402 challenge, agent signs, retries
with proof, facilitator verifies and submits on-chain, resource released, and
USDC moves to the receiving address. Gas is paid by the facilitator, not the
agent and not you.

If you have been running this rail and seeing nothing settle, this is why.

## 0.4.0

### The Coinbase rail authenticates the way CDP actually requires

`wayleave/x402` sent `cb-access-key` and `cb-access-secret` headers. That is
not how the Coinbase Developer Platform authenticates, so every verify and
settle call was refused before it reached the rail — the facilitator was
wired, credentialed and incapable of moving money.

`cdp-auth.js` mints the short-lived, request-bound bearer token CDP expects,
signed with the Secret API Key. It accepts the PEM and the base64 key formats
Coinbase hands out, binds the token to the exact method and URL being called,
and refuses a non-HTTPS endpoint or one carrying credentials in the URL. The
secret never leaves the process and never reaches a log line.

### A dry run no longer opens the door

With `settle: false`, `verifyPayment` returned `{ ok: true }` on a valid
authorization. A valid authorization is not settled money, so verification-only
mode released the priced resource and recorded billed revenue while nobody had
paid. It now denies with `Payment verified only; settlement is disabled`. If
you ran a dry run against real routes, that traffic was served for free and the
claimed amounts in your ledger were never collectable.

### `signRequest` can issue a nonce, so replay protection is no longer inert

`verifySignature` has always read RFC 9421's `nonce` parameter, and the gate
has always refused a nonce it had seen before. Nothing in this package could
produce one. `replayProtection: true` was therefore configuration with no
effect for anyone signing with our own helper, and a captured signature stayed
usable for the whole validity window — on every path of the host, because the
Web Bot Auth profile covers only `@authority`.

`signRequest(..., nonce)` closes that. Pass `true` for 16 random bytes, or a
string of your own. `buildParams` takes the same optional argument.

It is opt-in rather than the default because it changes what a retry means: an
agent that signs once and resends those exact headers after a socket error is
behaving reasonably, and a nonce turns that retry into a rejected replay. Sign
per attempt and pass `true`; hold headers across attempts and do not.

Nonces are namespaced by directory and keyid before they are remembered, so
two operators choosing the same value cannot burn each other's.

Unchanged for existing callers: omit the argument and the wire format, the
lanes and the retry behaviour are exactly as they were in 0.3.0.

## 0.3.0

**A bug that meant nobody could ever have been paid, and the fix that makes
selling two lines instead of an integration.**

`verifyPayment` could not be async. `_checkPayment` was synchronous and tested
`r.ok === true`; a Promise has no `.ok`, so it fell through to "not settled".
Every asynchronous verifier denied every payment, silently — and since
confirming settlement is a network call, *every real verifier is
asynchronous*. The README documented exactly that pattern
(`verifyPayment: (proof, ctx) => facilitator.confirmSettled(...)`), so the
documented way to sell anything has never worked since it was introduced in
0.1.5. It failed closed rather than open, which is the right direction, but it
failed silently, which is the wrong way.

- **`handleAsync(req, now, proof)`** awaits your verifier. `express()` now
  uses it, so anyone on the Express adapter gets the fix for free.
- **A Promise on the synchronous path is now refused loudly**, naming
  `handleAsync` in the reason, instead of being read as a falsy verdict.
- `_decide` and its async twin share one `_preDecide`, so the policy, replay,
  and rate-limit logic exists once. Two copies would drift and the drifted one
  would be the untested one.

- **`wayleave/x402`** — a ready-made `verifyPayment` for the Coinbase rail:

  ```js
  import { coinbaseFacilitator } from 'wayleave/x402';

  verifyPayment: coinbaseFacilitator({
    apiKeyId: process.env.CDP_API_KEY_ID,
    apiKeySecret: process.env.CDP_API_KEY_SECRET,
    receivingAddress: process.env.WAYLEAVE_RECEIVING_ADDRESS,
  })
  ```

  It handles the two endpoints, the request shape, atomic-unit conversion
  (string arithmetic — `0.07 * 1e6` floats to `70000.00000000001`), and the
  fact that the facilitator answers HTTP 200 even when a payment fails. Your
  credentials, your receiving address; the module has no method that moves
  value and there's a test asserting it never grows one.

- **`meter: { apiKey }`** builds a `MeterSink` for you. An explicit `sink`
  still wins.
- A missing `receivingAddress` throws at construction rather than at a
  customer's first sale.
- Tests: 87 → 101.

## 0.2.1

**Ships `wayleave/meter`, which 0.2.0 promised and did not include.**

0.2.0 added the `sink` interface and put `idempotencyKey` on every event so a
retrying sink could be deduplicated at the far end. The sink itself landed
after the tarball was cut, so `import { MeterSink } from 'wayleave/meter'`
failed on anything installed from npm. This release is that import working.

- **`MeterSink`** — a `sink` that buffers, batches, and retries against a
  wayleave meter. The default `DirectSink` hands each event to `onEvent` and
  swallows what it throws: correct for uptime, lossy for revenue. This one
  survives a backend having a bad day.

  Retrying is only safe because every event already carries an
  `idempotencyKey`. Sending a batch twice costs a round trip, not a
  double-billed customer.

  Three properties it holds, each under test: `emit` never throws, never
  awaits, and does no I/O, so a billing backend cannot become a serving
  outage. Nothing is dropped silently — the buffer is bounded and every shed
  event is counted and reported, because a silent drop is a billing hole. And
  a 4xx that is not 429 is consumed rather than retried, since retrying an
  unauthorised or malformed batch forever is how a buffer becomes a memory
  leak.

- `close()` drains on shutdown. Without it, whatever is buffered when a
  container cycles is revenue you paid attention for and never received.
- Tests: 70 → 87.

No behaviour changes to the gate. If you do not import `wayleave/meter`,
0.2.1 is byte-identical to 0.2.0 in every path you use.

## 0.2.0

**Interfaces where there were implementations. No behaviour changes.**

Three things this library does were hardcoded to one strategy: state lived in
a `Map`, metering called a function, keys were read out of an object. Each is
now a seam with today's behaviour as the default, so a shared backend, a
durable meter, and key rotation can arrive as configuration rather than as
surgery on the gate. Everything below is additive — omit all of it and 0.2.0
behaves exactly as 0.1.6, which is what the suite asserts.

- **`store`** — rate-limit counters and consumed nonces behind
  `hit` / `hasNonce` / `rememberNonce`. Defaults to the exported `MemoryStore`,
  bounded and per-process as before. A Redis or Postgres implementation is now
  roughly forty lines that the gate never sees. Deliberately synchronous: this
  runs on every request, and an awaited round trip per crossing costs more than
  the crossing earns. Put a distributed backend behind a local view.
- **`sink`** — metering events go to an object with `emit`, defaulting to the
  exported `DirectSink` that calls `onEvent` and swallows what it throws.
  Buffering, batching and retry now have somewhere to live.
- **Every event carries `v` and `idempotencyKey`.** A schema version so a meter
  outliving one release knows what it is reading, and a per-crossing key so a
  retrying sink can be deduplicated at the far end. Both are cheap now and
  expensive after receipts exist in the wild — you would be reconciling two
  formats forever.
- **`directories` may be a resolver function.** Point it at a cache your app
  refreshes from a JWKS endpoint on a timer and keys rotate without a restart.
  The config-object form is unchanged. Synchronous for the same reason as the
  store: fetch on a schedule, resolve from memory.
- **`verifyAgentIP`** — the one genuinely new capability. A `user-agent` naming
  a known operator is a claim, and claims are checkable when that operator
  publishes its ranges. Claiming to be GPTBot from an address OpenAI does not
  own now lands in `suspected_bot`, on the same reasoning that puts a failed
  signature there. Returning null, or throwing, means "cannot check" and leaves
  the request merely `declared_agent` — unknown is not guilty, and a DNS blip
  must never demote the agents we most want to bill.
- Tests: 56 → 70.

What this release deliberately does NOT include: a Redis backend, a durable
queue, a live JWKS fetcher. Those are implementations, and implementations
should follow a customer rather than precede one.

## 0.1.6

**The free lane was whatever failed to look automated. Now you can demand
proof instead.**

`human` is a fall-through classification: a request reaches it by tripping
none of the automation tells. Since humans are never priced, that asymmetry
paid the spoofer — a browser `user-agent` plus an `accept-language` header
was the entire bypass of every priced route. Nothing about that is subtle,
and a bot doing it costs nothing to write.

- **`strictPricedPaths: true`** inverts the burden on priced routes only.
  Absence of a bot signal stops being a free pass; a priced route then admits
  a verified signature (which pays) or an application-confirmed human (which
  browses), and nothing else. Unpriced routes are untouched.
- **`confirmHuman(req)`** is where that confirmation comes from — your
  session, your cookie, your challenge, never a header. It fails closed:
  absent, throwing, or returning anything other than `true` all deny. Same
  doctrine as `verifyPayment` in 0.1.5.
- **The Express adapter now forwards the framework request as `req.raw`**,
  which `confirmHuman` receives. Without it the callback would only ever see
  the projected `{method, path, headers, ip}` shape — no session, no cookies,
  so it would return false for everyone and bill signed-in users as bots.
  Classification still reads only the fields it declares.
- The 402 now names which check failed, so the ledger distinguishes an agent
  that has not paid from a visitor who could not be confirmed.
- Default behaviour is unchanged. Off, 0.1.6 classifies and prices exactly as
  0.1.5 did.
- README states the bypass outright rather than leaving it to be discovered,
  and the test suite asserts it works as described — a documented property
  needs a test, not a paragraph. Tests: 46 → 55.

This does not make Wayleave a bot wall. TLS fingerprinting, IP-range
verification and behavioural analysis belong at an edge or CDN, not in Express
middleware. Wayleave prices disclosure; it does not detect concealment.

## 0.1.5

**Security. Upgrade if you price any route.**

The payment path trusted a string the payer wrote. `paymentProof` was compared
against `paid:<resource>:<price>` — every part of which the agent had just been
handed in the 402 challenge. An agent that echoed it back got free passage on
every priced route, and the metering hook recorded `billedUsd` for money that
never moved. A ledger of settlements that never settled is worse than no ledger.

- **`verifyPayment(proof, ctx)` is now the only way to turn a 402 into a 200,
  and it defaults to deny.** Configure nothing and priced routes stay 402
  forever. Your verifier receives the price, resource, identity, and path, and
  may return a settlement `ref` that lands in the ledger. A verifier that
  throws denies passage; nothing but a confirmed settlement is booked as
  billed. This is the "pluggable payment check" the docs previously claimed.
- **Rate limits no longer key on `x-forwarded-for`.** It is client-written
  unless a proxy you own overwrites it, so rotating it minted an unlimited
  supply of fresh buckets — the limiter did not function against the traffic
  it exists to limit. Identity now comes from the connection address
  (`req.ip`; the Express adapter supplies it). Opt back in with
  `trustProxy: true` only behind a proxy you control.
- **In-memory state is bounded.** The hit table grew forever and, combined
  with the above, let an attacker exhaust the host's memory. Counters now
  clear on window rollover, with a `maxTracked` ceiling (default 10,000) on
  both hit and nonce tables.
- **Replay is rejected for signers that supply RFC 9421's `nonce`** — one
  signature, one crossing. Deliberately NOT keyed on signature bytes:
  Ed25519 is deterministic and the profile covers only `@authority`, so two
  legitimate same-second requests are byte-identical and would be falsely
  refused. Without a signer nonce, replay stays bounded by the expiry window.
- Tests: 29 → 44, including guessed and echoed payment proofs, a throwing
  verifier, rotated forwarding headers, memory flooding, window rollover, and
  a nonce-free signer that must not be accused of replaying.

## 0.1.4

**Interop fix. Previous versions rejected legitimately signed traffic.**

The signature-input parser hardcoded one parameter ordering, one signature
label, and had no slot for the mandatory `alg` parameter. A request signed
per Cloudflare's documented Web Bot Auth format was rejected as
"malformed signature-input" and classified `suspected_bot` — the fraud lane.
Real verified agents were being treated as forgers.

- `signature-input` parameters are now parsed as an RFC 9421 dictionary:
  **order-independent**, so `created;keyid;alg;expires;tag` and any other
  arrangement both work.
- **`alg` is understood and enforced.** Anything other than `ed25519` is
  refused rather than silently accepted.
- **The signature label is no longer hardcoded to `sig1`.** Cloudflare emits
  `sig2`; any RFC 9421 label is accepted, and the `signature` header is
  matched by that same label.
- **The signature base is built from the components the signer declared**,
  not a fixed `("@authority" "signature-agent")` pair. Signatures covering
  only `("@authority")` verify correctly.
- **`@authority` coverage is now required** — a signature that doesn't cover
  the target authority is refused.
- Optional `nonce` is tolerated.
- `signature-agent` is emitted and read as a structured-field string (quoted),
  matching the wire format.
- `buildParams` now emits `alg="ed25519"`.

Seven interop tests added that sign at the byte level in other
implementations' formats rather than round-tripping through this library's
own signer — which is why the bug survived 23 passing tests.

## 0.1.3

Packaging and provenance. No behaviour changes — `index.js` is byte-identical
to 0.1.2.

- **TypeScript declarations** (`index.d.ts`), covering `Wayleave`, `LANES`,
  `classify`, `verifySignature`, `signRequest`, `buildParams` and the option
  and result shapes. Deliberately self-contained: the key type is declared
  structurally rather than imported from `node:crypto`, so the types do not
  pull in `@types/node` and the package stays dependency-free. Compiles under
  `--strict`.
- **Published with provenance** via GitHub Actions OIDC, so npm can show the
  attestation linking this tarball to the commit and workflow that built it.
  No publish token is involved.
- **CI on every push** across Node 18, 20, 22 and 24, with the declaration
  file type-checked in the matrix. The suite runs again before publishing, so
  a red build cannot ship.

## 0.1.2

First public release.

- Ed25519 signature verification over an RFC 9421 signature base, Web Bot Auth
  profile (`@authority`, `signature-agent`), against key directories you configure.
- Four lanes: `verified_agent`, `declared_agent`, `suspected_bot`, `human`.
  A signature that fails verification lands in `suspected_bot`, not `human`.
- Per-lane policy: allow, deny, rate-limit.
- `402 Payment Required` with an x402-shaped challenge on priced paths, for
  non-human lanes only.
- `onEvent` metering hook. It can throw without affecting serving.
- 22 adversarial tests (forgery, tampering, expiry, replay windows, a throwing
  metering hook) plus a per-request latency test.

Settlement is a pluggable stub: the 402 challenge and payment-proof check work,
wiring a real payment network is next. Key directories load from config rather
than a live JWKS fetch.
