# Changelog

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
