# Changelog

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
