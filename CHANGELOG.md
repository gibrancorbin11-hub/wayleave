# Changelog

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
