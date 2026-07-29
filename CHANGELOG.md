# Changelog

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
