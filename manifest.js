/**
 * Discovery manifest — E-1.
 *
 * The problem it solves: a developer installs the gate, prices a route, and
 * nothing finds it. Agent discovery indexes register resources they can read a
 * price for, so an unadvertised priced route is invisible to the exact agents
 * that could pay it.
 *
 * ── WHAT THE SPEC ACTUALLY SAYS, as of 2026-09-18 ──────────────────────────
 *
 * The merged x402 specification has NO well-known discovery document. Its
 * mechanism is the `bazaar` extension carried inside 402 responses, which a
 * facilitator catalogs as it sees them (specs/extensions/bazaar.md).
 *
 * The well-known manifest is a PROPOSED extension: draft-hawkins-x402-dns-
 * discovery-01, plus an open PR against the foundation repo. It is widely used
 * in the wild — validators and index tooling fetch it — so it is worth serving,
 * but it is a convention, not a ratified standard, and this comment is here so
 * nobody later mistakes it for one.
 *
 * The path is `/.well-known/x402`. NOT `.json`: tooling that looks for the
 * manifest requests the extensionless path, and a document served only at
 * `.json` is a document nobody fetches. We answer both, because answering the
 * alias costs nothing and a 404 costs a listing.
 *
 * Field names below were read from the draft and from
 * specs/x402-specification-v1.md, not from memory. Two traps in particular:
 *   - `asset` is the TOKEN CONTRACT ADDRESS, not a symbol like "usdc".
 *   - `maxTimeoutSeconds` is REQUIRED in PaymentRequirements.
 * An entry that gets either wrong is an entry an index silently skips, which
 * is indistinguishable from not publishing at all.
 */

import { toAtomicUnits } from './x402.js';

/** Networks whose USDC contract we have actually verified. See x402.js. */
const KNOWN_ASSETS = {
  'base': { asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', decimals: 6 },
  'base-sepolia': { asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', decimals: 6 },
};

const DEFAULT_TIMEOUT_SECONDS = 60;

/**
 * Build the manifest from configuration. A pure function of `pricedPaths` and
 * `payment`: there is no separate document to author, and therefore none to
 * drift out of step with what the gate actually charges.
 *
 * Returns null when there is nothing honest to publish. An empty manifest is
 * worse than no manifest — it tells an index there is nothing to buy here,
 * which is a claim, and a false one.
 */
export function buildManifest({ pricedPaths = {}, payment = {}, origin,
                                name, description, docs, contact,
                                now = () => new Date() } = {}) {
  const routes = Object.entries(pricedPaths);
  if (!routes.length || !origin) return null;

  const network = payment.network || 'base';
  const known = KNOWN_ASSETS[network];
  // An address we were given wins over our table; a symbol never does.
  const asset = isAddress(payment.asset) ? payment.asset : known?.asset;
  const decimals = Number.isInteger(payment.decimals) ? payment.decimals : known?.decimals;
  const payTo = payment.payTo;

  // Priceable only when we can name a real contract and a real payee. Without
  // both, publish the resource without `accepts` rather than inventing fields:
  // a wrong address is worse than a missing one.
  const priceable = Boolean(asset && payTo && Number.isInteger(decimals));

  const resources = routes.map(([path, priceUsd]) => {
    const url = origin.replace(/\/+$/, '') + path;
    const entry = { url, method: 'GET', description: 'x402-priced route' };
    if (priceable) {
      entry.accepts = [{
        scheme: 'exact',
        network,
        maxAmountRequired: toAtomicUnits(String(priceUsd), decimals),
        asset,
        payTo,
        resource: url,
        description: 'x402-priced route',
        mimeType: 'application/json',
        maxTimeoutSeconds: payment.maxTimeoutSeconds || DEFAULT_TIMEOUT_SECONDS,
      }];
    }
    return entry;
  });

  const manifest = {
    // What we actually speak. The draft's example shows 2; advertising a
    // version we do not implement would be a lie an index acts on.
    x402Version: 1,
    kind: 'resource-server',
    name: name || hostOf(origin),
    description: description || 'Paid routes served behind Wayleave.',
    resources,
    attestation: { type: 'none' },
    updated: now().toISOString(),
  };
  if (docs) manifest.docs = docs;
  if (contact) manifest.contact = contact;
  return manifest;
}

const isAddress = v => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
const hostOf = origin => { try { return new URL(origin).host; } catch { return 'wayleave resource server'; } };

/**
 * The x402 PaymentRequirements for one priced path.
 *
 * The gate's own `challenge` is an internal shape — `{scheme:'x402',
 * price_usd, resource}` — which is fine for an application that speaks it and
 * wrong for anything that validates against the x402 schema. An index reading
 * that body skips the endpoint, silently, which is the same as never having
 * published. Applications returning a 402 body should use this, so the 402 and
 * the manifest cannot describe different prices.
 */
export function paymentRequirementsFor(manifest, path) {
  if (!manifest) return null;
  const entry = manifest.resources?.find(r => { try { return new URL(r.url).pathname === path; } catch { return false; } })
    || manifest.resources?.find(r => r.url.endsWith(path));
  return entry?.accepts?.[0] ?? null;
}

/** The canonical path and the alias we also answer. */
export const MANIFEST_PATHS = ['/.well-known/x402', '/.well-known/x402.json'];

/**
 * Serve the manifest, computed once per origin and held.
 *
 * No I/O in the handler, and never priced: a discovery document behind a
 * paywall cannot be discovered, which defeats its only purpose.
 */
export class ManifestServer {
  #cache = new Map();
  constructor(config) { this.config = config; }

  /** Cached per origin, since the same install may answer on several hosts. */
  forOrigin(origin) {
    if (!this.#cache.has(origin))
      this.#cache.set(origin, buildManifest({ ...this.config, origin }));
    return this.#cache.get(origin);
  }

  /** Invalidate when configuration changes underneath us. */
  reset(config) { if (config) this.config = config; this.#cache.clear(); }
}

/** Origin from the request, unless the app configured one explicitly. */
export function originFor(req, publicOrigin) {
  if (publicOrigin) return publicOrigin.replace(/\/+$/, '');
  const host = headerish(req, 'x-forwarded-host') || headerish(req, 'host');
  if (!host) return null;
  const proto = headerish(req, 'x-forwarded-proto') || 'https';
  return `${proto}://${host}`;
}

function headerish(req, name) {
  const h = req?.headers || {};
  const v = h[name] ?? h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : (typeof v === 'string' ? v.split(',')[0].trim() : null);
}
