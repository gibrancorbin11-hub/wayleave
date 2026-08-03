/**
 * wayleave/x402 — a ready-made `verifyPayment` for the Coinbase x402 rail.
 *
 * Before this existed, selling anything meant writing your own integration
 * against the facilitator API: two endpoints, a request body shaped
 * { x402Version, paymentPayload, paymentRequirements }, atomic-unit
 * conversion, and a response that returns HTTP 200 even when the payment is
 * bad. That is a lot of surface to get subtly wrong in the one place where
 * being wrong means giving away data for free or billing for money that never
 * moved.
 *
 * So it lives here instead, tested, and you configure it:
 *
 *   import Wayleave from 'wayleave';
 *   import { coinbaseFacilitator } from 'wayleave/x402';
 *
 *   const gate = new Wayleave({
 *     pricedPaths: { '/api/premium': 0.05 },
 *     strictPricedPaths: true,
 *     confirmHuman: req => Boolean(req.session?.userId),
 *     verifyPayment: coinbaseFacilitator({
 *       apiKeyId: process.env.CDP_API_KEY_ID,
 *       apiKeySecret: process.env.CDP_API_KEY_SECRET,
 *       receivingAddress: process.env.WAYLEAVE_RECEIVING_ADDRESS,
 *     }),
 *   });
 *
 * YOUR credentials, YOUR receiving address. Money moves agent -> facilitator
 * -> you. Wayleave is not a hop, does not hold funds, and this module has no
 * method that moves value — there is a test asserting that, because the day it
 * gains one this stops being metering and becomes money transmission.
 *
 * Zero dependencies: fetch is global from Node 18.
 */

const DEFAULT_BASE = 'https://api.cdp.coinbase.com/platform';
const X402_VERSION = 1;
const DEFAULT_DECIMALS = 6;      // USDC and most stablecoins
const TIMEOUT_MS = 10000;

/**
 * Dollars -> atomic units, as a decimal string.
 *
 * String arithmetic, not `usd * 10 ** decimals`, because floating point
 * mangles money: 0.07 * 1e6 is 70000.00000000001 in JavaScript, and rounding
 * that is how a ledger acquires a cent of drift per transaction.
 */
export function toAtomicUnits(usd, decimals = DEFAULT_DECIMALS) {
  const s = String(usd);
  if (!/^\d+(\.\d+)?$/.test(s))
    throw new Error(`amount must be a non-negative decimal, got "${usd}"`);
  const [whole, frac = ''] = s.split('.');
  if (frac.length > decimals)
    throw new Error(`amount ${usd} is finer than the asset's ${decimals} decimals`);
  return (whole + frac.padEnd(decimals, '0')).replace(/^0+(?=\d)/, '');
}

/**
 * Build a `verifyPayment(proof, ctx)` for the Coinbase x402 facilitator.
 *
 * @param {object} opts
 * @param {string} opts.apiKeyId          CDP API key id
 * @param {string} opts.apiKeySecret      CDP API key secret
 * @param {string} opts.receivingAddress  YOUR address. Never ours.
 * @param {string} [opts.network]         'base' (default) | 'base-sepolia' | ...
 * @param {string} [opts.asset]           token contract; omit for the network default
 * @param {number} [opts.decimals]        asset decimals, 6 for USDC
 * @param {boolean} [opts.settle]         true (default) submits on-chain.
 *                                        false only verifies — useful for a
 *                                        dry run, but nobody gets paid.
 * @param {(err:Error, info:object)=>void} [opts.onError]
 * @returns {(proof:string, ctx:object)=> Promise<{ok:boolean, ref?:string, reason?:string}>}
 */
export function coinbaseFacilitator({
  apiKeyId, apiKeySecret, receivingAddress,
  network = 'base', asset = null, decimals = DEFAULT_DECIMALS,
  settle = true, baseUrl = DEFAULT_BASE, onError = () => {}, fetch: f = fetch,
} = {}) {
  if (!apiKeyId || !apiKeySecret)
    throw new Error('coinbaseFacilitator requires apiKeyId and apiKeySecret');
  if (!receivingAddress)
    throw new Error('coinbaseFacilitator requires receivingAddress — the address YOU get paid at');

  const base = baseUrl.replace(/\/$/, '');

  return async function verifyPayment(proof, ctx) {
    // The middleware hands us the proof as a string; agents send the signed
    // payload as JSON. Accept either so a customer does not have to care.
    let paymentPayload = proof;
    if (typeof proof === 'string') {
      try { paymentPayload = JSON.parse(proof); }
      catch { return deny('payment proof is not a valid x402 payload'); }
    }
    if (!paymentPayload || typeof paymentPayload !== 'object')
      return deny('no payment payload supplied');

    let requirements;
    try {
      requirements = {
        scheme: 'exact',
        network,
        // We assert what was required; the facilitator checks the payment
        // matches. Under the exact scheme the transfer MUST equal this and
        // MUST land at payTo, so a wrong amount or wrong address cannot come
        // back valid. That is stronger than trusting a number the payer sent.
        maxAmountRequired: toAtomicUnits(ctx.price, decimals),
        resource: ctx.resource ?? ctx.path ?? '',
        description: '',
        mimeType: 'application/json',
        payTo: receivingAddress,
        maxTimeoutSeconds: 60,
        ...(asset ? { asset } : {}),
      };
    } catch (err) {
      return deny(`cannot build payment requirements: ${err.message}`);
    }

    const body = { x402Version: X402_VERSION, paymentPayload, paymentRequirements: requirements };
    const path = settle ? '/v2/x402/settle' : '/v2/x402/verify';

    let res;
    try {
      res = await post(f, `${base}${path}`, body, apiKeyId, apiKeySecret);
    } catch (err) {
      // Unreachable facilitator denies. An outage must degrade into unpaid,
      // never into free passage recorded as revenue.
      onError(err, { phase: 'facilitator', path });
      return deny(`facilitator unreachable: ${err.message}`);
    }

    if (!res.ok) {
      onError(new Error(`facilitator ${res.status}`), { phase: 'facilitator', path });
      return deny(`facilitator returned ${res.status}`);
    }

    const d = res.data ?? {};

    // CRITICAL: the facilitator answers HTTP 200 even when the payment is
    // bad. Reading the status code alone books every rejected payment as
    // revenue — which is exactly the bug 0.1.5 fixed, one layer down.
    if (settle) {
      if (d.success !== true)
        return deny(`settlement failed: ${d.errorReason ?? 'no reason given'}`);
      if (!d.transaction)
        return deny('settlement reported success with nothing to reference');
      return { ok: true, ref: String(d.transaction) };
    }

    if (d.isValid !== true)
      return deny(`payment not valid: ${d.invalidReason ?? 'no reason given'}`);
    return { ok: true, ref: d.payer ? `payer:${d.payer}` : null };
  };
}

async function post(f, url, body, keyId, keySecret) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await f(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cb-access-key': keyId,
        'cb-access-secret': keySecret,
      },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    let data = null;
    try { data = await r.json(); } catch { /* non-JSON body stays null */ }
    return { ok: r.ok, status: r.status, data };
  } finally {
    clearTimeout(timer);
  }
}

function deny(reason) {
  return { ok: false, reason };
}

export default coinbaseFacilitator;
