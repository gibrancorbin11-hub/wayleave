import type { PaymentVerifier } from './index.js';

export interface CoinbaseFacilitatorOptions {
  /** CDP API key id. Yours. */
  apiKeyId: string;
  /** CDP API key secret. Yours. */
  apiKeySecret: string;
  /**
   * The address YOU get paid at. Money moves agent → facilitator → here.
   * Wayleave is never a hop and holds nothing.
   */
  receivingAddress: string;
  /** Default 'base'. */
  network?: string;
  /** Token contract address; omit for the network default (USDC). */
  asset?: string;
  /** Asset decimals. 6 for USDC. */
  decimals?: number;
  /**
   * true (default) submits the payment on-chain. false only verifies it,
   * which is useful for a dry run but pays nobody.
   */
  settle?: boolean;
  baseUrl?: string;
  onError?: (err: Error, info: Record<string, unknown>) => void;
  fetch?: typeof fetch;
}

/**
 * A ready-made `verifyPayment` for the Coinbase x402 rail.
 *
 * Returns a Promise, so use it with `gate.express()` or `gate.handleAsync()`.
 * The synchronous `handle()` cannot await it and will say so rather than
 * silently deny.
 */
export function coinbaseFacilitator(opts: CoinbaseFacilitatorOptions): PaymentVerifier;

/** Dollars → atomic units as a decimal string. Throws on excess precision. */
export function toAtomicUnits(usd: number | string, decimals?: number): string;

export default coinbaseFacilitator;
