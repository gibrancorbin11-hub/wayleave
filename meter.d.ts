import type { MeterEvent, Sink } from './index.js';

export interface MeterSinkOptions {
  /** Base URL of your meter, e.g. "https://meter.wayleave.dev". */
  endpoint: string;
  /** API key issued by the meter. Sent as a bearer token. */
  apiKey: string;
  /** Drain interval in ms. Default 5000. */
  flushMs?: number;
  /** Events per request. Default 500; the meter caps batches at 1000. */
  maxBatch?: number;
  /**
   * Hard ceiling on buffered events. Default 10000. Past this the oldest are
   * shed — counted in `stats.dropped` and reported through `onError`, never
   * dropped silently.
   */
  maxBuffer?: number;
  /** Retries per batch, exponential backoff with jitter. Default 5. */
  maxRetries?: number;
  /** Per-request timeout in ms. Default 10000. */
  timeoutMs?: number;
  /**
   * Observability hook for drops, permanent rejections, and unreachable
   * meters. Anything it throws is swallowed — a broken error handler must not
   * reach the request path either.
   */
  onError?: (err: Error, info: Record<string, unknown>) => void;
  /** Injectable for tests. Defaults to global fetch. */
  fetch?: typeof fetch;
}

export interface MeterSinkStats {
  queued: number;
  sent: number;
  /** Shed from a full buffer, or permanently rejected by the meter. */
  dropped: number;
  failedBatches: number;
  /** Reported by the meter as already-seen. Retries are supposed to produce these. */
  duplicates: number;
}

/**
 * A `Sink` that buffers, batches, and retries against a wayleave meter.
 *
 * Retrying is safe because every event carries an `idempotencyKey` and the
 * meter deduplicates on it: sending a batch twice costs a round trip, not a
 * double-billed customer.
 *
 * ```js
 * import Wayleave from 'wayleave';
 * import { MeterSink } from 'wayleave/meter';
 *
 * const sink = new MeterSink({
 *   endpoint: 'https://meter.wayleave.dev',
 *   apiKey: process.env.WAYLEAVE_METER_KEY,
 *   onError: (err, info) => log.warn({ err, info }, 'meter'),
 * });
 *
 * const gate = new Wayleave({ pricedPaths: { '/api/premium': 0.05 }, sink });
 * process.on('SIGTERM', () => sink.close());
 * ```
 */
export class MeterSink implements Sink {
  constructor(opts: MeterSinkOptions);
  readonly stats: MeterSinkStats;
  /** Synchronous, non-throwing, no I/O. Safe on the request path. */
  emit(event: MeterEvent): void;
  /** Drain the buffer. Never rejects; concurrent calls collapse into one. */
  flush(): Promise<void>;
  /** Stop accepting events and make a final drain. Call on SIGTERM. */
  close(): Promise<MeterSinkStats>;
}

export default MeterSink;
