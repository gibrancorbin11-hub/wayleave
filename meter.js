/**
 * MeterSink — ships metering events to a wayleave meter.
 *
 * This is the concrete `sink` that 0.2.0's interface was shaped for. The
 * default DirectSink hands each event straight to `onEvent` and swallows what
 * it throws: correct for uptime, lossy for revenue. This one buffers, batches,
 * and retries, so a meter that is briefly unreachable costs you nothing.
 *
 * Three rules govern every line in this file, in this order:
 *
 *   1. NEVER throw into the request path. A billing backend having a bad day
 *      must not become your customers having a bad day. `emit` cannot throw,
 *      cannot await, and cannot block.
 *
 *   2. NEVER lose an event silently. Dropping is sometimes unavoidable — a
 *      buffer that grows forever is an outage, not a feature — but a drop is
 *      always counted and always reported.
 *
 *   3. Retry freely. Every event carries an `idempotencyKey`, and the meter
 *      deduplicates on it. Sending the same batch twice costs a round trip,
 *      not a double-billed customer. This is the entire reason that field was
 *      added before there was anything to receive it.
 *
 * Zero dependencies: `fetch` is global from Node 18.
 */

const DEFAULTS = {
  flushMs: 5000,
  maxBatch: 500,
  maxBuffer: 10000,
  maxRetries: 5,
  timeoutMs: 10000,
};

export class MeterSink {
  /**
   * opts = {
   *   endpoint: 'https://meter.wayleave.dev',   // required
   *   apiKey:   'wm_live_...',                  // required
   *   flushMs:   5000,   // how often to drain the buffer
   *   maxBatch:  500,    // events per request; the meter caps at 1000
   *   maxBuffer: 10000,  // hard ceiling before shedding
   *   maxRetries: 5,     // per batch, exponential backoff
   *   timeoutMs: 10000,
   *   onError: (err, info) => {}   // observability hook; never called with
   *                                // anything that should crash your process
   * }
   */
  constructor(opts = {}) {
    if (!opts.endpoint) throw new Error('MeterSink requires an endpoint');
    if (!opts.apiKey) throw new Error('MeterSink requires an apiKey');

    this.endpoint = String(opts.endpoint).replace(/\/$/, '');
    this.apiKey = opts.apiKey;
    this.flushMs = opts.flushMs ?? DEFAULTS.flushMs;
    this.maxBatch = opts.maxBatch ?? DEFAULTS.maxBatch;
    this.maxBuffer = opts.maxBuffer ?? DEFAULTS.maxBuffer;
    this.maxRetries = opts.maxRetries ?? DEFAULTS.maxRetries;
    this.timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
    this.onError = typeof opts.onError === 'function' ? opts.onError : () => {};
    this._fetch = opts.fetch || globalThis.fetch;

    this._buffer = [];
    this._inFlight = false;
    this._closed = false;

    /** Counters worth exposing: a silent drop is a billing hole. */
    this.stats = { queued: 0, sent: 0, dropped: 0, failedBatches: 0, duplicates: 0 };

    this._timer = setInterval(() => { this.flush(); }, this.flushMs);
    // Do not hold the process open just to run a billing timer.
    if (typeof this._timer.unref === 'function') this._timer.unref();
  }

  /**
   * Called by the gate, once per request, on the hot path.
   *
   * Synchronous, non-throwing, and does no I/O. The only work here is a push
   * and possibly scheduling a flush on a later tick.
   */
  emit(event) {
    if (this._closed) return;
    try {
      if (this._buffer.length >= this.maxBuffer) {
        // Shed the oldest. They have been failing longest and are the most
        // likely to be stale; the newest are the most likely to succeed on
        // the next attempt. Either choice loses billing data, which is why
        // this is counted and surfaced rather than quietly absorbed.
        const shed = this._buffer.shift();
        this.stats.dropped++;
        this.onError(new Error('meter buffer full, dropped oldest event'), {
          dropped: this.stats.dropped, idempotencyKey: shed?.idempotencyKey,
        });
      }
      this._buffer.push(event);
      this.stats.queued++;

      // Schedule rather than await: emit must return to the request handler
      // immediately.
      if (this._buffer.length >= this.maxBatch && !this._inFlight)
        queueMicrotask(() => this.flush());
    } catch (err) {
      // Even the buffering path must not throw into serving.
      try { this.onError(err, { phase: 'emit' }); } catch { /* nothing left to do */ }
    }
  }

  /**
   * Drain the buffer. Safe to call at any time; concurrent calls collapse
   * into the one already running.
   *
   * Never rejects. Failures are reported through `onError` and the events go
   * back on the buffer for the next attempt.
   */
  async flush() {
    if (this._inFlight || this._buffer.length === 0) return;
    this._inFlight = true;
    try {
      while (this._buffer.length > 0) {
        const batch = this._buffer.splice(0, this.maxBatch);
        const ok = await this._sendWithRetry(batch);
        if (!ok) {
          // Put them back at the FRONT so ordering is preserved, and stop —
          // hammering a meter that is down helps nobody.
          this._buffer.unshift(...batch.slice(0, Math.max(0, this.maxBuffer - this._buffer.length)));
          break;
        }
      }
    } catch (err) {
      try { this.onError(err, { phase: 'flush' }); } catch { /* ignore */ }
    } finally {
      this._inFlight = false;
    }
  }

  async _sendWithRetry(batch) {
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const r = await this._send(batch);

      if (r.ok) {
        this.stats.sent += r.accepted ?? batch.length;
        this.stats.duplicates += r.duplicates ?? 0;
        if (r.rejected?.length) {
          // The meter refused specific events permanently — a schema mismatch,
          // usually. Retrying cannot fix them and would wedge everything
          // queued behind. Report and move on.
          this.onError(new Error(`meter rejected ${r.rejected.length} event(s)`), {
            phase: 'send', rejected: r.rejected,
          });
        }
        return true;
      }

      // 4xx other than 429 is our bug, not a blip. Retrying a malformed or
      // unauthorised request forever is how a buffer becomes a memory leak.
      if (r.status && r.status >= 400 && r.status < 500 && r.status !== 429) {
        this.stats.failedBatches++;
        this.stats.dropped += batch.length;
        this.onError(new Error(`meter rejected batch: ${r.status} ${r.error ?? ''}`.trim()), {
          phase: 'send', status: r.status, dropped: batch.length, permanent: true,
        });
        return true; // consumed: do not requeue something that can never succeed
      }

      if (attempt < this.maxRetries) {
        // Exponential backoff with jitter, so a fleet of instances coming back
        // after an outage does not stampede the meter in lockstep.
        const base = Math.min(30000, 500 * 2 ** attempt);
        await sleep(base / 2 + Math.random() * base / 2);
      }
    }

    this.stats.failedBatches++;
    this.onError(new Error('meter unreachable after retries; events requeued'), {
      phase: 'send', batch: batch.length,
    });
    return false;
  }

  async _send(batch) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await this._fetch(`${this.endpoint}/v1/events`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({ events: batch }),
        signal: ctrl.signal,
      });
      let body = null;
      try { body = await res.json(); } catch { /* non-JSON body stays null */ }
      if (!res.ok) return { ok: false, status: res.status, error: body?.error };
      return { ok: true, ...body };
    } catch (err) {
      return { ok: false, status: 0, error: err.message };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Stop accepting events and make a final attempt to drain.
   *
   * Call this on SIGTERM. Without it, whatever is buffered at shutdown is
   * revenue you never billed for. With it, a rolling deploy costs nothing.
   */
  async close() {
    this._closed = true;
    clearInterval(this._timer);
    await this.flush();
    return this.stats;
  }
}

/**
 * Deliberately NOT unref'd, unlike the flush interval.
 *
 * The interval is a heartbeat and must not hold a process open. A backoff is
 * an operation already in flight: unref'ing it lets the event loop drain
 * mid-retry, which abandons events that were about to be delivered — during
 * exactly the shutdown where `close()` is trying to save them.
 */
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

export default MeterSink;
