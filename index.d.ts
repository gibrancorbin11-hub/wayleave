/**
 * wayleave — charge AI agents for passage across your app.
 *
 * Verifies Web Bot Auth signatures (RFC 9421 profile, Ed25519), classifies
 * every request into a lane, applies per-lane policy, and returns 402 with an
 * x402-shaped challenge on routes you price. Humans browse free.
 */

/**
 * A Node `KeyObject` from `node:crypto`. Typed structurally rather than
 * imported so this declaration file needs no @types/node — the package has
 * zero dependencies and the types shouldn't reintroduce one. A real
 * KeyObject satisfies this.
 */
export interface KeyObjectLike {
  readonly type: string;
  readonly asymmetricKeyType?: string;
}

/** The four lanes every request is sorted into. */
export type Lane =
  | 'verified_agent'
  | 'declared_agent'
  | 'suspected_bot'
  | 'human';

export const LANES: Readonly<{
  VERIFIED: 'verified_agent';
  DECLARED: 'declared_agent';
  SUSPECT: 'suspected_bot';
  HUMAN: 'human';
}>;

/**
 * A public key for a signature agent. Accepts a KeyObject, a PEM string, or a
 * bare base64 raw Ed25519 public key (32 bytes, SPKI prefix added for you).
 * Strings are converted to a KeyObject and cached on first use.
 */
export type PublicKeyLike = KeyObjectLike | string;

/**
 * Key directories you trust, keyed by the URL an agent presents in its
 * `signature-agent` header, then by keyid.
 *
 * Note: these are read from config, not fetched. Rotation is not handled.
 */
export type KeyDirectories = Record<string, Record<string, PublicKeyLike>>;

/** Incoming request, normalised. Framework-agnostic on purpose. */
export interface WayleaveRequest {
  method: string;
  path: string;
  /** Host authority the signature was computed over, e.g. "example.com". */
  authority: string;
  headers: Record<string, string | string[] | undefined>;
  /**
   * The connection's source address, e.g. `req.socket.remoteAddress`. Used to
   * key rate limits for unsigned traffic. Supply it: without it every
   * anonymous client shares one bucket. Never taken from a header unless
   * `trustProxy` is on.
   */
  ip?: string;
  /**
   * Your framework's own request, when an adapter supplied one. Never read
   * for classification — it exists so `confirmHuman` can reach the session and
   * cookies that the projection into this shape leaves behind.
   */
  raw?: unknown;
}

export interface VerifyResult {
  ok: boolean;
  /** `${directoryUrl}#${keyid}` when ok, otherwise null. */
  agentId: string | null;
  /** Human-readable reason, safe to log. */
  reason: string;
  /**
   * Single-use token, set only when the signer supplied RFC 9421's `nonce`
   * parameter. Null otherwise — a signature hash is NOT a safe substitute,
   * because deterministic Ed25519 over `@authority` alone makes two
   * legitimate same-second requests byte-identical.
   */
  nonce?: string | null;
  /** Unix seconds the signature stops being valid. */
  expires?: number;
}

export interface Classification {
  lane: Lane;
  agentId: string | null;
  /** Why this lane was chosen. Loggable. */
  evidence: string[];
  /** Present only for verified agents whose signer sent a nonce. */
  nonce?: string | null;
  sigExpires?: number;
}

/** What `verifyPayment` is told about the crossing it is confirming. */
export interface PaymentContext {
  /** Price in USD for the matched resource. */
  price: number;
  /** The priced path prefix that matched. */
  resource: string;
  /** Cryptographic agent identity when verified, else lane:address. */
  identity: string;
  path: string;
  /** Unix seconds. */
  now: number;
}

/**
 * Your answer to "did this actually settle?". Return `true`, or an object
 * carrying the settlement reference so it reaches the ledger. Anything else
 * — including a throw — denies passage.
 */
export type PaymentVerifier = (
  proof: string,
  ctx: PaymentContext
) => boolean | { ok: boolean; ref?: string; reason?: string }
  | Promise<boolean | { ok: boolean; ref?: string; reason?: string }>;

/** x402-shaped payment challenge returned with a 402. */
export interface PaymentChallenge {
  scheme: 'x402';
  price_usd: number;
  /** The priced path prefix that matched. */
  resource: string;
}

export interface Decision {
  lane: Lane;
  /** agentId when verified, else `${lane}:${xff ?? 'unknown'}`. */
  identity: string;
  status: 200 | 402 | 403 | 429;
  /** Why this status was returned. */
  why: string;
  evidence: string[];
  /** Present only on 402. */
  challenge?: PaymentChallenge;
  /** Present only when `verifyPayment` confirmed settlement. */
  billed?: number;
  /** Settlement reference returned by your verifier, if any. */
  paymentRef?: string | null;
}

/** What the metering hook receives. It may throw; serving continues. */
export interface MeterEvent {
  /**
   * Event schema version. Present so a meter that outlives one release can
   * tell which shape it is reading. Currently always 1.
   */
  v: number;
  /**
   * Unique per crossing and stable across retries of the same event, so a
   * sink that resends after a failure can be deduplicated at the far end.
   * Namespaced per process — two instances never collide.
   */
  idempotencyKey: string;
  /** Unix seconds. */
  t: number;
  path: string;
  lane: Lane;
  identity: string;
  status: number;
  why: string;
  evidence: string[];
  /** Zero unless settlement was confirmed. Never records an unpaid crossing. */
  billedUsd: number;
  /** Settlement reference from your verifier, when it supplied one. */
  paymentRef?: string;
}

/** `[pathPrefix, allow]` — first matching prefix wins. */
export type PolicyRule = [prefix: string, allow: boolean];

/**
 * Rate-limit counters and consumed nonces. Implement this against Redis or
 * Postgres and pass it as `store` to share state across instances.
 *
 * Must be synchronous — it is called on every request, and an awaited round
 * trip per crossing costs more than the crossing earns. Put a distributed
 * backend behind a local view that replicates asynchronously.
 *
 * Note the two uses differ in how much they mind approximation: fixed-window
 * rate limiting tolerates it, replay does not. A nonce that has not yet
 * replicated is a nonce that can be spent twice.
 */
export interface Store {
  /** Requests by this identity in the current window. Returns the new count. */
  hit(identity: string, windowSeconds: number, now: number): number;
  hasNonce(nonce: string): boolean;
  rememberNonce(nonce: string, expiresAt: number): void;
}

/** The default `Store`: bounded, in this process's memory, lost on restart. */
export class MemoryStore implements Store {
  constructor(opts?: { maxTracked?: number });
  maxTracked: number;
  hit(identity: string, windowSeconds: number, now: number): number;
  hasNonce(nonce: string): boolean;
  rememberNonce(nonce: string, expiresAt: number): void;
}

/**
 * Where metering events go. Implement `emit` to buffer, batch, retry, and
 * dedup on `idempotencyKey`. It must never throw into the request path.
 */
export interface Sink {
  emit(event: MeterEvent): void;
}

/** The default `Sink`: calls `onEvent` and swallows whatever it throws. */
export class DirectSink implements Sink {
  constructor(onEvent?: (event: MeterEvent) => void);
  emit(event: MeterEvent): void;
}

/**
 * Key lookup. The function form is what makes rotation possible: point it at
 * a cache your app refreshes from a JWKS endpoint on a timer. Synchronous by
 * design — do not fetch here.
 */
export type KeyResolver = (directoryUrl: string) =>
  Record<string, PublicKeyLike> | undefined;

/**
 * Checks whether a request claiming to be a known operator actually came from
 * that operator's published addresses.
 *
 * Return `true` to confirm, `false` to accuse — a false claim is a stronger
 * fraud signal than silence, so it lands in `suspected_bot` alongside an
 * invalid signature. Return `null`/`undefined` for "cannot check", which
 * leaves the request merely `declared_agent`: unknown is not guilty. A throw
 * is treated as "cannot check" too, so a DNS blip never demotes real agents.
 */
export type AgentIPVerifier = (
  ip: string | undefined,
  userAgent: string
) => boolean | null | undefined;

export interface WayleaveOptions {
  /** Config object, or a resolver function for rotatable keys. */
  directories?: KeyDirectories | KeyResolver;
  /**
   * Verify that a self-declared operator is on its published addresses.
   * Without it, `declared_agent` is a claim taken at face value.
   */
  verifyAgentIP?: AgentIPVerifier;
  /**
   * Rate-limit and replay state. Defaults to a bounded `MemoryStore`, which
   * is per-process: two instances mean two independent limiters. Supply a
   * shared implementation to fix that without touching anything else.
   */
  store?: Store;
  /**
   * Where metering events go. Defaults to a `DirectSink` wrapping `onEvent`.
   * Replace it with a buffering, retrying sink when losing events costs money.
   */
  sink?: Sink;
  /** Per-lane allow/deny rules, evaluated in order. */
  rules?: Partial<Record<Lane, PolicyRule[]>>;
  /** Max requests per identity per window, per lane. */
  rateLimits?: Partial<Record<Lane, number>>;
  /** Window length in seconds. Default 60. */
  rateWindow?: number;
  /** Path prefix -> price in USD. Non-human lanes get 402 here. */
  pricedPaths?: Record<string, number>;
  /**
   * Confirms a payment actually settled. **Without this, every priced route
   * stays 402 forever** — deny is the only safe default, since the proof is a
   * string the payer wrote. Wire it to your facilitator, not to a comparison
   * against the challenge you just issued.
   */
  verifyPayment?: PaymentVerifier;
  /**
   * Price priced routes for everything except an application-confirmed human.
   * Default false.
   *
   * Off, the `human` lane crosses priced routes free — and that lane is a
   * fall-through meaning "no automation tell was found", so a bot sending a
   * browser `user-agent` and an `accept-language` header reaches it. On,
   * absence of evidence stops being a free pass: only a verified signature
   * (which pays) or `confirmHuman` returning true (which browses) crosses.
   * Recommended wherever a route has a price on it.
   */
  strictPricedPaths?: boolean;
  /**
   * Positive proof a person is present — your session, your cookie, your
   * challenge. Only consulted under `strictPricedPaths`. Fails closed: absent,
   * throwing, or non-`true` all mean "pay or leave" on a priced route.
   *
   * Receives your framework's request under an adapter (the Express `req`,
   * session and cookies intact), otherwise whatever you passed to `handle`.
   * Do not infer humanity from headers here — a bot sends those too, which is
   * the whole reason this callback exists.
   */
  confirmHuman?: (req: any) => boolean;
  /**
   * Believe `x-forwarded-for` for the client address. Default false. Turn on
   * ONLY behind a proxy you control that overwrites the header — otherwise
   * clients mint themselves unlimited rate-limit buckets.
   */
  trustProxy?: boolean;
  /**
   * Reject a second use of a signature whose signer supplied a nonce.
   * Default true. In-process only: it does not span instances or restarts.
   */
  replayProtection?: boolean;
  /**
   * Ceiling on in-memory identities and nonces. Default 10000. Bounds memory
   * under a flood of distinct clients; oldest entries are evicted.
   */
  maxTracked?: number;
  /**
   * Metering hook, called once per request. Exceptions are swallowed —
   * billing must never break serving.
   */
  onEvent?: (event: MeterEvent) => void;
  /**
   * Shorthand for wiring a `MeterSink` yourself: `meter: { apiKey }` builds
   * one pointed at meter.wayleave.dev. Pass `sink` directly for full control;
   * an explicit `sink` always wins.
   */
  meter?: { apiKey: string; endpoint?: string; [k: string]: unknown };
}

/** Build the `@signature-params` value for the Web Bot Auth profile. */
export function buildParams(
  keyid: string,
  created: number,
  expires: number
): string;

/**
 * Sign a request the way a legitimate agent operator's SDK would.
 * Mutates and returns `headers`.
 */
export function signRequest(
  headers: Record<string, string>,
  authority: string,
  privateKey: KeyObjectLike,
  keyid: string,
  directoryUrl: string,
  created?: number,
  expires?: number
): Record<string, string>;

/** Verify a presented signature against your configured directories. */
export function verifySignature(
  headers: Record<string, string | string[] | undefined>,
  authority: string,
  directories: KeyDirectories | KeyResolver,
  now?: number
): VerifyResult;

/**
 * Sort a request into a lane. A signature that FAILS verification lands in
 * `suspected_bot`, not `human` — forging identity is the loudest signal there is.
 */
export function classify(
  req: WayleaveRequest,
  directories: KeyDirectories | KeyResolver,
  now?: number,
  opts?: {
    /** Confirms a declared operator is on its published addresses. */
    verifyAgentIP?: AgentIPVerifier;
    /** Source address handed to `verifyAgentIP`. */
    ip?: string;
  }
): Classification;

export class Wayleave {
  constructor(opts?: WayleaveOptions);
  /**
   * Async twin of `handle`. Required if `verifyPayment` returns a Promise —
   * which any real facilitator does, since confirming settlement is a network
   * call. `express()` uses this.
   */
  handleAsync(req: WayleaveRequest, now?: number, paymentProof?: string): Promise<Decision>;
  /** Classify, apply policy, price, and emit the metering event. */
  handle(
    req: WayleaveRequest,
    now?: number,
    paymentProof?: string
  ): Decision;
  /** Express/Connect adapter. Sets `req.wayleave` to the Decision. */
  express(): (req: any, res: any, next: (err?: any) => void) => void;
}

export default Wayleave;
