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
) => boolean | { ok: boolean; ref?: string; reason?: string };

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

export interface WayleaveOptions {
  directories?: KeyDirectories;
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
  directories: KeyDirectories,
  now?: number
): VerifyResult;

/**
 * Sort a request into a lane. A signature that FAILS verification lands in
 * `suspected_bot`, not `human` — forging identity is the loudest signal there is.
 */
export function classify(
  req: WayleaveRequest,
  directories: KeyDirectories,
  now?: number
): Classification;

export class Wayleave {
  constructor(opts?: WayleaveOptions);
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
