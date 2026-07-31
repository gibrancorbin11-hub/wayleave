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
}

export interface VerifyResult {
  ok: boolean;
  /** `${directoryUrl}#${keyid}` when ok, otherwise null. */
  agentId: string | null;
  /** Human-readable reason, safe to log. */
  reason: string;
}

export interface Classification {
  lane: Lane;
  agentId: string | null;
  /** Why this lane was chosen. Loggable. */
  evidence: string[];
}

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
  /** Present only when a priced request was paid. */
  billed?: number;
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
  billedUsd: number;
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
