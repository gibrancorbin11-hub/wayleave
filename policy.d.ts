/** Remote policy: fetched out of band, cached on disk, fail-open by construction. */
export interface PolicyRule {
  id: string;
  route?: string;
  method?: string;
  tool?: string;
  lane?: 'verified_agent' | 'declared_agent' | 'suspected_bot' | 'human';
  subject?: string;
  operator?: string;
  verified?: boolean;
  action: 'allow' | 'deny' | 'pay' | 'quota';
  priceMicros?: number;
  rail?: string;
  quota?: { limit: number; windowSeconds: number };
}

export interface PolicyDocument {
  version: string;
  default: 'allow' | 'deny';
  rules: PolicyRule[];
  fetched?: string;
  onUnreachable?: string;
}

export interface CompiledPolicy {
  rules: Record<string, [string, boolean][]>;
  rateLimits: Record<string, number>;
  pricedPaths: Record<string, number>;
  /** Rule ids the gate can enforce at this layer. */
  applied: string[];
  /** Rules deliberately not applied, with the reason. Never silently widened. */
  skipped: { id: string; why: string }[];
}

export function compilePolicy(doc: PolicyDocument | null): CompiledPolicy;

export interface RemotePolicyOptions {
  apiKey: string;
  endpoint?: string;
  refreshMs?: number;
  cachePath?: string;
  onEvent?: (event: { type: string; [k: string]: unknown }) => void;
  onChange?: (compiled: CompiledPolicy) => void;
  fetchImpl?: typeof fetch;
}

export class RemotePolicy {
  constructor(options: RemotePolicyOptions);
  document: PolicyDocument | null;
  etag: string | null;
  fetchedAt: number | null;
  compiled(): CompiledPolicy;
  /** Never rejects. A gate must boot even when the meter is unreachable. */
  start(): Promise<this>;
  refresh(): Promise<PolicyDocument | null>;
  stop(): void;
}
