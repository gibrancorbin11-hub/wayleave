/**
 * The policy evaluator, evaluated IN THE GATE.
 *
 * ── THIS FILE IS A COPY ────────────────────────────────────────────────
 * It must stay byte-identical in behaviour to src/policy-engine.js in the
 * meter. The meter validates what it stores; the gate evaluates what it
 * fetched. If the two ever disagree, a customer sees a rule accepted by the
 * dashboard and ignored at their origin, which is the worst kind of wrong:
 * it looks like it is working.
 *
 * The copy exists because the gate has zero dependencies and cannot import
 * from the meter. policy-engine.parity.test.js asserts the two files match.
 * ───────────────────────────────────────────────────────────────────────
 */
/* Documents that have already been through validatePolicy.
   
   A WeakSet, so remembering a document cannot keep it alive: entries vanish
   when the policy is replaced by the next fetch. The point is that a policy
   is validated once, when it arrives, and not again on every request that
   consults it -- a hot path doing full schema validation per crossing is
   work nobody asked for, repeated forever. */
const VALIDATED = new WeakSet();

/** True when this exact object has already been validated. */
export function isValidated(policy) {
  return typeof policy === 'object' && policy !== null && VALIDATED.has(policy);
}

export function validatePolicy(policy) {
  if (!policy || typeof policy.version !== 'string' || !policy.version || !Array.isArray(policy.rules) || policy.rules.length > 100) throw new Error('Version and at most 100 rules required');
  if (!['allow','deny'].includes(policy.default)) throw new Error('Explicit default required');
  const ids = new Set();
  for (const r of policy.rules) {
    if (!r || typeof r.id !== 'string' || !r.id || ids.has(r.id)) throw new Error('Unique rule IDs required');
    ids.add(r.id);
    const supported = ['id','route','method','tool','lane','subject','operator','verified','action','priceMicros','rail','quota'];
    if (Object.keys(r).some(k => !supported.includes(k))) throw new Error('Unknown rule property');
    if (!['allow','deny','pay','quota','allowance'].includes(r.action)) throw new Error('Unsupported action');
    if (r.route !== undefined && (typeof r.route !== 'string' || !r.route.startsWith('/') || /[?#\\]/.test(r.route))) throw new Error('Invalid route prefix');
    for (const k of ['method','tool','subject','operator']) if (r[k] !== undefined && (typeof r[k] !== 'string' || !r[k])) throw new Error('Invalid selector');
    // The lane is the gate's own classification of the request. It is not an
    // identity: suspected_bot means nothing was proven, so a rule written
    // against it is a rule about absence of evidence, which is what a site
    // owner actually wants to act on.
    if (r.lane !== undefined && !['verified_agent','declared_agent','suspected_bot','human'].includes(r.lane)) throw new Error('Unknown lane');
    if (r.verified !== undefined && typeof r.verified !== 'boolean') throw new Error('Invalid verified selector');
    if (r.action === 'pay' && (!Number.isSafeInteger(r.priceMicros) || r.priceMicros <= 0 || typeof r.rail !== 'string' || !r.rail)) throw new Error('Payment requires positive integer USD micros and rail');
    if ((r.action === 'quota' || r.action === 'allowance') && (!r.quota || !Number.isSafeInteger(r.quota.limit) || r.quota.limit < 1 || !Number.isSafeInteger(r.quota.windowSeconds) || r.quota.windowSeconds < 1)) throw new Error('Invalid quota');
  }
  VALIDATED.add(policy);
  return policy;
}
/**
 * Everything both evaluators need before either can decide anything.
 *
 * Extracted so the matching rules exist once. Two copies of "does this rule
 * apply" is how a sync path and an async path quietly begin enforcing
 * different policies from the same document — which is the bug this file
 * already had between the gate and the meter, and is not worth reproducing
 * inside a single file.
 */
function prepare(policy, context) {
  /* Validated once, when the document arrived — not again here. A caller
     handing over a document nobody has checked still gets it checked, because
     evaluating an unvalidated policy is how a malformed rule becomes a wrong
     decision. But the normal path, where the fetcher validated it before it
     became the live document, does no schema work per request at all. */
  if (!isValidated(policy)) validatePolicy(policy);
  if (typeof context.tenant !== 'string' || !context.tenant || typeof context.path !== 'string') throw new Error('Trusted tenant and path required');
  const identity = context.identity?.verified === true ? context.identity : null;
  const matches = r =>
    (r.route === undefined || context.path === r.route || context.path.startsWith(r.route.endsWith('/') ? r.route : r.route+'/')) &&
    (r.method === undefined || r.method === context.method) &&
    (r.lane === undefined || r.lane === context.lane) &&
    (r.tool === undefined || r.tool === context.tool) &&
    (r.verified === undefined || r.verified === !!identity) &&
    (r.subject === undefined || r.subject === identity?.subject) &&
    (r.operator === undefined || r.operator === identity?.operator);
  return { identity, matches };
}

/** A rule that needs no I/O to answer. Shared by both evaluators. */
function plainDecision(r, base) {
  return r.action === 'pay'
    ? { ...base, action: 'pay', priceMicros: r.priceMicros, currency: 'USD', rail: r.rail }
    : { ...base, action: r.action };
}

/**
 * Evaluate without touching the quota store.
 *
 * `handle()` is synchronous, so it could not evaluate a policy at all — and
 * simply did not. The same document enforced through `express()` and was
 * ignored through `handle()`, which is one policy behaving as two.
 *
 * Everything needing no I/O is decided here: allow, deny, pay, and the
 * default. A quota or allowance rule cannot be, because consuming from the
 * store is a network or database call. Rather than skip such a rule — which
 * would silently pass exactly the traffic the operator metered — it stops and
 * says so, and the caller can use handleAsync() or treat the answer as the
 * refusal it is.
 */
export function evaluatePolicySync(policy, context) {
  const { matches } = prepare(policy, context);
  for (const r of policy.rules) {
    if (!matches(r)) continue;
    const base = { policyVersion: policy.version, ruleId: r.id };
    if (r.action === 'quota' || r.action === 'allowance')
      return { ...base, action: 'needs-async', reason: 'quota rule requires handleAsync' };
    return plainDecision(r, base);
  }
  return { policyVersion: policy.version, ruleId: null, action: policy.default };
}

export async function evaluatePolicy(policy, context, { quotaStore } = {}) {
  const { identity, matches } = prepare(policy, context);
  // An exhausted allowance does not answer the request; it steps aside for the
  // rule behind it. Carried so the eventual answer can say why it was reached.
  let spent = null;
  for (const r of policy.rules) {
    if (!matches(r)) continue;
    const base = { policyVersion: policy.version, ruleId: r.id, ...(spent ? { reason: spent } : {}) };
    if (r.action === 'quota' || r.action === 'allowance') {
      const subject = identity?.subject || context.anonymousBucket;
      if (!subject || !quotaStore) {
        if (r.action === 'quota') return { ...base, action: 'deny', reason: 'Quota store or identity bucket unavailable' };
        spent = 'Free allowance could not be verified'; continue;
      }
      const key = JSON.stringify([context.tenant, policy.version, r.id, subject]);
      let allowed;
      try { allowed = await quotaStore.consume({ key, limit: r.quota.limit, windowSeconds: r.quota.windowSeconds }); }
      catch {
        if (r.action === 'quota') return { ...base, action: 'deny', reason: 'Quota store unavailable' };
        // Unknown consumption must not spend the allowance on the operator's
        // behalf. Step aside so the priced rule behind this one applies.
        spent = 'Free allowance could not be verified'; continue;
      }
      if (r.action === 'quota')
        return { ...base, action: allowed === true ? 'allow' : 'deny', reason: allowed === true ? 'Within quota' : 'Quota exceeded' };
      if (allowed === true) return { ...base, action: 'allow', reason: 'Within free allowance' };
      spent = 'Free allowance exhausted'; continue;
    }
    return plainDecision(r, base);
  }
  // A route the operator metered never falls back to a permissive default.
  if (spent) return { policyVersion: policy.version, ruleId: null, action: 'deny', reason: spent };
  return { policyVersion: policy.version, ruleId: null, action: policy.default };
}
