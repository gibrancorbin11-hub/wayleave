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
export function validatePolicy(policy) {
  if (!policy || typeof policy.version !== 'string' || !policy.version || !Array.isArray(policy.rules) || policy.rules.length > 100) throw new Error('Version and at most 100 rules required');
  if (!['allow','deny'].includes(policy.default)) throw new Error('Explicit default required');
  const ids = new Set();
  for (const r of policy.rules) {
    if (!r || typeof r.id !== 'string' || !r.id || ids.has(r.id)) throw new Error('Unique rule IDs required');
    ids.add(r.id);
    const supported = ['id','route','method','tool','lane','subject','operator','verified','action','priceMicros','rail','quota'];
    if (Object.keys(r).some(k => !supported.includes(k))) throw new Error('Unknown rule property');
    if (!['allow','deny','pay','quota'].includes(r.action)) throw new Error('Unsupported action');
    if (r.route !== undefined && (typeof r.route !== 'string' || !r.route.startsWith('/') || /[?#\\]/.test(r.route))) throw new Error('Invalid route prefix');
    for (const k of ['method','tool','subject','operator']) if (r[k] !== undefined && (typeof r[k] !== 'string' || !r[k])) throw new Error('Invalid selector');
    // The lane is the gate's own classification of the request. It is not an
    // identity: suspected_bot means nothing was proven, so a rule written
    // against it is a rule about absence of evidence, which is what a site
    // owner actually wants to act on.
    if (r.lane !== undefined && !['verified_agent','declared_agent','suspected_bot','human'].includes(r.lane)) throw new Error('Unknown lane');
    if (r.verified !== undefined && typeof r.verified !== 'boolean') throw new Error('Invalid verified selector');
    if (r.action === 'pay' && (!Number.isSafeInteger(r.priceMicros) || r.priceMicros <= 0 || typeof r.rail !== 'string' || !r.rail)) throw new Error('Payment requires positive integer USD micros and rail');
    if (r.action === 'quota' && (!r.quota || !Number.isSafeInteger(r.quota.limit) || r.quota.limit < 1 || !Number.isSafeInteger(r.quota.windowSeconds) || r.quota.windowSeconds < 1)) throw new Error('Invalid quota');
  }
  return policy;
}
export async function evaluatePolicy(policy, context, { quotaStore } = {}) {
  validatePolicy(policy);
  if (typeof context.tenant !== 'string' || !context.tenant || typeof context.path !== 'string') throw new Error('Trusted tenant and path required');
  const identity = context.identity?.verified === true ? context.identity : null;
  const r = policy.rules.find(r =>
    (r.route === undefined || context.path === r.route || context.path.startsWith(r.route.endsWith('/') ? r.route : r.route+'/')) &&
    (r.method === undefined || r.method === context.method) &&
    (r.lane === undefined || r.lane === context.lane) &&
    (r.tool === undefined || r.tool === context.tool) &&
    (r.verified === undefined || r.verified === !!identity) &&
    (r.subject === undefined || r.subject === identity?.subject) &&
    (r.operator === undefined || r.operator === identity?.operator));
  const base = { policyVersion: policy.version, ruleId: r?.id || null };
  if (!r) return { ...base, action: policy.default };
  if (r.action === 'quota') {
    const subject = identity?.subject || context.anonymousBucket;
    if (!subject || !quotaStore) return { ...base, action: 'deny', reason: 'Quota store or identity bucket unavailable' };
    const key = JSON.stringify([context.tenant, policy.version, r.id, subject]);
    try {
      const allowed = await quotaStore.consume({ key, limit: r.quota.limit, windowSeconds: r.quota.windowSeconds });
      return { ...base, action: allowed === true ? 'allow' : 'deny', reason: allowed === true ? 'Within quota' : 'Quota exceeded' };
    } catch { return { ...base, action: 'deny', reason: 'Quota store unavailable' }; }
  }
  return r.action === 'pay' ? { ...base, action: 'pay', priceMicros: r.priceMicros, currency: 'USD', rail: r.rail } : { ...base, action: r.action };
}
