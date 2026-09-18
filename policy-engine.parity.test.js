/**
 * The gate's policy-engine.js is a copy of the meter's. This asserts they have
 * not drifted.
 *
 * If they drift, a customer sees a rule the dashboard accepted and the origin
 * ignores -- which looks exactly like the product working, and is the worst
 * failure available to us. The check is skipped when the meter checkout is not
 * present, so this suite still runs for anyone who only has the package.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';

const METER = '/Users/gibrancorbin/Desktop/business domains/wayleave-meter/src/policy-engine.js';

test('the ported evaluator matches the meter, body for body', async t => {
  try { await access(METER); } catch { return t.skip('meter checkout not present'); }
  const strip = s => s.replace(/^\/\*\*[\s\S]*?\*\/\s*/, '').trim();
  const [mine, theirs] = await Promise.all([readFile('./policy-engine.js', 'utf8'), readFile(METER, 'utf8')]);
  assert.equal(strip(mine), strip(theirs),
    'gate and meter evaluators have drifted — re-port policy-engine.js');
});
