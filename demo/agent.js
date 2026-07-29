/** A legitimate agent: signs its request, gets verified, pays, gets data. */
import { signRequest } from '../index.js';
import { demoAgent, DIRECTORY, KEYID } from './keys.js';

const headers = { 'user-agent': 'DemoAgent/1.0' };
signRequest(headers, 'localhost:4020', demoAgent.privateKey, KEYID, DIRECTORY);

// first call: verified but unpaid -> 402 with a challenge
let r = await fetch('http://localhost:4020/api/premium/comps', { headers });
console.log('signed, unpaid  ->', r.status);
const challenge = JSON.parse(r.headers.get('x-payment-challenge'));

// pay the wayleave and retry (payment stub for demo)
headers['x-payment-proof'] = `paid:${challenge.resource}:${challenge.price_usd}`;
// re-sign: never reuse a signature
delete headers['signature']; delete headers['signature-input'];
signRequest(headers, 'localhost:4020', demoAgent.privateKey, KEYID, DIRECTORY);
r = await fetch('http://localhost:4020/api/premium/comps', { headers });
const body = await r.json();
console.log('signed, paid    ->', r.status, JSON.stringify(body, null, 2));

// The whole point of the demo: the signature actually verified.
if (body.lane !== 'verified_agent') {
  console.error(`\nFAILED: expected lane "verified_agent", got "${body.lane}".`);
  process.exit(1);
}
console.log('\nverified by signature, charged $%s. Humans pay nothing.', body.billed);
