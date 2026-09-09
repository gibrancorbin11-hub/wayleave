import { createPrivateKey, randomBytes, sign } from 'node:crypto';

/** Short-lived, request-bound CDP bearer token. The secret never leaves this process.
 * https://docs.cdp.coinbase.com/api-reference/v2/authentication
 */
export function cdpBearerToken({ apiKeyId, apiKeySecret, url, now = Math.floor(Date.now() / 1000) }) {
  if (!apiKeyId || !apiKeySecret) throw new Error('CDP credentials are required');
  const target = new URL(url);
  if (target.protocol !== 'https:' || target.username || target.password || target.hash)
    throw new Error('CDP endpoint must be an HTTPS URL without credentials or fragment');
  let key;
  try {
    if (apiKeySecret.includes('-----BEGIN')) {
      key = createPrivateKey(apiKeySecret.replaceAll('\\n', '\n'));
    } else {
      const raw = Buffer.from(apiKeySecret, 'base64');
      if (raw.length !== 64) throw new Error('Invalid length');
      key = createPrivateKey({ key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'), raw.subarray(0, 32),
      ]), format: 'der', type: 'pkcs8' });
    }
  } catch {
    throw new Error('Invalid CDP signing key; use the Secret API Key, not a client or wallet key');
  }
  const ed = key.asymmetricKeyType === 'ed25519';
  if (!ed && !(key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'))
    throw new Error('CDP signing key must be Ed25519 or P-256');
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ alg: ed ? 'EdDSA' : 'ES256', typ: 'JWT', kid: apiKeyId, nonce: randomBytes(16).toString('hex') });
  const claims = encode({ sub: apiKeyId, iss: 'cdp', aud: ['cdp_service'], nbf: now, exp: now + 120,
    uri: `POST ${target.host}${target.pathname}` });
  const input = `${header}.${claims}`;
  const signature = sign(ed ? null : 'sha256', Buffer.from(input), ed ? key : { key, dsaEncoding: 'ieee-p1363' });
  return `${input}.${signature.toString('base64url')}`;
}
