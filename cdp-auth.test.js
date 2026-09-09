import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify } from 'node:crypto';
import { cdpBearerToken } from './cdp-auth.js';
import { coinbaseFacilitator } from './x402.js';
const pair = generateKeyPairSync('ed25519');
const pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
const target = 'https://api.cdp.coinbase.com/platform/v2/x402/settle';
for (const format of ['pem', 'base64']) {
  test(`CDP ${format} JWT has verifiable signature, request binding and short expiry`, () => {
    const secret = format === 'pem' ? pem : Buffer.concat([
      pair.privateKey.export({type:'pkcs8',format:'der'}).subarray(-32),
      pair.publicKey.export({type:'spki',format:'der'}).subarray(-32),
    ]).toString('base64');
    const token = cdpBearerToken({apiKeyId:'test-id',apiKeySecret:secret,url:target,now:1000});
    const [h,p,s]=token.split('.');const header=JSON.parse(Buffer.from(h,'base64url'));const claims=JSON.parse(Buffer.from(p,'base64url'));
    assert.equal(header.alg,'EdDSA');assert.equal(header.kid,'test-id');assert.equal(claims.exp,1120);assert.equal(claims.nbf,1000);
    assert.equal(claims.uri,'POST api.cdp.coinbase.com/platform/v2/x402/settle');
    assert.ok(verify(null,Buffer.from(`${h}.${p}`),pair.publicKey,Buffer.from(s,'base64url')));
  });
}
test('invalid credentials and insecure URLs fail before transport',()=>{
 assert.throws(()=>cdpBearerToken({apiKeyId:'id',apiKeySecret:'invalid',url:target}),/Invalid CDP/);
 assert.throws(()=>cdpBearerToken({apiKeyId:'id',apiKeySecret:pem,url:'http://example.com'}),/HTTPS/);
});
test('facilitator sends bearer auth and never transmits the API secret',async()=>{
 let headers;
 const f=coinbaseFacilitator({apiKeyId:'id',apiKeySecret:pem,receivingAddress:'0xfixture',fetch:async(url,init)=>{headers=init.headers;return {ok:true,status:200,json:async()=>({success:true,transaction:'test'})}}});
 assert.equal((await f('{}',{price:.10})).ok,true);
 assert.match(headers.authorization,/^Bearer /);assert.equal(headers['cb-access-secret'],undefined);assert.ok(!JSON.stringify(headers).includes(pem));
});
test('verification-only mode never grants paid access or reports billed success',async()=>{
 const f=coinbaseFacilitator({apiKeyId:'id',apiKeySecret:pem,receivingAddress:'0xfixture',settle:false,fetch:async()=>({ok:true,status:200,json:async()=>({isValid:true,payer:'payer'})})});
 assert.equal((await f('{}',{price:.10})).ok,false);
});
