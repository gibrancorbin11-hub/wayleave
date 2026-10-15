/**
 * A paying x402 agent.
 *
 * The gate in this repo has always been able to CHARGE. Nothing in it could
 * PAY, so the whole priced path had never been exercised by a client that
 * behaves like a stranger's agent — which is how two bugs survived in it:
 * the payment header was read under a name x402 does not use, and the
 * payload was required as raw JSON when the protocol sends base64. Both are
 * fixed; this is the thing that proves it.
 *
 * Separate package, with viem, so the gate stays dependency-free. Signing an
 * EIP-712 payload needs keccak256 and Node has no builtin for it — `sha3-256`
 * is a different algorithm despite the name, and using it would produce
 * signatures that verify nowhere.
 *
 * ── What "paying" actually is here ───────────────────────────────────────
 *
 * No transaction is sent and no gas is spent by the agent. Under the `exact`
 * scheme the agent signs an EIP-3009 `TransferWithAuthorization` — an
 * off-chain authorisation saying "this much USDC may move from me to that
 * address, once, within this window". The facilitator submits it. So the
 * agent needs USDC and a key; it does not need ETH.
 *
 * That is also why the authorisation is the dangerous artefact: anybody
 * holding it can execute that transfer. It goes to the resource server and
 * nowhere else, which is why `payFetch` will not follow a redirect while
 * carrying one.
 */
import { createWalletClient, http, keccak256, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base, baseSepolia } from 'viem/chains';

/**
 * The EIP-712 domain each USDC deployment enforces.
 *
 * It cannot be guessed and it is NOT published in the 402 challenge: the
 * `accepts` block this gate emits carries scheme, network, amount, asset,
 * payTo and timeout, but no `extra`. A signature made against the wrong
 * domain is well-formed and verifies nowhere, so the values are pinned per
 * deployment, read from each contract rather than assumed.
 *
 * The names genuinely differ — Base mainnet USDC calls itself "USD Coin",
 * the Sepolia test token calls itself "USDC". One hardcoded string is wrong
 * on the other chain.
 */
const DOMAINS = {
  'base': {
    chain: base,
    asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    name: 'USD Coin', version: '2',
  },
  'base-sepolia': {
    chain: baseSepolia,
    asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    name: 'USDC', version: '2',
  },
};

const TRANSFER_WITH_AUTHORIZATION = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
};

/** A fresh 32-byte nonce. Reusing one makes the second transfer fail. */
function randomNonce() {
  const b = new Uint8Array(32);
  (globalThis.crypto ?? require('node:crypto').webcrypto).getRandomValues(b);
  return toHex(b);
}

/**
 * Sign one payment authorisation against a 402's requirements.
 *
 * Returns the x402 payload object. It is NOT encoded here — `payFetch` does
 * that — so a caller can inspect exactly what was signed before it travels.
 */
export async function signPayment(requirements, { privateKey, now = () => Date.now() } = {}) {
  if (!requirements || typeof requirements !== 'object')
    throw new Error('no payment requirements to sign against');
  const { scheme, network, maxAmountRequired, payTo, asset, resource } = requirements;

  /* `exact` is the only scheme implemented. Signing an authorisation for a
     scheme whose rules are different risks authorising more than intended,
     so an unknown scheme refuses rather than guessing. */
  if (scheme !== 'exact') throw new Error(`unsupported x402 scheme: ${scheme}`);

  const d = DOMAINS[network];
  if (!d) throw new Error(`no EIP-712 domain known for network "${network}"`);

  /* The asset in the challenge must be the one whose domain we are about to
     sign against. A server naming a different token would otherwise get a
     signature valid for USDC. */
  if (asset && asset.toLowerCase() !== d.asset.toLowerCase())
    throw new Error(`challenge asset ${asset} is not the ${network} USDC this client can sign for`);

  const account = privateKeyToAccount(privateKey);
  const validAfter = 0n;
  const validBefore = BigInt(Math.floor(now() / 1000) +
    (Number(requirements.maxTimeoutSeconds) || 600));

  const authorization = {
    from: account.address,
    to: payTo,
    value: BigInt(maxAmountRequired),
    validAfter,
    validBefore,
    nonce: randomNonce(),
  };

  const signature = await account.signTypedData({
    domain: { name: d.name, version: d.version, chainId: d.chain.id, verifyingContract: d.asset },
    types: TRANSFER_WITH_AUTHORIZATION,
    primaryType: 'TransferWithAuthorization',
    message: authorization,
  });

  return {
    x402Version: 1,
    scheme: 'exact',
    network,
    payload: {
      signature,
      authorization: {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value.toString(),
        validAfter: authorization.validAfter.toString(),
        validBefore: authorization.validBefore.toString(),
        nonce: authorization.nonce,
      },
    },
    resource,
  };
}

/** The X-PAYMENT header value: base64 of the payload, as x402 specifies. */
export const encodePayment = (payload) =>
  Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');

/**
 * fetch(), but it pays a 402 and retries once.
 *
 * Deliberately once. A second 402 after paying means the payment was
 * rejected, and paying again would authorise a second transfer to answer a
 * question already answered.
 */
export async function payFetch(url, { privateKey, fetchImpl = fetch, now, ...init } = {}) {
  const first = await fetchImpl(url, { ...init, redirect: 'manual' });
  if (first.status !== 402) return first;

  const body = await first.clone().json().catch(() => null);
  const requirements = body?.accepts?.[0];
  if (!requirements)
    throw new Error('402 carried no accepts[0]; nothing says what to pay');

  const payload = await signPayment(requirements, { privateKey, now });

  /* `redirect: 'manual'`, carrying an authorisation.
     The signed payload is bearer-equivalent: whoever holds it can execute
     that transfer. Following a redirect would hand it to whatever host the
     server named, so a redirect is surfaced instead of followed. */
  const paid = await fetchImpl(url, {
    ...init,
    redirect: 'manual',
    headers: { ...(init.headers || {}), 'X-PAYMENT': encodePayment(payload) },
  });
  paid.wayleavePayment = payload;
  return paid;
}
