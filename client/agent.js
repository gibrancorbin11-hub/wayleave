#!/usr/bin/env node
/**
 * Pay for one API call, and show every step of it.
 *
 *   WAYLEAVE_AGENT_KEY=0x… node agent.js [url]
 *
 * Defaults to https://api.wayleave.dev/v1/identify.
 *
 * The key is read from the environment and never written anywhere — not to a
 * file, not to the output, not into an error message. It signs an EIP-3009
 * authorisation and nothing else; the agent sends no transaction and spends
 * no gas, so the wallet needs USDC and does not need ETH.
 *
 * Prints what happened at each step rather than just the outcome, because
 * the point of a first paid call is to be able to see where it went wrong.
 */
import { privateKeyToAccount } from 'viem/accounts';
import { createPublicClient, http, erc20Abi } from 'viem';
import { baseSepolia, base } from 'viem/chains';
import { payFetch } from './pay.js';

const URL_ARG = process.argv[2] || 'https://api.wayleave.dev/v1/identify';
const KEY = process.env.WAYLEAVE_AGENT_KEY;

const die = (msg) => { console.error(`\n  ${msg}\n`); process.exit(1); };

if (!KEY) die('set WAYLEAVE_AGENT_KEY to the agent wallet\'s private key (0x + 64 hex)');
if (!/^0x[0-9a-fA-F]{64}$/.test(KEY))
  die('WAYLEAVE_AGENT_KEY must be 0x followed by 64 hex characters.\n' +
      '  If what you have is 40 hex, that is an ADDRESS, not a key.');

const account = privateKeyToAccount(KEY);
console.log(`\n  agent wallet   ${account.address}`);
console.log(`  target         ${URL_ARG}\n`);

/* ── 1. the challenge ──────────────────────────────────────────────────── */
const body = JSON.stringify({
  method: 'GET', url: 'https://example.com/', headers: { 'user-agent': 'PayingAgent/1.0' },
});
const headers = { 'content-type': 'application/json' };

const probe = await fetch(URL_ARG, { method: 'POST', headers, body });
console.log(`  1. unpaid request         -> ${probe.status}`);

if (probe.status === 401)
  die('401, not 402. Payments are not enabled on that service yet.\n' +
      '  Check healthz: payments.enabled must be true (it needs CDP credentials).');
if (probe.status !== 402)
  die(`expected 402, got ${probe.status}. Nothing to pay.`);

const challenge = await probe.clone().json();
const req = challenge.accepts?.[0];
if (!req) die('the 402 carried no accepts[] — nothing says what to pay');

const usd = Number(req.maxAmountRequired) / 1e6;
console.log(`     price                  $${usd} USDC on ${req.network}`);
console.log(`     payable to             ${req.payTo}`);

/* ── 2. can this wallet actually pay it ────────────────────────────────── */
const chain = req.network === 'base' ? base : baseSepolia;
const pub = createPublicClient({ chain, transport: http() });
let balance = null;
try {
  balance = await pub.readContract({
    address: req.asset, abi: erc20Abi, functionName: 'balanceOf', args: [account.address],
  });
  console.log(`\n  2. wallet balance         $${Number(balance) / 1e6} USDC`);
} catch {
  console.log('\n  2. wallet balance         (could not read; continuing)');
}
if (balance !== null && balance < BigInt(req.maxAmountRequired))
  die(`not enough USDC. Need $${usd}, wallet holds $${Number(balance) / 1e6}.\n` +
      (req.network === 'base-sepolia'
        ? '  Testnet USDC is free: https://faucet.circle.com (pick Base Sepolia).'
        : '  This is MAINNET. Fund it deliberately.'));

/* ── 3. pay ────────────────────────────────────────────────────────────── */
console.log('\n  3. signing authorisation  (no transaction, no gas)');
const res = await payFetch(URL_ARG, { privateKey: KEY, method: 'POST', headers, body });
console.log(`     paid request           -> ${res.status}`);

const text = await res.text();
if (res.status !== 200) {
  let why = text.slice(0, 300);
  try { why = JSON.parse(text).error || why; } catch {}
  die(`payment was not accepted: ${why}`);
}

console.log('\n  ✓ paid and served.\n');
const auth = res.wayleavePayment?.payload?.authorization;
if (auth) {
  console.log(`     authorised  $${Number(auth.value) / 1e6} USDC`);
  console.log(`     from        ${auth.from}`);
  console.log(`     to          ${auth.to}`);
}
console.log(`\n  response: ${text.slice(0, 200)}\n`);
console.log('  The settlement appears at https://wayleave.dev/app/payments');
console.log(`  and on-chain at https://${req.network === 'base' ? '' : 'sepolia.'}basescan.org/address/${req.payTo}\n`);
