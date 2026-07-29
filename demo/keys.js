/**
 * The demo agent operator's identity, shared by the server and the agent.
 *
 * This key is FIXED and public on purpose: the server and the agent run as
 * two separate processes, so a freshly generated keypair would differ on each
 * side and every signature would fail verification. A real operator publishes
 * the public half at a key directory URL and keeps the private half secret.
 *
 * Throwaway demo key. Never use it for anything real.
 */

import { createPrivateKey, createPublicKey } from 'node:crypto';

const DEMO_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIaYe4rL5WB5pzEbed5ZzrZmmIpxCgeM2SzehA8BS+YF
-----END PRIVATE KEY-----
`;

export const demoAgent = {
  privateKey: createPrivateKey(DEMO_PRIVATE_PEM),
  publicKey: createPublicKey(createPrivateKey(DEMO_PRIVATE_PEM)),
};

export const DIRECTORY = 'https://demo-agent.example/keys';
export const KEYID = 'demo-1';
