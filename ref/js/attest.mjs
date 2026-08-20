// GVP Ed25519 attestation reference (JS/TS) — L2. Signs/verifies the attestation payload (spec §6).
// Ed25519 is deterministic (RFC 8032), so a conformant Python signer produces byte-identical
// signatures for the same key + payload; this is proven in vectors/attestation.json.
import { sign as edSign, verify as edVerify, createPublicKey, createPrivateKey } from 'node:crypto';
import { canonicalize } from './gvp.mjs';

export function loadPrivateKey(pkcs8B64) {
  return createPrivateKey({ key: Buffer.from(pkcs8B64, 'base64'), format: 'der', type: 'pkcs8' });
}
export function publicKeyB64(priv) {
  return createPublicKey(priv).export({ format: 'der', type: 'spki' }).toString('base64');
}

// The exact string the issuer signs (spec §6): canonical JSON of the attestation payload.
export function attestationPayload({ responseHash, endpoint, dataVintage, issuer, agentId, issuedAt }) {
  return canonicalize({ responseHash, endpoint, dataVintage, issuer, agentId: agentId ?? null, issuedAt });
}

export function attest(payloadString, priv) {
  return {
    alg: 'Ed25519',
    publicKey: publicKeyB64(priv),
    signature: edSign(null, Buffer.from(payloadString, 'utf8'), priv).toString('base64')
  };
}

// WITHOUT expectedPublicKey: integrity only (matches the receipt's own embedded key).
// WITH it: also proves issuer identity (spec §6).
export function verifyAttest(payloadString, sig, expectedPublicKey) {
  if (!sig || sig.alg !== 'Ed25519' || !sig.publicKey || !sig.signature) return false;
  if (expectedPublicKey && sig.publicKey !== expectedPublicKey) return false;
  try {
    const pub = createPublicKey({ key: Buffer.from(sig.publicKey, 'base64'), format: 'der', type: 'spki' });
    return edVerify(null, Buffer.from(payloadString, 'utf8'), pub, Buffer.from(sig.signature, 'base64'));
  } catch { return false; }
}
