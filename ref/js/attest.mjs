// GVP Ed25519 attestation reference (JS/TS) — L2. Signs/verifies the attestation payload (spec §6).
// Ed25519 is deterministic (RFC 8032), so a conformant Python signer produces byte-identical
// signatures for the same key + payload; this is proven in vectors/attestation.json (payload /1) and
// vectors/attestation-v2.json (payload /2).
import { sign as edSign, verify as edVerify, createPublicKey, createPrivateKey } from 'node:crypto';
import { canonicalize } from './gvp.mjs';

export function loadPrivateKey(pkcs8B64) {
  return createPrivateKey({ key: Buffer.from(pkcs8B64, 'base64'), format: 'der', type: 'pkcs8' });
}
export function publicKeyB64(priv) {
  return createPublicKey(priv).export({ format: 'der', type: 'spki' }).toString('base64');
}

// Signed-payload shapes (spec §6). The shape identifier is INSIDE the signed object, so a verifier learns
// which shape to reconstruct from the receipt itself and an attacker cannot strip or forge it without
// failing the signature. Two shapes exist:
//   GVP-Attestation/1 — the original 6-field payload (receipts issued before fixedPointVersion existed).
//   GVP-Attestation/2 — /1 plus { payloadVersion, fixedPointVersion }. fixedPointVersion lives here, in
//                       the SIGNED L2 payload — not in the hashed L1 fixed point (that would move every
//                       responseHash) and not unsigned beside the hash (that could be stripped/forged).
export const ATTESTATION_V1 = 'GVP-Attestation/1';
export const ATTESTATION_V2 = 'GVP-Attestation/2';
export const FIXED_POINT_V1 = 'GVP-FixedPoint/1';

// The exact string the issuer signs (spec §6): canonical JSON of the attestation payload.
// No payloadVersion (or /1) -> legacy 6-field shape. /2 -> adds payloadVersion + fixedPointVersion.
export function attestationPayload({ responseHash, endpoint, dataVintage, issuer, agentId, issuedAt,
                                     payloadVersion, fixedPointVersion }) {
  const base = { responseHash, endpoint, dataVintage, issuer, agentId: agentId ?? null, issuedAt };
  if (payloadVersion == null || payloadVersion === ATTESTATION_V1) return canonicalize(base);
  if (payloadVersion !== ATTESTATION_V2) throw new Error(`unsupported attestation payload version: ${payloadVersion}`);
  if (typeof fixedPointVersion !== 'string' || !fixedPointVersion) {
    throw new Error(`${ATTESTATION_V2} requires fixedPointVersion`);
  }
  return canonicalize({ ...base, payloadVersion: ATTESTATION_V2, fixedPointVersion });
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
