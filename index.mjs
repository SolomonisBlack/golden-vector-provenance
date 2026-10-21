// Golden-Vector Provenance (GVP) — package entry point.
//
// L1 (Reproducible): canonicalize + gvpHash — the canonical SHA-256 fixed point over
//   {endpoint, inputs, result, method, dataVintage} that anyone can re-derive for free.
// L2 (Signed): attest / verifyAttestation — an optional issuer attestation (Ed25519 or ML-DSA-65,
//   key-first dispatch, spec §6). It attests ISSUANCE, never correctness; correctness is established
//   only by reproduction. verifyAttest is the legacy boolean check for /1 and /2.
//
// Canonicalization is RFC 8785 (JCS) — see spec/gvp-0.2.md §2.2. `tools/check-jcs.mjs` gates that
// claim byte-for-byte against an independent RFC 8785 implementation.
export { canonicalize, gvpHash } from './ref/js/gvp.mjs';
export {
  loadPrivateKey,
  publicKeyB64,
  attestationPayload,
  attest,
  verifyAttest,
  verifyAttestation,
  createKeyListResolver,
  keepKeyList,
  algOfKey,
  ATTESTATION_V3,
  ALG_ED25519,
  ALG_ML_DSA_65,
} from './ref/js/attest.mjs';
