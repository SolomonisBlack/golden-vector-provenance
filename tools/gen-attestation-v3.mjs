// Generate the GVP-Attestation/3 conformance vectors (spec §6.1-§6.3):
//
//   vectors/attestation-v3.json        — the 8 canonicalization fixed points signed under payload shape /3,
//                                        once with the FIXED throwaway Ed25519 key (deterministic: the
//                                        Python reference re-signs byte-for-byte) and once with a FIXED
//                                        throwaway ML-DSA-65 key (pure, empty context; hedged, so these
//                                        are verify-only and change if regenerated)
//   vectors/attestation-outcomes.json  — the key-first outcome table: one published key list and the cases
//                                        a verifier MUST map to verified | unverifiable | contradicted
//   vectors/attestation-key-mldsa65.json — the ML-DSA-65 test key, generated once and then reused
//
// Neither key is, or has ever been, a production key.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { generateKeyPairSync, sign as cSign } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash } from '../ref/js/gvp.mjs';
import { loadPrivateKey, publicKeyB64, attestationPayload, attest, ATTESTATION_V2, ATTESTATION_V3,
         FIXED_POINT_V1, ALG_ED25519, ALG_ML_DSA_65 } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', 'vectors');

const edPriv = loadPrivateKey(JSON.parse(readFileSync(join(vDir, 'attestation-key.json'), 'utf8')).privateKeyPkcs8B64);
const mlKeyFile = join(vDir, 'attestation-key-mldsa65.json');
if (!existsSync(mlKeyFile)) {
  const { privateKey } = generateKeyPairSync('ml-dsa-65');
  writeFileSync(mlKeyFile, JSON.stringify({
    privateKeyPkcs8B64: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    note: 'FIXED throwaway ML-DSA-65 test key for GVP-Attestation/3 conformance vectors — NOT a production key.'
  }, null, 2) + '\n');
}
const mlPriv = loadPrivateKey(JSON.parse(readFileSync(mlKeyFile, 'utf8')).privateKeyPkcs8B64);

const ED_KEY_ID = 'gvp-test-ed25519-1';
const ML_KEY_ID = 'gvp-test-mldsa65-1';
const edPub = publicKeyB64(edPriv);
const mlPub = publicKeyB64(mlPriv);

const fixedPoints = JSON.parse(readFileSync(join(vDir, 'canonicalization.json'), 'utf8'));
const ISSUED_AT = '2026-10-21T00:00:00.000Z';
const payloadFor = (fp, alg) => ({
  responseHash: gvpHash(fp), endpoint: fp.endpoint, dataVintage: fp.dataVintage,
  issuer: 'gvp.example', agentId: '59110', issuedAt: ISSUED_AT,
  payloadVersion: ATTESTATION_V3, fixedPointVersion: FIXED_POINT_V1, alg
});

function group(priv, alg) {
  return {
    alg, publicKey: publicKeyB64(priv),
    vectors: fixedPoints.map(v => {
      const payload = payloadFor(v.fixedPoint, alg);
      const canonicalPayload = attestationPayload(payload);
      const sig = attest(canonicalPayload, priv);
      return { name: v.name, payload, canonicalPayload, expected: { publicKey: sig.publicKey, signature: sig.signature } };
    })
  };
}

writeFileSync(join(vDir, 'attestation-v3.json'), JSON.stringify({
  payloadVersion: ATTESTATION_V3,
  note: 'Ed25519 group: deterministic, re-sign byte-for-byte. ML-DSA-65 group: pure, empty context, hedged — verify-only.',
  groups: [group(edPriv, ALG_ED25519), group(mlPriv, ALG_ML_DSA_65)]
}, null, 2) + '\n');

// ---- outcome table (spec §6.3) ----
const keyList = {
  issuer: 'gvp.example',
  keys: [
    { keyId: ED_KEY_ID, alg: ALG_ED25519, publicKey: edPub },
    { keyId: ML_KEY_ID, alg: ALG_ML_DSA_65, publicKey: mlPub },
    // A listed key under an algorithm no reference implements: any receipt pointed at it is unverifiable.
    // A real SLH-DSA-SHA2-128s public key (fixed), so a future SLH-DSA verifier sees a well-formed entry.
    { keyId: 'gvp-test-slhdsa-1', alg: 'SLH-DSA-SHA2-128s', publicKey: 'MDAwCwYJYIZIAWUDBAMUAyEAm7GA+i54iPITgHpLeMOKr3b2I0qiZczPclI2hAV2meM=' }
  ]
};

const base = fixedPoints[0].fixedPoint;
const signed = (payload, priv, keyId, { context } = {}) => {
  const s = attestationPayload(payload);
  const signature = context
    ? cSign(null, Buffer.from(s, 'utf8'), { key: priv, context }).toString('base64')
    : attest(s, priv).signature;
  return { alg: payload.alg ?? ALG_ED25519, keyId, signature };
};
const ed3 = payloadFor(base, ALG_ED25519);
const ml3 = payloadFor(base, ALG_ML_DSA_65);
const edSig = signed(ed3, edPriv, ED_KEY_ID);
const mlSig = signed(ml3, mlPriv, ML_KEY_ID);
const { alg: _a, ...ed3NoAlg } = ed3;
const ed2 = { ...ed3NoAlg, payloadVersion: ATTESTATION_V2 };
const ed2Sig = signed(ed2, edPriv, ED_KEY_ID);
// Legacy receipts as issued before /3: keyId was OPTIONAL and publicKey REQUIRED.
const { keyId: _k, ...ed2SigNoKeyId } = { ...ed2Sig, publicKey: edPub };
const { payloadVersion: _pv, fixedPointVersion: _fpv, ...ed1 } = ed2;
const ed1Sig = { alg: ALG_ED25519, publicKey: edPub, signature: attest(attestationPayload(ed1), edPriv).signature };

const cases = [
  { name: 'ed25519-v3-intact', payload: ed3, signature: edSig, keyList: 'published', expected: 'verified' },
  { name: 'mldsa65-v3-intact', payload: ml3, signature: mlSig, keyList: 'published', expected: 'verified', requires: ALG_ML_DSA_65 },
  { name: 'mldsa65-v3-intact, verifier implements Ed25519 only', payload: ml3, signature: mlSig, keyList: 'published', implemented: [ALG_ED25519], expected: 'unverifiable' },
  { name: 'ed25519-v2-legacy-with-keyId', payload: ed2, signature: ed2Sig, keyList: 'published', expected: 'verified' },
  { name: 'ed25519-v2-legacy-no-keyId (matched by publicKey)', payload: ed2, signature: ed2SigNoKeyId, keyList: 'published', expected: 'verified' },
  { name: 'ed25519-v1-legacy-no-keyId (matched by publicKey)', payload: ed1, signature: ed1Sig, keyList: 'published', expected: 'verified' },
  { name: 'v2 no keyId, embedded publicKey not in list', payload: ed2, signature: { ...ed2SigNoKeyId, publicKey: mlPub }, keyList: 'published', expected: 'contradicted' },
  { name: 'v3 keyId stripped, integrity-only check', payload: ed3, signature: { alg: edSig.alg, publicKey: edPub, signature: edSig.signature }, keyList: 'none', expected: 'contradicted' },
  { name: 'v3 intact, integrity-only check', payload: ed3, signature: { ...edSig, publicKey: edPub }, keyList: 'none', expected: 'verified' },
  { name: 'keyId missing from fetched key list', payload: ed3, signature: { ...edSig, keyId: 'gvp-test-unknown-9f3a' }, keyList: 'published', expected: 'contradicted' },
  { name: 'key list unreachable', payload: ed3, signature: edSig, keyList: 'unreachable', expected: 'unverifiable' },
  { name: 'keyId points at a key under an unimplemented alg', payload: { ...ed3, alg: 'SLH-DSA-SHA2-128s' }, signature: { ...edSig, keyId: 'gvp-test-slhdsa-1' }, keyList: 'published', expected: 'unverifiable' },
  { name: 'signed alg rewritten Ed25519 -> ML-DSA-65', payload: { ...ed3, alg: ALG_ML_DSA_65 }, signature: edSig, keyList: 'published', expected: 'contradicted' },
  { name: 'signed alg rewritten to an unknown string', payload: { ...ed3, alg: 'none' }, signature: edSig, keyList: 'published', expected: 'contradicted' },
  { name: 'keyId rewritten to the other algorithm\'s key', payload: ed3, signature: { ...edSig, keyId: ML_KEY_ID }, keyList: 'published', expected: 'contradicted' },
  { name: 'v2 receipt pointed at the ML-DSA-65 key', payload: ed2, signature: { ...ed2Sig, keyId: ML_KEY_ID }, keyList: 'published', expected: 'contradicted' },
  { name: 'v3 alg stripped', payload: ed3NoAlg, signature: edSig, keyList: 'published', expected: 'contradicted' },
  { name: 'v3 keyId stripped', payload: ed3, signature: { alg: edSig.alg, signature: edSig.signature }, keyList: 'published', expected: 'contradicted' },
  { name: 'v3 downgraded to v2 shape', payload: ed2, signature: edSig, keyList: 'published', expected: 'contradicted' },
  { name: 'embedded publicKey differs from listed key', payload: ed3, signature: { ...edSig, publicKey: mlPub }, keyList: 'published', expected: 'contradicted' },
  { name: 'mldsa65 signed with a non-empty context', payload: ml3, signature: signed(ml3, mlPriv, ML_KEY_ID, { context: Buffer.from('GVP') }), keyList: 'published', expected: 'contradicted', requires: ALG_ML_DSA_65 },
  { name: 'unsupported payloadVersion', payload: { ...ed3, payloadVersion: 'GVP-Attestation/9' }, signature: edSig, keyList: 'published', expected: 'unverifiable' },
  { name: 'CONTROL: responseHash tampered', payload: { ...ed3, responseHash: 'sha256:' + '0'.repeat(64) }, signature: edSig, keyList: 'published', expected: 'contradicted' },
  { name: 'CONTROL: mldsa65 responseHash tampered', payload: { ...ml3, responseHash: 'sha256:' + '0'.repeat(64) }, signature: mlSig, keyList: 'published', expected: 'contradicted', requires: ALG_ML_DSA_65 }
];

writeFileSync(join(vDir, 'attestation-outcomes.json'), JSON.stringify({
  spec: 'spec/gvp-0.2.md §6.3',
  note: 'keyList "published" = the list below, fetched from the origin the verifier paid; "unreachable" = it could not be fetched; ' +
        '"none" = integrity-only check against the embedded publicKey (verified means integrity, not identity). ' +
        '"implemented", when present, restricts the algorithms the verifier implements. A verifier that lacks the algorithm a case "requires" MUST report unverifiable for it (spec §8).',
  keyList, cases
}, null, 2) + '\n');

console.log(`generated 2 x ${fixedPoints.length} /3 vectors -> vectors/attestation-v3.json`);
console.log(`generated ${cases.length} outcome cases -> vectors/attestation-outcomes.json`);
