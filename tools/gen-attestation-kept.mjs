// Generate vectors/attestation-kept.json: the kept-key-list outcome table (spec §6.3, "Kept key lists").
//
// Ed25519 only, so every signature is deterministic and the file regenerates byte-for-byte. Two keys:
// the FIXED test key (vectors/attestation-key.json) and a second throwaway key derived from a fixed seed,
// standing in for whoever controls the origin after it changes hands. Neither is a production key.
// The existing /3 vectors and outcome table are not touched.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash } from '../ref/js/gvp.mjs';
import { loadPrivateKey, publicKeyB64, attestationPayload, attest, ATTESTATION_V2, ATTESTATION_V3,
         FIXED_POINT_V1, ALG_ED25519, ALG_ML_DSA_65 } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', 'vectors');

const edPriv = loadPrivateKey(JSON.parse(readFileSync(join(vDir, 'attestation-key.json'), 'utf8')).privateKeyPkcs8B64);
// Ed25519 PKCS#8 = fixed 16-byte prefix + 32-byte seed (RFC 8410).
const seed = createHash('sha256').update('gvp-test-ed25519-successor').digest();
const succPriv = loadPrivateKey(Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]).toString('base64'));

const ED_KEY_ID = 'gvp-test-ed25519-1';
const SUCC_KEY_ID = 'gvp-test-ed25519-2';
const edPub = publicKeyB64(edPriv);
const succPub = publicKeyB64(succPriv);
const KEPT_AT = '2026-10-01T00:00:00.000Z';

const keptList = { keys: [{ keyId: ED_KEY_ID, alg: ALG_ED25519, publicKey: edPub, lastSeenAt: KEPT_AT }] };
const keyLists = {
  current: { issuer: 'gvp.example', keys: [{ keyId: ED_KEY_ID, alg: ALG_ED25519, publicKey: edPub }] },
  rotated: { issuer: 'gvp.example', keys: [{ keyId: ED_KEY_ID, alg: ALG_ED25519, publicKey: edPub },
                                           { keyId: SUCC_KEY_ID, alg: ALG_ED25519, publicKey: succPub }] },
  dropped: { issuer: 'gvp.example', keys: [{ keyId: SUCC_KEY_ID, alg: ALG_ED25519, publicKey: succPub }] },
  rebound: { issuer: 'gvp.example', keys: [{ keyId: ED_KEY_ID, alg: ALG_ED25519, publicKey: succPub }] },
  // the same key, listed under a new keyId: the kept keyId is gone, so this is `dropped`
  renamed: { issuer: 'gvp.example', keys: [{ keyId: 'gvp-test-ed25519-renamed', alg: ALG_ED25519, publicKey: edPub }] }
};

const fixedPoints = JSON.parse(readFileSync(join(vDir, 'canonicalization.json'), 'utf8'));
const base = fixedPoints[0].fixedPoint;
const ed3 = {
  responseHash: gvpHash(base), endpoint: base.endpoint, dataVintage: base.dataVintage,
  issuer: 'gvp.example', agentId: '59110', issuedAt: '2026-10-21T00:00:00.000Z',
  payloadVersion: ATTESTATION_V3, fixedPointVersion: FIXED_POINT_V1, alg: ALG_ED25519
};
const signed = (payload, priv, keyId) => ({ alg: ALG_ED25519, keyId, signature: attest(attestationPayload(payload), priv).signature });
const edSig = signed(ed3, edPriv, ED_KEY_ID);
const succSig = signed(ed3, succPriv, SUCC_KEY_ID);
const succReusedSig = signed(ed3, succPriv, ED_KEY_ID);   // the successor signs under the old keyId
const { alg: _a, ...ed3NoAlg } = ed3;
const ed2 = { ...ed3NoAlg, payloadVersion: ATTESTATION_V2 };
const ed2NoKeyIdSig = { alg: ALG_ED25519, publicKey: edPub, signature: attest(attestationPayload(ed2), edPriv).signature };

const cases = [
  { name: 'origin unreachable, keyId in kept list', payload: ed3, signature: edSig, keyList: 'unreachable', kept: true,
    expected: 'verified', keptAt: KEPT_AT },
  { name: 'origin unreachable, keyId not in kept list', payload: ed3, signature: succSig, keyList: 'unreachable', kept: true,
    expected: 'unverifiable' },
  { name: 'origin unreachable, no kept list', payload: ed3, signature: edSig, keyList: 'unreachable', kept: false,
    expected: 'unverifiable' },
  { name: 'origin unreachable, kept key, responseHash tampered', payload: { ...ed3, responseHash: 'sha256:' + '0'.repeat(64) },
    signature: edSig, keyList: 'unreachable', kept: true, expected: 'contradicted', keptAt: KEPT_AT },
  { name: 'origin unreachable, kept key, signed alg rewritten', payload: { ...ed3, alg: ALG_ML_DSA_65 },
    signature: edSig, keyList: 'unreachable', kept: true, expected: 'contradicted', keptAt: KEPT_AT },
  { name: 'origin unreachable, v2 receipt without keyId, key in kept list', payload: ed2, signature: ed2NoKeyIdSig,
    keyList: 'unreachable', kept: true, expected: 'verified', keptAt: KEPT_AT },
  { name: 'fetched list agrees with kept list', payload: ed3, signature: edSig, keyList: 'current', kept: true,
    expected: 'verified' },
  { name: 'fetched list adds a keyId the kept list lacks', payload: ed3, signature: succSig, keyList: 'rotated', kept: true,
    expected: 'verified' },
  { name: 'fetched list dropped a kept keyId', payload: ed3, signature: edSig, keyList: 'dropped', kept: true,
    expected: 'verified', keptAt: KEPT_AT, discontinuity: 'dropped' },
  { name: 'fetched list rebound a kept keyId, original receipt', payload: ed3, signature: edSig, keyList: 'rebound', kept: true,
    expected: 'verified', keptAt: KEPT_AT, discontinuity: 'rebound' },
  { name: 'fetched list rebound a kept keyId, receipt under the new binding', payload: ed3, signature: succReusedSig,
    keyList: 'rebound', kept: true, expected: 'contradicted', keptAt: KEPT_AT, discontinuity: 'rebound' },
  { name: 'v2 receipt without keyId, fetched list rebound its kept keyId', payload: ed2, signature: ed2NoKeyIdSig,
    keyList: 'rebound', kept: true, expected: 'verified', keptAt: KEPT_AT, discontinuity: 'rebound' },
  { name: 'v2 receipt without keyId, fetched list moved its key to a new keyId', payload: ed2, signature: ed2NoKeyIdSig,
    keyList: 'renamed', kept: true, expected: 'verified', keptAt: KEPT_AT, discontinuity: 'dropped' },
  { name: 'LIMIT: same rebinding, verifier with no kept list', payload: ed3, signature: succReusedSig, keyList: 'rebound',
    kept: false, expected: 'verified' },
  { name: 'LIMIT: dropped keyId, verifier with no kept list', payload: ed3, signature: edSig, keyList: 'dropped',
    kept: false, expected: 'contradicted' }
];

writeFileSync(join(vDir, 'attestation-kept.json'), JSON.stringify({
  spec: 'spec/gvp-0.2.md §6.3 (Kept key lists)',
  note: 'keyList names one of keyLists (fetched from the origin the verifier paid) or "unreachable"; kept: true passes keptList ' +
        'as the verifier\'s kept list. keptAt / discontinuity, when present, MUST be reported with the outcome; when absent, the ' +
        'result does not rest on a kept entry. LIMIT cases show what a verifier with no history cannot detect.',
  keptList, keyLists, cases
}, null, 2) + '\n');

console.log(`generated ${cases.length} kept-list cases -> vectors/attestation-kept.json`);
