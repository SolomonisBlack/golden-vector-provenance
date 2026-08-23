// Generate the L2 attestation conformance vectors: a FIXED throwaway Ed25519 key signs the attestation
// payload for each canonicalization vector. The Python reference must (a) verify these signatures and
// (b) reproduce them byte-for-byte (Ed25519 determinism).
//
// Emits TWO files:
//   vectors/attestation.json     — payload shape GVP-Attestation/1 (legacy; unchanged inputs so old
//                                  receipts keep a conformance proof)
//   vectors/attestation-v2.json  — payload shape GVP-Attestation/2 (adds payloadVersion +
//                                  fixedPointVersion INSIDE the signed object)
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash } from '../ref/js/gvp.mjs';
import { loadPrivateKey, publicKeyB64, attestationPayload, attest, ATTESTATION_V2, FIXED_POINT_V1 } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', 'vectors');
const keyFile = join(vDir, 'attestation-key.json');

// Stable key: generate once, then reuse so the vectors are reproducible across runs.
let keyB64;
if (existsSync(keyFile)) {
  keyB64 = JSON.parse(readFileSync(keyFile, 'utf8')).privateKeyPkcs8B64;
} else {
  const { privateKey } = generateKeyPairSync('ed25519');
  keyB64 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
  writeFileSync(keyFile, JSON.stringify({
    privateKeyPkcs8B64: keyB64,
    note: 'FIXED throwaway test key for GVP attestation conformance vectors — NOT a production key.'
  }, null, 2) + '\n');
}
const priv = loadPrivateKey(keyB64);
const pub = publicKeyB64(priv);

const fixedPoints = JSON.parse(readFileSync(join(vDir, 'canonicalization.json'), 'utf8'));
const ISSUED_AT = '2026-07-19T00:00:00.000Z';

function build(extra) {
  return fixedPoints.map(v => {
    const responseHash = gvpHash(v.fixedPoint);
    const payload = { responseHash, endpoint: v.fixedPoint.endpoint, dataVintage: v.fixedPoint.dataVintage,
                      issuer: 'gvp.example', agentId: '59110', issuedAt: ISSUED_AT, ...extra };
    const canonicalPayload = attestationPayload(payload);
    const sig = attest(canonicalPayload, priv);
    return { name: v.name, payload, canonicalPayload, expected: { publicKey: sig.publicKey, signature: sig.signature } };
  });
}

const v1 = build({});
writeFileSync(join(vDir, 'attestation.json'),
  JSON.stringify({ alg: 'Ed25519', payloadVersion: 'GVP-Attestation/1', publicKey: pub, vectors: v1 }, null, 2) + '\n');
const v2 = build({ payloadVersion: ATTESTATION_V2, fixedPointVersion: FIXED_POINT_V1 });
writeFileSync(join(vDir, 'attestation-v2.json'),
  JSON.stringify({ alg: 'Ed25519', payloadVersion: ATTESTATION_V2, publicKey: pub, vectors: v2 }, null, 2) + '\n');
console.log(`generated ${v1.length} /1 vectors -> vectors/attestation.json`);
console.log(`generated ${v2.length} /2 vectors -> vectors/attestation-v2.json`);
console.log(`publicKey: ${pub}`);
