// Generate the L2 attestation conformance vectors: a FIXED throwaway Ed25519 key signs the attestation
// payload for each canonicalization vector. The Python reference must (a) verify these signatures and
// (b) reproduce them byte-for-byte (Ed25519 determinism).
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash } from '../ref/js/gvp.mjs';
import { loadPrivateKey, publicKeyB64, attestationPayload, attest } from '../ref/js/attest.mjs';

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
const vectors = fixedPoints.map(v => {
  const responseHash = gvpHash(v.fixedPoint);
  const payload = { responseHash, endpoint: v.fixedPoint.endpoint, dataVintage: v.fixedPoint.dataVintage, issuer: 'gvp.example', agentId: '59110', issuedAt: ISSUED_AT };
  const canonicalPayload = attestationPayload(payload);
  const sig = attest(canonicalPayload, priv);
  return { name: v.name, payload, canonicalPayload, expected: { publicKey: sig.publicKey, signature: sig.signature } };
});

writeFileSync(join(vDir, 'attestation.json'), JSON.stringify({ alg: 'Ed25519', publicKey: pub, vectors }, null, 2) + '\n');
console.log(`generated ${vectors.length} attestation vectors -> vectors/attestation.json`);
console.log(`publicKey: ${pub}`);
