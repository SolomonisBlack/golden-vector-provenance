// Independent ML-DSA-65 signer cross-check for GVP-Attestation/3 (spec §6.1).
//
// Re-signs every ML-DSA-65 payload in vectors/attestation-v3.json with TenPrint's signing code path:
// @noble/post-quantum 0.3.0, ml_dsa65.sign(secretKey, messageBytes) — pure ML-DSA, empty context, no
// prehash — over the exact same canonicalPayload bytes, under a NEW throwaway key. Writes:
//
//   vectors/attestation-v3-tenprint-mldsa65.json      — same group shape as attestation-v3.json
//   vectors/attestation-key-tenprint-mldsa65.json     — the throwaway key, generated once and then reused,
//                                                       in the same PKCS#8 (seed + expanded key) form as
//                                                       vectors/attestation-key-mldsa65.json
//
// The key is NOT, and has never been, a TenPrint production key. ML-DSA-65 signing is hedged, so the
// signatures change if regenerated; they are verify-only. Runs on Node >= 18 (no node:crypto ML-DSA needed).
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { attestationPayload, ATTESTATION_V3, ALG_ML_DSA_65 } from '../../ref/js/attest.mjs';
import { NOBLE_VERSION, installedNobleVersion, SPKI_PREFIX, pkcs8Both, parsePkcs8Both, spki } from './der.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', '..', 'vectors');
const read = f => JSON.parse(readFileSync(join(vDir, f), 'utf8'));
const die = msg => { console.error(`FAIL ${msg}`); process.exit(1); };

const nobleVersion = installedNobleVersion();
if (nobleVersion !== NOBLE_VERSION) die(`@noble/post-quantum is ${nobleVersion}, pinned ${NOBLE_VERSION}`);

// ---- throwaway key ----
const keyFile = join(vDir, 'attestation-key-tenprint-mldsa65.json');
if (!existsSync(keyFile)) {
  const seed = randomBytes(32);
  const { secretKey } = ml_dsa65.keygen(seed);
  writeFileSync(keyFile, JSON.stringify({
    privateKeyPkcs8B64: pkcs8Both(seed, secretKey).toString('base64'),
    note: 'THROWAWAY ML-DSA-65 test key for the TenPrint @noble/post-quantum 0.3.0 cross-check of the ' +
          'GVP-Attestation/3 vectors — NOT a production key, never used by TenPrint for anything else.'
  }, null, 2) + '\n');
}
const { seed, expanded } = parsePkcs8Both(Buffer.from(read('attestation-key-tenprint-mldsa65.json').privateKeyPkcs8B64, 'base64'));
const { publicKey, secretKey } = ml_dsa65.keygen(seed);
if (!Buffer.from(secretKey).equals(expanded)) die('expanded key in the key file does not match keygen(seed)');
const publicKeyB64 = spki(publicKey).toString('base64');

// ---- sign the same payloads, same bytes ----
const src = read('attestation-v3.json').groups.find(g => g.alg === ALG_ML_DSA_65);
if (!src) die('attestation-v3.json has no ML-DSA-65 group');
if (!Buffer.from(src.publicKey, 'base64').subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
  die('attestation-v3.json ML-DSA-65 publicKey is not the expected SPKI form');
}
const vectors = src.vectors.map(v => {
  const canonicalPayload = attestationPayload(v.payload);
  if (canonicalPayload !== v.canonicalPayload) die(`${v.name}: canonicalPayload differs from attestation-v3.json`);
  const msg = new TextEncoder().encode(canonicalPayload);
  const sig = ml_dsa65.sign(secretKey, msg);                      // pure, empty context, no prehash
  if (!ml_dsa65.verify(publicKey, msg, sig)) die(`${v.name}: noble does not verify its own signature`);
  return { name: v.name, payload: v.payload, canonicalPayload,
           expected: { publicKey: publicKeyB64, signature: Buffer.from(sig).toString('base64') } };
});

writeFileSync(join(vDir, 'attestation-v3-tenprint-mldsa65.json'), JSON.stringify({
  payloadVersion: ATTESTATION_V3,
  note: 'Independent ML-DSA-65 cross-check: the ML-DSA-65 payloads of attestation-v3.json, same canonicalPayload ' +
        'bytes, re-signed by TenPrint signing code under a THROWAWAY key (attestation-key-tenprint-mldsa65.json, ' +
        'not a production key). Pure, empty context, hedged — verify-only.',
  signer: { library: '@noble/post-quantum', version: NOBLE_VERSION,
            call: 'ml_dsa65.sign(secretKey, utf8(canonicalPayload))', context: '', prehash: false },
  source: 'vectors/attestation-v3.json (ML-DSA-65 group)',
  groups: [{ alg: ALG_ML_DSA_65, publicKey: publicKeyB64, vectors }]
}, null, 2) + '\n');

console.log(`generated ${vectors.length} ML-DSA-65 /3 vectors (noble ${nobleVersion}) -> vectors/attestation-v3-tenprint-mldsa65.json`);
