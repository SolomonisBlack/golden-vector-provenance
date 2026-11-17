// Minimal fixed-length DER for ML-DSA-65 keys (FIPS 204 sizes; OID 2.16.840.1.101.3.4.3.18).
//   SPKI:   SEQUENCE { SEQUENCE { OID }, BIT STRING (0 unused) publicKey[1952] }
//   PKCS#8: SEQUENCE { INTEGER 0, SEQUENCE { OID }, OCTET STRING { SEQUENCE { OCTET STRING seed[32],
//           OCTET STRING expandedKey[4032] } } } — the "both" form OpenSSL writes, and the form of
//           vectors/attestation-key-mldsa65.json.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

export const NOBLE_VERSION = '0.3.0';
// The version of the copy that '@noble/post-quantum/ml-dsa' actually resolves to (package.json is not exported).
export function installedNobleVersion() {
  const entry = createRequire(import.meta.url).resolve('@noble/post-quantum/ml-dsa');
  return JSON.parse(readFileSync(join(dirname(entry), 'package.json'), 'utf8')).version;
}
const PK_LEN = 1952, SK_LEN = 4032, SEED_LEN = 32;
const hex = s => Buffer.from(s.replace(/\s+/g, ''), 'hex');
const ALG_ID = hex('300b 0609 608648016503040312');
export const SPKI_PREFIX = Buffer.concat([hex('308207b2'), ALG_ID, hex('038207a1 00')]);
const P8_HEAD = Buffer.concat([hex('30820ffe 020100'), ALG_ID, hex('04820fea 30820fe6 0420')]);
const P8_MID = hex('04820fc0');

export function spki(publicKey) {
  if (publicKey.length !== PK_LEN) throw new Error(`public key is ${publicKey.length} bytes, want ${PK_LEN}`);
  return Buffer.concat([SPKI_PREFIX, publicKey]);
}
export function rawPublicKey(spkiDer) {
  if (spkiDer.length !== SPKI_PREFIX.length + PK_LEN || !spkiDer.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
    throw new Error('not an ML-DSA-65 SPKI');
  }
  return spkiDer.subarray(SPKI_PREFIX.length);
}
export function pkcs8Both(seed, expanded) {
  if (seed.length !== SEED_LEN || expanded.length !== SK_LEN) throw new Error('bad ML-DSA-65 seed / expanded key length');
  return Buffer.concat([P8_HEAD, seed, P8_MID, expanded]);
}
export function parsePkcs8Both(der) {
  const s = P8_HEAD.length, m = s + SEED_LEN;
  if (der.length !== m + P8_MID.length + SK_LEN || !der.subarray(0, s).equals(P8_HEAD) || !der.subarray(m, m + P8_MID.length).equals(P8_MID)) {
    throw new Error('not an ML-DSA-65 PKCS#8 (seed + expanded key) key');
  }
  return { seed: der.subarray(s, m), expanded: der.subarray(m + P8_MID.length) };
}
