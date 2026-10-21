// Two-way ML-DSA-65 cross-check between the reference signer (node:crypto / OpenSSL) and TenPrint's signer
// (@noble/post-quantum 0.3.0). Exit non-zero on any failure:
//   A. noble 0.3.0 verifies every ML-DSA-65 signature in vectors/attestation-v3.json (pure, empty context)
//      over the canonicalPayload bytes the reference rebuilds.
//   B. the repo verify path (node:crypto, as in check-attestation-v3.mjs part 1, plus verifyAttestation)
//      verifies every signature in vectors/attestation-v3-tenprint-mldsa65.json; the throwaway PKCS#8 key
//      loads in node:crypto and derives the published SPKI. Needs Node >= 24.7 (node:crypto ML-DSA); on an
//      older Node, B is reported UNAVAILABLE and counted as a failure — it is not skipped silently.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify as cVerify, generateKeyPairSync } from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { loadPrivateKey, publicKeyB64, attestationPayload, verifyAttestation, ALG_ML_DSA_65 } from '../../ref/js/attest.mjs';
import { NOBLE_VERSION, installedNobleVersion, SPKI_PREFIX, rawPublicKey, parsePkcs8Both } from './der.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', '..', 'vectors');
const read = f => JSON.parse(readFileSync(join(vDir, f), 'utf8'));
let fails = 0;
const ok = (name, cond, extra = '') => { if (cond) console.log(`ok   ${name}`); else { fails++; console.error(`FAIL ${name}${extra ? ' :: ' + extra : ''}`); } };
const utf8 = s => new TextEncoder().encode(s);
const b64 = s => Buffer.from(s, 'base64');

const nobleVersion = installedNobleVersion();
ok(`@noble/post-quantum pinned at ${NOBLE_VERSION}`, nobleVersion === NOBLE_VERSION, `installed ${nobleVersion}`);

const mlGroup = f => read(f).groups.find(g => g.alg === ALG_ML_DSA_65);
const ref = mlGroup('attestation-v3.json');
const tp = mlGroup('attestation-v3-tenprint-mldsa65.json');

// The DER the generator writes is the DER the reference writes.
ok('SPKI prefix matches the reference ML-DSA-65 key', b64(ref.publicKey).subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX));
{ // Key generation agrees too: noble keygen(seed) on the reference (OpenSSL-made) key's seed rebuilds its
  // expanded key and its published public key.
  let refKey = null;
  try { refKey = parsePkcs8Both(b64(read('attestation-key-mldsa65.json').privateKeyPkcs8B64)); } catch {}
  ok('reference PKCS#8 key has the seed + expanded-key form the throwaway key uses', refKey !== null);
  const kp = refKey && ml_dsa65.keygen(refKey.seed);
  ok('noble keygen(reference seed) = reference expanded key and public key',
    !!kp && Buffer.from(kp.secretKey).equals(refKey.expanded) && Buffer.from(kp.publicKey).equals(rawPublicKey(b64(ref.publicKey))));
}
ok('same payload set: names and canonicalPayload bytes identical',
  ref.vectors.length === tp.vectors.length &&
  ref.vectors.every((v, i) => v.name === tp.vectors[i].name && v.canonicalPayload === tp.vectors[i].canonicalPayload));
ok('throwaway key differs from the reference key', tp.publicKey !== ref.publicKey);

// ---- A. noble verifies the reference (node:crypto) signatures ----
{
  const pk = rawPublicKey(b64(ref.publicKey));
  let n = 0;
  for (const v of ref.vectors) {
    const s = attestationPayload(v.payload);
    const good = s === v.canonicalPayload && ml_dsa65.verify(pk, utf8(s), b64(v.expected.signature));
    const tampered = ml_dsa65.verify(pk, utf8(s + ' '), b64(v.expected.signature));
    const ctx = ml_dsa65.verify(pk, utf8(s), b64(v.expected.signature), utf8('GVP'));
    if (good && !tampered && !ctx) n++; else { fails++; console.error(`FAIL A ${v.name} (verify=${good} tampered=${tampered} ctx=${ctx})`); }
  }
  ok(`A: noble ${nobleVersion} verifies ${n}/${ref.vectors.length} ML-DSA-65 signatures in attestation-v3.json`,
    n === ref.vectors.length && n > 0);
}

// ---- B. node:crypto (repo verify path) verifies the noble signatures ----
let hasMlDsa = false;
try { generateKeyPairSync('ml-dsa-65'); hasMlDsa = true; } catch {}
if (!hasMlDsa) {
  fails++;
  console.error(`FAIL B: UNAVAILABLE — node:crypto on Node ${process.version} has no ML-DSA-65 (needs Node >= 24.7); direction B NOT proven`);
} else {
  const key = createPublicKey({ key: b64(tp.publicKey), format: 'der', type: 'spki' });
  ok('B: published SPKI parses in node:crypto as ml-dsa-65', key.asymmetricKeyType === 'ml-dsa-65');
  const priv = loadPrivateKey(read('attestation-key-tenprint-mldsa65.json').privateKeyPkcs8B64);
  ok('B: throwaway PKCS#8 loads in node:crypto and derives the published SPKI', publicKeyB64(priv) === tp.publicKey);
  let n = 0;
  for (const v of tp.vectors) {
    const s = attestationPayload(v.payload);
    const raw = s === v.canonicalPayload && cVerify(null, Buffer.from(s, 'utf8'), key, b64(v.expected.signature));
    const r = verifyAttestation(v.payload, { alg: ALG_ML_DSA_65, keyId: 'tenprint-throwaway-mldsa65-1',
                                             publicKey: v.expected.publicKey, signature: v.expected.signature });
    const tampered = verifyAttestation({ ...v.payload, responseHash: 'sha256:' + '0'.repeat(64) },
      { alg: ALG_ML_DSA_65, keyId: 'tenprint-throwaway-mldsa65-1', publicKey: v.expected.publicKey, signature: v.expected.signature });
    if (raw && r.outcome === 'verified' && tampered.outcome === 'contradicted') n++;
    else { fails++; console.error(`FAIL B ${v.name} (cVerify=${raw} verifyAttestation=${r.outcome} tampered=${tampered.outcome})`); }
  }
  ok(`B: node:crypto (Node ${process.version}) verifies ${n}/${tp.vectors.length} noble signatures in attestation-v3-tenprint-mldsa65.json`,
    n === tp.vectors.length && n > 0);
}

console.log(`\nTenPrint ML-DSA-65 cross-check: ${fails} failure(s)`);
process.exit(fails ? 1 : 0);
