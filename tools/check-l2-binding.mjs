// L2 binding check: prove `fixedPointVersion` is TAMPER-EVIDENT under GVP-Attestation/2 — i.e. it lives
// inside the Ed25519-signed payload, so stripping or forging it FAILS verification. This is the exact
// four-case table from round 3 of review on x402-foundation/x402#3234, now expected to flip:
//   1. intact /2 receipt                 -> verifies
//   2. fixedPointVersion STRIPPED        -> FAILS   (was: verified — the silent-skew hole)
//   3. fixedPointVersion FORGED to /2    -> FAILS   (was: verified — denial-of-verification hole)
//   4. CONTROL: issuer tampered          -> FAILS   (verifier discriminates)
// Plus: a /2 receipt cannot be DOWNGRADED to /1 (verifier reconstructs the declared shape, never guesses).
// Exit non-zero on any failure.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { attestationPayload, verifyAttest, attest, loadPrivateKey, ATTESTATION_V2, FIXED_POINT_V1 } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', 'vectors');
const key = JSON.parse(readFileSync(join(vDir, 'attestation-key.json'), 'utf8')).privateKeyPkcs8B64;
const priv = loadPrivateKey(key);
const v2 = JSON.parse(readFileSync(join(vDir, 'attestation-v2.json'), 'utf8'));
let fails = 0;
const expect = (name, got, want) => {
  const ok = got === want;
  if (!ok) fails++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name.padEnd(58)} -> ${got ? 'verifies' : 'FAILS'}${ok ? '' : '  (expected ' + (want ? 'verifies' : 'FAILS') + ')'}`);
};

// Build a genuine /2 receipt: sign the /2 payload.
const base = v2.vectors[0].payload;   // already /2 shaped: has payloadVersion + fixedPointVersion
const signedString = attestationPayload(base);
const sig = attest(signedString, priv);
const verify = (payloadObj) => {
  let s; try { s = attestationPayload(payloadObj); } catch { return false; }
  return verifyAttest(s, sig, v2.publicKey);
};

// 1. intact
expect('1. intact /2 receipt', verify(base), true);
// 2. strip fixedPointVersion (and the shape id, as an attacker trying to make it look /1 would)
const { fixedPointVersion: _f, payloadVersion: _p, ...stripped } = base;
expect('2. fixedPointVersion STRIPPED (downgraded to /1 shape)', verify(stripped), false);
// 2b. strip only fixedPointVersion but keep payloadVersion=/2 -> payload builder rejects (no fpv) -> fails
expect('2b. fixedPointVersion stripped, /2 shape kept', verify({ ...base, fixedPointVersion: undefined }), false);
// 3. forge to an unsupported rule set
expect('3. fixedPointVersion FORGED to GVP-FixedPoint/2', verify({ ...base, fixedPointVersion: 'GVP-FixedPoint/2' }), false);
// 4. control
expect('4. CONTROL: issuer tampered', verify({ ...base, issuer: 'evil.example' }), false);
// 5. downgrade guard: a verifier that is handed the /1 reconstruction of a /2-signed receipt must NOT verify
const asV1 = attestationPayload(stripped);
expect('5. /2 signature does NOT verify over the /1 reconstruction', verifyAttest(asV1, sig, v2.publicKey), false);
// 6. sanity: the emitter puts fixedPointVersion INSIDE the signed bytes
expect('6. signed bytes contain fixedPointVersion', signedString.includes('"fixedPointVersion":"' + FIXED_POINT_V1 + '"'), true);
expect('7. signed bytes contain payloadVersion /2', signedString.includes('"payloadVersion":"' + ATTESTATION_V2 + '"'), true);

console.log(`\nL2 binding: ${fails} failure(s)`);
process.exit(fails ? 1 : 0);
