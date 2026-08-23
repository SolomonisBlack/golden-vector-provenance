// JS conformance check: assert the JS reference reproduces the committed L1 hash fixtures and
// verifies the L2 attestation signatures for BOTH signed-payload shapes (/1 legacy, /2 current).
// Exit non-zero on any failure.
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash } from '../ref/js/gvp.mjs';
import { attestationPayload, verifyAttest } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', 'vectors');
let fails = 0;

// L1: reproduce every expected hash
const expected = JSON.parse(readFileSync(join(vDir, 'expected.json'), 'utf8'));
for (const v of expected) {
  const got = gvpHash(v.fixedPoint);
  if (got !== v.expectedHash) { fails++; console.error(`L1 MISMATCH ${v.name}: ${got} != ${v.expectedHash}`); }
}

// L2: payload canonicalizes identically + the attestation signature verifies under the published key.
// Both shapes: attestation.json (GVP-Attestation/1) and attestation-v2.json (GVP-Attestation/2).
let l2 = 0;
for (const fname of ['attestation.json', 'attestation-v2.json']) {
  const fp = join(vDir, fname);
  if (!existsSync(fp)) continue;
  const att = JSON.parse(readFileSync(fp, 'utf8'));
  for (const v of att.vectors) {
    l2++;
    const payloadString = attestationPayload(v.payload);
    const ok = payloadString === v.canonicalPayload &&
      verifyAttest(payloadString, { alg: 'Ed25519', publicKey: v.expected.publicKey, signature: v.expected.signature }, att.publicKey);
    if (!ok) { fails++; console.error(`L2 MISMATCH ${fname} ${v.name}`); }
  }
}

console.log(`JS conformance: ${expected.length} L1 + ${l2} L2 vectors, ${fails} failures`);
process.exit(fails ? 1 : 0);
