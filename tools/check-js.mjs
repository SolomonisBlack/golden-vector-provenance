// JS conformance check: assert the JS reference reproduces the committed L1 hash fixtures and
// verifies the L2 attestation signatures. Exit non-zero on any failure.
import { readFileSync } from 'node:fs';
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

// L2: payload canonicalizes identically + the attestation signature verifies under the published key
const att = JSON.parse(readFileSync(join(vDir, 'attestation.json'), 'utf8'));
for (const v of att.vectors) {
  const payloadString = attestationPayload(v.payload);
  const ok = payloadString === v.canonicalPayload &&
    verifyAttest(payloadString, { alg: 'Ed25519', publicKey: v.expected.publicKey, signature: v.expected.signature }, att.publicKey);
  if (!ok) { fails++; console.error(`L2 MISMATCH ${v.name}`); }
}

console.log(`JS conformance: ${expected.length} L1 + ${att.vectors.length} L2 vectors, ${fails} failures`);
process.exit(fails ? 1 : 0);
