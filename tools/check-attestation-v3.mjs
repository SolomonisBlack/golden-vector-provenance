// GVP-Attestation/3 check (spec §6.1-§6.3). Four parts, exit non-zero on any failure:
//   1. vectors/attestation-v3.json — every payload canonicalizes identically and every signature verifies
//      under its group key; the Ed25519 group re-signs byte-for-byte (determinism).
//   2. vectors/attestation-outcomes.json — verifyAttestation reaches the expected outcome for every case
//      (key-first dispatch; the unverifiable / contradicted split).
//   3. ML-DSA-65 mode (§6.1): attest() signs pure with the empty context; a signature made under a
//      non-empty context does not verify; the unsigned `alg` label never selects the algorithm.
//   4. Key-list resolver (§6.3): refetch-once on a miss, coalesced per origin, gated by the freshness
//      floor, conditional (ETag), and a failed refetch is unverifiable — with an injected-keyId flood
//      producing exactly one fetch.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify as cVerify } from 'node:crypto';
import { loadPrivateKey, attestationPayload, attest, verifyAttestation, createKeyListResolver,
         ALG_ED25519, ALG_ML_DSA_65 } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', 'vectors');
const read = f => JSON.parse(readFileSync(join(vDir, f), 'utf8'));
let fails = 0;
const ok = (name, cond, extra = '') => { if (cond) console.log(`ok   ${name}`); else { fails++; console.error(`FAIL ${name}${extra ? ' :: ' + extra : ''}`); } };

// ---- 1. /3 vectors ----
const edPriv = loadPrivateKey(read('attestation-key.json').privateKeyPkcs8B64);
const mlPriv = loadPrivateKey(read('attestation-key-mldsa65.json').privateKeyPkcs8B64);
const v3 = read('attestation-v3.json');
let n = 0;
for (const g of v3.groups) {
  const key = createPublicKey({ key: Buffer.from(g.publicKey, 'base64'), format: 'der', type: 'spki' });
  for (const v of g.vectors) {
    n++;
    const s = attestationPayload(v.payload);
    const verifies = cVerify(null, Buffer.from(s, 'utf8'), key, Buffer.from(v.expected.signature, 'base64'));
    const det = g.alg !== ALG_ED25519 || attest(s, edPriv).signature === v.expected.signature;
    if (!(s === v.canonicalPayload && verifies && det)) { fails++; console.error(`FAIL /3 ${g.alg} ${v.name}`); }
  }
}
ok(`/3 vectors: ${n} (Ed25519 re-signed byte-for-byte, ML-DSA-65 verify-only)`, n === 16, `count ${n} != 16`);

// ---- 2. outcome table ----
const oc = read('attestation-outcomes.json');
for (const c of oc.cases) {
  const got = verifyAttestation(c.payload, c.signature, {
    keyList: c.keyList === 'published' ? oc.keyList : c.keyList === 'none' ? undefined : null,
    ...(c.implemented ? { implemented: c.implemented } : {})
  });
  ok(`outcome: ${c.name.padEnd(54)} -> ${c.expected}`, got.outcome === c.expected, `got ${got.outcome} (${got.reason})`);
}

// ---- 3. ML-DSA-65 mode ----
const ml3 = oc.cases.find(c => c.name === 'mldsa65-v3-intact');
const s = attestationPayload(ml3.payload);
const fresh = attest(s, mlPriv, { keyId: 'gvp-test-mldsa65-1' });
ok('attest() with an ML-DSA-65 key labels alg ML-DSA-65', fresh.alg === ALG_ML_DSA_65);
ok('attest() ML-DSA-65 signature verifies (pure, empty context)',
  verifyAttestation(ml3.payload, fresh, { keyList: oc.keyList }).outcome === 'verified');
ok('unsigned alg label is ignored for dispatch',
  verifyAttestation(ml3.payload, { ...fresh, alg: ALG_ED25519 }, { keyList: oc.keyList }).outcome === 'verified');
ok('integrity-only (embedded key) dispatches on the key type and is scoped "integrity"',
  (r => r.outcome === 'verified' && r.scope === 'integrity')(verifyAttestation(ml3.payload, fresh)));

// ---- 4. resolver ----
const listA = { keys: [{ keyId: 'k1' }] };
const listB = { keys: [{ keyId: 'k1' }, { keyId: 'k2' }] };
let t = 0;
const clock = () => t;
const mk = (impl) => { const calls = []; return { calls, r: createKeyListResolver({ now: clock, minRefetchMs: 60_000,
  fetchList: async (origin, etag) => { calls.push(etag ?? null); return impl(calls.length, etag); } }) }; };

{ // first lookup fetches; hit uses cache; miss inside the floor does not refetch
  t = 0; const { calls, r } = mk(() => ({ list: listA, etag: 'A' }));
  ok('first lookup fetches', (await r.lookup('o', 'k1')) === listA && calls.length === 1);
  t = 10_000;
  ok('miss inside the floor: cached list stands, no fetch', (await r.lookup('o', 'k2')) === listA && calls.length === 1);
}
{ // miss after the floor refetches once, conditionally; a rotated-in key is then found
  t = 0; const { calls, r } = mk((i) => i === 1 ? { list: listA, etag: 'A' } : { list: listB, etag: 'B' });
  await r.lookup('o', 'k1'); t = 61_000;
  const got = await r.lookup('o', 'k2');
  ok('miss after the floor refetches once with If-None-Match', got === listB && calls.length === 2 && calls[1] === 'A');
}
{ // injected-keyId flood: 50 concurrent misses after the floor -> one fetch
  t = 0; const { calls, r } = mk(() => ({ list: listA, etag: 'A' }));
  await r.lookup('o', 'k1'); t = 61_000;
  await Promise.all(Array.from({ length: 50 }, (_, i) => r.lookup('o', `rand-${i}`)));
  ok('50 concurrent injected keyIds -> exactly one refetch (coalesced)', calls.length === 2);
  await Promise.all(Array.from({ length: 50 }, (_, i) => r.lookup('o', `rand2-${i}`)));
  ok('next flood inside the new floor -> no fetch', calls.length === 2);
}
{ // 304 refreshes the floor
  t = 0; const { calls, r } = mk((i) => i === 1 ? { list: listA, etag: 'A' } : { notModified: true });
  await r.lookup('o', 'k1'); t = 61_000;
  ok('304 Not Modified keeps the cached list', (await r.lookup('o', 'k2')) === listA && calls.length === 2);
  t = 70_000; await r.lookup('o', 'k3');
  ok('...and restarts the floor', calls.length === 2);
}
{ // unreachable: first fetch fails -> null; failed refetch -> null, and floored
  t = 0; const { calls, r } = mk(() => null);
  ok('list never fetched -> unreachable (null)', (await r.lookup('o', 'k1')) === null);
  t = 1_000; await r.lookup('o', 'k1'); await r.lookup('o', 'k2');
  ok('a cold failure is floored too (one fetch for three lookups)', calls.length === 1);
  t = 61_000; await r.lookup('o', 'k1');
  ok('...and retried after the floor', calls.length === 2);
  t = 0; const m = mk((i) => i === 1 ? { list: listA, etag: 'A' } : null);
  await m.r.lookup('o', 'k1'); t = 61_000;
  ok('failed refetch on a miss -> unreachable (null), not contradicted', (await m.r.lookup('o', 'k2')) === null && m.calls.length === 2);
  t = 62_000;
  ok('failed refetch is floored too', (await m.r.lookup('o', 'k2')) === null && m.calls.length === 2);
  ok('a cached hit still resolves while the origin is down', (await m.r.lookup('o', 'k1')) === listA);
}

console.log(`\nAttestation /3: ${fails} failure(s)`);
process.exit(fails ? 1 : 0);
