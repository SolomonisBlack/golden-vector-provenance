// Conformance run for response-hash-check. Offline, zero deps, self-counting.
//   node interop/scvd/test.mjs
//
// The set carries its own expectations, in the style of scvd.store's own vectors: every case
// states what it asserts, and the adversarial cases exist to make the check fail when it should.
import { readFileSync } from 'node:fs';
import { checkResponseHash, canonicalize, sha256Hex, fixedPointOf, assertFit } from './response-hash-check.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));

let pass = 0, fail = 0;
const ok = (cond, label, detail = '') => {
  if (cond) { pass++; console.log(`ok    ${label}`); }
  else { fail++; console.log(`FAIL  ${label}${detail ? '  — ' + detail : ''}`); }
};

// Build a well-formed artifact whose hash is correct by construction.
function artifactFor(fp, mutate = a => a) {
  const response = {
    endpoint: fp.endpoint,
    result: fp.result,
    provenance: {
      method: fp.method,
      dataVintage: fp.dataVintage,
      responseHash: 'sha256:' + sha256Hex(canonicalize(fp)),
    },
  };
  return mutate({ response, inputs: fp.inputs });
}

const FP = {
  endpoint: '/v1/llc-cost',
  inputs: { state: 'DE' },
  result: { filingFee: 110, franchiseFlat: 300, year1Total: 410 },
  method: 'year1 = filingFee + franchiseFlat',
  dataVintage: '2026-07',
};

console.log('-- §8.1 self-exclusion (the instrument checks itself first)');
const fit = assertFit(vectors.fit);
ok(fit.fit, 'our canonicalizer reproduces its own fit vectors', JSON.stringify(fit.failures).slice(0, 200));

// A deliberately broken instrument must refuse to accuse anyone.
const brokenFit = { canonicalization: [{ name: 'sabotage', value: { a: 1 }, canonical: '{"a":999}' }] };
const refused = checkResponseHash(artifactFor(FP), brokenFit);
ok(refused.status === 'unable-to-verify', 'a broken instrument reports unable-to-verify, not a finding');
ok(refused.subject === 'this instrument', 'unable-to-verify is a claim about US, not the issuer');
ok(refused.class === undefined, 'unable-to-verify carries NO class slug (cannot be mistaken for an accusation)');

console.log('\n-- clean artifact');
const clean = checkResponseHash(artifactFor(FP), vectors.fit);
ok(clean.status === 'pass', 'a correct responseHash passes', JSON.stringify(clean).slice(0, 200));

console.log('\n-- adversarial: each MUST produce a finding');
const mutations = [
  ['result mutated after hashing',      a => { a.response.result.year1Total = 999; return a; }],
  ['inputs mutated after hashing',      a => { a.inputs = { state: 'CA' }; return a; }],
  ['endpoint swapped',                  a => { a.response.endpoint = '/v1/paycheck'; return a; }],
  ['method reworded',                   a => { a.response.provenance.method = 'year1 = fee + tax'; return a; }],
  ['dataVintage changed',               a => { a.response.provenance.dataVintage = '2026-08'; return a; }],
  ['hash re-attached from another call',a => { a.response.provenance.responseHash = 'sha256:' + sha256Hex(canonicalize({ ...FP, inputs: { state: 'TX' } })); return a; }],
];
for (const [label, mut] of mutations) {
  const r = checkResponseHash(artifactFor(FP, mut), vectors.fit);
  ok(r.status === 'finding' && r.class === 'response-hash-not-rederivable', label, r.status);
}

console.log('\n-- the finding does not attribute');
const f = checkResponseHash(artifactFor(FP, a => { a.response.result.year1Total = 1; return a; }), vectors.fit);
ok(/Either the artifact was altered, or it was issued/.test(f.asserts), 'states both branches');
ok(/cannot and does not say which/.test(f.asserts), 'explicitly refuses to attribute');
ok(typeof f.falsified_by === 'string' && f.falsified_by.length > 40, 'carries falsified_by');
ok(/THIS IS THE ARTIFACT YOU GAVE US/.test(f.scope), 'carries the supplied-body scope limit');
ok(/no origin fetch/i.test(f.detectable) && /supplied/i.test(f.detectable),
   'detectable explicitly disclaims an origin fetch and names the supplied artifact');

console.log('\n-- closed member set');
const shrunk = checkResponseHash(artifactFor(FP, a => { delete a.response.provenance.dataVintage; return a; }), vectors.fit);
ok(shrunk.status === 'finding', 'a missing fixed-point member is a finding, not a pass');

console.log('\n-- not applicable when no hash is declared');
const none = checkResponseHash(artifactFor(FP, a => { delete a.response.provenance.responseHash; return a; }), vectors.fit);
ok(none.status === 'not-applicable', 'no responseHash -> class does not apply (not a finding)');

console.log('\n-- JCS edge cases the naive serializers get wrong');
for (const c of vectors.fit.canonicalization) {
  ok(canonicalize(c.value) === c.canonical, `jcs: ${c.name}`, `got ${canonicalize(c.value)}`);
}

console.log(`\n${fail === 0 ? 'PASS' : 'FAIL'}: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
