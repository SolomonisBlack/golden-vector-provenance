// Receipt conformance (spec §6.4, §5, §7): the JS reference rebuilds every receipt's payload byte for
// byte, reaches every expected outcome and revocation status in vectors/receipt.json, and the
// spec-only verifier (tools/spec-only-verify.mjs) imports nothing from ref/.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash } from '../ref/js/gvp.mjs';
import { receiptPayload, verifyReceipt, revocationStatus, IMPLEMENTED_ALGS } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(readFileSync(join(here, '..', 'vectors', 'receipt.json'), 'utf8'));
let fails = 0;
const bad = (m) => { fails++; console.error('FAIL ' + m); };

for (const c of v.cases) {
  let payload = null; try { payload = receiptPayload(c.receipt); } catch { payload = null; }
  if (payload !== c.expectedPayload) bad(`${c.name}: payload differs`);
  const opts = c.keyList === 'none' ? {} : { keyList: c.keyList === 'live' ? v.liveKeyList : v.keyList };
  const got = verifyReceipt(c.receipt, opts);
  const want = c.requires && !IMPLEMENTED_ALGS.includes(c.requires) ? 'unverifiable' : c.expected;
  if (got.outcome !== want) bad(`${c.name}: ${got.outcome} (${got.reason}), expected ${c.expected}`);
  const r = c.receipt;
  const re = !!r && typeof r === 'object' && r.endpoint !== undefined &&
    gvpHash({ endpoint: r.endpoint, inputs: r.canonicalInputs, result: r.result, method: r.method, dataVintage: r.dataVintage }) === r.responseHash;
  if (re !== c.responseHashRederives) bad(`${c.name}: responseHash re-derivation ${re}`);
}
for (const c of v.revocationCases) {
  const got = revocationStatus(c.hash, c.list === 'unreachable' ? null : v.revocationLists[c.list], { keyList: v.keyList, kind: c.kind });
  if (got.status !== c.expected) bad(`${c.name}: ${got.status}, expected ${c.expected}`);
}
// The live receipt and the /2 + FixedPoint/2 shape must both be present: a regenerated file that lost
// them would otherwise read green.
for (const n of ['live-x402toll-receipt', 'v2-fixedpoint-2', 'v3-ed25519', 'v3-ml-dsa-65', 'payloadVersion-stripped-downgrade']) {
  if (!v.cases.some(c => c.name === n)) bad(`missing case ${n}`);
}
if (!v.revocationCases.some(c => c.name === 'entry-kind-null-unverifiable')) bad('missing case entry-kind-null-unverifiable');
const src = readFileSync(join(here, 'spec-only-verify.mjs'), 'utf8');
// one statement at a time (up to its ';'), so a side-effect import cannot borrow a later `from`
const imports = [...src.matchAll(/^import\b[^;]*;/gm)].map(m => (m[0].match(/['"]([^'"]+)['"]\s*(?:with\s*\{[^}]*\})?\s*;$/) ?? [])[1] ?? m[0]);
if (imports.some(i => !['node:crypto', 'node:fs', 'node:path', 'node:url', 'canonicalize'].includes(i))) bad(`spec-only-verify.mjs imports ${imports.join(', ')}`);
console.log(`receipt conformance (JS ref): ${v.cases.length} receipt + ${v.revocationCases.length} revocation cases, ${fails} failures`);
process.exit(fails ? 1 : 0);
