// Gate for GVP-FixedPoint/2 (spec §2.1.3) — and, just as importantly, a gate proving /1 did NOT move.
//
// Checks, in order:
//   1. every /2 vector re-derives byte-for-byte from its fixed point
//   2. dataVintage precision is significant — YYYY, YYYY-MM, YYYY-MM-DD hash differently
//   3. every non-conforming vintage is refused (these are the /1-legal values that caused the split)
//   4. /1 is frozen: vectors/expected.json still re-derives unchanged under the same canonicalizer
//
// Exit 0 only if all four hold. Run: node tools/check-fixedpoint-2.mjs
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalize } from '../ref/js/gvp.mjs';
import { isConformantVintage } from './gen-vectors-v2.mjs';

const read = f => JSON.parse(readFileSync(new URL(f, import.meta.url), 'utf8'));
const hash = fp => 'sha256:' + createHash('sha256').update(canonicalize(fp), 'utf8').digest('hex');

const v2 = read('../vectors/expected-v2.json');
let fail = 0;
const ok = (cond, label, detail = '') => {
  if (!cond) fail++;
  console.log(`${cond ? 'ok  ' : 'FAIL'}  ${label}${detail ? '  — ' + detail : ''}`);
};

// 1. re-derivation
console.log(`-- ${v2.fixedPointVersion}: re-derive ${v2.vectors.length} vectors`);
for (const v of v2.vectors) {
  const canon = canonicalize(v.fixedPoint);
  ok(canon === v.canonical && hash(v.fixedPoint) === v.responseHash, v.name);
}

// 2. precision is significant
console.log('\n-- precision is significant (three vintages, three hashes)');
const p = ['2026', '2026-07', '2026-07-01'].map(dv => v2.vectors.find(x => x.name === `vintage-precision-${dv}`));
ok(p.every(Boolean), 'all three precision vectors present');
const hashes = new Set(p.filter(Boolean).map(x => x.responseHash));
ok(hashes.size === 3, 'YYYY / YYYY-MM / YYYY-MM-DD hash differently', `${hashes.size} distinct`);

// 3. the reject set
console.log('\n-- non-conforming vintages are refused (spec §2.1.3)');
for (const r of v2.rejectVintages) {
  ok(isConformantVintage(r.value) === false, `reject ${JSON.stringify(r.value)}`, r.why);
}
// and the conforming forms are accepted
for (const good of ['2026', '2026-07', '2026-07-01', '2000-02-29']) {
  ok(isConformantVintage(good) === true, `accept ${JSON.stringify(good)}`);
}

// 4. /1 MUST be frozen — a rule-set change must not disturb the old rule set
console.log('\n-- GVP-FixedPoint/1 is frozen (vectors/expected.json unchanged)');
const v1 = read('../vectors/expected.json');
for (const v of v1) {
  // /1 vectors store the digest as `expectedHash` (the /2 fixture uses `responseHash`).
  ok(hash(v.fixedPoint) === v.expectedHash, `/1 ${v.name}`);
}
ok(v1.every(v => typeof v.fixedPoint.dataVintage === 'string'),
   '/1 dataVintage stays an unconstrained string');

console.log(`\n${fail === 0 ? 'PASS' : 'FAIL'}: ${fail} failure(s)`);
process.exit(fail === 0 ? 0 : 1);
