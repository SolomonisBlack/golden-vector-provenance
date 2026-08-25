// Generate GVP-FixedPoint/2 conformance vectors.
//
// /2 keeps /1's five members and changes exactly one thing: `dataVintage` MUST be an ISO 8601
// calendar date at reduced precision (YYYY | YYYY-MM | YYYY-MM-DD) — see spec §2.1.3. So the /2
// vectors are the /1 canonicalization cases with a conforming vintage, plus cases that exist only
// to pin the new rule: the three precisions hash differently, and non-conforming values are
// rejected rather than hashed.
//
// Run: node tools/gen-vectors-v2.mjs   (writes vectors/expected-v2.json)
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { canonicalize } from '../ref/js/gvp.mjs';

const VINTAGE_RE = /^[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?$/;

// Real calendar date at the stated precision (spec §2.1.3).
export function isConformantVintage(v) {
  if (typeof v !== 'string' || !VINTAGE_RE.test(v)) return false;
  const [y, m, d] = v.split('-').map(Number);
  if (y < 1 || y > 9999) return false;
  if (m !== undefined && (m < 1 || m > 12)) return false;
  if (d !== undefined) {
    const dim = new Date(Date.UTC(y, m, 0)).getUTCDate(); // day 0 of next month = last day of m
    if (d < 1 || d > dim) return false;
  }
  return true;
}

const hash = fp => 'sha256:' + createHash('sha256').update(canonicalize(fp), 'utf8').digest('hex');

// Only generate when run directly — check-fixedpoint-2.mjs imports isConformantVintage from here.
const RUN_DIRECTLY = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (RUN_DIRECTLY) { generate(); }

function generate() {

const base = JSON.parse(readFileSync(new URL('../vectors/canonicalization.json', import.meta.url), 'utf8'));

// 1. The eight /1 canonicalization cases, re-stated with a conforming vintage.
//    '2026.0' (the /1 vintage) is NOT conformant under /2 — that is the point of the change.
const vectors = base.map(v => {
  const fixedPoint = { ...v.fixedPoint, dataVintage: '2026-07' };
  return { name: v.name, fixedPointVersion: 'GVP-FixedPoint/2', fixedPoint,
           canonical: canonicalize(fixedPoint), responseHash: hash(fixedPoint) };
});

// 2. Precision is significant: the same data at three precisions is three vintages.
const precisionBase = {
  endpoint: '/v1/vintage-precision',
  inputs: { q: 1 },
  result: { a: 1 },
  method: 'identity; exists to pin dataVintage precision under GVP-FixedPoint/2'
};
for (const dv of ['2026', '2026-07', '2026-07-01']) {
  const fixedPoint = { ...precisionBase, dataVintage: dv };
  vectors.push({ name: `vintage-precision-${dv}`, fixedPointVersion: 'GVP-FixedPoint/2', fixedPoint,
                 canonical: canonicalize(fixedPoint), responseHash: hash(fixedPoint) });
}

// 3. Rejection cases — no hash exists for these; a /2 verifier MUST refuse them.
//    These are the representations that were legal under /1 and are the divergence source §2.1.3 names.
const rejects = [
  { value: 'July 2026',   why: 'prose; the reference service published this under /1' },
  { value: '2026.0',      why: "float-ish; this repo's own /1 vectors used it" },
  { value: '2026-07-01T00:00:00Z', why: 'timestamp; dataVintage is a date, not an instant' },
  { value: '2026-13',     why: 'month 13 is not a real calendar month' },
  { value: '2026-02-30',  why: 'February 30 is not a real calendar day' },
  { value: '26-07',       why: 'two-digit year' },
  { value: '',            why: 'empty' }
];

const out = {
  fixtureId: 'gvp-fixedpoint-2',
  fixedPointVersion: 'GVP-FixedPoint/2',
  spec: 'spec/gvp-0.2.md §2.1.3',
  note: 'GVP-FixedPoint/2 = /1 with dataVintage pinned to ISO 8601 reduced precision. /1 stays frozen and valid.',
  vintageGrammar: VINTAGE_RE.source,
  vectors,
  rejectVintages: rejects.map(r => ({ ...r, conformant: isConformantVintage(r.value) }))
};

writeFileSync(new URL('../vectors/expected-v2.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');

const badAccepts = out.rejectVintages.filter(r => r.conformant);
console.log(`wrote vectors/expected-v2.json — ${vectors.length} vectors, ${rejects.length} reject cases`);
console.log(badAccepts.length === 0
  ? 'reject set: all correctly refused'
  : `REJECT SET BROKEN: ${badAccepts.map(r => r.value).join(', ')} were accepted`);
process.exit(badAccepts.length === 0 ? 0 : 1);
}
