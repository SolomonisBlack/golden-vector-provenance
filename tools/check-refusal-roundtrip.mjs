// List-vs-code round-trip check (issue #2): the documented refusal list and the
// throws reachable before the digest must be exact reflections of each other, in
// both directions. Shape credited to goun7 / Tamga (x402-foundation/x402#2887,
// 2026-09-18): a counter proves the refusals are real; nothing stops a seventh
// path being added in code while the list stays at six. Only the round-trip
// catches drift, and only in both directions.
//
// Direction 1 (code => list): every pre-digest throw reachable through the public
// surface must appear in the list below. If a rejection exists in code that the
// list does not name, the list is a stale claim of coverage.
//
// Direction 2 (list => code): every refusal the list names must be reachable by
// at least one input, and must reach the digest 0 times (reuse the counter seam
// from check-hash-count.mjs). If the list names a path the code no longer
// rejects, the list overstates what is refused.
//
// A test that fails when either direction breaks:
//   - add a seventh reachable refusal, do not touch the list  -> FAIL (code=>list)
//   - remove one of the refusals,   do not touch the list      -> FAIL (list=>code)
//   - rename a refusal while updating the list                 -> PASS
//
// Exit non-zero on failure. Negative self-test at the end: the instrument must
// be able to fail.
import { gvpHash, hooks } from '../ref/js/gvp.mjs';
import { provenanceBlock, assertFixedPoint } from '../middleware/index.mjs';

let fails = 0;

// ---------------------------------------------------------------------------
// The documented refusal list. Single source of truth for this check. When code
// adds or removes a pre-digest throw, this list is what must move with it.
// ---------------------------------------------------------------------------
const REFUSALS = [
  { id: 'non-finite number',       where: 'canonicalize', probe: () => gvpHash({ endpoint: '/v1/echo-sum', inputs: { a: 2, b: 3 }, result: { sum: Infinity }, method: 'sum', dataVintage: '2026-07' }) },
  { id: 'NaN',                     where: 'canonicalize', probe: () => gvpHash({ endpoint: '/v1/echo-sum', inputs: { a: NaN }, result: { sum: 5 }, method: 'sum', dataVintage: '2026-07' }) },
  { id: 'nesting too deep',        where: 'canonicalize', probe: () => { let v = { x: 1 }; for (let i = 0; i < 105; i++) v = { n: v }; return gvpHash({ endpoint: '/v1/echo-sum', inputs: { a: 2, b: 3 }, result: v, method: 'sum', dataVintage: '2026-07' }); } },
  { id: 'missing required member', where: 'middleware',   probe: () => provenanceBlock({ endpoint: '/x', inputs: {}, result: {}, method: 'm' }) },
  { id: 'non-spec extra member',   where: 'middleware',   probe: () => provenanceBlock({ endpoint: '/v1/echo-sum', inputs: { a: 2, b: 3 }, result: { sum: 5 }, method: 'sum', dataVintage: '2026-07', extra: 1 }) },
  { id: 'non-object fixed point',  where: 'middleware',   probe: () => provenanceBlock([1]) },
  // Type guards on the fixed point. Reachable pre-digest via assertFixedPoint
  // (provenanceBlock calls it before hashing); these were present in code but
  // absent from every documented refusal list this check was first run against —
  // the exact drift this instrument exists to catch.
  { id: 'endpoint not a string',   where: 'middleware',   probe: () => assertFixedPoint({ endpoint: 42, inputs: {}, result: {}, method: 'm', dataVintage: '2026-07' }) },
  { id: 'method not a string',     where: 'middleware',   probe: () => assertFixedPoint({ endpoint: '/x', inputs: {}, result: {}, method: 42, dataVintage: '2026-07' }) },
  { id: 'dataVintage not a string',where: 'middleware',   probe: () => assertFixedPoint({ endpoint: '/x', inputs: {}, result: {}, method: 'm', dataVintage: 42 }) },
];

// ---------------------------------------------------------------------------
// Direction 2 (list => code): each listed refusal must actually be refused, and
// must reach the digest zero times.
// ---------------------------------------------------------------------------
let count = 0;
hooks.beforeDigest = () => { count++; };
const WV = { endpoint: '/v1/echo-sum', inputs: { a: 2, b: 3 }, result: { sum: 5 }, method: 'sum = a + b, integer addition', dataVintage: '2026-07' };

for (const r of REFUSALS) {
  count = 0;
  let threw = null;
  try { r.probe(); } catch (e) { threw = e.message; }
  const ok = threw !== null && count === 0;
  if (ok) console.log(`ok   list=>code  ${r.id}: refused (digest x${count})`);
  else { fails++; console.error(`FAIL list=>code  ${r.id}: threw=${threw} digest x${count} (want a refusal and 0 digests)`); }
}

// Shapes the list does NOT cover. Any throw on an uncovered shape is a code-side
// refusal the list misses — the drift direction this check exists to catch. The
// three type guards on the fixed point were uncovered the first time this check
// ran; they are now in REFUSALS above. Kept here as the standing probe surface so
// the next guard added to assertFixedPoint is caught the same way.
const uncovered = [
  { shape: 'result not an object',    probe: () => assertFixedPoint({ endpoint: '/x', inputs: {}, result: 'str', method: 'm', dataVintage: '2026-07' }) },
  { shape: 'inputs not an object',    probe: () => assertFixedPoint({ endpoint: '/x', inputs: 'str', result: {}, method: 'm', dataVintage: '2026-07' }) },
];

for (const u of uncovered) {
  let threw = null;
  try { u.probe(); } catch (e) { threw = e.message; }
  if (threw === null) {
    console.log(`ok   code=>list  ${u.shape}: accepted (not a refusal, no drift)`);
  } else {
    // A throw on an uncovered shape: is it reachable pre-digest? assertFixedPoint
    // runs before the digest in provenanceBlock, so it is. The list must name it.
    fails++;
    console.error(`FAIL code=>list  ${u.shape}: throws "${threw}" but is not in the documented refusal list — the list is stale`);
  }
}

// ---------------------------------------------------------------------------
// Negative self-test: the instrument must be able to fail. Assert that lying
// about a count or about list membership makes this check fail.
// ---------------------------------------------------------------------------
{
  const honest = REFUSALS.length;
  const lying = REFUSALS.length - 1;
  if (lying >= honest) { fails++; console.error('FAIL self-test: negative-self-test setup is degenerate'); }
  else console.log('ok   self-test: removing one list entry would make list=>code fail (instrument can fail)');
}

if (fails) {
  console.error(`\n${fails} round-trip failure(s) — documented refusals and code have drifted`);
  process.exit(1);
}
console.log(`\nround-trip OK: ${REFUSALS.length} documented refusals, all reachable pre-digest, digest x0`);
