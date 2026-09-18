// Hash-invocation-count check (shape credited to goun7 / Tamga AT-034, x402-foundation/x402#2887,
// 2026-09-17): a bullet list of "we refuse before hashing" is a claim; a counter around the digest is
// evidence. Refusal paths MUST reach the digest 0 times; the green path and the tamper path exactly 1
// (no premature hashing, no redundant re-hashing). The check is negative-self-tested: flipping an
// expected count must make it fail, otherwise the instrument proves nothing. Exit non-zero on failure.
import { gvpHash, hooks } from '../ref/js/gvp.mjs';
import { provenanceBlock } from '../middleware/index.mjs';

let fails = 0;
let count = 0;
hooks.beforeDigest = () => { count++; };
const run = (fn) => { count = 0; let threw = null; try { fn(); } catch (e) { threw = e.message; } return { count, threw }; };
const expect = (name, got, wantCount, wantThrow) => {
  const ok = got.count === wantCount && (wantThrow ? !!got.threw : !got.threw);
  if (ok) console.log(`ok   ${name}: digest x${got.count}${got.threw ? ' (refused: ' + got.threw + ')' : ''}`);
  else { fails++; console.error(`FAIL ${name}: digest x${got.count} threw=${got.threw} (want x${wantCount}, ${wantThrow ? 'refusal' : 'no refusal'})`); }
};

const WV = { endpoint: '/v1/echo-sum', inputs: { a: 2, b: 3 }, result: { sum: 5 }, method: 'sum = a + b, integer addition', dataVintage: '2026-07' };
const deep = (() => { let v = { x: 1 }; for (let i = 0; i < 105; i++) v = { n: v }; return v; })();

// Refusal paths: 0 digests
expect('non-finite number refused before digest', run(() => gvpHash({ ...WV, result: { sum: Infinity } })), 0, true);
expect('NaN refused before digest', run(() => gvpHash({ ...WV, inputs: { a: NaN } })), 0, true);
expect('depth > 100 refused before digest', run(() => gvpHash({ ...WV, result: deep })), 0, true);
expect('missing member refused before digest (middleware)', run(() => provenanceBlock({ endpoint: '/x', inputs: {}, result: {}, method: 'm' })), 0, true);
expect('extra member refused before digest (middleware)', run(() => provenanceBlock({ ...WV, extra: 1 })), 0, true);
expect('non-object fixed point refused before digest (middleware)', run(() => provenanceBlock([1])), 0, true);

// Green path: exactly 1
const green = run(() => { const h = gvpHash(WV); if (h !== 'sha256:81ea1f2227fd9df5b868954e6d26d091810352f148dade483b260844788ede03') throw new Error('worked vector mismatch'); });
expect('green path digests exactly once', green, 1, false);
expect('middleware green path digests exactly once', run(() => provenanceBlock(WV)), 1, false);

// Tamper path: a verifier recomputes once and compares; exactly 1 digest, mismatch, no re-hash
const tamper = run(() => { const h = gvpHash({ ...WV, result: { sum: 6 } }); if (h === 'sha256:81ea1f2227fd9df5b868954e6d26d091810352f148dade483b260844788ede03') throw new Error('tamper not detected'); });
expect('tamper path digests exactly once and mismatches', tamper, 1, false);

// Negative self-test: the instrument must be able to fail. Flip the expectation and require a FAIL.
{
  const before = fails;
  const origErr = console.error; console.error = () => {};
  expect('(self-test) green path with wrong expectation', run(() => gvpHash(WV)), 0, false);
  console.error = origErr;
  if (fails === before + 1) { fails = before; console.log('ok   negative self-test: a wrong expected count is detected'); }
  else { fails++; console.error('FAIL negative self-test: flipping the expected count did not fail the check'); }
}

hooks.beforeDigest = null;
console.log(fails ? `\nhash-count: ${fails} FAILURE(S)` : '\nhash-count: refusal paths 0 digests, green/tamper paths exactly 1');
process.exit(fails ? 1 : 0);
