// Tests for the GVP middleware - no framework deps; Express/Hono adapters are exercised with tiny
// fakes so the suite runs from a clean clone. Exit non-zero on any failure.
import { gvpHash } from '../ref/js/gvp.mjs';
import {
  EXTENSION_KEY, SPEC_URL, provenanceBlock, attachProvenance, expressProvenance, honoProvenance,
} from './index.mjs';

let fails = 0;
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.error(`FAIL ${name}\n  got : ${JSON.stringify(got)}\n  want: ${JSON.stringify(want)}`); }
  else console.log(`ok   ${name}`);
};
const truthy = (name, v) => { if (!v) { fails++; console.error(`FAIL ${name}`); } else console.log(`ok   ${name}`); };
const throws = (name, fn) => { try { fn(); fails++; console.error(`FAIL ${name} (did not throw)`); } catch { console.log(`ok   ${name}`); } };

const FP = {
  endpoint: '/v1/self-employment-tax',
  inputs: { netProfit: 80000, filingStatus: 'single' },
  result: { selfEmploymentTax: 11303.64 },
  method: 'Schedule SE: net earnings = profit x 0.9235; SS 12.4% to wage base; Medicare 2.9%',
  dataVintage: '2026.0',
};
const EXPECTED = 'sha256:7236fd58598c29a6d8ebf7721a83201c363f5d88755b3c39242b3a4355982352';

// 1. provenanceBlock computes the spec hash + declares the hashed fields
eq('provenanceBlock hash matches spec vector', provenanceBlock(FP).responseHash, EXPECTED);
eq('provenanceBlock declares fixedPoint fields', provenanceBlock(FP).fixedPoint,
   ['endpoint', 'inputs', 'result', 'method', 'dataVintage']);
eq('provenanceBlock carries spec url', provenanceBlock(FP).spec, SPEC_URL);

// 2. attachProvenance merges under extensions[KEY] without mutating input
const body = { result: { selfEmploymentTax: 11303.64 } };
const out = attachProvenance(body, FP);
eq('attach keeps original fields', out.result, body.result);
eq('attach adds responseHash', out.extensions[EXTENSION_KEY].responseHash, EXPECTED);
truthy('attach does not mutate caller', body.extensions === undefined);
eq('attach preserves pre-existing extensions',
   attachProvenance({ extensions: { bazaar: { x: 1 } } }, FP).extensions.bazaar, { x: 1 });
throws('attach rejects non-object body', () => attachProvenance([1, 2], FP));
throws('attach rejects null body', () => attachProvenance(null, FP));

// 3. Express adapter: res.json gains the extension transparently
function fakeRes() {
  const res = { locals: {}, sent: null, json(b) { this.sent = b; return this; } };
  return res;
}
{
  const res = fakeRes();
  const mw = expressProvenance((req, b) => FP);
  let nexted = false;
  mw({ path: FP.endpoint }, res, () => { nexted = true; });
  truthy('express calls next()', nexted);
  res.json({ result: { selfEmploymentTax: 11303.64 } });
  eq('express injects responseHash', res.sent.extensions[EXTENSION_KEY].responseHash, EXPECTED);
}
{
  // buildFixedPoint returning falsy -> body passes through untouched
  const res = fakeRes();
  expressProvenance(() => null)({}, res, () => {});
  res.json({ a: 1 });
  eq('express passthrough when no fixed point', res.sent, { a: 1 });
}
{
  // a throwing builder must not break serving
  const res = fakeRes();
  expressProvenance(() => { throw new Error('boom'); })({}, res, () => {});
  res.json({ a: 1 });
  eq('express never breaks serving on error', res.sent, { a: 1 });
  truthy('express records error in res.locals', res.locals.gvpError.includes('boom'));
}
throws('expressProvenance requires a function', () => expressProvenance('nope'));
throws('honoProvenance requires a function', () => honoProvenance(123));

// 4. Hono adapter: wraps a JSON Response
{
  const c = {
    res: new Response(JSON.stringify({ result: { selfEmploymentTax: 11303.64 } }),
      { status: 200, headers: { 'content-type': 'application/json' } }),
  };
  await honoProvenance(() => FP)(c, async () => {});
  const parsed = await c.res.clone().json();
  eq('hono injects responseHash', parsed.extensions[EXTENSION_KEY].responseHash, EXPECTED);
}
{
  // non-JSON response is left alone
  const original = new Response('hello', { status: 200, headers: { 'content-type': 'text/plain' } });
  const c = { res: original };
  await honoProvenance(() => FP)(c, async () => {});
  truthy('hono leaves non-JSON untouched', c.res === original);
}
{
  // a stale upstream content-length is dropped so the grown body isn't truncated
  const c = {
    res: new Response(JSON.stringify({ result: { selfEmploymentTax: 11303.64 } }),
      { status: 200, headers: { 'content-type': 'application/json', 'content-length': '41' } }),
  };
  await honoProvenance(() => FP)(c, async () => {});
  truthy('hono drops stale content-length', c.res.headers.get('content-length') === null);
  const parsed = await c.res.clone().json();
  eq('hono body intact after cl drop', parsed.extensions[EXTENSION_KEY].responseHash, EXPECTED);
}

// 4b. Structural integrity (review on x402-foundation/x402#3234): the fixed point is FIXED, not
//     self-declared. The attack: drop `inputs` from both the hash AND the declared list so a bare-200
//     artifact stays internally consistent and a checker can't see the fixed point shrank.
{
  const shrunk = { endpoint: FP.endpoint, result: FP.result, method: FP.method, dataVintage: FP.dataVintage }; // no inputs
  throws('shrunk fixed point (no inputs) is REJECTED, not emitted', () => provenanceBlock(shrunk));
  throws('fixed point without endpoint is rejected (must bind the question)',
    () => provenanceBlock({ inputs: FP.inputs, result: FP.result, method: FP.method, dataVintage: FP.dataVintage }));
  throws('fixed point with extra member is rejected (spec §2.1 no other member)',
    () => provenanceBlock({ ...FP, timestamp: '2026-08-23T00:00:00Z' }));
  throws('fixed point with non-string endpoint is rejected', () => provenanceBlock({ ...FP, endpoint: 42 }));
  // the declared list is the spec constant regardless of key order passed in
  const reordered = { dataVintage: FP.dataVintage, method: FP.method, result: FP.result, inputs: FP.inputs, endpoint: FP.endpoint };
  eq('declared fixedPoint list is the spec constant (not Object.keys order)',
     provenanceBlock(reordered).fixedPoint, ['endpoint', 'inputs', 'result', 'method', 'dataVintage']);
  eq('reordered keys hash identically (JCS sorts)', provenanceBlock(reordered).responseHash, EXPECTED);
  // and a checker recomputing over the five spec fields detects a hash computed over a shrunk set
  const shrunkHash = gvpHash(shrunk);
  truthy('hash over shrunk set != hash over full fixed point (checker catches omission)', shrunkHash !== EXPECTED);
  // express adapter: a shrunk builder degrades to no-provenance, never to a misleading block
  const res = fakeRes();
  expressProvenance(() => shrunk)({}, res, () => {});
  res.json({ a: 1 });
  eq('express: shrunk fixed point -> body served WITHOUT a provenance block', res.sent, { a: 1 });
  truthy('express: shrunk fixed point -> error recorded', String(res.locals.gvpError).includes('missing required member'));
}

// 5. Round-trip: a consumer re-derives the hash from the emitted body - the whole point
{
  const emitted = attachProvenance({ result: { selfEmploymentTax: 11303.64 } }, FP);
  const recomputed = gvpHash(FP);
  eq('consumer re-derives the emitted hash', emitted.extensions[EXTENSION_KEY].responseHash, recomputed);
}

console.log(`\nmiddleware: ${fails} failure(s)`);
process.exit(fails ? 1 : 0);
