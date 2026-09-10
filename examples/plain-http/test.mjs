// End-to-end check for the plain-HTTP example: real server on an ephemeral port, real fetch, real
// recomputation. Also proves the four-state vocabulary on this transport: verified, contradicted
// (tampered result), no_claim (extension stripped), unverifiable (member removed). Exit non-zero on
// any failure. No payment rail is involved anywhere in this file.
import { createServer } from './server.mjs';
import { callAndVerify, verify } from './verify.mjs';
import { gvpHash } from '../../ref/js/gvp.mjs';

let fails = 0;
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) { fails++; console.error(`FAIL ${name}\n  got : ${JSON.stringify(got)}\n  want: ${JSON.stringify(want)}`); }
  else console.log(`ok   ${name}`);
};

// The middleware test vector — this example's route reproduces it exactly.
const ENDPOINT = '/v1/self-employment-tax';
const INPUTS = { netProfit: 80000, filingStatus: 'single' };
const EXPECTED = 'sha256:7236fd58598c29a6d8ebf7721a83201c363f5d88755b3c39242b3a4355982352';

const server = createServer();
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

try {
  const { status, headers, body, verdict } = await callAndVerify(base, ENDPOINT, INPUTS);
  eq('HTTP 200', status, 200);
  eq('result reproduces the published vector', body.result, { selfEmploymentTax: 11303.64 });
  eq('outcome verified', verdict.outcome, 'verified');
  eq('responseHash equals the repository vector', verdict.responseHash, EXPECTED);
  eq('no payment header on the response', Object.keys(headers).some((h) => /payment/i.test(h)), false);

  // The verifier used its OWN inputs — prove that by re-deriving independently of the client code.
  eq('independent re-derivation agrees',
     gvpHash({ endpoint: ENDPOINT, inputs: INPUTS, result: body.result, method: body.method, dataVintage: body.dataVintage }),
     EXPECTED);

  // contradicted: alter the answer in transit
  const tampered = structuredClone(body); tampered.result.selfEmploymentTax += 1;
  eq('tampered result → contradicted', verify(ENDPOINT, INPUTS, tampered).outcome, 'contradicted');

  // contradicted: the question changed (verifier asks about different inputs than it sent)
  eq('different inputs → contradicted', verify(ENDPOINT, { ...INPUTS, netProfit: 80001 }, body).outcome, 'contradicted');

  // no_claim: extension stripped
  const stripped = structuredClone(body); delete stripped.extensions;
  eq('extension absent → no_claim', verify(ENDPOINT, INPUTS, stripped).outcome, 'no_claim');

  // unverifiable: a carried member removed
  const broken = structuredClone(body); delete broken.dataVintage;
  eq('member missing → unverifiable', verify(ENDPOINT, INPUTS, broken).outcome, 'unverifiable');

  // input validation on the issuer
  const bad = await fetch(base + ENDPOINT, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"netProfit":"80000"}' });
  eq('invalid inputs → 400, no hash issued', [bad.status, (await bad.json()).extensions === undefined], [400, true]);
} finally {
  server.close();
}

if (fails) { console.error(`\n${fails} failure(s)`); process.exit(1); }
console.log('\nplain-http example: all checks passed');
