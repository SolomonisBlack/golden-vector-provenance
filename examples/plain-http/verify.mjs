// Requester-side verification over plain HTTP — the spec's "recompute, don't trust" in ~40 lines.
//
// The verifier uses ITS OWN sent inputs and endpoint (never the server's restatement of them), takes
// `result`, `method`, `dataVintage` from the response as carried, recomputes the fixed point, and
// compares. Outcome is one of the spec's four states; it is never collapsed to pass/fail.
import { pathToFileURL } from 'node:url';
import { gvpHash } from '../../ref/js/gvp.mjs';
import { EXTENSION_KEY } from '../../middleware/index.mjs';

export async function callAndVerify(baseUrl, endpoint, inputs, { fetchImpl = fetch } = {}) {
  const res = await fetchImpl(baseUrl + endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(inputs),
  });
  const body = await res.json();
  const headers = Object.fromEntries(res.headers.entries());
  return { status: res.status, headers, body, verdict: verify(endpoint, inputs, body) };
}

export function verify(endpoint, inputs, body) {
  const ext = body?.extensions?.[EXTENSION_KEY];
  if (ext === undefined) return { outcome: 'no_claim' };
  if (typeof ext?.responseHash !== 'string' || !('result' in body)
      || typeof body.method !== 'string' || typeof body.dataVintage !== 'string') {
    return { outcome: 'unverifiable', reason: 'extension present but a fixed-point member is missing or malformed' };
  }
  let recomputed;
  try {
    recomputed = gvpHash({ endpoint, inputs, result: body.result, method: body.method, dataVintage: body.dataVintage });
  } catch (e) {
    return { outcome: 'unverifiable', reason: `canonicalization rejected: ${e.message}` };
  }
  if (recomputed === ext.responseHash) return { outcome: 'verified', responseHash: recomputed, fixedPointVersion: ext.fixedPointVersion };
  // Disjunction, per spec: altered artifact OR a hash issued in violation of the closure rule OR a
  // verifier defect. This verifier passes the repository's vectors (§8.1) before it is allowed to say so.
  return { outcome: 'contradicted', responseHash: ext.responseHash, recomputed, fixedPointVersion: ext.fixedPointVersion };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const base = process.argv[2] ?? 'http://127.0.0.1:8402';
  const out = await callAndVerify(base, '/v1/self-employment-tax', { netProfit: 80000, filingStatus: 'single' });
  console.log(JSON.stringify(out, null, 2));
  process.exit(out.verdict.outcome === 'verified' ? 0 : 1);
}
