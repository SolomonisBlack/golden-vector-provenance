// GVP over plain HTTP — no payment rail, no framework, no signing key.
//
// This is the smallest honest issuer: Node's built-in `http` module, one JSON route, and the
// package's `attachProvenance` from `golden-vector-provenance/middleware`. Nothing here knows what
// x402 is. The provenance member is identical to the one an x402-paid response would carry, which is
// the rail-agnostic claim made concrete: the fixed point binds the question and the answer, and says
// nothing about how — or whether — payment settled.
//
// The route reproduces the middleware test vector on purpose (Schedule SE, 2026 figures), so a
// verifier that recomputes this response lands on a hash this repository already publishes.
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { attachProvenance } from '../../middleware/index.mjs';

// 2026 Social Security wage base (SSA, published October 2025). The only external datum on this route.
const SS_WAGE_BASE_2026 = 184500;
const DATA_VINTAGE = '2026.0'; // GVP-FixedPoint/1 form, matching vectors/expected.json
const METHOD = 'Schedule SE: net earnings = profit x 0.9235; SS 12.4% to wage base; Medicare 2.9%';

const round2 = (n) => Math.round(n * 100) / 100;

function selfEmploymentTax({ netProfit }) {
  const netEarnings = netProfit * 0.9235;
  const socialSecurity = Math.min(netEarnings, SS_WAGE_BASE_2026) * 0.124;
  const medicare = netEarnings * 0.029;
  return { selfEmploymentTax: round2(socialSecurity + medicare) };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (c) => { raw += c; if (raw.length > 65536) { reject(new Error('body too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(json) });
  res.end(json);
}

export function createServer() {
  return http.createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/v1/self-employment-tax') {
      return send(res, 404, { error: 'not found' });
    }
    let inputs;
    try { inputs = await readJson(req); } catch { return send(res, 400, { error: 'invalid JSON body' }); }
    if (typeof inputs.netProfit !== 'number' || !Number.isFinite(inputs.netProfit) || inputs.netProfit < 0
        || typeof inputs.filingStatus !== 'string') {
      return send(res, 400, { error: 'netProfit (non-negative number) and filingStatus (string) are required' });
    }
    const result = selfEmploymentTax(inputs);
    // The fixed point: the question (endpoint + inputs exactly as received), the answer, the method,
    // and the data vintage. `attachProvenance` validates the member set and hashes it.
    const body = attachProvenance(
      { result, method: METHOD, dataVintage: DATA_VINTAGE },
      { endpoint: req.url, inputs, result, method: METHOD, dataVintage: DATA_VINTAGE },
    );
    send(res, 200, body);
  });
}

// `node server.mjs [port]` — run directly; imported by test.mjs on an ephemeral port.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.argv[2] ?? 8402);
  createServer().listen(port, () => console.log(`gvp plain-http issuer on http://127.0.0.1:${port}/v1/self-employment-tax`));
}
