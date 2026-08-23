// GVP drop-in middleware — attach a reproducible `responseHash` (GVP L1) to an API response so the
// payload is bound, not just the payment. Framework-agnostic core + thin Express/Hono adapters.
//
// The hash is computed exactly as the spec requires: gvpHash over the RFC 8785 (JCS) canonical form of
// the fixed point { endpoint, inputs, result, method, dataVintage } (spec §2.1). You provide
// `buildFixedPoint`, which returns that object for the current exchange.
//
// Two structural guarantees (from review on x402-foundation/x402#3234):
//  1. The fixed point is FIXED, not self-declared. A seller cannot shrink it: all five members are
//     required, and the emitted `fixedPoint` list is the spec's constant, not Object.keys() of whatever
//     was passed. On a bare 200 (no signed receipt) a self-declared list would be unbound — a seller
//     could drop `inputs` from both the hash and the list and still look internally consistent. Pinning
//     the member set closes that; a checker that recomputes over the five spec fields catches any
//     omission because the hash won't match.
//  2. The hash binds the QUESTION as well as the answer: `endpoint` and `inputs` are required members,
//     so `responseHash` attests "this body answered this request", not merely "this body is unaltered".
import { gvpHash } from '../ref/js/gvp.mjs';

export const EXTENSION_KEY = 'response-provenance';
export const SPEC_URL = 'https://github.com/SolomonisBlack/golden-vector-provenance';
// The spec's fixed-point members, in canonical order. Constant by design — see guarantee 1 above.
export const FIXED_POINT_FIELDS = Object.freeze(['endpoint', 'inputs', 'result', 'method', 'dataVintage']);

// Validate a candidate fixed point against spec §2.1: exactly these members, no extras, no missing.
// Throws with a precise message so a misconfigured buildFixedPoint fails loudly in development.
export function assertFixedPoint(fp) {
  if (fp === null || typeof fp !== 'object' || Array.isArray(fp)) {
    throw new TypeError('fixed point must be a JSON object');
  }
  const keys = Object.keys(fp);
  const missing = FIXED_POINT_FIELDS.filter(k => !(k in fp));
  if (missing.length) throw new TypeError(`fixed point missing required member(s): ${missing.join(', ')}`);
  const extra = keys.filter(k => !FIXED_POINT_FIELDS.includes(k));
  if (extra.length) throw new TypeError(`fixed point has non-spec member(s): ${extra.join(', ')} (spec §2.1: no other member participates)`);
  if (typeof fp.endpoint !== 'string') throw new TypeError('fixed point: endpoint must be a string');
  if (typeof fp.method !== 'string') throw new TypeError('fixed point: method must be a string');
  if (typeof fp.dataVintage !== 'string') throw new TypeError('fixed point: dataVintage must be a string');
  return fp;
}

// Core: given a (validated) fixed point, return the extension block to merge into a response body.
// Proves re-derivability, NOT correctness (a consumer recomputes the fixed point and re-hashes).
export function provenanceBlock(fixedPoint) {
  assertFixedPoint(fixedPoint);
  return {
    responseHash: gvpHash(fixedPoint),
    fixedPoint: [...FIXED_POINT_FIELDS],   // the spec constant — declaration cannot drift from the hash
    spec: SPEC_URL,
  };
}

// Merge the provenance block into a plain response object under the standard extensions envelope,
// without mutating the caller's object.
export function attachProvenance(body, fixedPoint) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new TypeError('attachProvenance: response body must be a JSON object');
  }
  return {
    ...body,
    extensions: { ...(body.extensions ?? {}), [EXTENSION_KEY]: provenanceBlock(fixedPoint) },
  };
}

// Express: res.json(body) transparently gains extensions["response-provenance"].
// `buildFixedPoint(req, body)` returns the fixed point for this response.
export function expressProvenance(buildFixedPoint) {
  if (typeof buildFixedPoint !== 'function') {
    throw new TypeError('expressProvenance(buildFixedPoint): buildFixedPoint must be a function');
  }
  return function gvpMiddleware(req, res, next) {
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      try {
        const fp = buildFixedPoint(req, body);
        return originalJson(fp ? attachProvenance(body, fp) : body);
      } catch (err) {
        // provenance must never break serving — emit the answer, log, move on
        if (res.locals) res.locals.gvpError = String(err);
        return originalJson(body);
      }
    };
    next();
  };
}

// Hono: post-process a JSON response. `buildFixedPoint(c, body)` returns the fixed point.
export function honoProvenance(buildFixedPoint) {
  if (typeof buildFixedPoint !== 'function') {
    throw new TypeError('honoProvenance(buildFixedPoint): buildFixedPoint must be a function');
  }
  return async function gvpMiddleware(c, next) {
    await next();
    const ct = c.res.headers.get('content-type') ?? '';
    if (!ct.includes('application/json')) return;
    try {
      const body = await c.res.clone().json();
      const fp = buildFixedPoint(c, body);
      if (!fp) return;
      // Body grows; drop any stale content-length so it isn't truncated to the old length.
      const headers = new Headers(c.res.headers);
      headers.delete('content-length');
      c.res = new Response(JSON.stringify(attachProvenance(body, fp)), {
        status: c.res.status,
        headers,
      });
    } catch { /* provenance must never break serving */ }
  };
}
