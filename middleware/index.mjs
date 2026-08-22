// GVP drop-in middleware — attach a reproducible `responseHash` (GVP L1) to an API response so the
// payload is bound, not just the payment. Framework-agnostic core + thin Express/Hono adapters.
//
// The hash is computed exactly as the spec requires: gvpHash over the RFC 8785 (JCS) canonical form of
// a *declared* fixed point. You provide `buildFixedPoint`, which returns the subset of the exchange
// that deterministically identifies the answer — for a calculator, typically
// { endpoint, inputs, result, method, dataVintage }.
import { gvpHash } from '../ref/js/gvp.mjs';

export const EXTENSION_KEY = 'response-provenance';
export const SPEC_URL = 'https://github.com/SolomonisBlack/golden-vector-provenance';

// Core: given a fixed point, return the extension block to merge into a response body.
// Proves re-derivability, NOT correctness (a consumer recomputes the fixed point and re-hashes).
export function provenanceBlock(fixedPoint) {
  return {
    responseHash: gvpHash(fixedPoint),
    fixedPoint: Object.keys(fixedPoint),   // which fields were hashed — a server can't silently omit one
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
