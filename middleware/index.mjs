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
// Named, frozen rule-set identifier for that member set (spec §2.1.1). Emitted BESIDE the hash, never
// inside it, so existing hashes stay valid. A different member set is a NEW identifier, never an edit.
//
// HONEST SCOPE (from round 3 of review on x402-foundation/x402#3234): on a bare L1 response this field
// is a plain string — it is NOT authenticated and CAN be stripped or forged, because nothing signs a bare
// L1 response. It is made tamper-evident only at L2: `attestationPayload` (ref/js/attest.mjs) with
// payloadVersion GVP-Attestation/2 puts fixedPointVersion INSIDE the Ed25519-signed payload, so stripping
// or forging it there fails the signature. L1 = re-derivable; L2 = re-derivable AND the rule-set claim is
// bound. Do not describe the L1 field as tamper-proof.
export const FIXED_POINT_VERSION = 'GVP-FixedPoint/1';

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

// Result carriage (x402#3304 carriage table): where a verifier recovers `result` on the wire.
//   "member" (default): the top-level response-body member `result`.
//   "body": the response body itself with its top-level `extensions` member removed and nothing else.
// A wire-recovery declaration, not a mode flag: the fixed point and the hash are identical either way.
export const RESULT_CARRIAGES = Object.freeze(['member', 'body']);

function assertCarriage(c) {
  if (!RESULT_CARRIAGES.includes(c)) throw new TypeError(`resultCarriage must be "member" or "body", got ${JSON.stringify(String(c)).slice(0, 40)}`);
  return c;
}

// Recover `result` from a wire body under a declared carriage (what a verifier does before hashing).
export function recoverResult(body, resultCarriage = 'member') {
  assertCarriage(resultCarriage);
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw new TypeError('recoverResult: body must be a JSON object');
  if (resultCarriage === 'member') {
    if (!('result' in body)) throw new TypeError('recoverResult: "member" carriage declared but the body has no result member');
    return body.result;
  }
  const { extensions, ...rest } = body;   // "body": everything except the top-level extensions member
  return rest;
}

// Core: given a (validated) fixed point, return the extension block to merge into a response body.
// Proves re-derivability, NOT correctness (a consumer recomputes the fixed point and re-hashes).
export function provenanceBlock(fixedPoint, { resultCarriage = 'member' } = {}) {
  assertCarriage(resultCarriage);
  assertFixedPoint(fixedPoint);
  const block = {
    responseHash: gvpHash(fixedPoint),
    fixedPoint: [...FIXED_POINT_FIELDS],   // the spec constant — declaration cannot drift from the hash
    fixedPointVersion: FIXED_POINT_VERSION, // which rule set defined "these five" — nameable at L1, BOUND only at L2 (signed payload)
    method: fixedPoint.method,              // restated beside the hash for recovery (#3304 carriage table)
    dataVintage: fixedPoint.dataVintage,
    spec: SPEC_URL,
  };
  if (resultCarriage !== 'member') block.resultCarriage = resultCarriage;   // default is implicit
  return block;
}

// Merge the provenance block into a plain response object under the standard extensions envelope,
// without mutating the caller's object. Under "body" carriage the fixed point's `result` MUST equal the
// body minus `extensions`; this is asserted so an issuer cannot declare a carriage it does not satisfy.
export function attachProvenance(body, fixedPoint, { resultCarriage = 'member' } = {}) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new TypeError('attachProvenance: response body must be a JSON object');
  }
  assertCarriage(resultCarriage);
  if (resultCarriage === 'body') {
    const recovered = recoverResult(body, 'body');
    if (gvpHash({ ...fixedPoint, result: recovered }) !== gvpHash(fixedPoint)) {
      throw new TypeError('attachProvenance: under "body" carriage the fixed point result must equal the body minus extensions');
    }
  }
  return {
    ...body,
    extensions: { ...(body.extensions ?? {}), [EXTENSION_KEY]: provenanceBlock(fixedPoint, { resultCarriage }) },
  };
}

// Convenience for root-level APIs: build the fixed point from the body itself under "body" carriage.
export function fixedPointFromBody(body, { endpoint, inputs, method, dataVintage }) {
  return { endpoint, inputs, result: recoverResult(body, 'body'), method, dataVintage };
}

// Express: res.json(body) transparently gains extensions["response-provenance"].
// `buildFixedPoint(req, body)` returns the fixed point for this response.
export function expressProvenance(buildFixedPoint, { resultCarriage = 'member' } = {}) {
  if (typeof buildFixedPoint !== 'function') {
    throw new TypeError('expressProvenance(buildFixedPoint): buildFixedPoint must be a function');
  }
  assertCarriage(resultCarriage);
  return function gvpMiddleware(req, res, next) {
    const originalJson = res.json.bind(res);
    res.json = (body) => {
      try {
        const fp = buildFixedPoint(req, body);
        return originalJson(fp ? attachProvenance(body, fp, { resultCarriage }) : body);
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
export function honoProvenance(buildFixedPoint, { resultCarriage = 'member' } = {}) {
  if (typeof buildFixedPoint !== 'function') {
    throw new TypeError('honoProvenance(buildFixedPoint): buildFixedPoint must be a function');
  }
  assertCarriage(resultCarriage);
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
      c.res = new Response(JSON.stringify(attachProvenance(body, fp, { resultCarriage })), {
        status: c.res.status,
        headers,
      });
    } catch { /* provenance must never break serving */ }
  };
}
