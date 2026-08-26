// response-hash-check — a conformance check for scvd.store's defect vocabulary.
//
// Offered to seancrecord/scvd-general-store-repo#193. Zero dependencies, offline, no network,
// no issuer cooperation. Written to that store's house rules: it states one dated observation,
// it refuses to overclaim, and it carries what would falsify it.
//
// WHAT IT CHECKS
//   A GVP artifact declares `provenance.responseHash` — a SHA-256 over the RFC 8785 (JCS)
//   canonical form of the closed five-member fixed point {endpoint, inputs, result, method,
//   dataVintage}. Anyone holding the response body can recompute it. A receipt proves payment
//   and issuer; it cannot reach the body. This closes that gap.
//
// WHAT IT DOES NOT DO
//   It never fetches the issuer's origin. The caller supplies the body, so a verdict reads
//   "this hash re-derives from the body you gave us" — never "the issuer served this". That
//   was the store's explicit requirement and it is enforced by having no fetch seam at all.
//
// THE FINDING IS A DISJUNCTION, NOT AN ATTRIBUTION
//   A failed re-derivation means the artifact was altered OR it was issued in violation of the
//   closure rule (GVP §2.1.2: an issuer MUST NOT emit a responseHash when the result depends on
//   anything outside the fixed point). Both are defects. Distinguishing them requires the
//   issuer's internals, which a third party cannot see — so the check states both branches and
//   names neither. Naming one would overclaim.
//
// SELF-EXCLUSION (GVP §8.1)
//   A third branch exists and it is the verifier's: our own canonicalization may be wrong. JCS
//   is exactly where that hides. So this module MUST pass its own vectors before it is allowed
//   to state a finding — see assertFit(). Fail that and it reports `unable-to-verify`, which is
//   a claim about this instrument and not about any issuer. The two are never conflated.
//
// Spec: https://github.com/SolomonisBlack/golden-vector-provenance/blob/main/spec/gvp-0.2.md
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';

export const CLASS_SLUG = 'response-hash-not-rederivable';
export const FIXED_POINT_MEMBERS = Object.freeze(['endpoint', 'inputs', 'result', 'method', 'dataVintage']);

// ---- RFC 8785 (JCS) canonicalization ---------------------------------------------------------
// Independent of the GVP reference implementation on purpose: a check that shares code with the
// thing it checks is a mirror, not evidence.

const ESCAPES = { '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t' };

function jcsString(s) {
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ESCAPES[ch]) out += ESCAPES[ch];
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += ch;                       // non-ASCII stays raw UTF-8; JCS does NOT \u-escape it
  }
  return out + '"';
}

function jcsNumber(n) {
  if (!Number.isFinite(n)) throw new TypeError('non-finite number is not valid JSON');
  if (n === 0) return '0';                // JCS: -0 serializes as 0
  return String(n);                       // V8's Number->String IS the ECMAScript algorithm JCS cites
}

export function canonicalize(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return jcsNumber(v);
  if (typeof v === 'string') return jcsString(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (typeof v === 'object') {
    // JCS orders by UTF-16 code units of the key, which is what Array#sort does by default.
    const keys = Object.keys(v).filter(k => v[k] !== undefined).sort();
    return '{' + keys.map(k => jcsString(k) + ':' + canonicalize(v[k])).join(',') + '}';
  }
  throw new TypeError('unserializable value: ' + typeof v);
}

export const sha256Hex = s => createHash('sha256').update(s, 'utf8').digest('hex');

// ---- the fixed point --------------------------------------------------------------------------

/** Rebuild the closed five-member fixed point. The member set is a spec constant, never taken
 *  from the artifact — an issuer that declared its own member list could shrink it and stay
 *  internally consistent. */
export function fixedPointOf(response, inputs) {
  return {
    endpoint: response?.endpoint,
    inputs,
    result: response?.result,
    method: response?.provenance?.method,
    dataVintage: response?.provenance?.dataVintage,
  };
}

const stripPrefix = h => (typeof h === 'string' && h.startsWith('sha256:') ? h.slice(7) : h);

// ---- §8.1 self-exclusion ----------------------------------------------------------------------

/** Our own canonicalizer must reproduce known vectors before we may accuse anyone.
 *  Returns {fit:boolean, failures:[...]}. Cheap enough to run per invocation. */
export function assertFit(vectors) {
  const failures = [];
  for (const v of vectors.canonicalization ?? []) {
    let got;
    try { got = canonicalize(v.value); } catch (e) { got = 'THREW: ' + e.message; }
    if (got !== v.canonical) failures.push({ name: v.name, expected: v.canonical, got });
  }
  for (const v of vectors.digests ?? []) {
    const got = sha256Hex(canonicalize(v.fixedPoint));
    if (got !== stripPrefix(v.expectedHash)) failures.push({ name: v.name, expected: v.expectedHash, got });
  }
  return { fit: failures.length === 0, failures };
}

// ---- the check --------------------------------------------------------------------------------

/**
 * @param {object} artifact  {response, inputs} — the body the CALLER supplies. Never fetched.
 * @param {object} vectors   the fit vectors this instrument is held to (§8.1).
 * @returns a finding in the store's vocabulary shape, or an unable-to-verify report about US.
 */
export function checkResponseHash(artifact, vectors) {
  const fit = assertFit(vectors);
  if (!fit.fit) {
    // A claim about this instrument. NOT a finding, and deliberately carries no class slug —
    // nothing downstream should be able to mistake it for an accusation against an issuer.
    return {
      status: 'unable-to-verify',
      subject: 'this instrument',
      detail: 'our canonicalizer does not reproduce its own vectors; per GVP §8.1 we may not state a finding',
      failures: fit.failures,
    };
  }

  const { response, inputs } = artifact ?? {};
  const declared = stripPrefix(response?.provenance?.responseHash);
  if (!declared) {
    return { status: 'not-applicable', subject: 'artifact', detail: 'no provenance.responseHash declared; this class does not apply' };
  }

  const fixedPoint = fixedPointOf(response, inputs);
  const missing = FIXED_POINT_MEMBERS.filter(m => fixedPoint[m] === undefined);
  if (missing.length) {
    return {
      status: 'finding', class: CLASS_SLUG, subject: 'artifact',
      asserts: `the artifact declares a responseHash but omits fixed-point member(s): ${missing.join(', ')}`,
      detail: 'the member set is closed; a hash over a subset is not a GVP responseHash',
      falsified_by: 'the artifact carrying all five members with a hash that re-derives over them',
    };
  }

  let canonical, recomputed;
  try {
    canonical = canonicalize(fixedPoint);
    recomputed = sha256Hex(canonical);
  } catch (e) {
    return { status: 'unable-to-verify', subject: 'this instrument', detail: 'canonicalization threw: ' + e.message };
  }

  if (recomputed === declared) {
    return {
      status: 'pass', class: CLASS_SLUG, subject: 'artifact',
      detail: 'responseHash re-derives from the supplied body over the declared fixed point',
      recomputed, declared,
    };
  }

  return {
    status: 'finding',
    class: CLASS_SLUG,
    subject: 'artifact',
    // The disjunction. Both branches are defects; we name neither, because we cannot see which.
    asserts:
      'the declared responseHash does not re-derive from the supplied body over the closed fixed point ' +
      '{endpoint, inputs, result, method, dataVintage}. Either the artifact was altered, or it was issued ' +
      'in violation of GVP §2.1.2 (a result depending on inputs outside the fixed point). Both are defects; ' +
      'this instrument cannot and does not say which.',
    costs:
      'a buyer relying on the hash believes it can prove what it was served, and cannot. The receipt may still ' +
      'be perfectly valid — it attests payment and issuer, never the body.',
    detectable: 'from a supplied artifact; no payment and no origin fetch by this instrument',
    falsified_by:
      'recomputing SHA-256 over the RFC 8785 (JCS) canonical form of {endpoint, inputs, result, method, ' +
      'dataVintage} from the same supplied body and obtaining the declared responseHash',
    scope: 'THIS IS THE ARTIFACT YOU GAVE US. We did not fetch it from the issuer origin and do not say they served it.',
    recomputed,
    declared,
    canonical,
  };
}
