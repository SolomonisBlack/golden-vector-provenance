// GVP reference implementation (JavaScript/TypeScript-compatible ESM) — the canonicalization + hash.
// This MUST produce byte-identical output to the Python reference (ref/py/gvp.py) for every
// conformance vector. Canonicalization is RFC 8785 (JCS); see spec/gvp-0.2.md §2.2.
import { createHash } from 'node:crypto';

const MAX_DEPTH = 100;

// GVP canonical JSON (normative, §Canonicalization):
//   - object keys sorted by UTF-16 code unit (JSON.stringify default), no whitespace
//   - arrays preserve order
//   - strings: JSON string escaping, non-ASCII emitted as raw UTF-8 (NOT \u-escaped)
//   - numbers: ECMAScript Number->String (integers have no decimal point; no +; no trailing zeros)
//   - booleans/null: true|false|null
export function canonicalize(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('input nesting too deep');
  if (Array.isArray(value)) return '[' + value.map(v => canonicalize(v, depth + 1)).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort()
      .map(k => JSON.stringify(k) + ':' + canonicalize(value[k], depth + 1)).join(',') + '}';
  }
  if (typeof value === 'number' && !isFinite(value)) throw new Error('non-finite number not allowed in GVP JSON');
  return JSON.stringify(value);
}

// Instrumentation seam (test-only by default): called with the canonical bytes immediately before the
// digest. Lets a conformance test COUNT hash invocations and assert that refusal paths (non-finite,
// depth, bad member set) reach the digest 0 times and the green/tamper paths exactly 1 (the
// hash-invocation-count instrument; see tools/check-hash-count.mjs). Default no-op; never set in
// production paths. A refusal that happens after this point would be a bug this seam can catch.
export const hooks = { beforeDigest: null };

// GVP response hash (§Hashing): sha256 over the canonical JSON of the fixed point
// {endpoint, inputs, result, method, dataVintage}. Prefixed "sha256:".
export function gvpHash(fixedPoint) {
  const canonical = canonicalize(fixedPoint);   // every refusal throws here, before any digest
  if (hooks.beforeDigest) hooks.beforeDigest(canonical);
  return 'sha256:' + createHash('sha256').update(canonical, 'utf8').digest('hex');
}
