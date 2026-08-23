# Changelog

## 0.4.0 — 2026-08-23
**Behavior change (security fix, from review on x402-foundation/x402#3234).** The fixed point is now
strictly the five spec members `{endpoint, inputs, result, method, dataVintage}` — all required, no
extras. `provenanceBlock`/`attachProvenance` **throw** on a subset or superset; the Express/Hono
middleware serves the body unchanged *without* a provenance block (error on `res.locals.gvpError` /
swallowed in Hono). The emitted `fixedPoint` list is now the spec constant, not `Object.keys()` of the
input. Why: on a bare 200 a self-declared list was unbound — a seller could drop `inputs` from both the
hash and the list and stay internally consistent. Also: `endpoint`+`inputs` being required means the
hash binds the *question*, not only the answer. If you passed extra fields (e.g. `timestamp`), remove
them — timestamps belong in the L2 attestation, not the fixed point.

## 0.3.0 — 2026-08-22
Add `golden-vector-provenance/middleware`: `expressProvenance`, `honoProvenance`, `provenanceBlock`,
`attachProvenance`. Hono adapter drops a stale `content-length` before re-wrapping.

## 0.2.0 — 2026-08-20
First public release. Canonicalization normatively RFC 8785 (JCS), gated byte-for-byte against an
independent implementation (`tools/check-jcs.mjs`). Full Apache-2.0 / CC-BY-4.0 licence texts.
