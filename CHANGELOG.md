# Changelog

## 0.6.0 — 2026-08-23
**`fixedPointVersion` is now bound — inside the signed L2 payload.** Round 3 of external review on
x402-foundation/x402#3234 demonstrated against 0.5.0 that the field, emitted beside the hash but
*outside* the signed payload, could be **stripped** (a 0.5 receipt became indistinguishable from 0.4 —
the silent skew 0.5.0 meant to close) or **forged** to an unsupported rule set (denial of verification)
while the signature still verified. Fix: a second signed-payload shape **`GVP-Attestation/2`** adds
`payloadVersion` + `fixedPointVersion` INSIDE the Ed25519-signed object (spec §6). Stripping or forging
now fails the signature; `tools/check-l2-binding.mjs` reproduces the reviewer's four-case table and
expects the flip. **`responseHash` is untouched** (not in the hashed L1 fixed point), so every hash and
all L1 vectors are byte-identical. `GVP-Attestation/1` (legacy 6-field) stays valid for receipts already
issued; shape is selected by the declared `payloadVersion` and NEVER guessed (no downgrade by trial).
New vectors `vectors/attestation-v2.json` (8) — genuinely new inputs to test against. The unsigned L1
`fixedPointVersion` is now documented honestly as informational (unauthenticated on a bare response).

## 0.5.0 — 2026-08-23
**Additive, no hash change.** The fixed-point member set is now a **named, frozen rule set,
`GVP-FixedPoint/1`** (spec §2.1.1). The middleware emits `fixedPointVersion: "GVP-FixedPoint/1"` beside
`responseHash`; the receipt schema gains an optional `fixedPointVersion`. It lives *beside* the hash, not
inside the hashed payload, so **every existing hash is unchanged** and the vectors still reproduce. Why:
with a constant member set, a future change would otherwise be silent — a verifier on one rule set and an
issuer on another would disagree indistinguishably from a forgery. Now a verifier reads the identifier
first and reports "unsupported rule set" by name. `GVP-FixedPoint/1` will never change; a different set is
a new identifier. Also resolves the spec-doc-vs-package version ambiguity (attestations are produced under
a named rule set, not a package version). From review on x402-foundation/x402#3234.

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
