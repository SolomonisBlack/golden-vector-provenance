# Changelog

## 0.7.0 — 2026-08-26
**Four normative rules, all from external conformance review, all backwards-compatible (`GVP-FixedPoint/1`
is frozen and every existing hash is byte-identical).** These accumulated on `main` above published npm
0.6.0 and are released together here.

- **`GVP-FixedPoint/2` pins `dataVintage`** (spec §2.1.3). `/1` typed it as an unconstrained `<string>`,
  so `"July 2026"`, `"2026-07"`, `"2026.0"` all hashed differently for identical data — a divergence that
  had already fired between this repo's own vectors and its reference service. `/2` requires ISO 8601
  reduced precision (`YYYY | YYYY-MM | YYYY-MM-DD`), precision significant, lexical order = chronological.
  Vectors `vectors/expected-v2.json`, gate `tools/check-fixedpoint-2.mjs`. Raised by @seancrecord (scvd.store).
- **`dataVintage` completeness** (spec §2.1.3). It MUST characterise **all** sources that contributed to
  `result`, MUST be the **oldest** where they differ, and a seller who cannot enumerate them MUST NOT emit
  a `responseHash` — which is §2.1.2 restated (an un-enumerable source is a hidden input). Raised by
  @kopko13 (Sirenic) from a live multi-source catalogue.
- **§2.1.2 closure rule** (normative). An issuer MUST NOT emit a `responseHash` when `result` depends on
  anything outside the fixed point. A failed re-derivation is therefore a disjunction — altered artifact
  OR a hash issued in violation — and a verifier need not (cannot) attribute between them for the finding
  to stand. Raised by @seancrecord; the first draft's "only remaining explanation" was itself wrong (a
  MUST NOT does not prevent its own violation) and was corrected in the same review.
- **§8.1 verifier precondition** (normative — the spec's first constraint on verifiers rather than
  issuers). A party MUST NOT state a re-derivation failure unless its own canonicalizer passes the L1
  vectors, the independent-implementation JCS gate, and the rule set's vectors. `npm run verifier-precondition`.

**Also:** `interop/scvd/` — a working conformance check offered to the scvd.store desk (independent
canonicalizer, 31/0, offline). **Licensing made machine-classifiable** — `LICENSE` is now the verbatim
Apache-2.0 text (the repo previously reported `NOASSERTION` because `LICENSE` was a pointer document);
the dual-licence split moved to `LICENSING.md`; the spec's CC-BY-4.0 grant is unchanged.

> **npm note:** npm `golden-vector-provenance@0.6.0` (published 2026-08-23) predates all of the above and
> does **not** contain it. This git tag `v0.7.0` is the accurate snapshot. Publishing npm 0.7.0 to match
> is an owner-gated follow-up; until then, pin the git tag, not the npm 0.6.0 package, for these rules.

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
New vectors `vectors/attestation-v2.json` — the same 8 canonicalization-adversarial cases (same fixed points, same `responseHash` values) re-signed under the `/2` shape; what is new is the signed payloads and signatures, not the inputs. The unsigned L1
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
