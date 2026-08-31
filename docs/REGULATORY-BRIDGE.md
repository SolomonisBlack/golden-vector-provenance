# The regulatory bridge: GVP artifacts as audit evidence

*Last verified 2026-08-30. **This is not legal advice.** It maps GVP's technical artifacts to the
evidence classes named by current AI regulation, standards, and (reportedly) insurance underwriting —
so that a team already subject to those regimes can see what a GVP receipt gives them. Whether any
artifact satisfies a given obligation is a determination for counsel, an auditor, or a regulator —
never this document.*

## The claim, sized honestly

GVP does one narrow thing: it makes a computed answer **re-derivable** — a SHA-256 fixed point over
`{endpoint, inputs, result, method, dataVintage}` that anyone can recompute offline with an
off-the-shelf RFC 8785 library, plus optional Ed25519 issuer attestation and an on-chain anchor.

That narrow thing happens to be the shape of evidence several regimes now ask for: a record that a
specific computation, on specific inputs, against specific data of a specific vintage, produced a
specific result — checkable later by a party who trusts nobody involved. GVP does not make anyone
"compliant." It produces artifacts that documentation, logging, and traceability obligations can
consume.

## EU AI Act (Regulation (EU) 2024/1689)

- **Article 12 — record-keeping (high-risk systems).** High-risk AI systems must automatically record
  events over their lifetime, with logs kept at least six months; enforcement for these obligations
  reached full effect in August 2026 ([Cooley, 2026-08-03](https://www.cooley.com/news/insight/2026/2026-08-03-eu-ai-act-transparency-obligations-take-effect-2-august-2026)).
  A GVP receipt is a *stronger-than-log* record for the computations it covers: a log line asserts
  what happened; a fixed point re-derives. Retention is trivial (a hash plus its members), and a
  retained receipt remains checkable after the system that produced it is gone.
- **Article 50 — transparency.** In force since 2026-08-02: providers of generative systems must mark
  outputs in machine-readable, detectable form, with cryptographic provenance mechanisms among the
  techniques the guidance recognizes ([CSA research note, 2026-07-29](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-article-50-transparency-20260729/)).
  Be precise about fit: Article 50 targets *marking synthetic content*; GVP provenances *computed
  answers*. A GVP hash is not a synthetic-content watermark. Where the two meet is machine-readable
  provenance as a discipline — an `extensions["response-provenance"]` member is machine-readable,
  standardized, and cryptographic, and a provider building an Article 50 marking pipeline can carry
  answer-provenance in the same envelope. Claiming more than that would be over-reading, so we don't.

## ISO/IEC 42001 and NIST AI RMF

- **ISO/IEC 42001** (certifiable AI management systems) asks organizations to demonstrate controls
  over AI system behavior, data provenance, and verification of outputs. An auditor working a 42001
  engagement receives, from a GVP-emitting system: per-answer re-derivable records, published golden
  vectors (the method's own test of correctness), versioned data vintages with a
  weakest-link rule (§2.1.3), and a closure rule that *forbids* claiming provenance where it cannot
  hold (§2.1.2). The last one matters most in an audit: a control that documents its own limits is
  the difference between a control environment and a brochure.
- **NIST AI RMF** — the MEASURE and MANAGE functions call for mechanisms to track, verify, and
  document AI system outputs. Same mapping, voluntary regime.

## Insurance (reported; treat as directional)

Trade coverage through 2026 reports major carriers filing AI-related exclusions on commercial
liability lines by default, while underwriters price coverage favorably where a **documented control
environment** exists. We have not confirmed individual carrier filings against primary regulatory
sources, and we say so. The directional point survives the hedge: if insurability turns on documented
controls over AI-derived outputs, a re-derivable receipt is close to the cheapest such document that
exists — it is the control *and* its own evidence, in one artifact a claims examiner can check
without trusting the insured's logs.

## What an auditor actually gets, artifact by artifact

| GVP artifact | Evidence class it feeds |
|---|---|
| `responseHash` (L1) | tamper-evidence + reproducibility of a specific answer, offline-checkable |
| fixed point members (`endpoint`, `inputs`, `result`, `method`, `dataVintage`) | the *question*, the *method*, and the *data currency* bound into one record — not just the answer |
| §2.1.3 `dataVintage` (all sources, oldest, own precision — or emit nothing) | data-provenance honesty; the freshness field that cannot silently omit its weakest source |
| §2.1.2 closure rule | documented scope-of-control: routes that cannot be re-derived say so by silence, not by a softer claim |
| golden vectors + §8.1 (verifier must reproduce them first) | correctness testing of the method itself, and discipline on whoever checks it |
| L2 Ed25519 attestation | issuer identity + timestamp, bound over the fixed point |
| on-chain anchor | existence-before-a-time, independent of the issuer's storage |

## The one-sentence version for a compliance memo

> Answers carrying GVP provenance are individually re-derivable by any party with a standard JCS
> library — the record of what was computed, from what, by what method, on data of what vintage, is
> cryptographic, machine-readable, retained at negligible cost, and does not depend on trusting the
> system or its operator.

Questions, corrections, or a mapping we got wrong: open an issue. Over-claiming is a defect here in
the same way a wrong hash is.
