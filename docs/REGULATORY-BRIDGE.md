# The regulatory bridge: GVP artifacts and the EU AI Act and NIST AI RMF provisions they relate to

*Corrected 2026-11-18: an earlier version said the high-risk logging obligations applied from August
2026. Under Article 113 as amended by Regulation (EU) 2026/1744 they apply from 2 December 2027
(Annex III systems) and 2 August 2028 (Annex I systems). Mapping wording was also narrowed after each
legal sentence was checked against the official texts (EUR-Lex for the EU regulations, NIST AI
100-1 for the NIST framework). Not legal advice.*

*Last revised 2026-11-18. **This is not legal advice.** It lists which provisions each GVP artifact
relates to. Whether any
artifact satisfies a given obligation is a determination for counsel, an auditor, or a regulator —
never this document.*

## The claim, sized honestly

GVP does one narrow thing: it makes a computed answer **re-derivable** — a SHA-256 fixed point over
`{endpoint, inputs, result, method, dataVintage}` that anyone can recompute offline with an
off-the-shelf RFC 8785 library, plus optional Ed25519 issuer attestation and an on-chain anchor.

Several regimes ask for logs and documentation. A GVP receipt is one kind of record a team may keep
alongside them. GVP does not make anyone "compliant." It produces records that relate to the
documentation and logging topics of those rules. Whether they count toward any obligation is for
counsel.

## EU AI Act (Regulation (EU) 2024/1689)

- **Article 12, record-keeping (high-risk systems).** Article 12(1) requires that systems classed as
  high-risk technically allow automatic recording of events over the system's lifetime. Articles
  19(1) and 26(6) require providers and deployers to keep the automatically generated logs under
  their control for at least six months, unless other Union or national law provides otherwise.
  Under Article 113 as amended by
  [Regulation (EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng), Articles 12, 19
  and 26 apply from 2 December 2027 for Annex III systems and from 2 August 2028 for Annex I
  systems. A GVP receipt is a different kind of record from a log line: it can be recomputed. It
  does not replace the logging Article 12 describes. A receipt is small to store. If its inputs
  include personal data, data protection law governs what may be kept and for how long. A retained
  receipt remains checkable after the system that produced it is gone.
- **Article 50, transparency.** Article 50 applies from 2 August 2026. For generative systems placed
  on the market before that date, Article 111(4) allows until 2 December 2026 to meet Article 50(2).
  Providers of generative systems must mark outputs in machine-readable, detectable form, as far as
  technically feasible. Recital 133 of the Regulation lists cryptographic methods for proving
  provenance among example techniques for marking synthetic content. Article 50(2) concerns marking
  synthetic content. A GVP hash is not such a marking. GVP records provenance for *computed
  answers*. Claiming more than that would be over-reading, so we don't.

## ISO/IEC 42001 and NIST AI RMF

- **ISO/IEC 42001.** ISO/IEC 42001 is a management-system standard we have not read in full. We make
  no statement about what it requires. Separately from any standard, a reviewer receives, from a
  GVP-emitting system: per-answer re-derivable records, published golden
  vectors (the method's own test of correctness), versioned data vintages with a
  weakest-link rule (§2.1.3), and a closure rule that *forbids* claiming provenance where it cannot
  hold (§2.1.2). The last one means a receipt states its own limits instead of
  overreaching them.
- **NIST AI RMF.** NIST AI RMF 1.0 (NIST AI 100-1) includes MEASURE 2.9 (the model is "explained,
  validated, and documented"), MEASURE 3 (mechanisms for tracking identified risks over time) and
  MANAGE 4.1 (post-deployment monitoring plans). A receipt is documentation a team may reference
  there. The framework describes itself as voluntary.

## Insurance (not confirmed)

We have not confirmed any insurer's requirements. A receipt is a record a third party can recompute
without relying on the issuer's logs.

## What a reviewer receives, artifact by artifact

| GVP artifact | What the artifact shows |
|---|---|
| `responseHash` (L1) | tamper-evidence + reproducibility of a specific answer, offline-checkable |
| fixed point members (`endpoint`, `inputs`, `result`, `method`, `dataVintage`) | the *question*, the *method*, and the *data currency* bound into one record — not just the answer |
| §2.1.3 `dataVintage` (all sources, oldest, own precision — or emit nothing) | data-provenance honesty; the freshness field that cannot silently omit its weakest source |
| §2.1.2 closure rule | states the scope of what it covers: routes that cannot be re-derived carry no hash, not a softer claim |
| golden vectors + §8.1 (verifier must reproduce them first) | correctness testing of the method itself, and discipline on whoever checks it |
| L2 Ed25519 attestation | issuer identity + timestamp, bound over the fixed point |
| on-chain anchor | existence-before-a-time, independent of the issuer's storage |
| `extensions["response-provenance"]` member | machine-readable, cryptographic answer provenance that travels in the response envelope beside any other extension members |

## The one-sentence version

> Answers carrying GVP provenance are individually re-derivable by any party with a standard JCS
> library — the record of what was computed, from what, by what method, on data of what vintage, is
> cryptographic, machine-readable, small to store, and does not depend on trusting the
> system or its operator.

Questions, corrections, or a mapping we got wrong: open an issue. Over-claiming is a defect here in
the same way a wrong hash is.
