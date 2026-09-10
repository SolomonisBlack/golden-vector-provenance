# Compliance memo: what a GVP receipt gives you under EU AI Act Article 50(2) and Article 12

*For audit, compliance, and AI-governance vendors evaluating evidence sources. One page. Last verified
2026-09-09. **This is not legal advice.** It states what a GVP artifact technically is and which
obligation classes can consume it; whether it satisfies any obligation is a determination for counsel,
an auditor, or a regulator. The companion document
[`REGULATORY-BRIDGE.md`](REGULATORY-BRIDGE.md) covers ISO/IEC 42001, NIST AI RMF, and insurance.*

## The artifact, in one line

A Golden-Vector Provenance (GVP) receipt is a SHA-256 hash over the RFC 8785 canonical form of
`{endpoint, inputs, result, method, dataVintage}`, carried beside the answer, that any party can
recompute offline with a standard JCS library and no trust in the issuer. Optional Ed25519 attestation
binds issuer identity and time; the hash itself needs no key. Reference: `spec/gvp-0.2.md`, npm
`golden-vector-provenance`, and the extension text under review at
[x402-foundation/x402#3304](https://github.com/x402-foundation/x402/pull/3304).

## Where the obligations stand (dates verified against the EU AI Act text and official guidance)

| Obligation | What it asks | In force |
|---|---|---|
| **Art. 50(2)** — providers of systems generating synthetic audio, image, video, or text must mark outputs in a machine-readable format and make them detectable as AI-generated | machine-readable marking + detectability | 2 August 2026; the May 2026 AI Omnibus provisional agreement gives generative systems already on the market until **2 December 2026** to meet the marking requirement ([artificialintelligenceact.eu](https://artificialintelligenceact.eu/transparency-rules-article-50/)) |
| **Art. 12** — high-risk systems must automatically record events over their lifetime; logs retained at least six months (Art. 19) | logging that supports traceability and post-market monitoring | high-risk obligations phased in from August 2026 ([Cooley, 2026-08-03](https://www.cooley.com/news/insight/2026/2026-08-03-eu-ai-act-transparency-obligations-take-effect-2-august-2026)) |

## The mapping, stated at the size it deserves

**Article 50(2).** The obligation targets *synthetic content*. C2PA is the accepted mechanism for
media. **A GVP hash is not a synthetic-content watermark and does not satisfy Art. 50(2) on its
own.** What it does: for the class of AI-system outputs that are *computed answers* (a tax figure, a
rate, a score, a classification with a stated method), it supplies the machine-readable, standardized,
cryptographic provenance member that a marking pipeline can carry in the same envelope as the
disclosure. No comparable standard exists for computed outputs today; C2PA does not cover them. That
is the gap this artifact fills, and the boundary is the whole claim.

**Article 12.** This is the direct fit. A log line asserts that an event happened; a GVP receipt lets a
later party *re-derive* it. For each covered computation the record binds the question (`endpoint`,
`inputs`), the method, the data currency (`dataVintage`, which must characterise every contributing
source and must be the oldest where they differ), and the result, in one hash checkable after the
producing system is gone. Retention cost is the hash plus its members. The closure rule (spec §2.1.2)
forbids emitting a hash where the result depends on anything outside the fixed point, so the record
documents its own scope of control by silence rather than by a softer claim.

## What an auditor receives, and what remains theirs to do

| You get | You still do |
|---|---|
| per-answer re-derivable records, offline | decide which computations are in scope for Art. 12 |
| published golden vectors: the method's own correctness test | verify the vectors against the authoritative source (the spec requires this of any verifier, §8.1) |
| a four-state verdict vocabulary (`verified`, `no_claim`, `unverifiable`, `contradicted`) that cannot be collapsed into pass/fail | map verdicts into your control framework |
| L2 issuer attestation (Ed25519) and an optional on-chain anchor for existence-before-a-time | key management and anchor policy |
| a rail-agnostic envelope: the same member rides in an x402 receipt, an AP2 mandate, a card-network token receipt, or an unpaid response (see `examples/plain-http/`) | nothing; that is the point |

## The sentence for your memo

> Computed outputs carrying GVP provenance are individually re-derivable by any party with a standard
> RFC 8785 library: the record of what was computed, from what inputs, by what method, on data of what
> vintage, is cryptographic, machine-readable, retained at negligible cost, and independent of trust in
> the system or its operator. It complements, and does not replace, synthetic-content marking.

Corrections: open an issue. Over-claiming is a defect here in the same way a wrong hash is.
