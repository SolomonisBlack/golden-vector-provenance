# What a GVP receipt is, and how it relates to Articles 50(2) and 12 of Regulation (EU) 2024/1689

*Corrected 2026-11-18: an earlier version said the high-risk logging obligations applied from August
2026. Under Article 113 as amended by Regulation (EU) 2026/1744 they apply from 2 December 2027
(Annex III systems) and 2 August 2028 (Annex I systems). Mapping wording was also narrowed after each
legal sentence was checked against the official texts on EUR-Lex. Not legal advice.*

*For audit, compliance, and AI-governance vendors evaluating provenance records. One page. Last revised
2026-11-18. **This is not legal advice.** It states what a GVP artifact technically is and which
provisions it relates to; whether it satisfies any obligation is a determination for counsel,
an auditor, or a regulator. The companion document
[`REGULATORY-BRIDGE.md`](REGULATORY-BRIDGE.md) covers the same provisions and NIST AI RMF.*

## The artifact, in one line

A Golden-Vector Provenance (GVP) receipt is a SHA-256 hash over the RFC 8785 canonical form of
`{endpoint, inputs, result, method, dataVintage}`, carried beside the answer, that any party can
recompute offline with a standard JCS library and no trust in the issuer. Optional Ed25519 attestation
binds issuer identity and time; the hash itself needs no key. Reference: `spec/gvp-0.2.md`, npm
`golden-vector-provenance`, and the extension text under review at
[x402-foundation/x402#3304](https://github.com/x402-foundation/x402/pull/3304).

## Where the obligations stand (dates read from EUR-Lex on 2026-11-18)

| Obligation | What it asks | Applies from |
|---|---|---|
| **Art. 50(2)**: providers of systems generating synthetic audio, image, video, or text must mark outputs in a machine-readable format and make them detectable as artificially generated or manipulated | machine-readable marking + detectability | 2 August 2026. Article 111(4), inserted by [Regulation (EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng) (OJ L, 24.7.2026), gives providers of generative systems placed on the market before 2 August 2026 until **2 December 2026** to meet Article 50(2). |
| **Art. 12**: Article 12(1) requires that systems classed as high-risk technically allow automatic recording of events over the system's lifetime. Articles 19(1) and 26(6) require providers and deployers to keep the automatically generated logs under their control for at least six months, unless other Union or national law provides otherwise. | logging that supports traceability and post-market monitoring | Under Article 113 as amended by Regulation (EU) 2026/1744, Articles 12, 19 and 26 apply from **2 December 2027** for Annex III systems and from **2 August 2028** for Annex I systems. |

## The mapping, stated at the size it deserves

**Article 50(2).** The obligation targets *synthetic content*. The Regulation names no specific
standard. **A GVP hash is not a marking of synthetic content under Article 50(2).** What it does:
for computed answers (a tax figure, a rate, a score with a stated method), whether or not the
producing software falls within the Regulation, it supplies a machine-readable provenance record.
The boundary is the whole claim.

**Article 12.** Article 12 is the provision these records most closely relate to. It concerns event
logging by systems classed as high-risk. A GVP receipt is a different kind of record from a log line: a
later party can *recompute* the answer it covers. For each covered computation the record binds the question (`endpoint`,
`inputs`), the method, the data currency (`dataVintage`, which must characterise every contributing
source and must be the oldest where they differ), and the result, in one hash checkable after the
producing system is gone. A receipt is small to store. If its inputs include personal data, data
protection law governs what may be kept and for how long. The closure rule (spec §2.1.2)
forbids emitting a hash where the result depends on anything outside the fixed point, so the record
states the scope of what it covers: an answer it cannot re-derive carries no hash rather than a softer claim.

## What a reviewer receives, and what remains theirs to do

| You get | You still do |
|---|---|
| per-answer re-derivable records, offline | decide, with counsel, whether the system is classed as high-risk under Article 6 and which events its logs must record |
| published golden vectors: the method's own correctness test | verify the vectors against the authoritative source (the spec requires this of any verifier, §8.1) |
| a four-state verdict vocabulary (`verified`, `no_claim`, `unverifiable`, `contradicted`) that cannot be collapsed into pass/fail | map verdicts into your control framework |
| L2 issuer attestation (Ed25519) and an optional on-chain anchor for existence-before-a-time | key management and anchor policy |
| a rail-agnostic envelope: the same member rides in an x402 receipt, an AP2 mandate, a card-network token receipt, or an unpaid response (see `examples/plain-http/`) | nothing; that is the point |

## The sentence for your memo

> Computed outputs carrying GVP provenance are individually re-derivable by any party with a standard
> RFC 8785 library: the record of what was computed, from what inputs, by what method, on data of what
> vintage, is cryptographic, machine-readable, small to store, and independent of trust in
> the system or its operator. It complements, and does not replace, synthetic-content marking.

Corrections: open an issue. Over-claiming is a defect here in the same way a wrong hash is.
