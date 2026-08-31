# Recompute, don't trust: where GVP sits in the AI verification stack

*A category note. Last verified 2026-08-30. Sources dated inline; corrections welcome by issue.*

When an AI agent (or anyone) needs to rely on an answer a machine produced, there are five working
ways to establish trust in it. They are not interchangeable, and most public discussion blurs them.
This note names them, states what each one actually proves, and locates GVP precisely — including
what it cannot do.

## The five trust models

| Model | You trust | It proves | Verify offline? | Production examples (2026) |
|---|---|---|---|---|
| **Signature attestation** | the signer's key + honesty | *this issuer emitted these bytes* | yes | Ed25519/ML-DSA receipt schemes across the x402 ecosystem |
| **TEE attestation** | the hardware vendor + enclave measurement | *this code ran in this enclave on these inputs* | partially (attestation doc verifies; the code's semantics you still read yourself) | Phala (Intel TDX + NVIDIA TEE), Marlin Oyster ([docs](https://docs.phala.com/network/overview/phala-network)) |
| **Crypto-economic (staking)** | that slashing outweighs cheating | *someone with money at risk vouched for this* | no (needs chain state) | EigenCloud / EigenVerify ([blog](https://blog.eigencloud.xyz/a-verifiable-cloud-for-the-agentic-era/)) |
| **zkML** | the proof system's soundness | *this exact model computed this output* | yes | not yet practical for LLM-scale inference — proving remains orders of magnitude slower than native inference ([Equilibrium Labs, State of Verifiable Inference](https://equilibrium.co/writing/state-of-verifiable-inference)) |
| **Recompute** | nothing and no one | *anyone who redoes the work gets the same bytes* | **yes, trivially** | Ambient's Proof of Logits (logit level), Space and Time's Proof of SQL (query level), **GVP (response level, this repo)** |

The last row is the class analysts have started calling **"don't trust, verify — by recomputing"**
([chainofthought.xyz, The AI Verification Stack](https://chainofthought.xyz/p/don-t-trust-verify-the-emerging-stack-for-ai-verification-e18a)):
no party has to be believed, because every party can recompute. A signature can be honest about
altered content; an enclave can run buggy code faithfully; a staker can be wrong at a profit smaller
than the slash. A recomputed hash has no counterparty.

## What recompute requires — and the honest boundary

Recomputation only works where the computation is a **closed function of declared inputs**. That is
not a limitation GVP discovered late; it is normative (§2.1.2): an issuer MUST NOT emit a
`responseHash` when the result depends on anything outside the fixed point. A cached model answer, a
live-merge feed, an unenumerable source — those routes emit *nothing*, honestly, rather than a hash
nobody can re-derive.

This draws the map of the stack cleanly:

- **Open-ended LLM inference** is not response-level recomputable (sampling, nondeterministic
  kernels). Verifying it belongs to TEE attestation today and zkML eventually; Ambient's logit-level
  hashing is the recompute-class attempt at that layer.
- **Deterministic computed answers** — tax math, rate lookups against pinned vintages, screening
  verdicts over pinned lists, anything with a published method and enumerable sources — are exactly
  recomputable, and for them the heavier machinery buys nothing: no enclave, no stake, no prover, no
  resolver. One JCS pass and one SHA-256 with an off-the-shelf library, offline.

GVP is the response-level convention for that second class. It deliberately proves the weaker,
checkable claim — *unaltered and reproducible* — and leaves *correct* to reproduction against
published golden vectors, which is the same recompute move applied to the method itself.

## Why this class composes with the others instead of competing

A recomputable hash is a primitive the other models can carry:

- a **signature** over a fixed point that re-derives upgrades "this issuer said it" to "this issuer
  said it, and anyone can confirm the content" (GVP L2 does exactly this);
- a **TEE attestation** whose output commitment is a GVP fixed point becomes checkable by parties who
  don't trust the enclave vendor;
- a **DID/CID envelope** over the same digest is an encoding, not a new primitive — verified
  concretely against `did:artifact` (OMA3): for a JSON artifact their method canonicalizes with the
  same RFC 8785 and the CID's multihash carries the byte-identical SHA-256 digest
  ([x402#3234](https://github.com/x402-foundation/x402/issues/3234)).

And it is **payment-rail-agnostic**: the fixed point binds the question and the answer, and says
nothing about how settlement happened. x402 receipts are the first carrier; an AP2 mandate, an ACP
order, a card-network token receipt, or no payment at all can carry the same member unchanged.

## Status of the class, stated plainly

As of late August 2026 no analyst firm sizes "recompute-based response verification" as its own
market; the nearest category (AI TRiSM) is estimated around $3.0–3.5B for 2026
([MarketsAndMarkets](https://www.marketsandmarkets.com/Market-Reports/ai-trust-risk-security-management-trism-market-8112669.html)).
Funded recompute-class projects exist at the logit and SQL layers; at the response layer, GVP's
implementations (four independent reproductions, one production conformance desk — see the README's
Status section for the evidenced list) are, to our knowledge, the extent of the field. That is a
statement about how early this is, not how large. Both readings are available; we hold the first and
are building for the second.
