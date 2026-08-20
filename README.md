# Golden-Vector Provenance (GVP)

**Every answer ships a hash anyone can re-derive for free — so you don't trust the server, you
recompute the math.**

GVP is a small, open convention for **reproducible provenance on computed answers**. An answer travels
with a canonical SHA-256 fixed point over `{endpoint, inputs, result, method, dataVintage}`. Anyone
holding the answer can recompute it and check the hash. No key exchange, no callback to the issuer, no
trust in us.

Optional layers add an Ed25519 issuer attestation (*who issued this, and when*) and an on-chain
identity anchor. They never assert that the answer is **correct** — correctness is established only by
reproduction.

- **Canonicalization is [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785)** — so implementing
  GVP means calling a JCS library you already have, not writing serialization code.
- Apache-2.0 (code) / CC-BY-4.0 (spec). Implement it freely; no permission or notification needed.

```
npm install golden-vector-provenance
```

```js
import { gvpHash } from 'golden-vector-provenance';

const responseHash = gvpHash({
  endpoint:    '/v1/self-employment-tax',
  inputs:      { netProfit: 80000, filingStatus: 'single' },
  result:      { selfEmploymentTax: 11303.64 },
  method:      'Schedule SE: net earnings = profit x 0.9235; SS 12.4% to wage base; Medicare 2.9%',
  dataVintage: '2026.0',
});
// -> "sha256:7236fd58598c29a6d8ebf7721a83201c363f5d88755b3c39242b3a4355982352"
// attach this to your response. That's L1. (The full self-employment-tax
// conformance vector in vectors/expected.json hashes differently — it carries
// more input/result fields; the hash is a fixed point over exactly what you pass.)
```

That is the whole of L1. If you already emit a signed receipt (x402, ACTA, or your own), adding
`responseHash` to it upgrades "you paid for this URL" into "and here is proof of what came back."

## What GVP proves — and what it doesn't

| Claim | GVP | How |
|---|---|---|
| The answer can be independently recomputed from the stated inputs and method | **Yes** | L1 fixed point + free re-derivation |
| The answer has not been altered since issuance | **Yes** | any change alters the hash |
| A specific issuer produced this record at a stated time | Optional | L2 Ed25519 attestation |
| That identity is bound to an on-chain handle | Optional | L3 anchor (e.g. ERC-8004) |
| **The answer is *correct*** | **No** | a signature proves a server ran, not that it was right — an LLM can sign a confident hallucination. GVP makes the answer *re-derivable* so a consumer can decide for themselves |

This distinction is the point of the standard, and it is deliberate. GVP is **not** a fact-checker,
an oracle, an endorsement, or a certification.

## Conformance levels
- **L1 — Reproducible:** the response carries the canonical hash and a free re-derivation path.
- **L2 — Signed:** L1 + an Ed25519 issuer attestation with a key-id (old keys stay verifiable).
- **L3 — Anchored:** L2 + an on-chain identity binding (e.g. ERC-8004).

**L1 is the layer that matters.** L2 and L3 are conveniences that other standards already provide;
if you have a signed-receipt mechanism, keep it and just carry the L1 hash inside it.

## Where this sits next to other standards

GVP is designed to be **carried by** existing receipt formats, not to compete with them. The agent
ecosystem has largely converged on Ed25519 + RFC 8785 JCS for signed receipts — which is exactly why
GVP uses the same primitives, and why its hash drops into any of them.

| Standard | Binds | Binds the response body? |
|---|---|---|
| x402 Signed Offers & Receipts | `resourceUrl`, `payer`, `network`, `issuedAt`, `txHash` | No |
| IETF `draft-farley-acta-signed-receipts` | decision-maker, tool, policy result, timestamp | No |
| Microsoft agent-governance-toolkit receipts | policy hashes, pre/post-execution signatures | No — attests policy/execution, not answer re-derivation |
| **GVP L1** | `endpoint`, `inputs`, `result`, `method`, `dataVintage` | **Yes**, + free re-derivation |

## Canonicalization

Canonical JSON in GVP **is RFC 8785 (JCS)**. GVP defines no bespoke serialization; RFC 8785 governs.
Use any verified implementation — `canonicalize` (npm), `erdtman/java-json-canonicalization`, or the
`cyberphone/json-canonicalization` ports (Go, .NET/C#, Python 3), all listed in RFC 8785 Appendix G;
`json-canon` is a further Go implementation.

GVP adds exactly three restrictions on top: non-finite numbers (NaN, ±Infinity) are rejected, object
keys must be unique, and nesting depth should be bounded (the references reject depth > 100).

See [`spec/gvp-0.2.md`](spec/gvp-0.2.md) §2.2 for the normative text, an informative restatement, and
the evidence below.

## Interop is proven, not asserted

Two implementations only interoperate if they (a) serialize **byte-for-byte identically** before
hashing and (b) produce mutually-verifiable signatures. Number formatting and non-ASCII escaping are
where naive JSON serializers diverge (JS integer `1500` vs Python float `1500.0`; `ensure_ascii`
escaping non-ASCII). This repo proves all of it empirically before relying on the prose:

```bash
npm install
npm test                                       # L1 hashes + L2 signatures + the JCS gate

node tools/check-js.mjs                        # JS: reproduce L1 hashes + verify L2 signatures
node tools/check-jcs.mjs                       # JS canonicalization vs an INDEPENDENT RFC 8785 impl
py -3 ref/py/gvp.py vectors/expected.json      # Python: reproduce every hash byte-for-byte
uv run --with cryptography ref/py/attest.py    # Python: verify JS's signatures AND reproduce them
                                               # byte-identically (Ed25519 is deterministic)
node tools/gen-vectors.mjs                     # regenerate L1 vectors from vectors/canonicalization.json
```

`gen-vectors.mjs` can also cross-check the reference against a second implementation you point it at
via `GVP_CALC_CORE=/path/to/impl.mjs` (must export `canonicalJson(value)`); unset, it just regenerates
the vectors and runs from a clean clone with no external paths.

**Status (verified 2026-08-20):**

- **L1 + L2 conformance:** 8 vectors — integral floats, negatives, non-ASCII UTF-8, control-char
  escaping, nested arrays/objects, empty containers, and the ECMAScript number edge cases (`0.00001`,
  `1e15`, `1e16`, `1e21`, `5e-324`) — pass in **both** references at L1 and L2 with **0 failures**.
- **JCS equivalence gated:** `tools/check-jcs.mjs` reports **0 divergences across 39 comparisons**
  against `canonicalize` v2.1.0 (an independent implementation listed in RFC 8785 Appendix G) — the
  39 = 8 L1 canonicalizations + 8 L1 hash re-derivations + 8 L2 attestation payloads + 15 adversarial
  probes covering key ordering (ASCII, mixed case, non-ASCII keys, shared prefixes), number edges,
  `-0`, safe-integer bounds, raw UTF-8, emoji/surrogate pairs, control characters, unescaped solidus,
  empty containers and nested arrays. The JS↔Python byte agreement carries the result to Python.
- Both references implement the full ECMAScript `Number`→`String` algorithm, so they agree on any
  finite double, not just typical values.
- The JS reference's canonical bytes match those of the deployed service at
  [x402toll.com](https://x402toll.com) (verified by the maintainer against that codebase; see the
  `GVP_CALC_CORE` cross-check above), so hashes issued by that service re-derive under this reference.

## The test key is a test key

`vectors/attestation-key.json` contains a **fixed throwaway private key**, published deliberately so
anyone can reproduce the L2 attestation vectors byte-for-byte. It is not, and has never been, a
production signing key — verified: it derives public key `MCowBQYDK2VwAyEA/UETLdE5...`, which differs
from the live issuer key published at `x402toll.com/.well-known/receipt-pubkey.json`.

## Layout
```
spec/gvp-0.2.md               the normative specification (RFC 2119 MUST/SHOULD/MAY)
schema/receipt.schema.json    JSON Schema (draft 2020-12) for a Verification Receipt
schema/revocation-list.schema.json  JSON Schema for the signed, append-only revocation list
index.mjs                     package entry point (re-exports L1 + L2)
ref/js/gvp.mjs                JS reference: canonicalize() + gvpHash()  (L1)
ref/js/attest.mjs             JS reference: Ed25519 attest()/verifyAttest()  (L2)
ref/py/gvp.py                 Python reference: canonicalize() + gvp_hash() + a vectors runner (L1)
ref/py/attest.py              Python reference: Ed25519 attest/verify + cross-lang proof (L2)
vectors/                      conformance vectors + generated expected.json / attestation.json
tools/check-js.mjs            JS conformance check (L1 + L2)
tools/check-jcs.mjs           RFC 8785 equivalence gate (vs an independent implementation)
tools/gen-vectors.mjs         generate L1 hashes (optional GVP_CALC_CORE cross-check vs a 2nd impl)
tools/gen-attestation.mjs     generate L2 attestation vectors with the fixed test key
LICENSE                       Apache-2.0 (code) / CC-BY-4.0 (spec) — full texts included
```

## Status and governance

GVP v0.2 is a **draft, authored and maintained by its original implementer.** It is not ratified by
any standards body, and at the time of writing it has **no external adopters.**

One deployment computes GVP hashes today: the [x402toll.com](https://x402toll.com) service, by the same
author. Its canonicalization is byte-identical to this reference (verified above), so the hashes agree.
But note the two are **not yet aligned in wording**: the informal description that service serves at
`/v1/spec` predates this document — it does not name RFC 8785, uses the tier names
`GVP-Core/Verify/Receipt` rather than `L1/L2/L3`, and states a different licence. **This repository is
the formal specification and supersedes that description where they differ**; the served spec is
expected to be realigned to it. Treat this document, not the deployed `/v1/spec`, as authoritative.

It is published in the hope that the L1 idea is useful enough to be carried by standards that do have
adoption.

If you implement it, or want a field like `responseHash` in a receipt format you maintain, please open
an issue — an external implementer is the single thing this most needs.

## Implementation checklist ("a stranger can implement it from the repo alone")
- [x] Canonicalization + hash (L1), JS + Python references, byte-agreement proven.
- [x] **Canonicalization is normatively RFC 8785 (JCS)** — implementable with an off-the-shelf library.
- [x] **JCS equivalence gated** against an independent implementation (`tools/check-jcs.mjs`, 0 divergences).
- [x] Normative `spec/gvp-0.2.md` (MUST/SHOULD/MAY over canonicalization, hash, receipt, attestation, revocation, conformance).
- [x] Receipt schema `schema/receipt.schema.json`.
- [x] Revocation-list mechanism (spec §7) + `schema/revocation-list.schema.json`.
- [x] Ed25519 attestation (L2) in both references — cross-implementation verify + byte-identical signatures.
- [x] Conformance suite (L1 + L2 golden vectors) passing in both references.
- [x] Full verbatim Apache-2.0 + CC-BY-4.0 licence texts, copyright holder set.
- [x] Publishable npm package (`golden-vector-provenance`) with `npm test` green from a clean install.
- [ ] **Owner step:** push to a public repository and publish to npm.
- [ ] Revocation-list reference generator/verifier (schema + spec are done; a small signed-list signer/checker would round it out).
