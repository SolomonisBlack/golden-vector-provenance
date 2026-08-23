# Golden-Vector Provenance (GVP) — v0.2

**Status:** Draft. **Intended track:** an open, neutrally-governed provenance standard for computed
answers, submittable as a companion/extension to x402. **License:** this document CC-BY-4.0; reference
code Apache-2.0.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in
RFC 2119 / RFC 8174.

## 1. Abstract & trust model

GVP makes a computed answer **independently reproducible**: the answer travels with a canonical
SHA-256 **fixed point** over exactly what determines it — `{endpoint, inputs, result, method,
dataVintage}` — so a consumer recomputes the answer and checks the hash rather than trusting the
issuer. This is **recompute-trust**, and it is PRIMARY. An optional Ed25519 issuer attestation (§6)
and an optional on-chain identity anchor (§4, L3) add *who issued the record and when* — they MUST NOT
be construed as evidence that the answer is **correct**; correctness is established only by
reproduction (§2–§3).

## 2. The fixed point and canonicalization (normative)

### 2.1 The fixed point
The hashed object, called the **fixed point**, is exactly:

```
{ "endpoint": <string>, "inputs": <JSON>, "result": <JSON>, "method": <string>, "dataVintage": <string> }
```

No other member participates in the hash. In particular a timestamp MUST NOT be included in the fixed
point (timestamps belong in the attestation, §6). `dataVintage` is the **only** permitted axis of
variation: the same fixed point MUST always produce the same hash, forever, modulo a declared
`dataVintage`.

**All five members are REQUIRED and the set is closed.** An implementation MUST NOT emit a
`responseHash` over a subset (e.g. omitting `inputs`) or a superset of these members. Two consequences
are deliberate:

- **The fixed point is fixed, not self-declared.** Where an emitted artifact lists which fields were
  hashed (e.g. the `fixedPoint` array in the x402 `response-provenance` extension), that list is the
  spec constant `["endpoint","inputs","result","method","dataVintage"]`, never a description supplied by
  the issuer. On a bare response with no signed receipt, a self-declared list would be unbound: an issuer
  could drop `inputs` from both the hash and the list and the artifact would remain internally
  consistent. Pinning the member set closes that — a verifier always recomputes over the five spec
  members, so any omission changes the hash and is detected.
- **The hash binds the question, not only the answer.** Because `endpoint` and `inputs` are required,
  `responseHash` attests "this `result` answered *this request*", not merely "this `result` is
  unaltered". An artifact that bound only the answer would let an issuer re-attach a valid hash to a
  different request.

A verifier MUST reject an artifact whose fixed point is missing any member or carries an extra one, and
MUST recompute the hash over exactly these five members rather than over whatever an issuer declares.

### 2.2 Canonical JSON (byte-level; this is the interop boundary)
Two implementations interoperate only if they produce **identical bytes** before hashing.

> **Canonical JSON in GVP is [RFC 8785, the JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785).**
> An implementation MUST serialize the fixed point exactly as RFC 8785 specifies. RFC 8785 is
> normative here; where anything in this document appears to disagree with it, **RFC 8785 governs.**

This is deliberate and it is the whole of the implementation burden: GVP defines **no bespoke
serialization**. A conforming implementation SHOULD simply call an existing JCS library rather than
write canonicalization code. Verified implementations are listed in RFC 8785 Appendix G, and include
`canonicalize` (npm, JavaScript), `erdtman/java-json-canonicalization` (Java), and the
`cyberphone/json-canonicalization` ports (Go, .NET/C#, Python 3); `json-canon` is a further Go
implementation. Reusing one of these is the recommended path to conformance.

**GVP adds exactly three constraints on top of JCS**, all of them restrictions rather than changes to
the byte format:

1. **Non-finite numbers** (NaN, ±Infinity) MUST be rejected. They are not valid JSON and MUST NOT
   appear in a fixed point. (RFC 8785 likewise excludes them.)
2. **Object keys MUST be unique**, and SHOULD be ASCII.
3. **Nesting depth SHOULD be bounded** — the reference implementations reject depth > 100 — so a
   hostile deeply nested payload cannot cause a stack overflow. This is an implementation safety
   limit, not a change to the serialization.

#### 2.2.1 Informative restatement (non-normative)
For readers implementing from scratch, or auditing an existing serializer, JCS amounts to the
following. **This restatement is informative only**; RFC 8785 is the authority.

1. **Objects:** members are emitted with keys sorted ascending by UTF-16 code unit. Format: `{` then,
   for each key, `<canonical-string(key)>` `:` `<canonical(value)>` joined by `,`, then `}`. **No
   whitespace.**
2. **Arrays:** `[` then each element's canonical form joined by `,` then `]`. Order is preserved.
3. **Strings:** JSON string escaping — a `"` delimiter; escape `"` `\` and the C0 control characters
   (U+0000–U+001F) using `\"` `\\` `\b` `\f` `\n` `\r` `\t` or `\u00XX` (lowercase hex). All other
   characters, **including non-ASCII, are emitted raw as UTF-8** and MUST NOT be `\u`-escaped. (This is
   the common divergence: a serializer that escapes non-ASCII, e.g. Python's default `ensure_ascii=True`,
   is non-conformant.)
4. **Numbers:** serialized per the ECMAScript `Number`→`String` algorithm (RFC 8785 §3.2.2.3):
   shortest round-tripping decimal; integers carry **no** decimal point and no trailing zeros; no
   leading `+`; no leading zeros. A whole-valued number is serialized without a fractional part
   (`1500`, never `1500.0`). Exponential form is used exactly when the decimal exponent is `< -6` or
   `>= 21`, written `e` + sign + unpadded exponent (`1e-7`, `1e+21`). `-0` serializes as `0`. Numbers
   are IEEE-754 doubles: a JSON integer beyond ±2^53 is treated as its nearest double (identically on
   both sides).
5. **Booleans / null:** the literals `true`, `false`, `null`.

#### 2.2.2 Evidence for the JCS claim
This equivalence is **gated, not asserted**. `tools/check-jcs.mjs` diffs the GVP reference
canonicalizer against the independent `canonicalize` library (an implementation listed in RFC 8785 Appendix G)
byte-for-byte and fails the build on any divergence. As of 2026-08-20 it reports **0 divergences across
39 comparisons**: all 8 L1 conformance vectors, all 8 L2 attestation payloads, and 15 adversarial
probes covering key ordering (ASCII, mixed case, non-ASCII keys, shared prefixes), ECMAScript number
edge cases (`1e21`, `1e-7`, `5e-324`, `1e16`, `0.1+0.2`), `-0`, safe-integer bounds, raw UTF-8, emoji
and surrogate pairs, control characters, unescaped solidus, empty containers, and nested arrays.

Both reference implementations (`ref/js`, `ref/py`) implement the full ECMAScript number algorithm and
are byte-identical to each other across every vector, so the JS↔JCS result carries to Python. The JS
reference is also byte-identical to the deployed x402toll implementation, so receipts issued before
this document remain valid.

## 3. Hashing (normative)

```
responseHash = "sha256:" + lowercase_hex( SHA-256( UTF-8-bytes( canonical(fixedPoint) ) ) )
```

The `sha256:` prefix is REQUIRED. The digest is lowercase hex, 64 chars. An implementation claiming
conformance MUST reproduce every `expectedHash` in `vectors/expected.json`.

## 4. Conformance levels

| Level | Name | Requirements |
|---|---|---|
| **L1** | Reproducible | The answer carries `responseHash` (§3) **and** a free, unauthenticated way to re-derive it (a golden-vector endpoint returning the canonical `inputs → result → hash`, or the fixed point itself). Anyone can recompute and compare. |
| **L2** | Signed | L1 **plus** an Ed25519 issuer attestation (§6) with a resolvable key-id; the issuer publishes the verifying public key. |
| **L3** | Anchored | L2 **plus** an on-chain identity binding for the issuer (e.g. an ERC-8004 `agentId` in a named registry/chain). |

A receipt (§5) declares its level implicitly by which members are present. L1 is the floor; a consumer
MUST be able to verify an L1 receipt with no secrets, no accounts, and no network access to the issuer
(only to the public re-derivation path, which itself is optional if the fixed point is included).

## 5. The Verification Receipt

A **receipt** is a portable record wrapping a fixed point plus its recompute-trust primitives and
(optionally) an attestation and anchor. Its normative JSON Schema is `schema/receipt.schema.json`
(draft 2020-12). A conformant receipt MUST validate against that schema and MUST satisfy:

- `responseHash` MUST equal the §3 hash of `{endpoint, canonicalInputs, result, method, dataVintage}`.
- `trustModel` MUST be `"recompute-trust"`.
- `howToVerify` MUST describe, in order, how to (a) recompute the fixed point, (b) re-derive for free,
  (c) tamper-check a stored copy, and (d) resolve issuer identity.
- If `signature` is present it MUST verify under §6; a present-but-invalid signature makes the receipt
  non-conformant (a consumer MUST reject it).

## 6. Ed25519 attestation (L2)

The issuer signs the **attestation payload**, which is the canonical JSON (§2.2) of:

```
{ "responseHash": <string>, "endpoint": <string>, "dataVintage": <string>,
  "issuer": <string>, "agentId": <string|null>, "issuedAt": <RFC3339 string> }
```

- Algorithm: **Ed25519** (RFC 8032), over the UTF-8 bytes of that canonical string. Because Ed25519 is
  deterministic, independent conformant signers produce identical signature bytes for the same key and
  payload.
- The `signature` object carries `alg: "Ed25519"`, the `publicKey` (base64 SPKI DER), the base64
  `signature`, and the `signed` recipe string. It MAY carry a `keyId`.
- **Key rotation & key-ids:** an issuer MAY rotate signing keys. Every attestation MUST be verifiable
  for the life of the receipt: the issuer MUST keep all historical public keys resolvable (by key-id),
  so a receipt signed by a rotated-out key still verifies. A verifier proving *issuer identity* (not
  just integrity) MUST compare the embedded `publicKey` against the issuer's published key for that
  key-id; a match under the receipt's own embedded key proves integrity only.

## 7. Revocation (errata path)

Reproducibility means a wrong answer, once issued, stays reproducibly wrong — so GVP needs an errata
channel. An issuer that discovers a defect (bad datum, formula error) affecting already-issued receipts
MUST publish a **revocation list**: a signed, append-only document naming the revoked `responseHash`
values. Schema: `schema/revocation-list.schema.json`.

```
{ "revocationListVersion": "GVP-Revocation/0.2",
  "issuer": <string>,
  "updatedAt": <RFC3339 string>,
  "revoked": [ { "responseHash": <string>, "reason": <string>, "revokedAt": <RFC3339>,
                 "supersededBy": <string|null> } ],
  "signature": { "alg": "Ed25519", "publicKey": <b64>, "signature": <b64> } }
```

- The list is signed over the canonical JSON (§2.2) of the document with the `signature` member
  removed, using the §6 scheme.
- It is **append-only**: a `responseHash` once listed MUST remain listed (monotonic); consumers MAY
  cache it and MUST treat a hash's disappearance as tampering.
- A conformant verifier SHOULD check a receipt's `responseHash` against the issuer's current revocation
  list and surface a revoked answer as **revoked**, citing `supersededBy` when present.

## 8. Conformance test suite

`vectors/canonicalization.json` holds the input fixed points; `vectors/expected.json` holds the
canonical-hash fixtures. An implementation is **L1-conformant** iff it reproduces every `expectedHash`.
L2 conformance additionally requires reproducing the attestation vectors in `vectors/attestation.json`
(sign-and-verify round trips and a cross-implementation verify). The suite MUST pass in at least two
independent implementations; the repo ships JS (`ref/js`) and Python (`ref/py`) references that do.

## 9. Security considerations

- Recompute-trust is the security boundary; a signature attests issuance, never correctness (§1).
- The fixed point excludes timestamps precisely so it stays reproducible; attestation carries time.
- Reject non-finite numbers and over-deep nesting (§2) to keep hashing total and DoS-resistant.
- A signature over the issuer's *own embedded* key proves integrity, not identity — identity requires
  the issuer's independently-published key (§6).
- Revocation is the only sanctioned way to walk back an issued answer; keep it signed and append-only
  (§7) so it cannot itself be used to silently rewrite history.
