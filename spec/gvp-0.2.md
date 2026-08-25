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

### 2.1.1 The fixed-point rule set is versioned by name, beside the hash
The five-member definition above is a **named, frozen rule set**: **`GVP-FixedPoint/1`**. Because the
fixed point is a constant rather than an issuer-declared list, a future change to the member set would
otherwise be *silent*: a verifier built for one rule set and an issuer using another would compute
different hashes over the same logical response, indistinguishable from a forged or corrupted hash. To
make such skew visible and nameable rather than silent:

- Any artifact that carries a `responseHash` MUST also carry the identifier of the rule set that defined
  its fixed point, as a sibling field **`fixedPointVersion`** — e.g. in the x402 `response-provenance`
  extension block. For this document's rule set the value is the string `"GVP-FixedPoint/1"`.
  **Backward-compatibility carve-out for the Verification Receipt (§5):** receipts issued before this
  section existed carry no `fixedPointVersion`; the receipt schema therefore keeps it OPTIONAL so those
  receipts remain valid. A verifier MUST treat a receipt with no `fixedPointVersion` as
  `"GVP-FixedPoint/1"` (the only rule set that has ever existed). New receipts SHOULD carry it.
- The identifier lives **beside** the hash, never inside the hashed L1 fixed point. Placing it inside
  would change every existing hash and break the §2.1 guarantee that the same fixed point always
  produces the same hash.
- **Where it is bound.** At L1 (a bare response, no signature) `fixedPointVersion` is an unauthenticated
  string: it CAN be stripped or forged, because nothing signs a bare L1 response. This document does
  NOT claim otherwise. It becomes **tamper-evident at L2**: under signed-payload shape
  `GVP-Attestation/2` (§6) the identifier is a member of the **Ed25519-signed attestation payload**, so
  stripping or forging it fails the signature. L1 therefore proves *re-derivability*; L2 proves
  re-derivability **and** binds the rule-set claim. An issuer that needs the claim bound MUST emit L2.
- A verifier MUST read `fixedPointVersion` before recomputing. An unknown or unsupported identifier MUST
  be reported as **"unsupported fixed-point rule set"**, never as a hash mismatch or forgery. At L2 the
  verifier MUST take the identifier from the *signed payload*, never from an unsigned sibling field.
- **`GVP-FixedPoint/1` is frozen.** It will never gain or lose a member. A need for a different member
  set MUST be published as a new identifier (`GVP-FixedPoint/2`, …) with its own conformance vectors; it
  MUST NOT be introduced by editing this definition.

This also resolves the document-vs-package versioning ambiguity: an attestation is produced under a
named rule set (`GVP-FixedPoint/1`) and a named receipt format (`GVP-Receipt/0.2`, §5), not under "the
spec at some package version"; those names are stable across document revisions.

### 2.1.2 Closure: the result MUST be a function of the fixed point (normative)

The rule above says the same fixed point always produces the same hash. That is a statement about
*hashing*. This section states the matching requirement about *issuing*, because without it a failed
re-derivation is unfalsifiable.

**An issuer MUST NOT emit a `responseHash` for a response whose `result` depends on any input not
present in the fixed point.** If reproducing `result` requires a clock, a live feed, a random draw,
mutable server state, or any value the verifier cannot see in `{endpoint, inputs, method, dataVintage}`,
that endpoint is **out of scope for GVP** and MUST NOT claim conformance at any level.

The hidden-input case is why this must be normative rather than advisory. Consider a re-derivation that
fails. Before this section existed, two explanations competed:

1. the artifact was altered, or
2. the result legitimately moved, because it depended on something outside the fixed point.

While (2) is permitted, no failed re-derivation can be acted on at all, and `responseHash` degrades from
evidence into a claim about the issuer's good intentions — the issuer answers "the data moved" and the
verifier has no reply.

**What this section does, stated precisely.** A normative MUST NOT does not make (2) impossible; it
makes (2) a violation. So a failed re-derivation now means:

1. the artifact was altered, **or**
2. the issuer emitted a `responseHash` it was not permitted to emit.

**Both are defects, and a verifier does not need to decide which one it is** for the finding to stand.
That is the property that matters, and it is stronger than attribution: deciding between (1) and (2)
would require seeing the issuer's internals, which a third-party verifier by definition cannot do.
Requiring attribution would make the check unissuable by exactly the parties it exists to serve. "The
data moved" is no longer a defence, because an issuer for whom the data can move was never permitted to
emit the hash — the answer stops being an excuse and becomes an admission of (2).

A finding SHOULD therefore be stated as the disjunction rather than picking a side: *this hash does not
re-derive from the declared fixed point; the artifact was altered or it was issued in violation of
§2.1.2.* Naming one branch that the verifier cannot actually distinguish would overclaim.

**There is a third branch, and it is not the issuer's.** A re-derivation can also fail because:

3. the *verifier's* canonicalization is wrong.

JCS is precisely the surface where that happens quietly — number formatting, non-ASCII escaping, key
ordering across surrogate pairs. A verifier whose canonicalizer is a hair off produces failed
re-derivations against perfectly clean artifacts, and from the outside those findings are
indistinguishable from (1) and (2). In that state the verifier is the defect, publishing accusations
against issuers who did nothing wrong.

(3) is deliberately **not** a third clause in the finding. A finding that hedged "…or our own arithmetic
may be broken" would be unusable. It is instead excluded *before* a finding may be stated — see
**§8.1**, which makes verifier conformance a precondition rather than an assumption. That is the same
move as §2.1.2 itself: the earlier draft of this section reasoned in a world where issuers obey the
rule; naming (3) without §8.1 would reason in a world where the verifier's arithmetic is correct.
Neither is the world a conformance desk operates in.

Time-varying data is not excluded from GVP; **hidden** time-varying data is. A live rate becomes
conformant the moment it is lifted into the fixed point — as an explicit member of `inputs` (the quoted
rate the caller supplied or the issuer echoes back), or as the `dataVintage` axis (§2.1.3). The
discipline is that everything the answer depends on is visible to the party checking it.

*Rationale: raised by @seancrecord (scvd.store conformance desk, 2026-08-24), who observed that a defect
class is only usable if it carries what would falsify it. GVP had no such sentence; this is it. The
falsifiable-but-not-attributable distinction, and the requirement to state the finding as a disjunction,
are theirs too (2026-08-25) — the first draft of this section claimed forbidding (2) left (1) as "the
only remaining explanation", which is false: a rule does not prevent its own violation.*

### 2.1.3 `dataVintage` MUST be machine-comparable (rule-set change — see §2.1.1)

`dataVintage` was previously typed only as `<string>`, with no constraint on its representation. That is
not sufficient for interop, and the failure mode is specific: **JCS canonicalizes the JSON, not the
semantics of a value.** Two honest implementations describing the same data year as `"July 2026"`,
`"2026-07"`, `"2026.0"` and `1783987200` all produce well-formed, spec-conformant, *mutually
irreproducible* hashes over otherwise identical data.

This is not hypothetical. At the time of writing this repository's own conformance vectors used
`"2026.0"` while its reference service published `"July 2026"` — one project, two representations of the
same data year, neither wrong under the old text.

Under **`GVP-FixedPoint/2`**, `dataVintage` MUST be an **ISO 8601 calendar date at reduced precision**,
one of exactly three forms, and nothing else:

```
YYYY          e.g. "2026"        the data is current as of that year
YYYY-MM       e.g. "2026-07"     … that month
YYYY-MM-DD    e.g. "2026-07-01"  … that day
```

Normative rules for `GVP-FixedPoint/2`:

- The value MUST match `^[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?$` and MUST be a real calendar date at the
  precision given. A verifier MUST reject a fixed point whose `dataVintage` does not match.
- Precision is **significant**, not decorative: `"2026"`, `"2026-07"` and `"2026-07-01"` are three
  different vintages and hash differently. Declare the precision you actually have; padding a year out
  to a day asserts a currency you cannot support.
- No time component, no timezone, no offset. `dataVintage` denotes the currency of the underlying
  reference data, not an instant. A timestamp still MUST NOT enter the fixed point (§2.1).
- Ordering falls out for free: under this grammar lexical comparison equals chronological comparison, so
  a verifier can decide which of two vintages is newer without parsing.

`GVP-FixedPoint/1` is unchanged and remains valid: it is frozen, and receipts declaring it MUST still be
verified under its rules (§2.1.1). Its `dataVintage` stays an unconstrained `<string>`. An implementation
moving to `/2` re-hashes its artifacts under the new rule set and declares
`fixedPointVersion: "GVP-FixedPoint/2"`; because that identifier is inside the signed payload at L2
(§6), the migration is detectable rather than silent — which is the entire reason the identifier exists.

*Rationale: raised by @seancrecord (scvd.store conformance desk, 2026-08-24).*

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

The issuer signs the **attestation payload**, the canonical JSON (§2.2) of a **named payload shape**.
Two shapes are defined; the shape identifier is itself a member of the signed object, so a verifier
learns which shape to reconstruct *from the receipt* and an attacker cannot strip or forge it without
failing the signature:

```
GVP-Attestation/1  (legacy — receipts issued before fixedPointVersion existed; no payloadVersion member)
{ "responseHash": <string>, "endpoint": <string>, "dataVintage": <string>,
  "issuer": <string>, "agentId": <string|null>, "issuedAt": <RFC3339 string> }

GVP-Attestation/2  (current)
{ "responseHash": <string>, "endpoint": <string>, "dataVintage": <string>,
  "issuer": <string>, "agentId": <string|null>, "issuedAt": <RFC3339 string>,
  "payloadVersion": "GVP-Attestation/2", "fixedPointVersion": "GVP-FixedPoint/1" }
```

- **Shape selection is explicit, never guessed.** A payload with no `payloadVersion` member is shape
  `/1`. A verifier MUST reconstruct the shape the receipt declares and MUST NOT try alternatives on
  failure (trying shapes until one verifies would let an attacker downgrade a `/2` receipt to `/1`).
  New receipts SHOULD be `/2`; `/1` remains valid for receipts already issued.
- **`fixedPointVersion` is bound here, at L2** — inside the signed payload — and nowhere else. It is
  deliberately NOT inside the hashed L1 fixed point (that would move every existing `responseHash`) and
  its unsigned L1 sibling (§2.1.1) is informational only.
- `/1` and `/2` sign different byte strings for the same logical receipt; that is intended and the
  conformance vectors cover both (`vectors/attestation.json`, `vectors/attestation-v2.json`).
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

### 8.1 Verifier conformance is a precondition for stating a finding (normative)

Sections 2.1.2 and 3 constrain **issuers**. This section constrains **verifiers**, because a verifier
that publishes findings is making accusations, and an accusation produced by a broken canonicalizer is
a defect in the verifier rather than in the artifact.

**A party MUST NOT state a finding that a `responseHash` fails to re-derive unless its own
canonicalizer, at the time of the finding, passes all of:**

1. **the L1 vectors** — reproduces every `expectedHash` in `vectors/expected.json` byte-for-byte;
2. **the JCS equivalence gate** — its canonical output is byte-identical to an *independent* RFC 8785
   implementation across the published probe set (this repo: `tools/check-jcs.mjs`, which covers key
   ordering including non-ASCII and shared-prefix keys, the ECMAScript number edge cases, `-0`,
   safe-integer bounds, raw UTF-8, emoji and surrogate pairs, control characters, unescaped solidus,
   and empty containers);
3. **the vectors of the rule set it is checking** — for `GVP-FixedPoint/2`, additionally
   `vectors/expected-v2.json`, including the `dataVintage` rejection cases (§2.1.3).

In this repository the three together are one command:

```bash
npm run verifier-precondition     # check-js (L1 vectors) + check-jcs (independent RFC 8785) + check-fixedpoint-2 (/2 + rejects)
```

A verifier that cannot demonstrate this MUST NOT publish the finding. It MAY report that it was unable
to verify, which is a statement about itself and not about the issuer — and those are different claims
that MUST NOT be conflated.

This excludes branch (3) of §2.1.2 **by construction rather than by assumption**. It is deliberately
cheap to satisfy: the vectors and both gates are published in this repository and run offline with no
network and no issuer cooperation, so the precondition costs a verifier one test run, not a
relationship with the party it is auditing.

*Rationale: raised by @seancrecord (scvd.store conformance desk, 2026-08-25), who observed that the
corrected §2.1.2 still reasoned in a world where the verifier's own arithmetic is correct, and that the
remedy is a precondition on issuing a finding rather than another branch inside one.*

## 9. Security considerations

- Recompute-trust is the security boundary; a signature attests issuance, never correctness (§1).
- The fixed point excludes timestamps precisely so it stays reproducible; attestation carries time.
- Reject non-finite numbers and over-deep nesting (§2) to keep hashing total and DoS-resistant.
- A signature over the issuer's *own embedded* key proves integrity, not identity — identity requires
  the issuer's independently-published key (§6).
- Revocation is the only sanctioned way to walk back an issued answer; keep it signed and append-only
  (§7) so it cannot itself be used to silently rewrite history.
