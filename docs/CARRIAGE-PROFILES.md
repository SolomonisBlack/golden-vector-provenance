# Carriage profiles: where a GVP `responseHash` travels

*Normative for the carriages named here. Last verified 2026-09-15.*

The hash is defined once ([spec §2, §3](../spec/gvp-0.2.md)): `responseHash` is the SHA-256 over the
RFC 8785 canonical form of the closed fixed point `{endpoint, inputs, result, method, dataVintage}`
under rule set `GVP-FixedPoint/1`, encoded as the string `"sha256:" + 64 lowercase hex characters`
(schema: [`receipt.schema.json`](../schema/receipt.schema.json)). Its sibling `fixedPointVersion`
names the rule set ([§2.1.1](../spec/gvp-0.2.md)).

Where those two values sit in a response or a receipt is a **carriage** question. The hash bytes are
identical under every carriage below; a verifier that accepts more than one carriage recomputes the
same value. The bytes hashed never include the carriage itself.

## C1. x402 extension envelope (the middleware default)

```json
{ "extensions": { "response-provenance": {
    "responseHash": "sha256:…", "fixedPointVersion": "GVP-FixedPoint/1" } } }
```

Emitted by `golden-vector-provenance/middleware` (Express, Hono, and the framework-agnostic
`attachProvenance`). This is the carriage proposed to the x402 specification in
[x402-foundation/x402#3304](https://github.com/x402-foundation/x402/pull/3304), where the
member carriage table (result at top level, `method` and `dataVintage` restated beside the hash,
`endpoint` = request path as served, `inputs` per the normative request mapping) is normative for
x402 responses.

## C2. `provenance` block (the original issuer carriage)

```json
{ "endpoint": "/v1/paycheck", "result": { … },
  "provenance": { "method": "…", "dataVintage": "2026-07", "responseHash": "sha256:…", … } }
```

x402toll.com has emitted this carriage since before C1 existed and still does on all 59 endpoints
(the source is `calc-core/src/provenance.js`, `buildResponse`). Same fixed point, same hash. A verifier
that reads only C1 will not find the hash on a C2 response; a verifier that reads both finds the same
value. Free re-derivation for C2 responses: `POST /v1/verify-hash`. The SCVD conformance desk reads this
carriage (`provenance.responseHash`; a body without it is `applies: false`, per their 2026-09-15 review on
[x402-foundation/x402#3304](https://github.com/x402-foundation/x402/pull/3304)).

## C3. Compliance-receipt extension field (`response_provenance`)

For signed action-receipt profiles that canonicalize with RFC 8785 and admit registered extension
fields, GVP defines one extension field:

| Field | Scope | Value |
|---|---|---|
| `response_provenance` | **signed-payload** | object `{ "responseHash": "sha256:<64 hex>", "fixedPointVersion": "<rule-set id>" }` |

Vocabulary: `responseHash` MUST match `^sha256:[0-9a-f]{64}$`; `fixedPointVersion` MUST be a
registered GVP rule-set identifier, currently only `"GVP-FixedPoint/1"` ([§2.1.1](../spec/gvp-0.2.md)).
An independent verifier validates the two values syntactically without any GVP code; a verifier that
also holds the response body and the request inputs recomputes the hash per [§3](../spec/gvp-0.2.md)
and MUST treat a mismatch as a non-conformance of the receipt, not of the verifier.

The scope is signed-payload on purpose: a provenance field outside the signed bytes can be stripped
or forged without failing the signature. GVP learned this on its own L2 and moved `fixedPointVersion`
inside the Ed25519-signed payload for the same reason ([§6](../spec/gvp-0.2.md), shape
`GVP-Attestation/2`).

Relationship to a profile's own result digest (for example a digest "over the canonicalized bytes of
the downstream Action's result body"): that digest binds the **result bytes**. `responseHash` binds
the **question and the answer together** (`endpoint` and `inputs` are required members). The two
are complementary and can travel in the same receipt; neither replaces the other.

Change controller and contact for this field: the GVP repository maintainer
(`SolomonisBlack`, issues on this repository).
