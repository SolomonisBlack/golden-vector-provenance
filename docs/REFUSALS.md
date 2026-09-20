# Refusals: every input the reference implementation refuses before the digest

*Normative for this repository's reference code. Machine-checked by `tools/check-refusal-drift.mjs`
(in `npm test`): the list below and the `throw` sites in `ref/js/gvp.mjs` and `middleware/index.mjs`
must be exact reflections of each other in both directions, and every entry's probe must reach the
digest 0 times. Property filed by goun7 as [issue #2](https://github.com/SolomonisBlack/golden-vector-provenance/issues/2)
(2026-09-18): a list that is prose drifts the moment code changes; a list that is verified as a set
with the code is load-bearing.*

Two directions, both required:

- **List ⇒ code.** Every entry names a `message` that is the literal prefix of a reachable `throw`, and
  a probe input that triggers it with zero digest invocations (the `hooks.beforeDigest` counter).
- **Code ⇒ list.** Every `throw` in the two modules matches exactly one entry. A refusal added in code
  without an entry here fails the check; an entry here without a throw in code fails the check.

The check is negative-self-tested: a fabricated seventh throw with no entry, and an entry with its throw
removed, both make it fail.

```json
[
  { "id": "nesting-too-deep",           "module": "ref/js/gvp.mjs",       "layer": "canonicalizer", "message": "input nesting too deep",                                        "probe": "a fixed point whose result nests 105 levels" },
  { "id": "non-finite-number",          "module": "ref/js/gvp.mjs",       "layer": "canonicalizer", "message": "non-finite number not allowed in GVP JSON",                     "probe": "Infinity or NaN anywhere in the fixed point" },
  { "id": "fp-not-object",              "module": "middleware/index.mjs", "layer": "fixed-point",   "message": "fixed point must be a JSON object",                             "probe": "an array or null as the fixed point" },
  { "id": "fp-missing-member",          "module": "middleware/index.mjs", "layer": "fixed-point",   "message": "fixed point missing required member(s): ",                      "probe": "a fixed point without dataVintage" },
  { "id": "fp-extra-member",            "module": "middleware/index.mjs", "layer": "fixed-point",   "message": "fixed point has non-spec member(s): ",                          "probe": "the five members plus one more" },
  { "id": "fp-endpoint-not-string",     "module": "middleware/index.mjs", "layer": "fixed-point",   "message": "fixed point: endpoint must be a string",                        "probe": "endpoint given as a number" },
  { "id": "fp-method-not-string",       "module": "middleware/index.mjs", "layer": "fixed-point",   "message": "fixed point: method must be a string",                          "probe": "method given as an object" },
  { "id": "fp-datavintage-not-string",  "module": "middleware/index.mjs", "layer": "fixed-point",   "message": "fixed point: dataVintage must be a string",                     "probe": "dataVintage given as a number" },
  { "id": "carriage-unknown",           "module": "middleware/index.mjs", "layer": "carriage",      "message": "resultCarriage must be \"member\" or \"body\", got ",           "probe": "resultCarriage: \"weird\"" },
  { "id": "recover-body-not-object",    "module": "middleware/index.mjs", "layer": "recovery",      "message": "recoverResult: body must be a JSON object",                     "probe": "recoverResult on an array" },
  { "id": "recover-member-no-result",   "module": "middleware/index.mjs", "layer": "recovery",      "message": "recoverResult: \"member\" carriage declared but the body has no result member", "probe": "\"member\" carriage on a root-level body" },
  { "id": "attach-body-not-object",     "module": "middleware/index.mjs", "layer": "attach",        "message": "attachProvenance: response body must be a JSON object",         "probe": "attachProvenance on an array body" },
  { "id": "attach-body-carriage-mismatch","module": "middleware/index.mjs","layer": "attach",       "message": "attachProvenance: under \"body\" carriage the fixed point result must equal the body minus extensions", "probe": "\"body\" carriage where the body's answer differs from the fixed point's result" },
  { "id": "express-not-function",       "module": "middleware/index.mjs", "layer": "configuration", "message": "expressProvenance(buildFixedPoint): buildFixedPoint must be a function", "probe": "expressProvenance('nope')" },
  { "id": "hono-not-function",          "module": "middleware/index.mjs", "layer": "configuration", "message": "honoProvenance(buildFixedPoint): buildFixedPoint must be a function",    "probe": "honoProvenance(123)" }
]
```

Layers: `canonicalizer` and `fixed-point` refuse the bytes that would be hashed; `carriage`, `recovery`
and `attach` refuse a wire shape before any hash is issued or recovered; `configuration` refuses a
misuse of the API at setup. All fifteen reach the digest 0 times.
