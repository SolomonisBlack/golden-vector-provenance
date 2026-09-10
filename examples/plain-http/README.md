# GVP over plain HTTP — no payment rail

The smallest honest issuer and verifier. Node's built-in `http`, one JSON route, and the package's
`attachProvenance`. Nothing in this directory imports or mentions a payment protocol.

```
node examples/plain-http/server.mjs          # issuer on :8402
node examples/plain-http/verify.mjs          # requester: call, recompute, print the verdict
node examples/plain-http/test.mjs            # the gate: ephemeral port, all four outcomes, exit code
```

What it demonstrates:

- **The provenance member is rail-independent.** The `extensions["response-provenance"]` block this
  server emits is byte-identical to what the same route would carry inside an x402-paid response, an
  AP2 mandate, or a card-network token receipt. Payment is not a member of the fixed point.
- **The verifier recomputes from its own question.** `verify.mjs` uses the `endpoint` and `inputs` it
  sent, never the server's restatement, and returns one of the spec's four outcomes (`verified`,
  `no_claim`, `unverifiable`, `contradicted`). It is never collapsed to a boolean.
- **The route reproduces a published vector.** `POST {netProfit: 80000, filingStatus: "single"}` yields
  `sha256:7236fd58…`, the same hash `middleware/test.mjs` pins, so a third party can check this example
  against the repository's own vectors without trusting either side.

Carriage note: this example follows the envelope the published npm package (0.7.0) emits, with `method`
and `dataVintage` as top-level body members. The extension text under review at
[x402-foundation/x402#3304](https://github.com/x402-foundation/x402/pull/3304) restates those two
members inside the extension object; the example will move when that text settles, and the hash does not
change either way.
