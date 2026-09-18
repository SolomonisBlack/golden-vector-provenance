# gvp-audit: the closure audit for x402 sellers

*Does a served response body have hidden inputs? Which carriage fits it? Is it ready to emit
`response-provenance`? Free, offline, zero dependencies beyond this package. Apache-2.0.*

The response-provenance extension ([x402-foundation/x402#3304](https://github.com/x402-foundation/x402/pull/3304))
binds a hash to `{endpoint, inputs, result, method, dataVintage}`, and its closure rule says an issuer MUST NOT
emit that hash when `result` depends on anything outside those five members. The first seller to run a real
catalogue against the text found the cost was not the hash: it was enumerating sources per route and
discovering three routes that carried request-time-clock values at the root. This tool finds that class of
problem before a buyer does.

**What it can and cannot say.** It finds closure *violations* and readiness *gaps*. It cannot prove a route
closed: the closure rule is an issuer-side contract about how `result` was computed, and no body can show
that. The verdict vocabulary is chosen to keep that honest:

| Verdict | Meaning |
|---|---|
| `no-closure-violation-found` | nothing in the body looks like a hidden input (a finding of absence, not a proof) |
| `review-needed` | medium signals to explain or remove (an `age` in months, a `uuid`, a datetime with no telling key) |
| `hidden-inputs-found` | at least one high signal (clock key with a datetime value, a member that drifted between two samples on identical inputs) or a `responseHash` that does not re-derive |
| `format-violation` | the body cannot enter a fixed point as served: an integer beyond 2^53-1 as a JSON number (I-JSON), duplicate member names, nesting over 100 |
| `out-of-scope` | not a JSON object |

## Install and run

```
npm i -g golden-vector-provenance      # gives you `gvp-audit`
gvp-audit bodies ./served --json report.json --md report.md
gvp-audit fetch https://your.api/free-route https://your.api/other --times 2 --md report.md
gvp-audit bodies ./served --strict     # exit 1 on hidden-inputs-found / format-violation / out-of-scope (CI)
```

`bodies` is fully offline. `fetch` only GETs free surfaces; it never signs, never pays, sends no cookies or
credentials, and records a 402 as "paid route: supply served bodies". The audit is over what the buyer
actually received, and only you have that. `fetch` follows redirects and caps each body at 16 MiB and
`--times` at 10; point it only at hosts you trust to redirect, and keep API keys out of the URL (the route
id in the report is origin + path, but the request itself is whatever you typed).

## The bodies directory

```
served/
  sanctions-screening.1.json     # a paid response you served (sweep 1)
  sanctions-screening.2.json     # the same route, same inputs, a later sweep
  sanctions-screening.meta.json  # optional: {"endpoint":"/v1/sanctions","inputs":{...}} enables re-derivation
  sector-benchmark.json          # a single sample is fine; two samples enable drift detection
```

Two samples of a closed route on identical inputs are byte-identical after RFC 8785. Anything that differs is
either a hidden input (clock, nonce, runtime) or a data or vintage change you must be able to name.

## What it checks

- **Hidden-input signals** on every primitive member: key patterns (`consultedAt`, `generated_at`,
  `monthsSince…`, `request_id`, `latency_ms`, `freshness`), value patterns (ISO datetimes, UUIDs, epoch values
  near now, short relative phrases like "next 12 months"). Severity: high when key and value agree, medium on
  one of them. Each finding says where it sits: inside `result` (a hidden input under either carriage), at the
  root (a hidden input under `"body"`), or in a provenance block.
- **Carriage**: a top-level `result` member means `"member"` works unchanged; answer fields at the root mean
  declare `resultCarriage: "body"`, and the report reminds you that under `"body"` the closure rule reaches
  every top-level member, seller metadata included.
- **Format**: integers beyond 2^53-1 written as numbers (JSON.parse already rounded them), duplicate member
  names (a scanner over the raw text, since parsers hide them), depth over 100.
- **Vintage**: members that look like a data vintage (`asOf`, `dataVintage`, `taxYear`, `updated`, …) and
  whether each matches the `GVP-FixedPoint/2` grammar (`YYYY`, `YYYY-MM`, `YYYY-MM-DD`). No candidate at all
  is a medium finding: `dataVintage` completeness is the work.
- **Provenance already present**: `extensions["response-provenance"]` (C1, `member` or `body` carriage) or a
  `provenance.responseHash` block (C2). With `endpoint` and `inputs` known, the hash is re-derived with the
  reference implementation and reported as `verified`, `contradicted`, `unverifiable`, or `no_claim`.
- **Drift** between samples, classified: clock, nonce, runtime, vintage, data.

## Honest limits

Heuristics have false negatives (a clock value under an innocent key and a plain number will pass) and false
positives (an echoed input named `age` is flagged medium). Two samples catch more than one. The tool never
sends a payment, never runs a route's code, and never claims a route is closed.

Run `node audit/test.mjs` for the suite (unit + CLI end-to-end on generated fixtures, no network).
