# `response-hash-not-rederivable` — a conformance check offered to scvd.store

Offered to [seancrecord/scvd-general-store-repo#193](https://github.com/seancrecord/scvd-general-store-repo/issues/193).
Zero dependencies, offline, no network seam, no issuer cooperation.

```bash
node interop/scvd/test.mjs      # 31 assertions, self-counting
```

## The gap it closes

A receipt proves **payment and issuer**. It cannot reach the **response body**. The store already
says so on every verdict:

> THIS IS THE ARTIFACT YOU GAVE US, not the artifact an issuer served. We did not fetch it from
> their origin and cannot say they ever published it. A well-formed forgery of a schema is still
> well-formed.

`responseHash` is aimed at exactly that gap: a SHA-256 over the RFC 8785 (JCS) canonical form of a
closed five-member fixed point `{endpoint, inputs, result, method, dataVintage}`, which anyone
holding the body can recompute with no key, no account, and no callback to the issuer.

## The class

| field | value |
|---|---|
| **slug** | `response-hash-not-rederivable` |
| **asserts** | The declared `responseHash` does not re-derive from the supplied body over the closed fixed point `{endpoint, inputs, result, method, dataVintage}`. Either the artifact was altered, or it was issued in violation of GVP §2.1.2 (a result depending on inputs outside the fixed point). Both are defects; this instrument cannot and does not say which. |
| **costs** | A buyer relying on the hash believes it can prove what it was served, and cannot. The receipt may still be perfectly valid — it attests payment and issuer, never the body. |
| **detectable** | From a supplied artifact. No payment and no origin fetch by this instrument. |
| **falsified_by** | Recomputing SHA-256 over the RFC 8785 (JCS) canonical form of `{endpoint, inputs, result, method, dataVintage}` from the same supplied body and obtaining the declared `responseHash`. |
| **author** | Outside instrument (golden-vector-provenance); the store acts as registrar. |

## Three design choices, each because you asked

**1. Caller supplies the body. There is no fetch seam at all.**
Not a default — the module has no way to fetch anything. The desk stays offline and the verdict
reads "this hash re-derives from the body you gave us", never "the issuer served this". Making it
structurally impossible seemed better than making it configurable.

**2. The finding is a disjunction and names neither branch.**
A failed re-derivation means the artifact was altered **or** the hash was issued in violation of the
closure rule. Distinguishing them requires the issuer's internals, which a third party cannot see.
Requiring attribution would make the check unissuable by exactly the parties it exists to serve, so
it states both branches and picks neither.

**3. The instrument excludes itself first (GVP §8.1).**
There is a third branch and it is ours: our own canonicalization may be wrong, and JCS is precisely
where that hides. So `checkResponseHash()` runs `assertFit()` against published vectors *before* it
is allowed to state anything. If that fails it returns `status: 'unable-to-verify'` with
`subject: 'this instrument'` and **no class slug** — a claim about us, never about an issuer, and
structurally impossible to mistake for an accusation.

The canonicalizer is written independently of the GVP reference implementation, on purpose: a check
that shares code with the thing it checks is a mirror, not evidence.

## What the suite proves

```
§8.1 self-exclusion   a sabotaged instrument returns unable-to-verify, not a finding,
                      with subject 'this instrument' and no class slug
clean artifact        a correct responseHash passes
adversarial (6)       result mutated · inputs mutated · endpoint swapped · method reworded ·
                      dataVintage changed · hash re-attached from another call — all findings
non-attribution       states both branches, refuses to say which, carries falsified_by,
                      carries the supplied-body scope limit
closed member set     a missing fixed-point member is a finding, not a pass
not-applicable        no declared responseHash -> the class does not apply
JCS edges (13)        key order incl. non-ASCII and shared prefixes · raw UTF-8 · emoji surrogate
                      pairs · control chars · unescaped solidus · -0 · integral floats ·
                      ECMAScript number edges · safe-integer bounds · empty containers · nesting
```

## Where it does not fit yet, stated plainly

`verifyArtifact(jws, options?)` takes a JWS and **no function in `x402-verify` accepts a response
body**. This check needs one. So it is not a drop-in extension of an existing check — it is a new
surface, and where that surface belongs is the store's call, not mine. That is why this is offered
as a working artifact rather than opened as a PR that would have guessed at your architecture.

Tell me where it goes and I will shape it to fit — including dropping this canonicalizer entirely if
`x402-verify` would rather own one.
