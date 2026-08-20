"""GVP reference implementation (Python) — canonicalization + hash.

Produces byte-identical output to the JavaScript reference (ref/js/gvp.mjs), so a receipt hashed by
either side re-derives the same responseHash. Canonicalization is RFC 8785 (JCS); see spec §2.2.

Canonicalization (normative):
  - object keys sorted by code point (== UTF-16 code unit for the ASCII keys GVP uses), no whitespace
  - arrays preserve order
  - strings: JSON string escaping, non-ASCII emitted raw as UTF-8 (NOT \\u-escaped)  -> ensure_ascii=False
  - numbers: ECMAScript Number->String (integers carry no decimal point; no '+'; no trailing zeros)
  - booleans/null: true|false|null
"""
import json
import hashlib
from decimal import Decimal

MAX_DEPTH = 100


def _num(v):
    """Serialize a JSON number byte-identically to ECMAScript Number::toString (JS JSON.stringify /
    RFC 8785 JCS). Handles the full double range, not just the financial value domain: integers with
    no decimal point, the -6<n<=0 and n>21 exponential thresholds, unpadded signed exponents, -0 -> 0.
    All values are formatted through float(), so an int outside +-2^53 rounds the way JS parsing does."""
    if isinstance(v, bool):  # bool subclasses int — handle first
        return "true" if v else "false"
    x = float(v)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite number not allowed in GVP JSON")
    if x == 0.0:
        return "0"                       # covers -0.0 (ECMAScript: "0")
    neg = x < 0
    ax = -x if neg else x
    # repr() is the shortest round-tripping decimal (same digits JS's Grisu/Ryu emit); decompose it.
    _, digits, exp = Decimal(repr(ax)).as_tuple()
    mant = int("".join(map(str, digits)))
    while mant != 0 and mant % 10 == 0:  # strip trailing zeros -> shortest significand s
        mant //= 10
        exp += 1
    s = str(mant)
    k = len(s)
    n = exp + k                          # value = s x 10^(n-k); n = digits left of the point
    if k <= n <= 21:
        out = s + "0" * (n - k)          # integer form, no decimal point
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:                                # exponential: n>21 or n<=-6
        e = n - 1
        out = (s if k == 1 else s[0] + "." + s[1:]) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return ("-" + out) if neg else out


def _str(s):
    # Matches JS JSON.stringify string escaping: escapes ", \\ and control chars; keeps non-ASCII raw.
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def canonicalize(value, depth=0):
    if depth > MAX_DEPTH:
        raise ValueError("input nesting too deep")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _num(value)
    if isinstance(value, str):
        return _str(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        return "{" + ",".join(_str(k) + ":" + canonicalize(value[k], depth + 1) for k in keys) + "}"
    raise TypeError("unsupported type in GVP JSON: %r" % type(value))


def gvp_hash(fixed_point):
    canon = canonicalize(fixed_point)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    import sys
    # Read a vectors file {name, fixedPoint, expectedHash?}[] on argv[1]; print each computed hash,
    # and if expectedHash is present, assert agreement (exit 1 on any mismatch).
    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as fh:
        vectors = json.load(fh)
    failures = 0
    for v in vectors:
        got = gvp_hash(v["fixedPoint"])
        exp = v.get("expectedHash")
        status = "OK" if (exp is None or got == exp) else "MISMATCH"
        if status == "MISMATCH":
            failures += 1
        print("%-28s %s  %s" % (v["name"], status, got))
    print("\n%d vectors, %d mismatches" % (len(vectors), failures))
    sys.exit(1 if failures else 0)
