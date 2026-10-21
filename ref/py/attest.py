"""GVP issuer attestation reference (Python) — L2 (spec §6).

Requires the `cryptography` package, 46+ for ML-DSA-65 (run via `uv run --with cryptography ref/py/attest.py`).
Proves cross-implementation interop: this reference (a) verifies the JS-produced attestation
signatures and (b) reproduces the Ed25519 ones byte-for-byte, since Ed25519 is deterministic (RFC 8032).
ML-DSA-65 (FIPS 204, pure, empty context) is hedged, so its vectors are verify-only. It also reaches the
expected key-first outcome (spec §6.3) for every case in vectors/attestation-outcomes.json.
"""
import json
import base64
import sys
import os

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:  # older cryptography: ML-DSA-65 keys are then "not implemented" -> unverifiable
    mldsa = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gvp import canonicalize  # noqa: E402


def load_priv(b64):
    return serialization.load_der_private_key(base64.b64decode(b64), password=None)


def pub_b64(priv):
    der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


ATTESTATION_V1 = "GVP-Attestation/1"
ATTESTATION_V2 = "GVP-Attestation/2"
ATTESTATION_V3 = "GVP-Attestation/3"
ALG_ED25519 = "Ed25519"
ALG_ML_DSA_65 = "ML-DSA-65"
IMPLEMENTED_ALGS = [ALG_ED25519] + ([ALG_ML_DSA_65] if mldsa else [])


class PayloadError(ValueError):
    """A payload the verifier cannot build (spec §6.3): an unimplemented shape is `unverifiable`; a /3
    payload missing a member the issuer MUST sign is `contradicted`."""

    def __init__(self, message, outcome):
        super().__init__(message)
        self.outcome = outcome


def attestation_payload(p):
    """Canonical signed payload (spec §6). The shape id is INSIDE the signed object so a verifier learns
    which shape to reconstruct from the receipt and an attacker cannot strip/forge it without failing the
    signature. No payloadVersion (or /1) -> legacy 6 fields; /2 adds payloadVersion + fixedPointVersion
    (fixedPointVersion lives HERE, in the signed L2 payload, never in the hashed L1 fixed point); /3 adds
    alg as well (spec §6.1)."""
    base = {
        "responseHash": p["responseHash"], "endpoint": p["endpoint"], "dataVintage": p["dataVintage"],
        "issuer": p["issuer"], "agentId": p.get("agentId"), "issuedAt": p["issuedAt"],
    }
    pv = p.get("payloadVersion")
    if pv is None or pv == ATTESTATION_V1:
        return canonicalize(base)
    if pv not in (ATTESTATION_V2, ATTESTATION_V3):
        raise PayloadError("unsupported attestation payload version: %r" % pv, "unverifiable")
    fpv = p.get("fixedPointVersion")
    if not isinstance(fpv, str) or not fpv:
        raise PayloadError("%s requires fixedPointVersion" % pv, "contradicted")
    base.update({"payloadVersion": pv, "fixedPointVersion": fpv})
    if pv == ATTESTATION_V3:
        alg = p.get("alg")
        if not isinstance(alg, str) or not alg:
            raise PayloadError("%s requires alg" % ATTESTATION_V3, "contradicted")
        base["alg"] = alg
    return canonicalize(base)


def alg_of_key(key):
    """The algorithm a key is pinned to, read from the key itself, never from a receipt."""
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return ALG_ED25519
    if mldsa and isinstance(key, (mldsa.MLDSA65PublicKey, mldsa.MLDSA65PrivateKey)):
        return ALG_ML_DSA_65
    return None


def signed_alg(p):
    """The alg a payload signs: its own member under /3, "Ed25519" for /1 and /2 (spec §6.1)."""
    return p.get("alg") if p.get("payloadVersion") == ATTESTATION_V3 else ALG_ED25519


def attest(payload_string, priv, key_id=None):
    # Pure Ed25519 / pure ML-DSA-65 with the empty context string (spec §6.1).
    alg = alg_of_key(priv)
    if alg is None:
        raise ValueError("unsupported signing key type: %s" % type(priv).__name__)
    sig = priv.sign(payload_string.encode("utf-8"))
    out = {"alg": alg, "publicKey": pub_b64(priv), "signature": base64.b64encode(sig).decode()}
    if key_id is not None:
        out["keyId"] = key_id
    return out


def verify_attest(payload_string, sig, expected_pub=None):
    """Legacy boolean check for /1 and /2 (Ed25519 only)."""
    if not sig or sig.get("alg") != "Ed25519" or not sig.get("publicKey") or not sig.get("signature"):
        return False
    if expected_pub and sig["publicKey"] != expected_pub:
        return False
    try:
        pub = serialization.load_der_public_key(base64.b64decode(sig["publicKey"]))
        pub.verify(base64.b64decode(sig["signature"]), payload_string.encode("utf-8"))
        return True
    except Exception:
        return False


def _raw_verify(payload_string, key, signature_b64):
    try:
        key.verify(base64.b64decode(signature_b64 or ""), payload_string.encode("utf-8"))
        return True
    except Exception:
        return False


def _load_spki(b64):
    return serialization.load_der_public_key(base64.b64decode(b64))


_UNSET = object()


def verify_attestation(p, sig, key_list=_UNSET, implemented=None):
    """Key-first verification (spec §6.3) -> (outcome, reason, scope|None).

    key_list: the issuer key list resolved from the origin the verifier paid; None = could not be
    fetched; omitted = integrity-only check against the embedded publicKey."""
    implemented = IMPLEMENTED_ALGS if implemented is None else implemented
    try:
        payload_string = attestation_payload(p)
    except PayloadError as e:
        return (e.outcome, str(e), None)
    except Exception as e:
        return ("contradicted", str(e), None)
    is_v3 = p.get("payloadVersion") == ATTESTATION_V3
    if not isinstance(sig, dict):
        return ("contradicted", "no signature object", None)
    if is_v3 and not sig.get("keyId"):
        return ("contradicted", "%s requires keyId" % ATTESTATION_V3, None)

    if key_list is _UNSET:  # integrity-only: dispatch on the embedded key
        if not sig.get("publicKey"):
            return ("unverifiable", "no key list and no embedded publicKey", None)
        try:
            key = _load_spki(sig["publicKey"])
        except UnsupportedAlgorithm:
            return ("unverifiable", "embedded key type not implemented", None)
        except Exception:
            return ("contradicted", "embedded publicKey is not SPKI DER", None)
        alg = alg_of_key(key)
        if alg is None or alg not in implemented:
            return ("unverifiable", "embedded key type not implemented: %s" % type(key).__name__, None)
        if signed_alg(p) != alg:
            return ("contradicted", "signed alg %s != key alg %s" % (signed_alg(p), alg), None)
        if _raw_verify(payload_string, key, sig.get("signature")):
            return ("verified", "signature verifies under the embedded key", "integrity")
        return ("contradicted", "signature does not verify", None)

    if key_list is None:
        return ("unverifiable", "key list unreachable", None)
    # By keyId; a /1 or /2 receipt without one (keyId was OPTIONAL there) is matched by its embedded
    # publicKey, the pre-/3 identity rule (spec §6.3).
    keys = key_list.get("keys", [])
    key_id = sig.get("keyId")
    if key_id:
        entry = next((k for k in keys if isinstance(k.get("keyId"), str) and k["keyId"] == key_id), None)
    elif sig.get("publicKey"):
        entry = next((k for k in keys if k.get("publicKey") == sig["publicKey"]), None)
    else:
        entry = None
    if entry is None:
        return ("contradicted", "keyId not in fetched key list: %s" % key_id if key_id
                else "embedded publicKey not in fetched key list", None)
    # A mismatch is a contradiction whether or not this verifier implements either algorithm.
    if signed_alg(p) != entry.get("alg"):
        return ("contradicted", "signed alg %s != key alg %s" % (signed_alg(p), entry.get("alg")), None)
    if entry.get("alg") not in implemented:
        return ("unverifiable", "key alg not implemented: %s" % entry.get("alg"), None)
    try:
        key = _load_spki(entry["publicKey"])
    except Exception:
        return ("contradicted", "listed publicKey is not SPKI DER", None)
    if alg_of_key(key) != entry["alg"]:
        return ("contradicted", "listed key type does not match its pinned alg %s" % entry["alg"], None)
    if sig.get("publicKey") and sig["publicKey"] != entry["publicKey"]:
        return ("contradicted", "embedded publicKey differs from the listed key", None)
    if _raw_verify(payload_string, key, sig.get("signature")):
        return ("verified", "signature verifies under listed key %s" % entry.get("keyId", "(matched by publicKey)"), "identity")
    return ("contradicted", "signature does not verify", None)


if __name__ == "__main__":
    vdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "vectors")
    # Run all three signed-payload shapes: /1 (legacy, attestation.json), /2 (attestation-v2.json) and
    # /3 (attestation-v3.json; Ed25519 re-signed byte-for-byte, ML-DSA-65 verify-only).
    datasets = []
    for fname in ("attestation.json", "attestation-v2.json", "attestation-v3.json"):
        fp = os.path.join(vdir, fname)
        if os.path.exists(fp):
            with open(fp, encoding="utf-8") as fh:
                datasets.append((fname, json.load(fh)))
    with open(os.path.join(vdir, "attestation-key.json"), encoding="utf-8") as fh:
        keyb64 = json.load(fh)["privateKeyPkcs8B64"]

    priv = load_priv(keyb64)
    pub = pub_b64(priv)
    fails = 0
    total = 0
    for fname, data in datasets:
        print("== %s (%s)" % (fname, data.get("payloadVersion", ATTESTATION_V1)))
        groups = data.get("groups") or [{"alg": ALG_ED25519, "publicKey": data["publicKey"], "vectors": data["vectors"]}]
        for g in groups:
            ed = g["alg"] == ALG_ED25519
            if ed and pub != g["publicKey"]:
                print("PUBKEY MISMATCH: our key does not match the fixture")
                fails += 1
            if g["alg"] not in IMPLEMENTED_ALGS:
                print("SKIP %s group: not implemented by this cryptography build" % g["alg"])
                continue
            for v in g["vectors"]:
                total += 1
                payload_string = attestation_payload(v["payload"])
                canon_ok = payload_string == v["canonicalPayload"]          # payload canonicalizes identically
                key = _load_spki(g["publicKey"])                            # (a) verify JS's signature
                verify_ok = alg_of_key(key) == g["alg"] and _raw_verify(payload_string, key, v["expected"]["signature"])
                det_ok = True                                               # ML-DSA-65 is hedged: verify-only
                if ed:                                                      # (b) re-sign; must be byte-identical
                    mine = attest(payload_string, priv)
                    det_ok = mine["signature"] == v["expected"]["signature"] and mine["publicKey"] == v["expected"]["publicKey"]
                if not (canon_ok and verify_ok and det_ok):
                    fails += 1
                print("%-10s %-30s canon=%s verifyJSsig=%s reSign==JS=%s" % (
                    g["alg"], v["name"], canon_ok, verify_ok, det_ok if ed else "n/a"))

    # Key-first outcomes (spec §6.3)
    fp = os.path.join(vdir, "attestation-outcomes.json")
    if os.path.exists(fp):
        with open(fp, encoding="utf-8") as fh:
            oc = json.load(fh)
        print("== attestation-outcomes.json")
        for c in oc["cases"]:
            total += 1
            kl = {"published": oc["keyList"], "none": _UNSET}.get(c["keyList"])
            impl = c.get("implemented")
            impl = IMPLEMENTED_ALGS if impl is None else [a for a in impl if a in IMPLEMENTED_ALGS]
            want = c["expected"]
            if c.get("requires") and c["requires"] not in impl:
                want = "unverifiable"   # this build lacks the algorithm: spec §8 says report unverifiable
            got = verify_attestation(c["payload"], c["signature"], kl, impl)
            ok = got[0] == want
            if not ok:
                fails += 1
            print("%s %-52s -> %-12s %s" % ("ok  " if ok else "FAIL", c["name"], got[0],
                                             "" if ok else "(expected %s: %s)" % (want, got[1])))

    print("\n%d vectors, %d failures" % (total, fails))
    sys.exit(1 if fails else 0)
