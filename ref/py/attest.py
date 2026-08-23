"""GVP Ed25519 attestation reference (Python) — L2 (spec §6).

Requires the `cryptography` package (run via `uv run --with cryptography ref/py/attest.py`).
Proves cross-implementation interop: this reference (a) verifies the JS-produced attestation
signatures and (b) reproduces them byte-for-byte, since Ed25519 is deterministic (RFC 8032).
"""
import json
import base64
import sys
import os

from cryptography.hazmat.primitives import serialization

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


def attestation_payload(p):
    """Canonical signed payload (spec §6). The shape id is INSIDE the signed object so a verifier learns
    which shape to reconstruct from the receipt and an attacker cannot strip/forge it without failing the
    signature. No payloadVersion (or /1) -> legacy 6 fields; /2 adds payloadVersion + fixedPointVersion
    (fixedPointVersion lives HERE, in the signed L2 payload, never in the hashed L1 fixed point)."""
    base = {
        "responseHash": p["responseHash"], "endpoint": p["endpoint"], "dataVintage": p["dataVintage"],
        "issuer": p["issuer"], "agentId": p.get("agentId"), "issuedAt": p["issuedAt"],
    }
    pv = p.get("payloadVersion")
    if pv is None or pv == ATTESTATION_V1:
        return canonicalize(base)
    if pv != ATTESTATION_V2:
        raise ValueError("unsupported attestation payload version: %r" % pv)
    fpv = p.get("fixedPointVersion")
    if not isinstance(fpv, str) or not fpv:
        raise ValueError("%s requires fixedPointVersion" % ATTESTATION_V2)
    base.update({"payloadVersion": ATTESTATION_V2, "fixedPointVersion": fpv})
    return canonicalize(base)


def attest(payload_string, priv):
    sig = priv.sign(payload_string.encode("utf-8"))
    return {"alg": "Ed25519", "publicKey": pub_b64(priv), "signature": base64.b64encode(sig).decode()}


def verify_attest(payload_string, sig, expected_pub=None):
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


if __name__ == "__main__":
    vdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "vectors")
    # Run BOTH signed-payload shapes: /1 (legacy, attestation.json) and /2 (attestation-v2.json).
    datasets = []
    for fname in ("attestation.json", "attestation-v2.json"):
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
        if pub != data["publicKey"]:
            print("PUBKEY MISMATCH: our key does not match the fixture")
            fails += 1
        for v in data["vectors"]:
            total += 1
            payload_string = attestation_payload(v["payload"])
            canon_ok = payload_string == v["canonicalPayload"]             # payload canonicalizes identically
            verify_ok = verify_attest(                                     # (a) verify JS's signature
                payload_string,
                {"alg": "Ed25519", "publicKey": v["expected"]["publicKey"], "signature": v["expected"]["signature"]},
                pub,
            )
            mine = attest(payload_string, priv)                           # (b) re-sign; must be byte-identical
            det_ok = mine["signature"] == v["expected"]["signature"] and mine["publicKey"] == v["expected"]["publicKey"]
            if not (canon_ok and verify_ok and det_ok):
                fails += 1
            print("%-30s canon=%s verifyJSsig=%s reSign==JS=%s" % (v["name"], canon_ok, verify_ok, det_ok))

    print("\n%d vectors, %d failures" % (total, fails))
    sys.exit(1 if fails else 0)
