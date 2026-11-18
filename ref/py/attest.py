"""GVP issuer attestation reference (Python) — L2 (spec §6).

Requires the `cryptography` package, 46+ for ML-DSA-65 (run via `uv run --with cryptography ref/py/attest.py`).
Proves cross-implementation interop: this reference (a) verifies the JS-produced attestation
signatures and (b) reproduces the Ed25519 ones byte-for-byte, since Ed25519 is deterministic (RFC 8032).
ML-DSA-65 (FIPS 204, pure, empty context) is hedged, so its vectors are verify-only. It also reaches the
expected key-first outcome (spec §6.3) for every case in vectors/attestation-outcomes.json.
"""
import json
import base64
from datetime import datetime, timezone
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


class Outcome(tuple):
    """(outcome, reason, scope) — unpacks as a 3-tuple; `info` carries keptAt / discontinuity when the
    result rests on a kept key-list entry (spec §6.3, "Kept key lists")."""

    def __new__(cls, outcome, reason, scope=None, info=None):
        t = super().__new__(cls, (outcome, reason, scope))
        t.info = dict(info or {})
        return t


def _same_binding(a, b):
    """A keyId, once listed, stays bound to one alg and one key (spec §6.2)."""
    return a.get("keyId") == b.get("keyId") and a.get("alg") == b.get("alg") and a.get("publicKey") == b.get("publicKey")


def keep_key_list(kept, key_list, seen_at=None):
    """Fold a successfully fetched key list into a kept list: first binding wins, and lastSeenAt records
    the last fetch that confirmed it (RFC 3339; default now)."""
    if seen_at is None:
        seen_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    keys = [dict(k) for k in (kept or {}).get("keys", [])]
    for k in (key_list or {}).get("keys", []):
        if not isinstance(k.get("keyId"), str):
            continue
        prior = next((e for e in keys if e.get("keyId") == k["keyId"]), None)
        if prior is None:
            keys.append({"keyId": k["keyId"], "alg": k.get("alg"), "publicKey": k.get("publicKey"), "lastSeenAt": seen_at})
        elif _same_binding(prior, k):
            prior["lastSeenAt"] = seen_at
    return {"keys": keys}


def verify_attestation(p, sig, key_list=_UNSET, implemented=None, kept=None):
    """Key-first verification (spec §6.3) -> Outcome(outcome, reason, scope|None).

    key_list: the issuer key list resolved from the origin the verifier paid; None = could not be
    fetched; omitted = integrity-only check against the embedded publicKey.
    kept: an optional kept key list (see keep_key_list) fetched from the same origin earlier; a result
    that rests on a kept entry carries info["keptAt"], plus info["discontinuity"] ("dropped" |
    "rebound") when the fetched list disagrees with it. Ignored in integrity-only mode (key_list
    omitted)."""
    implemented = IMPLEMENTED_ALGS if implemented is None else implemented
    try:
        payload_string = attestation_payload(p)
    except PayloadError as e:
        return Outcome(e.outcome, str(e))
    except Exception as e:
        return Outcome("contradicted", str(e))
    is_v3 = p.get("payloadVersion") == ATTESTATION_V3
    if not isinstance(sig, dict):
        return Outcome("contradicted", "no signature object")
    if is_v3 and not sig.get("keyId"):
        return Outcome("contradicted", "%s requires keyId" % ATTESTATION_V3)

    if key_list is _UNSET:  # integrity-only: dispatch on the embedded key
        if not sig.get("publicKey"):
            return Outcome("unverifiable", "no key list and no embedded publicKey")
        try:
            key = _load_spki(sig["publicKey"])
        except UnsupportedAlgorithm:
            return Outcome("unverifiable", "embedded key type not implemented")
        except Exception:
            return Outcome("contradicted", "embedded publicKey is not SPKI DER")
        alg = alg_of_key(key)
        if alg is None or alg not in implemented:
            return Outcome("unverifiable", "embedded key type not implemented: %s" % type(key).__name__)
        if signed_alg(p) != alg:
            return Outcome("contradicted", "signed alg %s != key alg %s" % (signed_alg(p), alg))
        if _raw_verify(payload_string, key, sig.get("signature")):
            return Outcome("verified", "signature verifies under the embedded key", "integrity")
        return Outcome("contradicted", "signature does not verify")

    # By keyId; a /1 or /2 receipt without one (keyId was OPTIONAL there) is matched by its embedded
    # publicKey, the pre-/3 identity rule (spec §6.3).
    key_id = sig.get("keyId")

    def find(lst):
        keys = (lst or {}).get("keys", [])
        if key_id:
            return next((k for k in keys if isinstance(k.get("keyId"), str) and k["keyId"] == key_id), None)
        if sig.get("publicKey"):
            return next((k for k in keys if k.get("publicKey") == sig["publicKey"]), None)
        return None

    # A kept entry proves presence, never absence (spec §6.3, "Kept key lists").
    kept_entry = find(kept)
    info = {}
    if key_list is None:
        if kept_entry is None:
            return Outcome("unverifiable", "key list unreachable; keyId not in kept list" if kept else "key list unreachable")
        entry = kept_entry
        info = {"keptAt": kept_entry.get("lastSeenAt")}
    else:
        fetched = find(key_list)
        if kept_entry is not None and not (fetched is not None and _same_binding(fetched, kept_entry)):
            entry = kept_entry
            # Classified by the kept entry's keyId, whichever way the receipt was matched (spec §6.3).
            by_id = any(k.get("keyId") == kept_entry.get("keyId") for k in key_list.get("keys", []))
            info = {"keptAt": kept_entry.get("lastSeenAt"), "discontinuity": "rebound" if by_id else "dropped"}
        else:
            entry = fetched
        if entry is None:
            return Outcome("contradicted", "keyId not in fetched key list: %s" % key_id if key_id
                           else "embedded publicKey not in fetched key list")

    def out(outcome, reason, scope=None):
        return Outcome(outcome, reason, scope, info)

    # A mismatch is a contradiction whether or not this verifier implements either algorithm.
    if signed_alg(p) != entry.get("alg"):
        return out("contradicted", "signed alg %s != key alg %s" % (signed_alg(p), entry.get("alg")))
    if entry.get("alg") not in implemented:
        return out("unverifiable", "key alg not implemented: %s" % entry.get("alg"))
    try:
        key = _load_spki(entry["publicKey"])
    except Exception:
        return out("contradicted", "listed publicKey is not SPKI DER")
    if alg_of_key(key) != entry["alg"]:
        return out("contradicted", "listed key type does not match its pinned alg %s" % entry["alg"])
    if sig.get("publicKey") and sig["publicKey"] != entry["publicKey"]:
        return out("contradicted", "embedded publicKey differs from the listed key")
    if _raw_verify(payload_string, key, sig.get("signature")):
        return out("verified", "signature verifies under %s key %s" % (
            "kept" if "keptAt" in info else "listed", entry.get("keyId", "(matched by publicKey)")), "identity")
    return out("contradicted", "signature does not verify")


# ---- receipts (spec §6.4): rebuild the signed payload from a receipt, no guessing --------------------
def _is_str(v):
    return isinstance(v, str)


def receipt_payload_members(receipt):
    """Each payload member has exactly one source in the receipt (spec §6.4). A member of the wrong type,
    or a required one that is missing, cannot have been signed by a conformant issuer: contradicted."""
    if not isinstance(receipt, dict):
        raise PayloadError("receipt is not an object", "contradicted")
    for m in ("responseHash", "endpoint", "dataVintage", "issuedAt"):
        if not _is_str(receipt.get(m)):
            raise PayloadError("receipt.%s missing or not a string" % m, "contradicted")
    iss = receipt.get("issuer")
    if not isinstance(iss, dict) or not _is_str(iss.get("service")):
        raise PayloadError("receipt.issuer must be an object with a string service", "contradicted")
    anchor = receipt.get("onChainAnchor")
    agent_id = None
    if anchor is not None:
        if not isinstance(anchor, dict) or not _is_str(anchor.get("agentId")):
            raise PayloadError("receipt.onChainAnchor must be null or an object with a string agentId", "contradicted")
        agent_id = anchor["agentId"]
    sig = receipt.get("signature") if isinstance(receipt.get("signature"), dict) else {}
    members = {"responseHash": receipt["responseHash"], "endpoint": receipt["endpoint"],
               "dataVintage": receipt["dataVintage"], "issuer": iss["service"], "agentId": agent_id,
               "issuedAt": receipt["issuedAt"]}
    pv = sig.get("payloadVersion")
    if pv is None or pv == ATTESTATION_V1:
        return members
    if pv not in (ATTESTATION_V2, ATTESTATION_V3):
        raise PayloadError("unsupported attestation payload version: %r" % (pv,), "unverifiable")
    fpv = receipt.get("fixedPointVersion")
    if not _is_str(fpv) or not fpv:
        raise PayloadError("%s requires receipt.fixedPointVersion" % pv, "contradicted")
    members["payloadVersion"] = pv
    members["fixedPointVersion"] = fpv
    if pv == ATTESTATION_V3:
        if not _is_str(sig.get("alg")) or not sig.get("alg"):
            raise PayloadError("%s requires signature.alg" % ATTESTATION_V3, "contradicted")
        members["alg"] = sig["alg"]
    return members


def receipt_payload(receipt):
    """The exact string a receipt's issuer signed."""
    return attestation_payload(receipt_payload_members(receipt))


def verify_receipt(receipt, key_list=_UNSET, implemented=None, kept=None):
    """Verify a whole receipt (spec §6.3 + §6.4). An unsigned receipt is unverifiable (L1 only)."""
    if isinstance(receipt, dict) and receipt.get("signature") is None:
        return Outcome("unverifiable", "receipt is unsigned: L1 only, no attestation to check")
    try:
        members = receipt_payload_members(receipt)
    except PayloadError as e:
        return Outcome(e.outcome, str(e))
    return verify_attestation(members, receipt["signature"], key_list, implemented, kept)


# ---- revocation lists (spec §7) --------------------------------------------------------------------
REVOCATION_V02 = "GVP-Revocation/0.2"


def revocation_list_payload(lst):
    return canonicalize({k: v for k, v in lst.items() if k != "signature"})


def _valid_revocation_entry(e):
    """{responseHash} (kind absent or "responseHash") or {kind: "reportHash", reportHash}; any other kind,
    None included, makes the list malformed (spec §7)."""
    if not isinstance(e, dict):
        return False
    if "kind" not in e or e["kind"] == "responseHash":
        return isinstance(e.get("responseHash"), str)
    return e["kind"] == "reportHash" and isinstance(e.get("reportHash"), str)


def verify_revocation_list(lst, key_list):
    if lst is None:
        return Outcome("unverifiable", "revocation list unreachable")
    if not isinstance(lst, dict) or lst.get("revocationListVersion") != REVOCATION_V02 or not isinstance(lst.get("revoked"), list):
        return Outcome("contradicted", "not a GVP-Revocation/0.2 document")
    if not all(_valid_revocation_entry(e) for e in lst["revoked"]):
        return Outcome("contradicted", "an entry has an unknown kind or no hash (spec §7)")
    sig = lst.get("signature")
    if not isinstance(sig, dict):
        return Outcome("unverifiable", "revocation list is unsigned")
    if not key_list:
        return Outcome("unverifiable", "key list unreachable")
    keys = key_list.get("keys", [])
    entry = next((k for k in keys if (k.get("keyId") == sig.get("keyId") if sig.get("keyId") else k.get("publicKey") == sig.get("publicKey"))), None)
    if entry is None:
        return Outcome("contradicted", "revocation list key not in the key list")
    if entry.get("alg") not in IMPLEMENTED_ALGS:
        return Outcome("unverifiable", "key alg not implemented: %s" % entry.get("alg"))
    if sig.get("publicKey") and sig["publicKey"] != entry["publicKey"]:
        return Outcome("contradicted", "embedded publicKey differs from the listed key")
    try:
        key = _load_spki(entry["publicKey"])
    except Exception:
        return Outcome("contradicted", "listed publicKey is not SPKI DER")
    if alg_of_key(key) != entry["alg"]:
        return Outcome("contradicted", "listed key type does not match its pinned alg %s" % entry["alg"])
    if _raw_verify(revocation_list_payload(lst), key, sig.get("signature")):
        return Outcome("verified", "revocation list signed by %s" % entry.get("keyId"))
    return Outcome("contradicted", "revocation list signature does not verify")


def revocation_status(h, lst, key_list, kind="responseHash"):
    """not-revoked | revoked | unverifiable (spec §7). A list that does not verify never reads as not-revoked."""
    v = verify_revocation_list(lst, key_list)
    if v[0] != "verified":
        return "unverifiable"
    for e in lst["revoked"]:
        if (e["kind"] if "kind" in e else "responseHash") == kind and e.get(kind) == h:
            return "revoked"
    return "not-revoked"


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

    # Kept key lists (spec §6.3)
    fp = os.path.join(vdir, "attestation-kept.json")
    if os.path.exists(fp):
        with open(fp, encoding="utf-8") as fh:
            kp = json.load(fh)
        print("== attestation-kept.json")
        for c in kp["cases"]:
            total += 1
            kl = None if c["keyList"] == "unreachable" else kp["keyLists"][c["keyList"]]
            got = verify_attestation(c["payload"], c["signature"], kl, kept=kp["keptList"] if c["kept"] else None)
            ok = (got[0] == c["expected"] and got.info.get("keptAt") == c.get("keptAt")
                  and ("keptAt" in got.info) == ("keptAt" in c) and got.info.get("discontinuity") == c.get("discontinuity"))
            if not ok:
                fails += 1
            print("%s %-62s -> %-12s %s" % ("ok  " if ok else "FAIL", c["name"], got[0],
                                             "" if ok else "(expected %s %s: %s %s)" % (c["expected"], c.get("discontinuity"), got[1], got.info)))

    # Full receipts (spec §6.4) and revocation lists (spec §7)
    fp = os.path.join(vdir, "receipt.json")
    if os.path.exists(fp):
        with open(fp, encoding="utf-8") as fh:
            rv = json.load(fh)
        print("== receipt.json")
        for c in rv["cases"]:
            total += 1
            kl = {"published": rv["keyList"], "live": rv.get("liveKeyList"), "none": _UNSET}[c["keyList"]]
            got = verify_receipt(c["receipt"], kl)
            want = c["expected"]
            if c.get("requires") and c["requires"] not in IMPLEMENTED_ALGS:
                want = "unverifiable"
            ok = got[0] == want
            if "expectedPayload" in c:
                try:
                    ok = ok and receipt_payload(c["receipt"]) == c["expectedPayload"]
                except PayloadError:
                    ok = ok and c["expectedPayload"] is None
            if not ok:
                fails += 1
            print("%s %-52s -> %-12s %s" % ("ok  " if ok else "FAIL", c["name"], got[0], "" if ok else "(expected %s: %s)" % (c["expected"], got[1])))
        for c in rv["revocationCases"]:
            total += 1
            lst = None if c["list"] == "unreachable" else rv["revocationLists"][c["list"]]
            got = revocation_status(c["hash"], lst, rv["keyList"], c.get("kind", "responseHash"))
            ok = got == c["expected"]
            if not ok:
                fails += 1
            print("%s %-52s -> %s" % ("ok  " if ok else "FAIL", c["name"], got))

    print("\n%d vectors, %d failures" % (total, fails))
    sys.exit(1 if fails else 0)
