// GVP issuer attestation reference (JS/TS) — L2. Signs/verifies the attestation payload (spec §6).
// Ed25519 is deterministic (RFC 8032), so a conformant Python signer produces byte-identical
// signatures for the same key + payload; this is proven in vectors/attestation.json (payload /1),
// vectors/attestation-v2.json (payload /2) and the Ed25519 part of vectors/attestation-v3.json (/3).
// ML-DSA-65 (FIPS 204, pure, empty context) is hedged, so its vectors are verify-only.
import { sign as cSign, verify as cVerify, createPublicKey, createPrivateKey } from 'node:crypto';
import { canonicalize } from './gvp.mjs';

export function loadPrivateKey(pkcs8B64) {
  return createPrivateKey({ key: Buffer.from(pkcs8B64, 'base64'), format: 'der', type: 'pkcs8' });
}
export function publicKeyB64(priv) {
  return createPublicKey(priv).export({ format: 'der', type: 'spki' }).toString('base64');
}

// Signed-payload shapes (spec §6). The shape identifier is INSIDE the signed object, so a verifier learns
// which shape to reconstruct from the receipt itself and an attacker cannot strip or forge it without
// failing the signature. Three shapes exist:
//   GVP-Attestation/1 — the original 6-field payload (receipts issued before fixedPointVersion existed).
//   GVP-Attestation/2 — /1 plus { payloadVersion, fixedPointVersion }. fixedPointVersion lives here, in
//                       the SIGNED L2 payload — not in the hashed L1 fixed point (that would move every
//                       responseHash) and not unsigned beside the hash (that could be stripped/forged).
//   GVP-Attestation/3 — /2 plus { alg }, so the algorithm claim is signed too (spec §6.1). /1 and /2
//                       read as alg "Ed25519".
export const ATTESTATION_V1 = 'GVP-Attestation/1';
export const ATTESTATION_V2 = 'GVP-Attestation/2';
export const ATTESTATION_V3 = 'GVP-Attestation/3';
export const FIXED_POINT_V1 = 'GVP-FixedPoint/1';
export const ALG_ED25519 = 'Ed25519';
export const ALG_ML_DSA_65 = 'ML-DSA-65';
export const IMPLEMENTED_ALGS = [ALG_ED25519, ALG_ML_DSA_65];

// A payload the verifier cannot build splits two ways (spec §6.3): a shape it does not implement is
// `unverifiable`; a /3 payload missing a member the issuer MUST sign is `contradicted`.
function payloadError(message, outcome) {
  const e = new Error(message);
  e.outcome = outcome;
  return e;
}

// The exact string the issuer signs (spec §6): canonical JSON of the attestation payload.
// No payloadVersion (or /1) -> legacy 6-field shape. /2 -> adds payloadVersion + fixedPointVersion.
// /3 -> /2 plus alg.
export function attestationPayload({ responseHash, endpoint, dataVintage, issuer, agentId, issuedAt,
                                     payloadVersion, fixedPointVersion, alg }) {
  const base = { responseHash, endpoint, dataVintage, issuer, agentId: agentId ?? null, issuedAt };
  if (payloadVersion == null || payloadVersion === ATTESTATION_V1) return canonicalize(base);
  if (payloadVersion !== ATTESTATION_V2 && payloadVersion !== ATTESTATION_V3) {
    throw payloadError(`unsupported attestation payload version: ${payloadVersion}`, 'unverifiable');
  }
  if (typeof fixedPointVersion !== 'string' || !fixedPointVersion) {
    throw payloadError(`${payloadVersion} requires fixedPointVersion`, 'contradicted');
  }
  if (payloadVersion === ATTESTATION_V2) {
    return canonicalize({ ...base, payloadVersion: ATTESTATION_V2, fixedPointVersion });
  }
  if (typeof alg !== 'string' || !alg) throw payloadError(`${ATTESTATION_V3} requires alg`, 'contradicted');
  return canonicalize({ ...base, payloadVersion: ATTESTATION_V3, fixedPointVersion, alg });
}

// The algorithm a key is pinned to, read from the key itself (its SPKI/PKCS#8 type), never from a receipt.
export function algOfKey(key) {
  const t = key.asymmetricKeyType;
  if (t === 'ed25519') return ALG_ED25519;
  if (t === 'ml-dsa-65') return ALG_ML_DSA_65;
  return null;
}

// The alg a payload signs: its own member under /3, "Ed25519" for /1 and /2 (spec §6.1).
export function signedAlg(payload) {
  return payload.payloadVersion === ATTESTATION_V3 ? payload.alg : ALG_ED25519;
}

// sign(null, ...) is pure Ed25519 / pure ML-DSA-65 with the empty context string (spec §6.1).
export function attest(payloadString, priv, { keyId } = {}) {
  const alg = algOfKey(priv);
  if (!alg) throw new Error(`unsupported signing key type: ${priv.asymmetricKeyType}`);
  const out = {
    alg,
    publicKey: publicKeyB64(priv),
    signature: cSign(null, Buffer.from(payloadString, 'utf8'), priv).toString('base64')
  };
  if (keyId != null) out.keyId = keyId;
  return out;
}

// Legacy boolean check for /1 and /2 (Ed25519 only).
// WITHOUT expectedPublicKey: integrity only (matches the receipt's own embedded key).
// WITH it: also proves issuer identity (spec §6).
export function verifyAttest(payloadString, sig, expectedPublicKey) {
  if (!sig || sig.alg !== 'Ed25519' || !sig.publicKey || !sig.signature) return false;
  if (expectedPublicKey && sig.publicKey !== expectedPublicKey) return false;
  try {
    const pub = createPublicKey({ key: Buffer.from(sig.publicKey, 'base64'), format: 'der', type: 'spki' });
    return cVerify(null, Buffer.from(payloadString, 'utf8'), pub, Buffer.from(sig.signature, 'base64'));
  } catch { return false; }
}

function spkiKey(b64) {
  return createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
}

function rawVerify(payloadString, key, signatureB64) {
  try {
    return cVerify(null, Buffer.from(payloadString, 'utf8'), key, Buffer.from(signatureB64 ?? '', 'base64'));
  } catch { return false; }
}

const result = (outcome, reason, scope) => ({ outcome, reason, ...(scope ? { scope } : {}) });

// Key-first verification (spec §6.3). Terminates in exactly one of verified | unverifiable | contradicted.
//   keyList: the issuer key list ({ keys: [{ keyId, alg, publicKey }] }) the verifier resolved from the
//            origin it paid (spec §6.2); null = the list could not be fetched; undefined = integrity-only
//            check against the receipt's embedded publicKey.
//   implemented: the algorithms this verifier implements (default: both).
export function verifyAttestation(payload, sig, { keyList, implemented = IMPLEMENTED_ALGS } = {}) {
  let payloadString;
  try { payloadString = attestationPayload(payload); }
  catch (e) { return result(e.outcome ?? 'contradicted', e.message); }
  const isV3 = payload.payloadVersion === ATTESTATION_V3;
  if (!sig || typeof sig !== 'object') return result('contradicted', 'no signature object');
  if (isV3 && !sig.keyId) return result('contradicted', `${ATTESTATION_V3} requires keyId`);

  if (keyList === undefined) {                       // integrity-only: dispatch on the embedded key
    if (!sig.publicKey) return result('unverifiable', 'no key list and no embedded publicKey');
    let key; try { key = spkiKey(sig.publicKey); } catch { return result('contradicted', 'embedded publicKey is not SPKI DER'); }
    const alg = algOfKey(key);
    if (!alg || !implemented.includes(alg)) return result('unverifiable', `embedded key type not implemented: ${key.asymmetricKeyType}`);
    if (signedAlg(payload) !== alg) return result('contradicted', `signed alg ${signedAlg(payload)} != key alg ${alg}`);
    return rawVerify(payloadString, key, sig.signature)
      ? result('verified', 'signature verifies under the embedded key', 'integrity')
      : result('contradicted', 'signature does not verify');
  }

  if (keyList === null) return result('unverifiable', 'key list unreachable');
  // By keyId; a /1 or /2 receipt without one (keyId was OPTIONAL there) is matched by its embedded
  // publicKey, the pre-/3 identity rule (spec §6.3).
  const keys = keyList.keys ?? [];
  const keyId = sig.keyId;
  const entry = keyId
    ? keys.find(k => typeof k.keyId === 'string' && k.keyId === keyId)
    : (sig.publicKey ? keys.find(k => k.publicKey === sig.publicKey) : undefined);
  if (!entry) {
    return result('contradicted', keyId ? `keyId not in fetched key list: ${keyId}` : 'embedded publicKey not in fetched key list');
  }
  // A mismatch is a contradiction whether or not this verifier implements either algorithm.
  if (signedAlg(payload) !== entry.alg) return result('contradicted', `signed alg ${signedAlg(payload)} != key alg ${entry.alg}`);
  if (!implemented.includes(entry.alg)) return result('unverifiable', `key alg not implemented: ${entry.alg}`);
  let key; try { key = spkiKey(entry.publicKey); } catch { return result('contradicted', 'listed publicKey is not SPKI DER'); }
  if (algOfKey(key) !== entry.alg) return result('contradicted', `listed key type does not match its pinned alg ${entry.alg}`);
  if (sig.publicKey && sig.publicKey !== entry.publicKey) return result('contradicted', 'embedded publicKey differs from the listed key');
  return rawVerify(payloadString, key, sig.signature)
    ? result('verified', `signature verifies under listed key ${entry.keyId ?? '(matched by publicKey)'}`, 'identity')
    : result('contradicted', 'signature does not verify');
}

// Key-list resolver with the bounded refetch of spec §6.3. `fetchList(origin, etag)` returns
// { list, etag } on 200, { notModified: true } on 304, or throws / returns null when unreachable.
// lookup(origin, keyId) -> the key list to pass to verifyAttestation (null = unreachable).
//   - a cached list that contains keyId is used as is
//   - a miss refetches once, but only if the cached list is older than minRefetchMs (the freshness
//     floor); inside the floor the cached list is the fresh read and the miss stands
//   - concurrent refetches for one origin share a single in-flight fetch (coalesced)
//   - a refetch that fails means the fresh read did not happen: the miss is `unverifiable` (null), and
//     the failure is floored too, so a down origin is not hammered either
export function createKeyListResolver({ fetchList, minRefetchMs = 60_000, now = () => Date.now() }) {
  // origin -> { list, etag, fetchedAt, failedAt? }; list is null for an origin never fetched successfully
  // (a cold failure is cached too, so it is floored like any other)
  const cache = new Map();
  const inflight = new Map();   // origin -> Promise<entry|null>

  function refresh(origin) {
    if (inflight.has(origin)) return inflight.get(origin);
    const prev = cache.get(origin);
    const p = (async () => {
      let res;
      try { res = await fetchList(origin, prev?.etag); } catch { res = null; }
      if (res?.notModified && prev?.list) { prev.fetchedAt = now(); delete prev.failedAt; return prev; }
      if (!res || !res.list) {
        if (prev) prev.failedAt = now();
        else cache.set(origin, { list: null, fetchedAt: -Infinity, failedAt: now() });
        return null;
      }
      const entry = { list: res.list, etag: res.etag, fetchedAt: now() };
      cache.set(origin, entry);
      return entry;
    })().finally(() => inflight.delete(origin));
    inflight.set(origin, p);
    return p;
  }

  const has = (entry, keyId) => (entry.list.keys ?? []).some(k => k.keyId === keyId);

  return {
    async lookup(origin, keyId) {
      const entry = cache.get(origin);
      if (entry) {
        if (entry.list && (has(entry, keyId) || now() - entry.fetchedAt < minRefetchMs)) return entry.list;
        if (entry.failedAt != null && now() - entry.failedAt < minRefetchMs) return null;
      }
      const fresh = await refresh(origin);
      return fresh ? fresh.list : null;
    }
  };
}
