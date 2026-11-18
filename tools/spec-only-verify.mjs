// A receipt verifier written from the spec text alone (§5, §6.2-§6.4, §7). It imports node:crypto and
// the independent `canonicalize` package (RFC 8785) and NOTHING from ref/, so a pass here means the
// spec is enough to verify, not that our code agrees with itself. Outside this repo it needs one
// package: npm i canonicalize (any RFC 8785 implementation would do).
//
//   node tools/spec-only-verify.mjs                                   run every case in vectors/receipt.json
//   node tools/spec-only-verify.mjs --receipt r.json --keys k.json    check one receipt against a key list
//        [--revocations list.json]                                   ... and its revocation status
// Exit 0 only when every case reaches its expected result.
import { createPublicKey, createHash, verify, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import canonicalize from 'canonicalize';

const str = (v) => typeof v === 'string';
const fail = (outcome, reason) => { const e = new Error(reason); e.outcome = outcome; throw e; };

// §6.4: one source per payload member.
export function rebuild(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) fail('contradicted', 'not an object');
  for (const m of ['responseHash', 'endpoint', 'dataVintage', 'issuedAt']) if (!str(receipt[m])) fail('contradicted', `${m} not a string`);
  if (!receipt.issuer || typeof receipt.issuer !== 'object' || Array.isArray(receipt.issuer) || !str(receipt.issuer.service)) fail('contradicted', 'issuer.service');
  const a = receipt.onChainAnchor;
  if (a != null && (typeof a !== 'object' || Array.isArray(a) || !str(a.agentId))) fail('contradicted', 'onChainAnchor.agentId');
  const p = { responseHash: receipt.responseHash, endpoint: receipt.endpoint, dataVintage: receipt.dataVintage,
    issuer: receipt.issuer.service, agentId: a == null ? null : a.agentId, issuedAt: receipt.issuedAt };
  const s = receipt.signature ?? {};
  const pv = s.payloadVersion;
  if (pv === undefined || pv === null || pv === 'GVP-Attestation/1') return p;
  if (pv !== 'GVP-Attestation/2' && pv !== 'GVP-Attestation/3') fail('unverifiable', `payloadVersion ${pv}`);
  if (!str(receipt.fixedPointVersion) || !receipt.fixedPointVersion) fail('contradicted', 'fixedPointVersion');
  p.payloadVersion = pv; p.fixedPointVersion = receipt.fixedPointVersion;
  if (pv === 'GVP-Attestation/3') { if (!str(s.alg) || !s.alg) fail('contradicted', 'signature.alg'); p.alg = s.alg; }
  return p;
}

// What this runtime can verify; an algorithm it lacks is unverifiable, never contradicted (§6.3, §8).
export const IMPLEMENTED = ['Ed25519', ...(() => { try { generateKeyPairSync('ml-dsa-65'); return ['ML-DSA-65']; } catch { return []; } })()];
const keyAlg = (k) => ({ ed25519: 'Ed25519', 'ml-dsa-65': 'ML-DSA-65' })[k.asymmetricKeyType] ?? null;
const spki = (b64) => createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
const sigOk = (bytes, key, b64) => { try { return verify(null, Buffer.from(bytes, 'utf8'), key, Buffer.from(b64 ?? '', 'base64')); } catch { return false; } };

// §6.3 key-first: the algorithm comes from the listed key, never from the receipt.
export function check(receipt, keyList) {
  if (receipt && typeof receipt === 'object' && receipt.signature == null) return 'unverifiable';
  let payload;
  try { payload = rebuild(receipt); } catch (e) { return e.outcome; }
  const s = receipt.signature;
  if (payload.payloadVersion === 'GVP-Attestation/3' && !s.keyId) return 'contradicted';
  const signedAlg = payload.payloadVersion === 'GVP-Attestation/3' ? payload.alg : 'Ed25519';
  const bytes = canonicalize(payload);
  if (keyList === undefined) {                      // integrity only, against the embedded key
    if (!s.publicKey) return 'unverifiable';
    if (!IMPLEMENTED.includes(signedAlg)) return 'unverifiable';   // decided from the signed payload, before parsing
    let k; try { k = spki(s.publicKey); } catch { return 'contradicted'; }
    if (keyAlg(k) !== signedAlg) return 'contradicted';
    return sigOk(bytes, k, s.signature) ? 'verified' : 'contradicted';
  }
  if (keyList === null) return 'unverifiable';
  const entry = (keyList.keys ?? []).find(k => s.keyId ? k.keyId === s.keyId : k.publicKey === s.publicKey);
  if (!entry) return 'contradicted';
  if (signedAlg !== entry.alg) return 'contradicted';
  if (!IMPLEMENTED.includes(entry.alg)) return 'unverifiable';
  if (s.publicKey && s.publicKey !== entry.publicKey) return 'contradicted';
  let k; try { k = spki(entry.publicKey); } catch { return 'contradicted'; }
  if (keyAlg(k) !== entry.alg) return 'contradicted';
  return sigOk(bytes, k, s.signature) ? 'verified' : 'contradicted';
}

// §5: responseHash over the five-member fixed point, `inputs` taken from canonicalInputs.
export const rederives = (r) => !!r && typeof r === 'object' && r.endpoint !== undefined &&
  'sha256:' + createHash('sha256').update(canonicalize({ endpoint: r.endpoint, inputs: r.canonicalInputs, result: r.result, method: r.method, dataVintage: r.dataVintage }), 'utf8').digest('hex') === r.responseHash;

// §7: not-revoked | revoked | unverifiable.
export function revocation(hash, list, keyList, kind = 'responseHash') {
  if (!list || list.revocationListVersion !== 'GVP-Revocation/0.2' || !Array.isArray(list.revoked) || !list.signature || !keyList) return 'unverifiable';
  const entryOk = (e) => e && typeof e === 'object' && (!('kind' in e) || e.kind === 'responseHash' ? str(e.responseHash) : e.kind === 'reportHash' && str(e.reportHash));
  if (!list.revoked.every(entryOk)) return 'unverifiable';
  const { signature: s, ...doc } = list;
  const entry = (keyList.keys ?? []).find(k => s.keyId ? k.keyId === s.keyId : k.publicKey === s.publicKey);
  if (!entry) return 'unverifiable';
  let k; try { k = spki(entry.publicKey); } catch { return 'unverifiable'; }
  if (keyAlg(k) !== entry.alg || !sigOk(canonicalize(doc), k, s.signature)) return 'unverifiable';
  return list.revoked.some(e => ('kind' in e ? e.kind : 'responseHash') === kind && e[kind] === hash) ? 'revoked' : 'not-revoked';
}

function main() {
  const args = process.argv.slice(2);
  const arg = (n) => { const i = args.indexOf(n); return i >= 0 ? JSON.parse(readFileSync(args[i + 1], 'utf8')) : undefined; };
  if (args.includes('--receipt')) {
    const r = arg('--receipt'), keys = arg('--keys'), rev = arg('--revocations');
    const out = { signature: check(r, keys), responseHashRederives: rederives(r) };
    if (rev !== undefined) out.revocation = revocation(r.responseHash, rev, keys);
    console.log(JSON.stringify(out));
    process.exit(out.signature === 'verified' && out.responseHashRederives && (out.revocation ?? 'not-revoked') === 'not-revoked' ? 0 : 1);
  }
  const v = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'vectors', 'receipt.json'), 'utf8'));
  let fails = 0;
  for (const c of v.cases) {
    const kl = { published: v.keyList, live: v.liveKeyList, none: undefined }[c.keyList];
    let payload = null; try { payload = canonicalize(rebuild(c.receipt)); } catch { payload = null; }
    const got = check(c.receipt, kl), re = rederives(c.receipt);
    const want = c.requires && !IMPLEMENTED.includes(c.requires) ? 'unverifiable' : c.expected;
    const ok = got === want && re === c.responseHashRederives && payload === c.expectedPayload;
    if (!ok) { fails++; console.error(`FAIL ${c.name}: ${got}/${re}/${payload === c.expectedPayload} expected ${c.expected}/${c.responseHashRederives}`); }
  }
  for (const c of v.revocationCases) {
    const got = revocation(c.hash, c.list === 'unreachable' ? null : v.revocationLists[c.list], v.keyList, c.kind);
    if (got !== c.expected) { fails++; console.error(`FAIL ${c.name}: ${got} expected ${c.expected}`); }
  }
  console.log(`spec-only verifier: ${v.cases.length} receipt + ${v.revocationCases.length} revocation cases, ${fails} failures`);
  process.exit(fails ? 1 : 0);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
