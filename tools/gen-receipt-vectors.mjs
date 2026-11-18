// Generate vectors/receipt.json: FULL receipts (not payload objects) with the exact payload string each
// one signs (spec §6.4), the expected key-first outcome (§6.3), whether responseHash re-derives (§5),
// and signed revocation lists with expected statuses (§7). Deterministic: fixed test key, fixed times.
//   node tools/gen-receipt-vectors.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash } from '../ref/js/gvp.mjs';
import { loadPrivateKey, publicKeyB64, attest, receiptPayload, verifyReceipt, revocationListPayload, revocationStatus, ATTESTATION_V2, ATTESTATION_V3 } from '../ref/js/attest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vDir = join(here, '..', 'vectors');
const priv = loadPrivateKey(JSON.parse(readFileSync(join(vDir, 'attestation-key.json'), 'utf8')).privateKeyPkcs8B64);
const publicKey = publicKeyB64(priv);
const KEY_ID = 'issuer-example-ed25519-1';
const mldsaPriv = loadPrivateKey(JSON.parse(readFileSync(join(vDir, 'attestation-key-mldsa65.json'), 'utf8')).privateKeyPkcs8B64);
const MLDSA_KEY_ID = 'issuer-example-mldsa65-1';
const keyList = { issuer: 'issuer.example', keys: [{ keyId: KEY_ID, alg: 'Ed25519', publicKey }, { keyId: MLDSA_KEY_ID, alg: 'ML-DSA-65', publicKey: publicKeyB64(mldsaPriv) }] };
const AT = '2026-11-18T04:00:00.000Z';
const clone = (v) => JSON.parse(JSON.stringify(v));

const FP = { endpoint: '/v1/paycheck', canonicalInputs: { salary: 85000, state: 'TX' }, result: { netAnnual: 68627.5, periodsPerYear: 26 }, method: 'net = salary - federal - fica', dataVintage: '2026-07' };
const hashOf = (r) => gvpHash({ endpoint: r.endpoint, inputs: r.canonicalInputs, result: r.result, method: r.method, dataVintage: r.dataVintage });
const ANCHOR = { standard: 'ERC-8004', chain: 'eip155:8453', chainId: 8453, registry: '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432', agentId: '42' };

// A receipt as an issuer would emit it; `shape` picks the signed-payload shape and what is signed.
function makeReceipt({ shape = 2, fixedPointVersion = 'GVP-FixedPoint/2', anchor = ANCHOR, omitAnchor = false, keyId = true, mldsa = false }) {
  const r = {
    receiptVersion: 'GVP-Receipt/0.2',
    issuer: { name: 'Example Issuer', service: 'issuer.example', url: 'https://issuer.example' },
    issuedAt: AT, tool: 'paycheck', ...clone(FP),
    responseHash: null,
    trustModel: 'recompute-trust',
    goldenVector: { reference: 'g', reproduceUrl: 'https://issuer.example/v1/golden/paycheck' },
    recheckUrl: 'https://issuer.example/v1/verify-hash',
    howToVerify: ['recompute', 're-derive', 'tamper-check', 'identity'],
    disclaimer: 'test vector'
  };
  r.responseHash = hashOf(r);
  if (shape >= 2) r.fixedPointVersion = fixedPointVersion;
  if (!omitAnchor) r.onChainAnchor = anchor;
  const sig = { payloadVersion: shape === 1 ? undefined : shape === 2 ? ATTESTATION_V2 : ATTESTATION_V3, alg: mldsa ? 'ML-DSA-65' : 'Ed25519' };
  if (shape === 1) delete sig.payloadVersion;
  r.signature = sig;                                   // receiptPayload reads payloadVersion/alg from here
  const s = attest(receiptPayload(r), mldsa ? mldsaPriv : priv, keyId ? { keyId: mldsa ? MLDSA_KEY_ID : KEY_ID } : {});
  r.signature = { ...s, ...(sig.payloadVersion ? { payloadVersion: sig.payloadVersion } : {}), signed: 'see spec §6.4' };
  return r;
}

const cases = [];
function add(name, receipt, expected, note, { keyList: kl = 'published', requires } = {}) {
  const c = { name, keyList: kl, ...(requires ? { requires } : {}), receipt, expected, responseHashRederives: receipt && typeof receipt === 'object' && receipt.endpoint !== undefined ? hashOf(receipt) === receipt.responseHash : false };
  try { c.expectedPayload = receiptPayload(receipt); } catch { c.expectedPayload = null; }
  if (note) c.note = note;
  const got = verifyReceipt(receipt, kl === 'none' ? {} : { keyList: kl === 'live' ? liveKeyList : keyList });
  if (got.outcome !== expected) throw new Error(`generator self-check: ${name} gave ${got.outcome} (${got.reason}), expected ${expected}`);
  cases.push(c);
}
const edit = (base, f) => { const r = clone(base); f(r); return r; };

// ---- positives -------------------------------------------------------------------------------------
const v2 = makeReceipt({ shape: 2 });
add('v1-legacy-matched-by-publicKey', makeReceipt({ shape: 1, keyId: false }), 'verified', 'No payloadVersion: shape /1, no fixedPointVersion member signed, no keyId (matched by embedded publicKey).');
add('v2-fixedpoint-1', makeReceipt({ shape: 2, fixedPointVersion: 'GVP-FixedPoint/1' }), 'verified');
add('v2-fixedpoint-2', v2, 'verified', 'The shape x402toll.com issues today: /2 signing GVP-FixedPoint/2.');
add('v2-anchor-null', makeReceipt({ shape: 2, anchor: null }), 'verified', 'onChainAnchor null: agentId is JSON null in the payload.');
add('v2-anchor-absent', makeReceipt({ shape: 2, omitAnchor: true }), 'verified', 'No onChainAnchor member: agentId is JSON null in the payload.');
add('v3-ed25519', makeReceipt({ shape: 3 }), 'verified', '/3 signs alg, read from signature.alg.');
add('v3-ml-dsa-65', makeReceipt({ shape: 3, mldsa: true }), 'verified', 'ML-DSA-65 (hedged, so this signature is verify-only and changes on every regeneration). A verifier without ML-DSA-65 reports unverifiable (spec §8).', { requires: 'ML-DSA-65' });
add('v2-integrity-only-no-key-list', v2, 'verified', 'No key list: verified against the embedded publicKey, scope integrity (not identity).', { keyList: 'none' });

// ---- unbound members: changing them does NOT break the signature (documented, spec §5 coverage) -------
add('unbound-issuer-name-changed', edit(v2, r => { r.issuer.name = 'Someone Else'; }), 'verified', 'issuer.name and issuer.url are not signed. Only issuer.service is.');
add('unbound-anchor-registry-changed', edit(v2, r => { r.onChainAnchor.registry = '0x0000000000000000000000000000000000000000'; r.onChainAnchor.chain = 'eip155:1'; }), 'verified', 'Only onChainAnchor.agentId is signed. A verifier takes registry and chain from its own context, never from the receipt.');
add('unbound-tool-howToVerify-recheckUrl-changed', edit(v2, r => { r.tool = 'x'; r.howToVerify = ['x']; r.recheckUrl = 'https://elsewhere.example/'; r.goldenVector.reproduceUrl = 'https://elsewhere.example/'; }), 'verified', 'Presentation members are not signed.');
add('unbound-signature-signed-and-note-changed', edit(v2, r => { r.signature.signed = 'anything'; r.signature.note = 'anything'; }), 'verified', 'signature.signed is an informational recipe, not the authority (spec §6.4 is).');
add('hash-bound-result-changed', edit(v2, r => { r.result.netAnnual = 1; }), 'verified', 'result, canonicalInputs and method are bound only through responseHash: the signature still verifies, and responseHashRederives is false. A verifier MUST run both checks.');

// ---- negatives -------------------------------------------------------------------------------------
add('issuer-service-changed', edit(v2, r => { r.issuer.service = 'evil.example'; }), 'contradicted');
add('issuer-as-string', edit(v2, r => { r.issuer = 'issuer.example'; }), 'contradicted', 'issuer must be an object; the payload member comes from issuer.service only.');
add('agentId-changed', edit(v2, r => { r.onChainAnchor.agentId = '43'; }), 'contradicted');
add('anchor-stripped', edit(v2, r => { delete r.onChainAnchor; }), 'contradicted', 'Stripping the anchor makes agentId null, which is not what was signed.');
add('issuedAt-reformatted-same-instant', edit(v2, r => { r.issuedAt = '2026-11-18T04:00:00Z'; }), 'contradicted', 'issuedAt is the exact string; a reformatted equal instant is different bytes.');
add('fixedPointVersion-stripped', edit(v2, r => { delete r.fixedPointVersion; }), 'contradicted', 'No default at L2: the §2.1.1 absent-means-/1 rule is for unsigned use only.');
add('fixedPointVersion-forged', edit(v2, r => { r.fixedPointVersion = 'GVP-FixedPoint/1'; }), 'contradicted');
add('payloadVersion-stripped-downgrade', edit(v2, r => { delete r.signature.payloadVersion; }), 'contradicted', 'Rebuilt as /1, which was not signed. A verifier MUST NOT then try /2.');
add('responseHash-changed', edit(v2, r => { r.responseHash = 'sha256:' + '0'.repeat(64); }), 'contradicted');
add('keyId-rewritten', edit(v2, r => { r.signature.keyId = 'not-listed'; }), 'contradicted');
add('payloadVersion-unknown', edit(v2, r => { r.signature.payloadVersion = 'GVP-Attestation/9'; }), 'unverifiable');
add('unsigned-receipt', edit(v2, r => { r.signature = null; }), 'unverifiable', 'L1 only: nothing to attest. A consumer that requires L2 rejects it by its own policy.');
add('v3-alg-stripped', edit(makeReceipt({ shape: 3 }), r => { delete r.signature.alg; }), 'contradicted');

// ---- one live receipt, verified against the issuer's published key list ------------------------------
const live = JSON.parse(readFileSync(join(here, 'fixtures', 'x402toll-receipt-2026-11-18.json'), 'utf8'));
const liveKeyList = JSON.parse(readFileSync(join(here, 'fixtures', 'x402toll-gvp-keys-2026-11-18.json'), 'utf8'));
add('live-x402toll-receipt', live, 'verified', 'A paid mainnet receipt from x402toll.com (2026-11-18, the one reproduced on x402-foundation/x402#2887), against its /.well-known/gvp-keys.json.', { keyList: 'live' });

// ---- revocation lists (spec §7) -----------------------------------------------------------------------
const signList = (doc) => ({ ...doc, signature: attest(revocationListPayload(doc), priv, { keyId: KEY_ID }) });
const REVOKED_HASH = v2.responseHash;
const REPORT_HASH = 'sha256:' + 'ab'.repeat(32);
const revocationLists = {
  empty: signList({ revocationListVersion: 'GVP-Revocation/0.2', issuer: 'issuer.example', updatedAt: AT, revoked: [] }),
  one: signList({ revocationListVersion: 'GVP-Revocation/0.2', issuer: 'issuer.example', updatedAt: AT, revoked: [
    { responseHash: REVOKED_HASH, reason: 'test: wrong dataset row', revokedAt: AT, supersededBy: null },
    { kind: 'reportHash', reportHash: REPORT_HASH, reason: 'test: report revoked', revokedAt: AT } ] })
};
revocationLists.tampered = { ...clone(revocationLists.one), revoked: [] };
revocationLists.badKind = signList({ revocationListVersion: 'GVP-Revocation/0.2', issuer: 'issuer.example', updatedAt: AT, revoked: [
  { kind: null, responseHash: v2.responseHash, reason: 'test: kind null', revokedAt: AT } ] });
revocationLists.unsigned = { ...clone(revocationLists.empty), signature: null };
const revocationCases = [
  { name: 'empty-signed-list-not-revoked', list: 'empty', hash: v2.responseHash, expected: 'not-revoked' },
  { name: 'listed-responseHash-revoked', list: 'one', hash: v2.responseHash, expected: 'revoked' },
  { name: 'listed-reportHash-revoked', list: 'one', hash: REPORT_HASH, kind: 'reportHash', expected: 'revoked' },
  { name: 'reportHash-does-not-match-responseHash-kind', list: 'one', hash: REPORT_HASH, expected: 'not-revoked' },
  { name: 'tampered-list-unverifiable', list: 'tampered', hash: v2.responseHash, expected: 'unverifiable', note: 'Removing an entry breaks the signature; the status is unverifiable, never not-revoked.' },
  { name: 'unreachable-list-unverifiable', list: 'unreachable', hash: v2.responseHash, expected: 'unverifiable' },
  { name: 'entry-kind-null-unverifiable', list: 'badKind', hash: v2.responseHash, expected: 'unverifiable', note: 'kind must be absent, "responseHash" or "reportHash"; any other value (null included) makes the list malformed.' },
  { name: 'unsigned-list-unverifiable', list: 'unsigned', hash: v2.responseHash, expected: 'unverifiable' }
];
for (const c of revocationCases) {
  const got = revocationStatus(c.hash, c.list === 'unreachable' ? null : revocationLists[c.list], { keyList, kind: c.kind });
  if (got.status !== c.expected) throw new Error(`generator self-check: ${c.name} gave ${got.status}`);
}

const out = {
  description: 'GVP receipt vectors (spec §6.4, §5, §7). Ed25519 cases regenerate byte for byte; the ML-DSA-65 case is verify-only (hedged signature). Each case is a FULL receipt. A conformant verifier rebuilds the payload by the §6.4 table, reproduces expectedPayload byte for byte (null = the table refuses to build one), reaches `expected` (§6.3), and recomputes responseHash (§5) to match responseHashRederives. keyList: "published" = keyList below, "live" = liveKeyList, "none" = integrity-only.',
  key: 'vectors/attestation-key.json (throwaway test key, NOT a production key)',
  keyList, liveKeyList,
  cases, revocationLists, revocationCases
};
writeFileSync(join(vDir, 'receipt.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`vectors/receipt.json: ${cases.length} receipt cases, ${revocationCases.length} revocation cases`);
