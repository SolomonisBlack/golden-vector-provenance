// gvp-audit: analysis of ONE served response body for response-provenance readiness.
// Everything here is heuristic and says so. The tool finds closure VIOLATIONS and readiness gaps; it
// never certifies a route as closure-safe (the closure rule is an issuer-side contract a body cannot
// prove). Zero dependencies beyond the GVP reference hash. Deterministic: same body, same report.
import { gvpHash } from '../../ref/js/gvp.mjs';

export const EXTENSION_KEY = 'response-provenance';
export const MAX_SAFE = 9007199254740991; // 2^53 - 1 (I-JSON exact-double range)
export const MAX_DEPTH = 100;

// ---------- raw-text checks (things a parsed value cannot show) ----------

// Integer literals outside +/-(2^53-1) written as JSON numbers: JSON.parse silently rounds them.
export function findUnsafeIntegers(raw) {
  const out = [];
  const re = /(?<![\w.\-"])-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?![\w.])/g;
  let m;
  while ((m = re.exec(raw))) {
    const lit = m[0];
    if (/[.eE]/.test(lit)) continue;              // floats/exponents are not the integer case
    const digits = lit.replace('-', '');
    if (digits.length < 16) continue;             // < 16 digits is always < 2^53
    if (digits.length === 16 && BigInt(digits) <= BigInt(MAX_SAFE)) continue;
    out.push({ literal: lit, offset: m.index });
  }
  return out;
}

// Duplicate member names inside one object: RFC 8785 requires unique names; JSON.parse keeps the last.
// Minimal scanner: tracks a stack of key-sets; strings are skipped correctly (escapes honoured).
export function findDuplicateKeys(raw) {
  const dups = [];
  const stack = []; // each: { keys:Set, expectKey:boolean, isObject:boolean }
  let i = 0;
  const n = raw.length;
  const readString = () => { // raw[i] === '"'; returns the DECODED string so "a" and "a" compare equal
    let j = i + 1;
    while (j < n) {
      const c = raw[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '"') { const lit = raw.slice(i, j + 1); i = j + 1; try { return JSON.parse(lit); } catch { return lit; } }
      j++;
    }
    const rest = raw.slice(i); i = n; return rest;
  };
  while (i < n) {
    const c = raw[i];
    if (c === '{') { stack.push({ keys: new Set(), expectKey: true, isObject: true }); i++; continue; }
    if (c === '[') { stack.push({ keys: null, expectKey: false, isObject: false }); i++; continue; }
    if (c === '}' || c === ']') { stack.pop(); i++; continue; }
    if (c === '"') {
      const top = stack[stack.length - 1];
      const s = readString();
      if (top && top.isObject && top.expectKey) {
        if (top.keys.has(s)) dups.push({ key: s, depth: stack.length });
        top.keys.add(s);
        top.expectKey = false;
      }
      continue;
    }
    if (c === ',') { const top = stack[stack.length - 1]; if (top && top.isObject) top.expectKey = true; i++; continue; }
    i++;
  }
  return dups;
}

// Iterative (explicit stack) so a hostile 20 000-deep body cannot blow the call stack; stops counting
// past MAX_DEPTH + 1 because anything deeper is already a format violation.
export function maxDepth(v) {
  let max = 0;
  const stack = [[v, 0]];
  while (stack.length) {
    const [x, d] = stack.pop();
    if (d > max) max = d;
    if (max > MAX_DEPTH) return max;
    if (Array.isArray(x)) { for (const y of x) stack.push([y, d + 1]); }
    else if (x && typeof x === 'object') { for (const y of Object.values(x)) stack.push([y, d + 1]); }
  }
  return max;
}

// ---------- hidden-input heuristics ----------

const KEY_CLOCK = /(^|[_\-.])(timestamp|generated|computed|consulted|retrieved|fetched|served|processed|requested|created|issued|checked|evaluated|calculated|rendered|queried)([_\-]?(at|on|time|date|utc))?$/i;
const KEY_CLOCK_SHORT = /^(now|time|date|ts|datetime|timestamp|current_?time|server_?time|as_?of_?now)$/i;
const KEY_NONCE = /(^|[_\-])(request|trace|correlation|session|txn|transaction|call|job|run)[_\-]?id$|^(nonce|uuid|guid|id)$|(^|[_\-])nonce$/i;
const KEY_RELATIVE = /(^|[_\-])(age|months|days|years|weeks|hours)[_\-]?(since|until|ago|old|elapsed|remaining|to|in)?|(since|until|elapsed|remaining|next|last|upcoming|recent)[_\-]?(\d+|n)?[_\-]?(months|days|years|weeks|hours|window)/i;
const KEY_PERF = /(^|[_\-])(latency|duration|took|elapsed|response_?time|processing_?time|cache|ttl|expires?|expiry|expiration)([_\-]?(ms|s|at|in))?$/i;
const KEY_RANDOM = /(^|[_\-])(random|seed|salt|entropy)$/i;
const KEY_FRESHNESS = /(^|[_\-])(freshness|staleness|is_?stale|is_?fresh|fresh_?until)$/i;

const VAL_DATETIME = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/;
const VAL_DATE = /^\d{4}(-\d{2}(-\d{2})?)?$/;
const VAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VAL_RELATIVE_PHRASE = /\b(as of (today|now)|right now|currently|(next|last|past|coming|upcoming|previous) (\d+|few|twelve|six|three) (months?|days?|weeks?|years?)|(\d+|\w+) (months?|days?|years?) (ago|old|from now)|today|yesterday|tomorrow|this (week|month|year|quarter))\b/i;
const VAL_HTTP_DATE = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/;

function epochLooksLikeNow(num) {
  if (!Number.isFinite(num)) return null;
  const nowS = Date.now() / 1000;
  const twoYears = 2 * 365 * 86400;
  if (Math.abs(num - nowS) < twoYears) return 'epoch-seconds';
  if (Math.abs(num / 1000 - nowS) < twoYears) return 'epoch-milliseconds';
  return null;
}

// Walk a value; for each member emit signals. `prefix` is the JSON-pointer-ish path.
export function findHiddenInputSignals(value, prefix = '') {
  const signals = [];
  const visit = (v, path, key) => {
    // Key-based signals apply to PRIMITIVE values only. An object or array under a suspicious key
    // (a JSON-schema property named "date", a "window" object) is descended into, never flagged by name.
    const primitive = v === null || typeof v !== 'object';
    if (key !== undefined && primitive) {
      const k = String(key);
      const kinds = [];
      if (KEY_CLOCK.test(k) || KEY_CLOCK_SHORT.test(k)) kinds.push('clock');
      if (KEY_NONCE.test(k)) kinds.push('nonce');
      if (KEY_RELATIVE.test(k)) kinds.push('relative-window');
      if (KEY_PERF.test(k)) kinds.push('runtime');
      if (KEY_RANDOM.test(k)) kinds.push('random');
      if (KEY_FRESHNESS.test(k)) kinds.push('freshness');
      let valueKind = null;
      if (typeof v === 'string') {
        if (VAL_DATETIME.test(v) || VAL_HTTP_DATE.test(v)) valueKind = 'datetime';
        else if (VAL_UUID.test(v)) valueKind = 'uuid';
        else if (v.length <= 64 && VAL_RELATIVE_PHRASE.test(v)) valueKind = 'relative-phrase'; // short labels only; prose descriptions are not values
        else if (VAL_DATE.test(v)) valueKind = 'date';
      } else if (typeof v === 'number' && Number.isInteger(v) && v > 1e9) {
        const e = epochLooksLikeNow(v); if (e) valueKind = e;
      }
      let severity = null;
      if (kinds.length && valueKind && valueKind !== 'date') severity = 'high';
      else if (valueKind === 'datetime' || valueKind === 'uuid' || valueKind === 'relative-phrase' || (valueKind && valueKind.startsWith('epoch'))) severity = 'medium';
      else if (kinds.length && !(kinds.length === 1 && kinds[0] === 'nonce' && /^id$/i.test(k))) severity = kinds.includes('clock') || kinds.includes('relative-window') || kinds.includes('random') ? 'medium' : 'low';
      if (severity) {
        signals.push({
          path, key: k, severity, kinds: kinds.length ? kinds : [valueKind],
          valueKind, sample: typeof v === 'string' ? v.slice(0, 60) : (typeof v === 'number' ? v : typeof v),
          note: kinds.includes('clock') || valueKind === 'datetime' ? 'looks computed from the request-time clock'
            : kinds.includes('nonce') || valueKind === 'uuid' ? 'looks per-call (nonce / request id)'
            : kinds.includes('relative-window') || valueKind === 'relative-phrase' ? 'looks anchored on the calendar day of the request'
            : kinds.includes('runtime') ? 'looks like a runtime measurement or cache metadata'
            : kinds.includes('random') ? 'looks random'
            : kinds.includes('freshness') ? 'freshness metadata; usually derived from the clock'
            : (valueKind && valueKind.startsWith('epoch')) ? 'epoch value near the current time' : 'heuristic'
        });
      }
    }
    if (Array.isArray(v)) v.forEach((x, i) => visit(x, `${path}/${i}`, undefined));
    else if (v && typeof v === 'object') for (const [k2, v2] of Object.entries(v)) visit(v2, `${path}/${k2}`, k2);
  };
  visit(value, prefix, undefined);
  return signals;
}

// ---------- vintage detection ----------
const KEY_VINTAGE = /(^|[_\-.])(data_?vintage|vintage|as_?of|as_?at|effective(_?date)?|tax_?year|fiscal_?year|data_?(date|year|version)|snapshot(_?date)?|dataset_?(date|version)|source_?date|updated|last_?updated|updated_?at|published|edition|release)$/i;
const VINTAGE_GRAMMAR = /^[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?$/;

export function findVintageCandidates(value) {
  const out = [];
  const visit = (v, path, key) => {
    if (key !== undefined && KEY_VINTAGE.test(String(key)) && (typeof v === 'string' || typeof v === 'number')) {
      const s = String(v);
      out.push({ path, key: String(key), value: s.slice(0, 60), fixedPoint2Conformant: VINTAGE_GRAMMAR.test(s) });
    }
    if (Array.isArray(v)) v.forEach((x, i) => visit(x, `${path}/${i}`, undefined));
    else if (v && typeof v === 'object') for (const [k2, v2] of Object.entries(v)) visit(v2, `${path}/${k2}`, k2);
  };
  visit(value, '', undefined);
  return out;
}

// ---------- provenance detection + re-derivation ----------

export function findProvenance(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const ext = body.extensions && body.extensions[EXTENSION_KEY];
  if (ext && typeof ext === 'object' && typeof ext.responseHash === 'string') {
    return { carriage: 'C1', block: ext, resultCarriage: ext.resultCarriage || 'member' };
  }
  const prov = body.provenance;
  if (prov && typeof prov === 'object' && typeof prov.responseHash === 'string') {
    return { carriage: 'C2', block: prov, resultCarriage: 'member' };
  }
  return null;
}

// Recover `result` per carriage. C2 (Tollbooth-style) keeps result at body.result.
export function recoverResult(body, prov) {
  if (prov.carriage === 'C2') return 'result' in body ? { ok: true, result: body.result } : { ok: false, why: 'C2 body has no result member' };
  if (prov.resultCarriage === 'member') return 'result' in body ? { ok: true, result: body.result } : { ok: false, why: '"member" declared but no result member' };
  if (prov.resultCarriage === 'body') {
    if (!body || typeof body !== 'object' || Array.isArray(body)) return { ok: false, why: '"body" declared on a non-object body' };
    const { extensions, ...rest } = body;
    return { ok: true, result: rest };
  }
  return { ok: false, why: `unrecognised resultCarriage ${JSON.stringify(String(prov.resultCarriage)).slice(0, 40)}` };
}

// Outcome per the extension text: verified | contradicted | unverifiable | no_claim.
export function rederive(body, { endpoint, inputs } = {}) {
  const prov = findProvenance(body);
  if (!prov) return { outcome: 'no_claim' };
  const b = prov.block;
  if (typeof b.method !== 'string' || typeof b.dataVintage !== 'string') return { outcome: 'unverifiable', why: 'block lacks method/dataVintage', carriage: prov.carriage };
  const ep = endpoint ?? body.endpoint;
  if (typeof ep !== 'string') return { outcome: 'unverifiable', why: 'endpoint unknown (pass --meta or an endpoint member)', carriage: prov.carriage };
  if (inputs === undefined) return { outcome: 'unverifiable', why: 'inputs unknown (a verifier recomputes over the inputs it sent; supply them in <route>.meta.json)', carriage: prov.carriage };
  const rec = recoverResult(body, prov);
  if (!rec.ok) return { outcome: 'unverifiable', why: rec.why, carriage: prov.carriage };
  let got;
  try { got = gvpHash({ endpoint: ep, inputs, result: rec.result, method: b.method, dataVintage: b.dataVintage }); }
  catch (e) { return { outcome: 'unverifiable', why: 'canonicalization rejected the fixed point: ' + e.message, carriage: prov.carriage }; }
  if (got === b.responseHash) return { outcome: 'verified', carriage: prov.carriage, fixedPointVersion: b.fixedPointVersion ?? null };
  return { outcome: 'contradicted', carriage: prov.carriage, claimed: b.responseHash, rederived: got,
    note: 'altered, or issued in violation of the closure rule, or this verifier is defective on this input' };
}

// ---------- one body ----------

export function analyzeBody(raw, meta = {}) {
  const findings = [];
  let body;
  try { body = JSON.parse(raw); } catch (e) {
    // No parser snippet in the note: a symlinked or mis-named file's first bytes must not leak into a report.
    return { parse: 'invalid-json', error: 'invalid JSON', shape: null, carriage: { recommended: null, note: 'body is not JSON; out of scope for the extension' },
      provenance: null, rederivation: { outcome: 'no_claim' }, vintage: [],
      findings: [{ severity: 'high', kind: 'not-json', note: 'body is not JSON; out of scope for the extension' }] };
  }
  const isObject = body && typeof body === 'object' && !Array.isArray(body);
  const shape = {
    isObject,
    hasResultMember: isObject && Object.prototype.hasOwnProperty.call(body, 'result'),
    hasExtensions: isObject && Object.prototype.hasOwnProperty.call(body, 'extensions'),
    topLevelMembers: isObject ? Object.keys(body) : [],
    depth: maxDepth(body),
  };
  const carriage = !isObject ? { recommended: null, note: 'not a JSON object: cannot attach the extension' }
    : shape.hasResultMember ? { recommended: 'member', note: 'a top-level result member exists; "member" (the default) works unchanged' }
    : { recommended: 'body', note: 'answer fields are at the root; declare resultCarriage:"body" so nothing is wrapped or duplicated. Under "body" the closure rule reaches EVERY top-level member, seller metadata included.' };

  for (const u of findUnsafeIntegers(raw)) findings.push({ severity: 'high', kind: 'i-json', path: null, note: `integer literal ${u.literal} exceeds 2^53-1 as a JSON number; it MUST be a string (RFC 7493). JSON.parse already rounded it.` });
  for (const d of findDuplicateKeys(raw)) findings.push({ severity: 'high', kind: 'duplicate-key', path: null, note: `duplicate member name "${d.key}" (depth ${d.depth}); RFC 8785 requires unique names; the fixed point would be unverifiable` });
  if (shape.depth > MAX_DEPTH) {
    // Too deep to walk safely or to canonicalize: report the format violation and stop here.
    findings.push({ severity: 'high', kind: 'depth', note: `nesting depth > ${MAX_DEPTH}; reference implementations reject it; heuristics skipped` });
    return { parse: 'ok', shape, carriage, provenance: null, rederivation: { outcome: 'unverifiable', why: 'depth exceeds the canonicalization bound' }, vintage: [], findings };
  }

  const signals = isObject ? findHiddenInputSignals(body) : [];
  for (const s of signals) {
    const inResult = shape.hasResultMember && s.path.startsWith('/result/');
    const inProvBlock = s.path.startsWith('/provenance/') || s.path.startsWith('/extensions/');
    const where = inResult ? 'inside result: a hidden input under either carriage'
      : inProvBlock ? 'inside the provenance/extension block: outside the fixed point under "member"; under "body" the extensions member is removed but a provenance block is NOT, so it becomes a hidden input'
      : shape.hasResultMember ? 'outside result: not hashed under "member"; a hidden input under "body"'
      : 'top-level member: a hidden input under "body" (the only carriage available to this shape)';
    findings.push({ severity: s.severity, kind: 'hidden-input', path: s.path, sample: s.sample, signals: s.kinds, note: `${s.note}; ${where}` });
  }

  const vintage = isObject ? findVintageCandidates(body) : [];
  if (isObject && vintage.length === 0) findings.push({ severity: 'medium', kind: 'vintage-missing', note: 'no structured vintage member found; dataVintage completeness (oldest contributing source, at its own precision) is the work the extension requires' });
  for (const v of vintage) if (!v.fixedPoint2Conformant) findings.push({ severity: 'low', kind: 'vintage-grammar', path: v.path, sample: v.value, note: 'vintage candidate is not GVP-FixedPoint/2 grammar (YYYY, YYYY-MM or YYYY-MM-DD); two honest spellings of one vintage hash differently' });

  const prov = isObject ? findProvenance(body) : null;
  const rederivation = isObject ? rederive(body, meta) : { outcome: 'no_claim' };
  if (rederivation.outcome === 'contradicted') findings.push({ severity: 'high', kind: 'contradicted', note: `responseHash does not re-derive (claimed ${rederivation.claimed.slice(0, 19)}..., got ${rederivation.rederived.slice(0, 19)}...): ${rederivation.note}` });
  if (rederivation.outcome === 'unverifiable') findings.push({ severity: 'medium', kind: 'unverifiable', note: `provenance present but not evaluable: ${rederivation.why}` });

  return { parse: 'ok', shape, carriage, provenance: prov ? { carriage: prov.carriage, resultCarriage: prov.resultCarriage, fixedPointVersion: prov.block.fixedPointVersion ?? null } : null,
    rederivation, vintage, findings };
}
