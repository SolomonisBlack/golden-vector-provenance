// gvp-audit: compare two served bodies of the SAME route (same inputs) and classify what moved.
// Two samples of a closed function on identical inputs must be byte-identical after JCS; anything that
// differs is a candidate hidden input, or a data/vintage change the seller must be able to explain.
import { canonicalize } from '../../ref/js/gvp.mjs';
import { findHiddenInputSignals } from './analyze.mjs';

export function deepDiff(a, b, path = '') {
  const out = [];
  const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
  if (isObj(a) && isObj(b)) {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!(k in a)) out.push({ path: `${path}/${k}`, change: 'added' });
      else if (!(k in b)) out.push({ path: `${path}/${k}`, change: 'removed' });
      else out.push(...deepDiff(a[k], b[k], `${path}/${k}`));
    }
    return out;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return [{ path, change: 'array-length', from: a.length, to: b.length }];
    a.forEach((x, i) => out.push(...deepDiff(x, b[i], `${path}/${i}`)));
    return out;
  }
  if (canonicalize(a) !== canonicalize(b)) out.push({ path, change: 'value', from: clip(a), to: clip(b) });
  return out;
}
const clip = (v) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s === undefined ? 'undefined' : s.slice(0, 60); };

// Classify each changed path with the hidden-input heuristics (key + both values). A change whose key or
// value looks clock/nonce-like is a hidden input; a change on a vintage-like key is a vintage move; the
// rest is "data changed" which is fine only if the seller can name the vintage that moved.
export function classifyDiff(a, b) {
  const changes = deepDiff(a, b);
  const sigA = new Map(findHiddenInputSignals(a).map(s => [s.path, s]));
  const sigB = new Map(findHiddenInputSignals(b).map(s => [s.path, s]));
  return changes.map(c => {
    const s = sigA.get(c.path) || sigB.get(c.path);
    const key = c.path.split('/').pop();
    const kind = s ? (s.kinds.includes('clock') || s.valueKind === 'datetime' ? 'clock' : s.kinds.includes('nonce') || s.valueKind === 'uuid' ? 'nonce'
      : s.kinds.includes('relative-window') || s.valueKind === 'relative-phrase' ? 'relative-window' : s.kinds.includes('runtime') ? 'runtime' : 'hidden-input')
      : /vintage|as_?of|updated|effective|snapshot|year|date/i.test(key) ? 'vintage'
      : 'data';
    return { ...c, kind, severity: kind === 'data' || kind === 'vintage' ? 'medium' : 'high' };
  });
}

export function identical(a, b) { return canonicalize(a) === canonicalize(b); }
