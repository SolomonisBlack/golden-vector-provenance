// Refusal-drift check (property filed by goun7, issue #2, 2026-09-18): the documented refusal list in
// docs/REFUSALS.md and the `throw` sites in ref/js/gvp.mjs + middleware/index.mjs must be exact
// reflections of each other, in both directions, and every listed refusal must reach the digest 0 times.
//   list => code (static):  every entry's message is the literal prefix of a throw in the named module
//   list => code (dynamic): every entry's probe throws, with hooks.beforeDigest counting 0 calls
//   code => list:           every throw in the two modules matches exactly one entry
// Negative self-tests: a fabricated extra throw (no entry) and a dropped entry (throw remains) both FAIL.
// Exit non-zero on any failure.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gvpHash, hooks } from '../ref/js/gvp.mjs';
import { provenanceBlock, attachProvenance, recoverResult, expressProvenance, honoProvenance } from '../middleware/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
let fails = 0;
const ok = (name, cond, extra = '') => { if (cond) console.log(`ok   ${name}`); else { fails++; console.error(`FAIL ${name}${extra ? ' :: ' + extra : ''}`); } };

// ---- the list (from the doc's fenced JSON block) ----
const doc = readFileSync(join(root, 'docs', 'REFUSALS.md'), 'utf8');
const m = doc.match(/```json\s*\n([\s\S]*?)\n```/);
if (!m) { console.error('FAIL docs/REFUSALS.md has no ```json block'); process.exit(1); }
const list = JSON.parse(m[1]);

// ---- the code (static scan of throw sites; the literal prefix of each message) ----
export function scanThrows(source) {
  const out = [];
  const re = /throw new \w*Error\((`|'|")((?:\\.|(?!\1)[^\\])*?)\1/g;
  let x;
  while ((x = re.exec(source))) {
    let msg = x[2];
    const t = msg.indexOf('${');
    if (t >= 0) msg = msg.slice(0, t);          // template literal: prefix up to the first interpolation
    msg = msg.replace(/\\"/g, '"').replace(/\\'/g, "'");
    out.push(msg);
  }
  return out;
}
const MODULES = ['ref/js/gvp.mjs', 'middleware/index.mjs'];
const codeThrows = MODULES.flatMap(mod => scanThrows(readFileSync(join(root, mod), 'utf8')).map(message => ({ module: mod, message })));

// ---- the property, as a pure function so it can be negative-self-tested ----
export function evaluate(entries, throwsInCode) {
  const problems = [];
  for (const t of throwsInCode) {
    const matches = entries.filter(e => e.module === t.module && t.message.startsWith(e.message));
    if (matches.length === 0) problems.push(`code => list: throw "${t.message}" in ${t.module} has no entry in docs/REFUSALS.md`);
    if (matches.length > 1) problems.push(`code => list: throw "${t.message}" matches ${matches.length} entries (${matches.map(e => e.id).join(', ')})`);
  }
  for (const e of entries) {
    const matches = throwsInCode.filter(t => t.module === e.module && t.message.startsWith(e.message));
    if (matches.length === 0) problems.push(`list => code: entry "${e.id}" names a message not thrown in ${e.module}`);
  }
  const ids = entries.map(e => e.id);
  if (new Set(ids).size !== ids.length) problems.push('duplicate entry ids');
  return problems;
}

// ---- dynamic probes: one per entry id; each must throw and reach the digest 0 times ----
const WV = { endpoint: '/v1/echo-sum', inputs: { a: 2, b: 3 }, result: { sum: 5 }, method: 'sum = a + b, integer addition', dataVintage: '2026-07' };
const deep = (() => { let v = { x: 1 }; for (let i = 0; i < 105; i++) v = { n: v }; return v; })();
const PROBES = {
  'nesting-too-deep':             () => gvpHash({ ...WV, result: deep }),
  'non-finite-number':            () => gvpHash({ ...WV, result: { x: Infinity } }),
  'fp-not-object':                () => provenanceBlock([1]),
  'fp-missing-member':            () => provenanceBlock({ endpoint: '/x', inputs: {}, result: {}, method: 'm' }),
  'fp-extra-member':              () => provenanceBlock({ ...WV, extra: 1 }),
  'fp-endpoint-not-string':       () => provenanceBlock({ ...WV, endpoint: 42 }),
  'fp-method-not-string':         () => provenanceBlock({ ...WV, method: {} }),
  'fp-datavintage-not-string':    () => provenanceBlock({ ...WV, dataVintage: 2026 }),
  'carriage-unknown':             () => provenanceBlock(WV, { resultCarriage: 'weird' }),
  'recover-body-not-object':      () => recoverResult([1], 'body'),
  'recover-member-no-result':     () => recoverResult({ sum: 5 }, 'member'),
  'attach-body-not-object':       () => attachProvenance([1], WV),
  'attach-body-carriage-mismatch':() => attachProvenance({ sum: 6 }, WV, { resultCarriage: 'body' }),
  'express-not-function':         () => expressProvenance('nope'),
  'hono-not-function':            () => honoProvenance(123),
};

let count = 0;
hooks.beforeDigest = () => { count++; };
for (const e of list) {
  const probe = PROBES[e.id];
  if (!probe) { ok(`probe exists for "${e.id}"`, false, 'add it to PROBES in this check'); continue; }
  count = 0; let threw = null;
  try { probe(); } catch (err) { threw = err.message; }
  ok(`${e.id}: probe refuses with the listed message`, threw !== null && threw.startsWith(e.message), `threw=${JSON.stringify(threw)} want prefix ${JSON.stringify(e.message)}`);
  ok(`${e.id}: reaches the digest 0 times`, count === 0, `digest x${count}`);
}
hooks.beforeDigest = null;
for (const id of Object.keys(PROBES)) ok(`every probe is listed: ${id}`, list.some(e => e.id === id));

// ---- static round-trip ----
const problems = evaluate(list, codeThrows);
ok(`list <=> code round-trip: ${list.length} entries, ${codeThrows.length} throw sites`, problems.length === 0, problems.join(' | '));

// ---- negative self-tests: the property must be able to fail ----
const withExtraThrow = evaluate(list, [...codeThrows, { module: 'middleware/index.mjs', message: 'seventh refusal nobody documented' }]);
ok('negative: a throw added in code without an entry FAILS', withExtraThrow.length === 1 && /code => list/.test(withExtraThrow[0]));
const withDroppedThrow = evaluate(list, codeThrows.filter(t => !t.message.startsWith('non-finite number')));
ok('negative: an entry whose throw was removed FAILS', withDroppedThrow.length === 1 && /list => code: entry "non-finite-number"/.test(withDroppedThrow[0]));
const renamedBoth = evaluate(list.map(e => e.id === 'non-finite-number' ? { ...e, message: 'renamed refusal' } : e), codeThrows.map(t => t.message.startsWith('non-finite number') ? { ...t, message: 'renamed refusal' } : t));
ok('control: a refusal renamed in code AND list PASSES', renamedBoth.length === 0);

console.log(fails ? `\nrefusal-drift: ${fails} FAILURE(S)` : `\nrefusal-drift: list and code agree in both directions; ${list.length} refusals, all 0 digests`);
process.exit(fails ? 1 : 0);
