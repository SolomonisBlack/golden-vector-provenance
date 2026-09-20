// gvp-audit tests: library units + CLI end-to-end on generated fixtures. No network, no deps.
// Fixtures are generated here from the reference hash so every provenance case is internally consistent.
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { gvpHash } from '../ref/js/gvp.mjs';
import { analyzeBody, findUnsafeIntegers, findDuplicateKeys, findHiddenInputSignals, rederive, findVintageCandidates } from './lib/analyze.mjs';
import { classifyDiff, identical } from './lib/diff.mjs';
import { auditRoute, summarize, toMarkdown } from './lib/report.mjs';
import { loadBodiesDir } from './lib/load.mjs';

let fails = 0;
const ok = (name, cond, extra = '') => { if (cond) console.log(`ok   ${name}`); else { fails++; console.error(`FAIL ${name} ${extra}`); } };
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `\n  got : ${JSON.stringify(got)}\n  want: ${JSON.stringify(want)}`);

// ---------- fixtures ----------
const WV = { endpoint: '/v1/echo-sum', inputs: { a: 2, b: 3 }, result: { sum: 5 }, method: 'sum = a + b, integer addition', dataVintage: '2026-07' };
const WV_HASH = 'sha256:81ea1f2227fd9df5b868954e6d26d091810352f148dade483b260844788ede03';
eq('worked vector reproduces', gvpHash(WV), WV_HASH);

const c1Member = { result: { sum: 5 }, extensions: { 'response-provenance': { responseHash: WV_HASH, fixedPointVersion: 'GVP-FixedPoint/2', method: WV.method, dataVintage: WV.dataVintage } } };
const c1Body = { sum: 5, extensions: { 'response-provenance': { responseHash: WV_HASH, fixedPointVersion: 'GVP-FixedPoint/2', resultCarriage: 'body', method: WV.method, dataVintage: WV.dataVintage } } };
const c1Tampered = JSON.parse(JSON.stringify(c1Member)); c1Tampered.result.sum = 6;
// Tollbooth-style C2 (provenance block at root, result member, request-time computedAt in the block)
const tbFP = { endpoint: '/v1/paycheck', inputs: { salary: 85000, state: 'TX' }, result: { netPerCheck: 2639.52, federalTax: 9870 }, method: 'brackets + FICA', dataVintage: 'July 2026' };
const c2 = (computedAt) => ({ endpoint: tbFP.endpoint, result: tbFP.result, provenance: { method: tbFP.method, dataVintage: tbFP.dataVintage, deterministic: true, responseHash: gvpHash(tbFP), computedAt } });
// root-level REST body with clock members (the kopko13 case)
const flatClock = { company: 'ACME', riskScore: 0.42, monthsSinceFiscalYearEnd: 7, consultedAt: '2026-09-17T11:09:26Z', window: 'next 12 months', asOf: '2026-09-01' };
const flatClean = { company: 'ACME', riskScore: 0.42, asOf: '2026-09-01', sources: [{ ref: 'registry', asOf: '2026-09' }] };
const wei = '{"result":{"balanceWei":123456789012345678901,"ok":true},"asOf":"2026-09"}';
const dupRaw = '{"result":{"a":1,"a":2},"asOf":"2026-09"}';
const deep = (() => { let v = { x: 1 }; for (let i = 0; i < 105; i++) v = { n: v }; return { result: v, asOf: '2026' }; })();

// ---------- unit: raw checks ----------
eq('unsafe integer found', findUnsafeIntegers(wei).map(u => u.literal), ['123456789012345678901']);
eq('16-digit safe integer not flagged', findUnsafeIntegers('{"a":9007199254740991}'), []);
eq('16-digit unsafe integer flagged', findUnsafeIntegers('{"a":9007199254740993}').length, 1);
eq('float not flagged', findUnsafeIntegers('{"a":1234567890123456.5}'), []);
eq('digits inside strings not flagged', findUnsafeIntegers('{"a":"12345678901234567890"}'), []);
eq('duplicate key found', findDuplicateKeys(dupRaw).map(d => d.key), ['a']);
eq('no false duplicate across objects', findDuplicateKeys('{"a":{"k":1},"b":{"k":2}}'), []);
eq('escaped quote in key handled', findDuplicateKeys('{"a\\"b":1,"a\\"b":2}').length, 1);

// ---------- unit: hidden-input heuristics ----------
const sig = findHiddenInputSignals(flatClock);
ok('consultedAt = high (clock key + datetime value)', sig.find(s => s.key === 'consultedAt')?.severity === 'high');
ok('monthsSinceFiscalYearEnd = relative-window', sig.find(s => s.key === 'monthsSinceFiscalYearEnd')?.kinds.includes('relative-window'));
ok('window "next 12 months" = relative phrase', sig.find(s => s.key === 'window')?.valueKind === 'relative-phrase');
ok('asOf date-only is NOT a hidden-input signal', !sig.find(s => s.key === 'asOf'));
ok('company/riskScore not flagged', !sig.find(s => s.key === 'company' || s.key === 'riskScore'));
ok('clean flat body has no signals', findHiddenInputSignals(flatClean).length === 0);
ok('uuid value = medium', findHiddenInputSignals({ ref: '3fa85f64-5717-4562-b3fc-2c963f66afa6' })[0]?.severity === 'medium');
ok('epoch-ms near now flagged', findHiddenInputSignals({ t: Date.now() }).length === 1);
ok('old epoch not flagged', findHiddenInputSignals({ t: 946684800 }).length === 0);
ok('plain id not flagged', findHiddenInputSignals({ id: 'ACME-1' }).length === 0);
// live-run regressions (2026-09-18, x402toll.com/v1/catalog): schema property objects and prose must not trip the rules
ok('schema property object under "date"/"age" keys not flagged', findHiddenInputSignals({ inputSchema: { properties: { date: { type: 'string' }, age: { type: 'integer', minimum: 0 }, years: { type: 'number' } } } }).length === 0);
ok('long prose containing "over the years" not flagged', findHiddenInputSignals({ description: 'Net present value and internal rate of return for a cash-flow series over a number of years, discounted at the stated rate; this year or any year.' }).length === 0);
ok('short label "next 12 months" still flagged', findHiddenInputSignals({ window: 'next 12 months' }).length === 1);
ok('age as a number is medium (review), not high', findHiddenInputSignals({ age: 45 })[0]?.severity === 'medium');

// ---------- unit: vintage ----------
const vin = findVintageCandidates(c2('2026-09-17T00:00:00Z'));
ok('dataVintage found as vintage candidate', vin.some(v => v.key === 'dataVintage'));
ok('"July 2026" flagged as not /2 grammar', vin.find(v => v.key === 'dataVintage')?.fixedPoint2Conformant === false);
ok('2026-09 is /2 grammar', findVintageCandidates(flatClean)[0].fixedPoint2Conformant === true);

// ---------- unit: re-derivation, both carriages ----------
eq('C1 member verified', rederive(c1Member, { endpoint: WV.endpoint, inputs: WV.inputs }).outcome, 'verified');
eq('C1 body carriage verified', rederive(c1Body, { endpoint: WV.endpoint, inputs: WV.inputs }).outcome, 'verified');
eq('C1 tampered contradicted', rederive(c1Tampered, { endpoint: WV.endpoint, inputs: WV.inputs }).outcome, 'contradicted');
eq('C2 verified', rederive(c2('x'), { inputs: tbFP.inputs }).outcome, 'verified');
eq('no inputs → unverifiable', rederive(c1Member, { endpoint: WV.endpoint }).outcome, 'unverifiable');
eq('no provenance → no_claim', rederive(flatClean, {}).outcome, 'no_claim');
eq('unknown resultCarriage → unverifiable', rederive({ ...c1Body, extensions: { 'response-provenance': { ...c1Body.extensions['response-provenance'], resultCarriage: 'weird' } } }, { endpoint: WV.endpoint, inputs: WV.inputs }).outcome, 'unverifiable');

// ---------- unit: analyzeBody ----------
const aWei = analyzeBody(wei);
ok('i-json finding on wei body', aWei.findings.some(f => f.kind === 'i-json'));
ok('duplicate-key finding', analyzeBody(dupRaw).findings.some(f => f.kind === 'duplicate-key'));
ok('depth finding', analyzeBody(JSON.stringify(deep)).findings.some(f => f.kind === 'depth'));
eq('flat body → carriage body', analyzeBody(JSON.stringify(flatClean)).carriage.recommended, 'body');
eq('result member → carriage member', analyzeBody(JSON.stringify(c1Member)).carriage.recommended, 'member');
eq('array body → not object', analyzeBody('[1,2]').carriage.recommended, null);
eq('invalid json → parse invalid', analyzeBody('{nope').parse, 'invalid-json');
const aC2 = analyzeBody(JSON.stringify(c2('2026-09-17T11:09:26Z')), { inputs: tbFP.inputs });
ok('C2 computedAt flagged inside provenance block', aC2.findings.some(f => f.kind === 'hidden-input' && f.path === '/provenance/computedAt' && /provenance block is NOT/.test(f.note)));
eq('C2 re-derivation verified despite computedAt (outside fixed point under member)', aC2.rederivation.outcome, 'verified');
ok('C2 dataVintage grammar low finding', aC2.findings.some(f => f.kind === 'vintage-grammar'));

// ---------- unit: diff ----------
const drift = classifyDiff(c2('2026-09-17T11:09:26Z'), c2('2026-09-17T11:10:00Z'));
eq('only computedAt drifted', drift.map(d => d.path), ['/provenance/computedAt']);
eq('drift classified as clock', drift[0].kind, 'clock');
ok('identical after JCS regardless of key order', identical({ a: 1, b: 2 }, { b: 2, a: 1 }));
const dataDrift = classifyDiff(flatClean, { ...flatClean, riskScore: 0.5 });
eq('data change classified as data/medium', [dataDrift[0].kind, dataDrift[0].severity], ['data', 'medium']);

// ---------- route verdicts ----------
const rClean = auditRoute({ id: 'clean', samples: [{ name: '1', raw: JSON.stringify(flatClean) }, { name: '2', raw: JSON.stringify(flatClean) }] });
eq('clean two-sample route → no-closure-violation-found', rClean.verdict, 'no-closure-violation-found');
const rClock = auditRoute({ id: 'clock', samples: [{ name: '1', raw: JSON.stringify(flatClock) }] });
eq('clock route → hidden-inputs-found', rClock.verdict, 'hidden-inputs-found');
const rC2 = auditRoute({ id: 'tb', inputs: tbFP.inputs, samples: [{ name: '1', raw: JSON.stringify(c2('2026-09-17T11:09:26Z')) }, { name: '2', raw: JSON.stringify(c2('2026-09-17T11:10:00Z')) }] });
eq('C2 with drifting computedAt → hidden-inputs-found (drift is high)', rC2.verdict, 'hidden-inputs-found');
eq('C2 rederivation still verified', rC2.rederivation.outcome, 'verified');
const rTamper = auditRoute({ id: 't', endpoint: WV.endpoint, inputs: WV.inputs, samples: [{ name: '1', raw: JSON.stringify(c1Tampered) }] });
eq('contradicted → hidden-inputs-found', rTamper.verdict, 'hidden-inputs-found');
eq('array → out-of-scope', auditRoute({ id: 'arr', samples: [{ name: '1', raw: '[1]' }] }).verdict, 'out-of-scope');
const rHtml = auditRoute({ id: 'html', samples: [{ name: '1', raw: '<!doctype html><p>402 Payment Required</p>' }] });
eq('non-JSON body → out-of-scope', rHtml.verdict, 'out-of-scope');
ok('non-JSON route renders in markdown without throwing', /out-of-scope/.test(toMarkdown({ tool: { version: 't', spec: 's' }, generatedAt: 'now', summary: summarize([rHtml]), routes: [rHtml] })));
const rNone = auditRoute({ id: 'none2', samples: [] });
ok('no-sample route renders in markdown', /unknown/.test(toMarkdown({ tool: { version: 't', spec: 's' }, generatedAt: 'now', summary: summarize([rNone]), routes: [rNone] })));
eq('no samples → unknown', auditRoute({ id: 'none', samples: [] }).verdict, 'unknown');
const summ = summarize([rClean, rClock, rC2, rTamper]);
eq('summary counts', [summ.routes, summ.noClosureViolationFound, summ.hiddenInputsFound, summ.provenance.verified, summ.provenance.contradicted, summ.driftedBetweenSamples], [4, 1, 3, 1, 1, 1]);
const md = toMarkdown({ tool: { version: 't', spec: 's' }, generatedAt: 'now', summary: summ, routes: [rClean, rClock, rC2, rTamper] });
ok('markdown never says closure-safe', !/closure-safe/i.test(md.replace(/no-closure-violation-found|closure-safe by handler/g, '')));
ok('markdown mentions the wording rule', /cannot prove a route closed/.test(md));
ok('markdown is ASCII-only (PowerShell 5.1 consoles garble UTF-8)', /^[\x00-\x7F]*$/.test(md));

// ---------- security-review regressions (2026-09-18) ----------
import { safeAuditRoute, cell } from './lib/report.mjs';
const hostile = '['.repeat(20000) + ']'.repeat(20000);
let deepVerdict = null; try { deepVerdict = auditRoute({ id: 'deep1', samples: [{ name: '1', raw: hostile }] }).verdict; } catch (e) { deepVerdict = 'THREW ' + e.message; }
eq('20000-deep body does not crash; single sample', deepVerdict, 'out-of-scope');
const deepObj = JSON.stringify(deep);
let deep2 = null; try { deep2 = auditRoute({ id: 'deep2', samples: [{ name: '1', raw: deepObj }, { name: '2', raw: deepObj }] }).verdict; } catch (e) { deep2 = 'THREW ' + e.message; }
eq('over-depth body with two samples -> format-violation, no crash', deep2, 'format-violation');
ok('safeAuditRoute never throws', safeAuditRoute({ id: 'x', samples: [{ name: '1', raw: 'null' }] }).verdict !== undefined);
// keys/values chosen so each produces a finding row: a datetime under a piped key, a clock key with a
// newline+table+heading payload, a clock key with backticks
const evil = { 'a|b': '2026-09-17T11:09:26Z', consultedAt: 'x\n| fake | row |\n### injected\n', generatedAt: '`code`' };
const rEvil = auditRoute({ id: 'ev|il\nheading', samples: [{ name: '1', raw: JSON.stringify(evil) }] });
const mdEvil = toMarkdown({ tool: { version: 't', spec: 's' }, generatedAt: 'now', summary: summarize([rEvil]), routes: [rEvil] });
ok('markdown: no raw newline from body values inside a table row', !/\| fake \| row \|/.test(mdEvil) && !/\n### injected/.test(mdEvil));
ok('markdown: pipes in paths are escaped', /a\\\|b/.test(mdEvil));
ok('markdown: no raw backticks from values', !/`code`/.test(mdEvil));
{
  const rImg = auditRoute({ id: 'img', samples: [{ name: '1', raw: '{"result":{"a":1,"a":2},"<img src=x onerror=1>":"2026-09-17T11:09:26Z"}' }] });
  const mdImg = toMarkdown({ tool: { version: 't', spec: 's' }, generatedAt: 'now', summary: summarize([rImg]), routes: [rImg] });
  ok('markdown: no inline HTML from keys (< is escaped everywhere)', !/<img/.test(mdImg) && /&lt;img/.test(mdImg));
}
eq('cell() flattens newlines and caps length', cell('a\nb\rc' + 'x'.repeat(500)).length <= 160 && /^a b c/.test(cell('a\nb\rc')), true);
eq('duplicate keys detected across \\u escapes', findDuplicateKeys('{"a":1,"\\u0061":2}').length, 1);
ok('not-json note carries no source snippet', !/BEGIN|Unexpected token/.test(JSON.stringify(analyzeBody('-----BEGIN PRIVATE KEY-----').findings)));
{
  const d2 = mkdtempSync(join(tmpdir(), 'gvp-audit-meta-'));
  writeFileSync(join(d2, 'r.json'), JSON.stringify(flatClean));
  writeFileSync(join(d2, 'r.meta.json'), '{not json');
  const routes = loadBodiesDir(d2);
  ok('malformed meta does not crash the loader and is reported', routes.length === 1 && /not valid JSON/.test(routes[0].metaError || ''));
}
import { MAX_TIMES, MAX_BODY_BYTES } from './lib/fetch.mjs';
ok('fetch caps exist (times <= 10, body <= 16 MiB)', MAX_TIMES === 10 && MAX_BODY_BYTES === 16 * 1024 * 1024);

// ---------- ambiguous absence (stillmarcus24, x402#2887 2026-09-19): KNOWN-ANSWER self-check ----------
// Their companion rule: a detector for this class must reproduce a known answer or its run is void.
// Known answer, from their own description of their corpus: rows carrying reason "no_live_payto_resolved"
// WITH a sibling discovery_ok boolean are NOT ambiguous (the sibling disambiguates); the same string with
// no sibling IS. A detector that flags the first is broken and must not report a number.
{
  const { findAmbiguousAbsence } = await import('./lib/analyze.mjs');
  const disambiguated = { door: 'https://a.example', reason: 'no_live_payto_resolved', discovery_ok: false };
  const ambiguous = { door: 'https://a.example', reason: 'no_live_payto_resolved' };
  const corpus = [disambiguated, disambiguated, ambiguous, { door: 'x', reason: 'none' }, { door: 'y', reason: 'no_live_payto_resolved', discovery_ok: true }];
  eq('known answer: sibling boolean disambiguates (not flagged)', findAmbiguousAbsence(disambiguated).length, 0);
  eq('known answer: same string with no sibling is flagged', findAmbiguousAbsence(ambiguous).map(a => a.path), ['/reason']);
  eq('known answer over the corpus: exactly 2 of 5 rows', corpus.filter(r => findAmbiguousAbsence(r).length).length, 2);
  ok('ordinary strings are not flagged', findAmbiguousAbsence({ company: 'ACME', reason: 'sanctions match' }).length === 0);
  ok('null with a status sibling is not flagged', findAmbiguousAbsence({ value: null, status: 'not-found' }).length === 0);
  ok('analyzeBody surfaces the class as low', analyzeBody(JSON.stringify(ambiguous)).findings.some(f => f.kind === 'ambiguous-absence' && f.severity === 'low'));
  ok('verdict unaffected by a low finding', auditRoute({ id: 'amb', samples: [{ name: '1', raw: JSON.stringify(ambiguous) }] }).verdict === 'no-closure-violation-found');
}

// ---------- determinism ----------
const r1 = JSON.stringify(auditRoute({ id: 'd', samples: [{ name: '1', raw: JSON.stringify(flatClock) }] }));
const r2 = JSON.stringify(auditRoute({ id: 'd', samples: [{ name: '1', raw: JSON.stringify(flatClock) }] }));
ok('same body → identical report', r1 === r2);

// ---------- CLI end-to-end on a fixtures dir ----------
const dir = mkdtempSync(join(tmpdir(), 'gvp-audit-'));
writeFileSync(join(dir, 'echo-sum.json'), JSON.stringify(c1Member));
writeFileSync(join(dir, 'echo-sum.meta.json'), JSON.stringify({ endpoint: WV.endpoint, inputs: WV.inputs }));
writeFileSync(join(dir, 'paycheck.1.json'), JSON.stringify(c2('2026-09-17T11:09:26Z')));
writeFileSync(join(dir, 'paycheck.2.json'), JSON.stringify(c2('2026-09-17T11:10:00Z')));
writeFileSync(join(dir, 'paycheck.meta.json'), JSON.stringify({ inputs: tbFP.inputs }));
writeFileSync(join(dir, 'risk.json'), JSON.stringify(flatClock));
writeFileSync(join(dir, 'clean.json'), JSON.stringify(flatClean));
writeFileSync(join(dir, 'wei.json'), wei);
const loaded = loadBodiesDir(dir);
eq('loader groups samples + meta', loaded.map(r => `${r.id}:${r.samples.length}:${r.inputs ? 'i' : '-'}`).sort(), ['clean:1:-', 'echo-sum:1:i', 'paycheck:2:i', 'risk:1:-', 'wei:1:-']);
const cli = join(dirname(fileURLToPath(import.meta.url)), 'cli.mjs');
const outJson = join(dir, 'report.json'), outMd = join(dir, 'report.md');
const stdout = execFileSync(process.execPath, [cli, 'bodies', dir, '--json', outJson, '--md', outMd], { encoding: 'utf8' });
ok('cli prints summary line', /gvp-audit: 5 route\(s\)/.test(stdout));
const rep = JSON.parse(readFileSync(outJson, 'utf8'));
eq('cli json: verdict per route', Object.fromEntries(rep.routes.map(r => [r.id, r.verdict])), { clean: 'no-closure-violation-found', 'echo-sum': 'no-closure-violation-found', paycheck: 'hidden-inputs-found', risk: 'hidden-inputs-found', wei: 'format-violation' });
eq('wei route verdict is format-violation (unit)', auditRoute({ id: 'w', samples: [{ name: '1', raw: wei }] }).verdict, 'format-violation');
eq('cli json: echo-sum verified', rep.routes.find(r => r.id === 'echo-sum').rederivation.outcome, 'verified');
ok('cli md written', /# gvp-audit report/.test(readFileSync(outMd, 'utf8')));
let strictCode = 0; try { execFileSync(process.execPath, [cli, 'bodies', dir, '--strict', '--quiet'], { encoding: 'utf8' }); } catch (e) { strictCode = e.status; }
eq('--strict exits 1 when hidden inputs found', strictCode, 1);
ok('version prints', /gvp-audit \d+\.\d+\.\d+/.test(execFileSync(process.execPath, [cli, 'version'], { encoding: 'utf8' })));

console.log(fails ? `\ngvp-audit: ${fails} FAILURE(S)` : '\ngvp-audit: all checks passed');
process.exit(fails ? 1 : 0);
