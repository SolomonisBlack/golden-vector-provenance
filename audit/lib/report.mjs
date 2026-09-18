// gvp-audit: per-route verdicts + the summary a seller can act on. Wording rule: the tool reports
// "no closure violation found" or "hidden inputs found"; it never says "closure-safe".
import { classifyDiff, identical } from './diff.mjs';
import { analyzeBody } from './analyze.mjs';

export function auditRoute(route) {
  // route: { id, endpoint?, inputs?, samples: [{ name, raw }] }
  const meta = { endpoint: route.endpoint, inputs: route.inputs };
  const analyses = route.samples.map(s => ({ name: s.name, ...analyzeBody(s.raw, meta) }));
  const first = analyses[0];
  const findings = [...(first ? first.findings : [])];
  let comparison = null;
  const comparable = analyses.length >= 2 && analyses.every(a => a.parse === 'ok' && !a.findings.some(f => f.kind === 'depth'));
  if (comparable) {
    const parsed = route.samples.map(s => JSON.parse(s.raw));
    comparison = { samples: analyses.length, identical: true, changes: [] };
    for (let i = 1; i < parsed.length; i++) {
      if (!identical(parsed[0], parsed[i])) {
        comparison.identical = false;
        for (const c of classifyDiff(parsed[0], parsed[i])) {
          comparison.changes.push({ against: analyses[i].name, ...c });
          findings.push({ severity: c.severity, kind: 'sample-drift', path: c.path, note: `${c.change} between ${analyses[0].name} and ${analyses[i].name} (${c.kind}${c.from !== undefined ? `: ${c.from} -> ${c.to}` : ''}); on identical inputs a closed route returns identical bytes` });
        }
      }
    }
  }
  const high = findings.filter(f => f.severity === 'high').length;
  const medium = findings.filter(f => f.severity === 'medium').length;
  const hiddenHigh = findings.filter(f => (f.kind === 'hidden-input' || f.kind === 'sample-drift') && f.severity === 'high').length;
  let verdict;
  if (!first) verdict = 'unknown';
  else if (first.parse !== 'ok' || !first.shape.isObject) verdict = 'out-of-scope';
  else if (findings.some(f => f.kind === 'i-json' || f.kind === 'duplicate-key' || f.kind === 'depth')) verdict = 'format-violation';
  else if (hiddenHigh > 0 || findings.some(f => f.kind === 'contradicted')) verdict = 'hidden-inputs-found';
  else if (findings.some(f => (f.kind === 'hidden-input' || f.kind === 'sample-drift') && f.severity === 'medium')) verdict = 'review-needed';
  else verdict = 'no-closure-violation-found';
  return { id: route.id, endpoint: route.endpoint ?? null, samples: analyses.length, verdict,
    carriage: first ? first.carriage : null, shape: first ? first.shape : null, provenance: first ? first.provenance : null,
    rederivation: first ? first.rederivation : null, vintage: first ? first.vintage : [], comparison, counts: { high, medium, low: findings.length - high - medium }, findings };
}

export function summarize(routes) {
  const by = (pred) => routes.filter(pred).length;
  return {
    routes: routes.length,
    noClosureViolationFound: by(r => r.verdict === 'no-closure-violation-found'),
    reviewNeeded: by(r => r.verdict === 'review-needed'),
    hiddenInputsFound: by(r => r.verdict === 'hidden-inputs-found'),
    formatViolation: by(r => r.verdict === 'format-violation'),
    outOfScope: by(r => r.verdict === 'out-of-scope'),
    unknown: by(r => r.verdict === 'unknown'),
    carriageMember: by(r => r.carriage && r.carriage.recommended === 'member'),
    carriageBody: by(r => r.carriage && r.carriage.recommended === 'body'),
    iJsonViolations: by(r => r.findings.some(f => f.kind === 'i-json')),
    duplicateKeys: by(r => r.findings.some(f => f.kind === 'duplicate-key')),
    vintagePresent: by(r => r.vintage && r.vintage.length > 0),
    vintageFixedPoint2: by(r => r.vintage && r.vintage.some(v => v.fixedPoint2Conformant)),
    provenance: {
      none: by(r => !r.provenance), C1: by(r => r.provenance && r.provenance.carriage === 'C1'), C2: by(r => r.provenance && r.provenance.carriage === 'C2'),
      verified: by(r => r.rederivation && r.rederivation.outcome === 'verified'), contradicted: by(r => r.rederivation && r.rederivation.outcome === 'contradicted'),
      unverifiable: by(r => r.rederivation && r.rederivation.outcome === 'unverifiable'),
    },
    withTwoSamples: by(r => r.samples >= 2),
    driftedBetweenSamples: by(r => r.comparison && !r.comparison.identical),
  };
}

// Every untrusted string that lands in a markdown cell or heading goes through this: no newlines (a
// value cannot end the table row), no raw backticks, pipes escaped, length capped. Seller-controlled
// bodies must not be able to truncate or "clean up" the rendered findings.
export function cell(v, max = 160) {
  // \r \n U+2028 U+2029: every JavaScript line terminator, written as escapes (a literal U+2028 in source is itself a line break).
  return String(v === undefined ? '' : v).replace(/[\r\n\u2028\u2029]/g, ' ').replace(/</g, '&lt;').replace(/`/g, "'").replace(/\|/g, '\\|').slice(0, max);
}
const code = (v) => '`' + cell(v) + '`';

export function safeAuditRoute(route) {
  try { return auditRoute(route); }
  catch (e) {
    return { id: route.id, endpoint: route.endpoint ?? null, samples: route.samples.length, verdict: 'unknown', carriage: null, shape: null, provenance: null,
      rederivation: null, vintage: [], comparison: null, counts: { high: 1, medium: 0, low: 0 },
      findings: [{ severity: 'high', kind: 'analysis-error', note: `analysis failed on this body (${cell(e && e.message, 80)}); the rest of the sweep continues` }] };
  }
}

export function toMarkdown(report) {
  const s = report.summary;
  const L = [];
  L.push(`# gvp-audit report`, ``, `Generated ${report.generatedAt} by gvp-audit ${report.tool.version}. Heuristic: this tool finds closure violations and readiness gaps; it cannot prove a route closed. Spec: ${report.tool.spec}`, ``);
  L.push(`## Summary`, ``, `| | |`, `|---|---|`);
  L.push(`| Routes audited | ${s.routes} |`, `| No closure violation found | ${s.noClosureViolationFound} |`, `| Review needed (medium signals) | ${s.reviewNeeded} |`, `| Hidden inputs found | ${s.hiddenInputsFound} |`, `| Format violation (I-JSON / duplicate keys / depth) | ${s.formatViolation} |`, `| Out of scope (not a JSON object) | ${s.outOfScope} |`);
  L.push(`| Carriage: "member" works as-is | ${s.carriageMember} |`, `| Carriage: needs resultCarriage:"body" | ${s.carriageBody} |`, `| I-JSON violations (integers > 2^53-1) | ${s.iJsonViolations} |`, `| Duplicate member names | ${s.duplicateKeys} |`);
  L.push(`| Structured vintage present | ${s.vintagePresent} (FixedPoint/2 grammar: ${s.vintageFixedPoint2}) |`, `| Provenance already emitted | C1 ${s.provenance.C1}, C2 ${s.provenance.C2}, none ${s.provenance.none} |`, `| Re-derivation | verified ${s.provenance.verified}, contradicted ${s.provenance.contradicted}, unverifiable ${s.provenance.unverifiable} |`, `| Routes with 2+ samples | ${s.withTwoSamples} (drifted: ${s.driftedBetweenSamples}) |`, ``);
  L.push(`## Routes`, ``);
  for (const r of report.routes) {
    L.push(`### ${cell(r.id, 200)}${r.endpoint ? ` (${cell(r.endpoint, 120)})` : ''} -- **${r.verdict}**`, ``);
    if (r.carriage) L.push(`- Carriage: ${r.carriage.recommended ? code(r.carriage.recommended) : 'n/a'} -- ${r.carriage.note}`);
    if (r.provenance) L.push(`- Provenance: ${cell(r.provenance.carriage)} (${cell(r.provenance.fixedPointVersion ?? 'no fixedPointVersion')}) -> re-derivation **${r.rederivation.outcome}**${r.rederivation.why ? ` (${cell(r.rederivation.why)})` : ''}`);
    if (r.http && r.http.note) L.push(`- HTTP: ${r.http.status ?? 'n/a'} -- ${cell(r.http.note)}`);
    if (r.vintage && r.vintage.length) {
      const shown = r.vintage.slice(0, 8).map(v => `${code(v.path)}=${cell(v.value, 60)}${v.fixedPoint2Conformant ? '' : ' (not /2 grammar)'}`);
      L.push(`- Vintage candidates (${r.vintage.length}): ${shown.join(', ')}${r.vintage.length > 8 ? `, +${r.vintage.length - 8} more (see JSON)` : ''}`);
    }
    if (r.comparison) L.push(`- Samples: ${r.comparison.samples}, ${r.comparison.identical ? 'byte-identical after JCS' : `${r.comparison.changes.length} member(s) differ`}`);
    if (r.findings.length) {
      L.push(``, `| Sev | Kind | Path | Note |`, `|---|---|---|---|`);
      for (const f of r.findings) L.push(`| ${f.severity} | ${f.kind} | ${f.path ? code(f.path) : ''} | ${cell(f.note, 400)}${f.sample !== undefined ? ` (sample: ${code(f.sample)})` : ''} |`);
    } else L.push(`- No findings.`);
    L.push(``);
  }
  L.push(`---`, `Verdict vocabulary: **no-closure-violation-found** = nothing in the body looks like a hidden input (not a proof); **review-needed** = medium signals to explain or remove; **hidden-inputs-found** = at least one high signal or a contradicted re-derivation; **format-violation** = the body cannot enter a fixed point as served (integer beyond 2^53-1 as a number, duplicate member names, depth over 100); **out-of-scope** = not a JSON object.`);
  return L.join('\n') + '\n';
}
