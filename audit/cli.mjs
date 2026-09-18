#!/usr/bin/env node
// gvp-audit -- closure audit for x402 sellers: does a served response body have hidden inputs, which
// carriage fits it, and is it ready for the response-provenance extension?
//   gvp-audit bodies <dir> [--json out.json] [--md out.md] [--strict]
//   gvp-audit fetch <url> [<url>...] [--times 2] [--json out.json] [--md out.md] [--strict]
//   gvp-audit version
// Offline in `bodies` mode. `fetch` only GETs free surfaces and never pays a 402.
// Exit code: 0; with --strict, 1 if any route is hidden-inputs-found or out-of-scope.
import { writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadBodiesDir } from './lib/load.mjs';
import { fetchSamples } from './lib/fetch.mjs';
import { safeAuditRoute, summarize, toMarkdown } from './lib/report.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));
const TOOL = { name: 'gvp-audit', version: pkg.version, spec: 'https://github.com/x402-foundation/x402/pull/3304 (response-provenance) | https://github.com/SolomonisBlack/golden-vector-provenance' };

function parseArgs(argv) {
  const opts = { _: [], times: 2 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json' || a === '--md' || a === '--times') {
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) { console.error(`${a} needs a value`); process.exit(2); }
      opts[a.slice(2)] = v; continue;
    }
    if (a === '--strict') { opts.strict = true; continue; }
    if (a === '--quiet') { opts.quiet = true; continue; }
    if (a.startsWith('--')) { console.error(`unknown option ${a}`); process.exit(2); }
    opts._.push(a);
  }
  return opts;
}

export function buildReport(routes) {
  const audited = routes.map(r => { const a = safeAuditRoute(r); if (r.metaError) { a.findings.push({ severity: 'medium', kind: 'meta-error', note: r.metaError }); a.counts.medium++; } return a; });
  return { tool: TOOL, generatedAt: new Date().toISOString(), summary: summarize(audited), routes: audited };
}

function emit(report, opts) {
  if (opts.json) writeFileSync(opts.json, JSON.stringify(report, null, 2) + '\n');
  if (opts.md) writeFileSync(opts.md, toMarkdown(report));
  if (!opts.quiet) {
    const s = report.summary;
    console.log(`gvp-audit: ${s.routes} route(s) -- no closure violation found ${s.noClosureViolationFound} | review needed ${s.reviewNeeded} | hidden inputs found ${s.hiddenInputsFound} | format violation ${s.formatViolation} | out of scope ${s.outOfScope}`);
    console.log(`  carriage: "member" ${s.carriageMember} | needs "body" ${s.carriageBody} | I-JSON violations ${s.iJsonViolations} | vintage present ${s.vintagePresent} | provenance verified ${s.provenance.verified} / contradicted ${s.provenance.contradicted}`);
    for (const r of report.routes) console.log(`  ${r.verdict.padEnd(28)} ${r.id}${r.counts.high ? `  high:${r.counts.high}` : ''}${r.counts.medium ? ` medium:${r.counts.medium}` : ''}`);
    if (!opts.json && !opts.md) console.log('  (write the full report with --json <file> and/or --md <file>)');
  }
  if (opts.strict && report.routes.some(r => r.verdict === 'hidden-inputs-found' || r.verdict === 'format-violation' || r.verdict === 'out-of-scope')) process.exitCode = 1;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const cmd = opts._[0];
  if (cmd === 'version') { console.log(`${TOOL.name} ${TOOL.version}`); return; }
  if (cmd === 'bodies') {
    const dir = opts._[1];
    if (!dir) { console.error('usage: gvp-audit bodies <dir> [--json out.json] [--md out.md] [--strict]'); process.exit(2); }
    const routes = loadBodiesDir(dir);
    if (!routes.length) { console.error(`no *.json bodies in ${dir}`); process.exit(2); }
    emit(buildReport(routes), opts);
    return;
  }
  if (cmd === 'fetch') {
    const urls = opts._.slice(1);
    if (!urls.length) { console.error('usage: gvp-audit fetch <url> [<url>...] [--times 2] [--json out.json] [--md out.md]'); process.exit(2); }
    const fetched = await fetchSamples(urls, { times: Number(opts.times) || 2 });
    const report = buildReport(fetched.map(f => ({ id: f.id, endpoint: f.endpoint, samples: f.samples })));
    report.routes.forEach((r, i) => { r.http = { status: fetched[i].status, contentType: fetched[i].contentType, note: fetched[i].note }; });
    emit(report, opts);
    for (const f of fetched) if (f.note) console.log(`  note ${f.id}: ${f.note}`);
    return;
  }
  console.error('usage: gvp-audit <bodies <dir> | fetch <url...> | version>');
  process.exit(2);
}

// No import.meta.url === argv[1] guard: on Unix `npm i -g` installs the bin as a symlink and that comparison
// is false (argv[1] is not realpath'd), which would make `gvp-audit` exit silently. Nothing imports this file.
main().catch(e => { console.error(e && e.message ? e.message : e); process.exit(2); });
