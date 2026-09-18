// gvp-audit: load a directory of served bodies into routes.
// Layout (flat):  <route>.json | <route>.<n>.json (extra samples of the same route, same inputs)
//                 <route>.meta.json  -> { "endpoint": "/v1/x", "inputs": {...} }  (optional; enables re-derivation)
// Route ids are filenames; keep them stable so two sweeps line up.
import { readdirSync, readFileSync, lstatSync } from 'node:fs';
import { join, basename } from 'node:path';

export function loadBodiesDir(dir) {
  // lstat: symlinks are skipped, so an untrusted archive cannot point a "body" at a file outside the dir.
  const files = readdirSync(dir).filter(f => { if (!f.endsWith('.json')) return false; try { return lstatSync(join(dir, f)).isFile(); } catch { return false; } }).sort();
  const routes = new Map();
  const metaFor = new Map();
  const badMeta = [];
  for (const f of files) {
    const base = basename(f, '.json');
    if (base.endsWith('.meta')) {
      try { metaFor.set(base.slice(0, -5), JSON.parse(readFileSync(join(dir, f), 'utf8'))); }
      catch { badMeta.push(base.slice(0, -5)); }
      continue;
    }
    const m = base.match(/^(.*?)(?:\.(\d+))?$/);
    const id = m[1];
    if (!routes.has(id)) routes.set(id, { id, samples: [] });
    routes.get(id).samples.push({ name: f, raw: readFileSync(join(dir, f), 'utf8') });
  }
  for (const [id, meta] of metaFor) {
    if (!routes.has(id)) routes.set(id, { id, samples: [] });
    const m = meta && typeof meta === 'object' && !Array.isArray(meta) ? meta : {};
    Object.assign(routes.get(id), { endpoint: typeof m.endpoint === 'string' ? m.endpoint : undefined, inputs: m.inputs });
  }
  for (const id of badMeta) {
    if (!routes.has(id)) routes.set(id, { id, samples: [] });
    routes.get(id).metaError = 'meta file is not valid JSON; re-derivation disabled for this route';
  }
  return [...routes.values()];
}
