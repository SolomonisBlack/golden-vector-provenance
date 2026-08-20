// Generate the expected L1 conformance hashes from the JS reference canonicalizer.
//
// Optional cross-check: if the environment variable GVP_CALC_CORE points at a second, independent
// implementation that exports `canonicalJson(value)`, this tool also asserts that implementation is
// byte-identical to the reference for every vector — a divergence would mean receipts issued by one
// side stop validating on the other. When GVP_CALC_CORE is unset (the default for anyone but a
// maintainer wiring in their own deployment), the cross-check is skipped and only the vectors are
// regenerated. The tool therefore runs from a clean clone with no external paths.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalize, gvpHash } from '../ref/js/gvp.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, '..', 'vectors', 'canonicalization.json'), 'utf8'));

let coreDiffs = 0;
const calcCorePath = process.env.GVP_CALC_CORE;
if (calcCorePath) {
  const core = await import(pathToFileURL(calcCorePath).href);
  for (const v of vectors) {
    const spec = canonicalize(v.fixedPoint);
    const other = core.canonicalJson(v.fixedPoint);
    if (spec !== other) {
      coreDiffs++;
      console.error(`SPEC != GVP_CALC_CORE for "${v.name}"`);
      console.error(`  spec:  ${spec}`);
      console.error(`  other: ${other}`);
    }
  }
}

const out = vectors.map(v => ({ name: v.name, fixedPoint: v.fixedPoint, expectedHash: gvpHash(v.fixedPoint) }));
writeFileSync(join(here, '..', 'vectors', 'expected.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`generated ${out.length} expected hashes -> vectors/expected.json`);
if (calcCorePath) console.log(`cross-check vs GVP_CALC_CORE canonicalization diffs: ${coreDiffs}`);
if (coreDiffs) process.exit(1);
