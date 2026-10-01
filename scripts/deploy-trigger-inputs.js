#!/usr/bin/env node
'use strict';

/**
 * Production deploy-trigger coverage.
 *
 * Invariant: any merge to main that can change what blog.cyberdudebivash.in
 * serves must trigger .github/workflows/cloudflare-production-deploy.yml on
 * push. A backend fix must never wait for the 30-minute drift reconciler (the
 * gap that left PR #318 undeployed after merge).
 *
 * The required inputs are derived, not hand-listed:
 *   1. the Worker bundle: esbuild's module graph from wrangler.jsonc "main"
 *      (exactly what Wrangler bundles). node_modules inputs are represented by
 *      package.json / package-lock.json;
 *   2. the static-asset build: scripts/build-cloudflare-assets.js, its
 *      PUBLIC_DIRS / PUBLIC_ROOT_FILES allowlist, and the modules it requires;
 *   3. deploy configuration: wrangler.jsonc, package manifests, the workflow.
 *
 *   node scripts/deploy-trigger-inputs.js   # exit 1 and list any uncovered input
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const WORKFLOW = '.github/workflows/cloudflare-production-deploy.yml';

/** GitHub Actions path-filter matching (the subset of syntax this repo uses). */
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') { i++; re += '(?:.*/)?'; } else { re += '.*'; }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

function matchesAny(file, patterns) {
  return patterns.some(p => globToRegExp(p).test(file));
}

function workflowPushPaths(file = path.join(ROOT, WORKFLOW)) {
  const yaml = require('js-yaml');
  const doc = yaml.load(fs.readFileSync(file, 'utf8'));
  const on = doc.on || doc[true]; // js-yaml may parse the bare key `on` as boolean true
  const push = on && on.push;
  if (!push || !Array.isArray(push.branches) || !push.branches.includes('main')) {
    throw new Error(`${WORKFLOW} must trigger on push to main`);
  }
  return push.paths || ['**'];
}

function workerModuleGraph() {
  const esbuild = require('esbuild');
  const wrangler = fs.readFileSync(path.join(ROOT, 'wrangler.jsonc'), 'utf8');
  const main = (wrangler.match(/"main"\s*:\s*"([^"]+)"/) || [])[1];
  if (!main) throw new Error('wrangler.jsonc has no "main"');
  const result = esbuild.buildSync({
    absWorkingDir: ROOT,
    entryPoints: [main],
    bundle: true,
    write: false,
    metafile: true,
    platform: 'node',
    format: 'cjs',
    logLevel: 'silent',
    external: ['cloudflare:*'],
    loader: { '.wasm': 'empty', '.woff': 'empty', '.woff2': 'empty', '.ttf': 'empty', '.bin': 'empty' },
  });
  return Object.keys(result.metafile.inputs).filter(f => !f.startsWith('node_modules/'));
}

function buildInputs() {
  const build = require(path.join(ROOT, 'scripts', 'build-cloudflare-assets.js'));
  const files = new Set(['scripts/build-cloudflare-assets.js']);
  for (const f of build.PUBLIC_ROOT_FILES) files.add(f);
  // Local modules the build itself requires (CVE page renderer, corrections, IOC projection).
  const src = fs.readFileSync(path.join(ROOT, 'scripts', 'build-cloudflare-assets.js'), 'utf8');
  for (const m of src.matchAll(/require\('(\.\.?\/[^']+)'\)/g)) {
    let rel = path.relative(ROOT, path.resolve(ROOT, 'scripts', m[1])).replace(/\\/g, '/');
    if (!/\.(js|json)$/.test(rel)) rel += '.js';
    files.add(rel);
  }
  // Representative file per public directory (any change under it is served).
  const dirs = build.PUBLIC_DIRS.map(d => `${d}/__deploy-trigger-probe__.html`);
  return { files: [...files], dirs };
}

function requiredInputs() {
  const config = ['wrangler.jsonc', 'package.json', 'package-lock.json', WORKFLOW];
  const { files, dirs } = buildInputs();
  return [...new Set([...workerModuleGraph(), ...files, ...dirs, ...config])].sort();
}

function uncovered(patterns = workflowPushPaths(), inputs = requiredInputs()) {
  return inputs.filter(f => !matchesAny(f, patterns));
}

if (require.main === module) {
  const missing = uncovered();
  if (missing.length) {
    console.error(`${WORKFLOW} push.paths misses ${missing.length} production runtime input(s):`);
    for (const f of missing) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log(`deploy trigger covers all ${requiredInputs().length} production runtime inputs`);
}

module.exports = { globToRegExp, matchesAny, workflowPushPaths, workerModuleGraph, buildInputs, requiredInputs, uncovered, WORKFLOW };
