#!/usr/bin/env node
'use strict';
// Release control for #381: all source changes since the last certified deploy
// must be accounted for. Unknown paths are NOT treated as documentation.
const fs = require('node:fs');
const { workflowPushPaths, matchesAny } = require('./deploy-trigger-inputs.js');

const SAFE_EXACT = new Set([
  'README.md', 'CLAUDE.md', 'CONTRIBUTING.md', 'LICENSE',
  '.github/workflows/test.yml',
  'scripts/soc-native-d1-local-certify.cjs',
]);
const SAFE_PREFIX = ['docs/', 'tests/', 'tests-js/'];
function classify(files, productionPaths = workflowPushPaths()) {
  const changed = [...new Set(files.filter(Boolean))];
  if (!changed.length) return { decision: 'blocked', reason: 'empty comparison' };
  const production = [], excluded = [], unknown = [];
  for (const f of changed) {
    if (f.startsWith('/') || f.includes('\\') || f.split('/').includes('..')) {
      unknown.push(f);
    } else if (matchesAny(f, productionPaths)) {
      production.push(f);
    } else if (SAFE_EXACT.has(f) || SAFE_PREFIX.some(p => f.startsWith(p))) {
      excluded.push(f);
    } else {
      unknown.push(f);
    }
  }
  return {
    decision: unknown.length ? 'blocked' : production.length ? 'deploy' : 'skip',
    production, excluded, unknown,
    reason: unknown.length ? 'unclassified changed paths' : production.length ? 'production inputs changed' : 'only explicitly excluded sources changed',
  };
}
if (require.main === module) {
  const source = process.argv[2];
  if (!source || !fs.existsSync(source)) { console.error('Missing complete NUL-delimited git diff'); process.exit(2); }
  const buf = fs.readFileSync(source);
  if (buf.length && buf[buf.length - 1] !== 0) { console.error('Incomplete changed-path list'); process.exit(2); }
  const files = buf.toString('utf8').split('\0').filter(Boolean);
  const result = classify(files);
  // No paths are printed to avoid disclosing unexpected filenames in log output.
  console.log(JSON.stringify({decision: result.decision, reason: result.reason, production_count: result.production?.length || 0, excluded_count: result.excluded?.length || 0, unknown_count: result.unknown?.length || 0}));
  if (result.decision === 'blocked') process.exit(2);
  if (result.decision === 'deploy') process.exit(10);
}
module.exports = { classify };
