'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/alert-delivery.yml'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));

test('watchlist alert dependency install is locked, bounded and ordered after fail-closed preflight', () => {
  const stages = [
    'run: node scripts/alert-delivery-execution-gate.cjs',
    'npm ci --legacy-peer-deps --ignore-scripts --omit=dev --no-audit --no-fund',
    'node -e "require.resolve(\'js-yaml\')"',
    'run: node scripts/evaluate-watchlist-changes.js',
    'run: node scripts/deliver-watchlist-notifications.js --limit=50',
  ];
  const positions = stages.map(stage => workflow.indexOf(stage));
  assert.ok(positions.every(index => index >= 0), 'required stages are present');
  assert.ok(positions.every((index, i) => i === 0 || index > positions[i - 1]),
    'preflight -> install -> smoke -> evaluation -> delivery order is preserved');
  assert.equal(workflow.split(stages[1]).length - 1, 1,
    'exactly one dependency install occurs');
  assert.equal(pkg.dependencies['js-yaml'], lock.packages[''].dependencies['js-yaml'],
    'manifest and lockfile production dependencies agree');
  assert.ok(lock.packages['node_modules/js-yaml']?.version,
    'lockfile actually pins js-yaml transitive metadata');
  assert.match(workflow, /cancel-in-progress:\s*false/,
    'no concurrency safety regression');
});
