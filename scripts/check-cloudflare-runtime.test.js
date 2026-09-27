'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudflare-gate-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const file of ['scripts/check-cloudflare-runtime.js', 'scripts/build-cloudflare-assets.js', 'workers/lib/security-headers.js', 'package.json', 'wrangler.jsonc']) {
    const dest = path.join(dir, file);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(path.join(root, file), dest);
  }
  return dir;
}
function run(dir) {
  return spawnSync(process.execPath, ['scripts/check-cloudflare-runtime.js'], { cwd: dir, encoding: 'utf8' });
}
test('native policy passes without retired deployment files', t => {
  const result = run(fixture(t));
  assert.equal(result.status, 0, result.stderr);
});
test('a reintroduced deployment file blocks release', t => {
  const dir = fixture(t);
  fs.writeFileSync(path.join(dir, 'vercel.json'), '{}');
  const result = run(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Retired deployment file reintroduced/);
});
test('missing production Worker Custom Domain blocks release', t => {
  const dir = fixture(t);
  const file = path.join(dir, 'wrangler.jsonc');
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('"pattern": "blog.cyberdudebivash.in"', '"pattern": "example.invalid"'));
  const result = run(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Production Worker Custom Domain is missing/);
});

test('downgrading production back to a Worker Route blocks release', t => {
  const dir = fixture(t);
  const file = path.join(dir, 'wrangler.jsonc');
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('"custom_domain": true', '"zone_name": "cyberdudebivash.in"').replace('"blog.cyberdudebivash.in"', '"blog.cyberdudebivash.in/*"'));
  const result = run(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Custom Domain|Legacy Worker Route/);
});

test('missing dynamic security headers block release', t => {
  const dir = fixture(t);
  fs.writeFileSync(path.join(dir, 'workers/lib/security-headers.js'), 'module.exports = {applyBaselineHeaders: response => response};');
  const result = run(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing Strict-Transport-Security/);
});
test('missing HTML CSP blocks release', t => {
  const dir = fixture(t);
  const file = path.join(dir, 'scripts/build-cloudflare-assets.js');
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replaceAll('Content-Security-Policy:', 'X-Removed-CSP:'));
  const result = run(dir);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing Content-Security-Policy/);
});
