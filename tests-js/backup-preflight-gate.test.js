'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { assessBackupPreflight } = require('../scripts/backup-preflight-gate.cjs');
const script = path.join(__dirname, '..', 'scripts', 'backup-preflight-gate.cjs');
const workflow = path.join(__dirname, '..', '.github', 'workflows', 'backup-customer-data.yml');

for (let mask = 0; mask < 8; mask++) {
  test('presence-only backup preflight truth table ' + mask + '/7', () => {
    const env = {
      HAS_REDIS_URL: mask & 1 ? 'true' : 'false',
      HAS_REDIS_TOKEN: mask & 2 ? 'true' : 'false',
      HAS_BACKUP_KEY: mask & 4 ? 'true' : 'false'
    };
    const expected = mask === 7;
    assert.equal(assessBackupPreflight(env).ready, expected);
    const result = spawnSync(process.execPath, [script], { env: { PATH: process.env.PATH || '', ...env }, encoding: 'utf8' });
    assert.equal(result.status, expected ? 0 : 2);
    assert.doesNotMatch(result.stdout + result.stderr, /UPSTASH_REDIS_REST_URL=|UPSTASH_REDIS_REST_TOKEN=|BACKUP_ENCRYPTION_KEY=/);
  });
}

test('workflow must fail closed before backup and upload, without skip-based green success', () => {
  const yml = fs.readFileSync(workflow, 'utf8');
  const preflight = yml.indexOf('run: node scripts/backup-preflight-gate.cjs');
  const backup = yml.indexOf('run: node scripts/backup-customer-data.js backups/customer-data.enc');
  const upload = yml.indexOf('uses: actions/upload-artifact@v4');
  assert.ok(preflight > 0 && backup > preflight && upload > backup);
  assert.doesNotMatch(yml, /if:\s*steps\.preflight\.outputs\.ready\s*==\s*'true'/);
  assert.match(yml, /if-no-files-found:\s*error/);
  assert.match(yml, /retention-days:\s*7/);
  assert.match(yml, /persist-credentials:\s*false/);
});
