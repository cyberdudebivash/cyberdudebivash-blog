'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/sentinel-apex.yml'), 'utf8');
const start = workflow.indexOf('      - name: "Run SENTINEL APEX v5.0 Pipeline"');
const end = workflow.indexOf('      # Evidence-only IOC feed', start);
assert.ok(start > 0 && end > start, 'native publisher step and next boundary are present');
const block = workflow.slice(start, end).split('\n');
const runIndex = block.findIndex(line => line.trim() === 'run: |');
assert.ok(runIndex > 0, 'publisher step uses a Bash block');
const shell = block.slice(runIndex + 1)
  .map(line => line.startsWith('          ') ? line.slice(10) : line)
  .join('\n');

test('publisher handles timeout under GitHub Bash errexit without disabling failure gates', () => {
  assert.match(shell, /if timeout 290 node fetch-live-intel\.js; then/);
  assert.match(shell, /EXIT_CODE=\$\?/);
  assert.match(shell, /rm -f pipeline\.lock/);
  assert.match(shell, /if \[ \$EXIT_CODE -eq 0 \]/);
  assert.match(shell, /exit \$EXIT_CODE/);
  assert.match(workflow, /node scripts\/assert-publication-ledger\.cjs/);
  assert.match(workflow, /node scripts\/check-intel-source-yield\.cjs/);
});

for (const scenario of [
  { code: 0, outcome: 0, expected: 'Pipeline completed successfully' },
  { code: 124, outcome: 0, expected: 'Intel Publisher Timed Out' },
  { code: 143, outcome: 0, expected: 'Intel Publisher Timed Out' },
  { code: 17, outcome: 17, expected: 'Pipeline Runtime Error' },
]) {
  test('native publisher Bash -e exit code ' + scenario.code + ' is handled correctly', () => {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'cdb-publisher-step-'));
    try {
      const simulated = shell.replace(
        'timeout 290 node fetch-live-intel.js',
        "bash -c 'exit " + scenario.code + "'"
      );
      assert.notEqual(simulated, shell, 'live timeout invocation replaced only in test');
      const result = spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', simulated], {
        cwd: scratch,
        encoding: 'utf8',
        timeout: 4000,
        env: process.env,
      });
      assert.equal(result.error, undefined, result.error && result.error.message);
      assert.equal(result.status, scenario.outcome, result.stdout + '\n' + result.stderr);
      assert.match(result.stdout, new RegExp(scenario.expected));
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
}
