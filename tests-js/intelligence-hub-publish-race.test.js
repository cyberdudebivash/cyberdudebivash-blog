'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const script = path.resolve(__dirname, '../scripts/publish-intelligence-hub.sh');
const workflow = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/intelligence-hub.yml'), 'utf8');
const realGit = cp.execFileSync('which', ['git'], { encoding: 'utf8' }).trim();

function call(bin, args, cwd, env = process.env) {
  return cp.execFileSync(bin, args, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}
function write(root, relative, value) {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, value);
}
const outputs = [
  'vendor/index.html', 'timeline/index.html', 'collections/index.html',
  'detections/live-feed.html', 'threat/index.html', 'api/intel/vendors.json',
  'api/intel/vendor/sample.json', 'api/intel/timeline.json',
  'api/intel/collections.json', 'api/intel/detections-library.json', 'sitemap.xml'
];

test('workflow is manual-content-only, bounded, and has no stale rebase or force push', () => {
  const shell = fs.readFileSync(script, 'utf8');
  assert.match(workflow, /run: bash scripts\/publish-intelligence-hub\.sh/);
  assert.doesNotMatch(workflow, /git pull --rebase/);
  assert.match(shell, /MAX_ATTEMPTS=3/);
  assert.match(shell, /git fetch --no-tags origin refs\/heads\/main/);
  assert.match(shell, /git merge-base --is-ancestor/);
  assert.match(shell, /git reset --hard "\$remote_head"/);
  assert.match(shell, /node generate-intelligence-hub\.js/);
  assert.match(shell, /git push origin HEAD:refs\/heads\/main/);
  assert.doesNotMatch(shell, /push\s+.*--force|push\s+-f|git pull --rebase/);
  call('bash', ['-n', script], path.dirname(script));
});

test('simulated concurrent writer is preserved and outputs are regenerated from latest main', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-hub-publish-test-'));
  try {
    const remote = path.join(temp, 'remote.git');
    const seed = path.join(temp, 'seed');
    const runner = path.join(temp, 'runner');
    const competitor = path.join(temp, 'competitor');
    const bin = path.join(temp, 'bin');
    const triggered = path.join(temp, 'triggered');
    fs.mkdirSync(bin);
    call(realGit, ['init', '--bare', '-b', 'main', remote], temp);
    call(realGit, ['clone', remote, seed], temp);
    call(realGit, ['config', 'user.name', 'Fixture Operator'], seed);
    call(realGit, ['config', 'user.email', 'fixture@example.invalid'], seed);
    write(seed, 'source-data.txt', 'OLD');
    write(seed, 'api/_lib/intelligence-hub.js', "'use strict';\n");
    write(seed, 'tests-js/intelligence-hub.test.js', "require('node:test')('fixture generator test',()=>{});\n");
    const generator = [
      "'use strict';",
      "const fs=require('node:fs');const path=require('node:path');",
      "const source=fs.readFileSync('source-data.txt','utf8').trim();",
      'for(const f of ' + JSON.stringify(outputs) + '){',
      "fs.mkdirSync(path.dirname(f),{recursive:true});",
      "fs.writeFileSync(f,source+'-generated\\n');}",
    ].join('\n');
    write(seed, 'generate-intelligence-hub.js', generator);
    for (const output of outputs) write(seed, output, 'baseline\n');
    call(realGit, ['add', '.'], seed);
    call(realGit, ['commit', '-m', 'fixture baseline'], seed);
    call(realGit, ['push', 'origin', 'HEAD:refs/heads/main'], seed);

    call(realGit, ['clone', remote, runner], temp);
    call(realGit, ['clone', remote, competitor], temp);
    call(realGit, ['config', 'user.name', 'Fixture Competitor'], competitor);
    call(realGit, ['config', 'user.email', 'fixture-competitor@example.invalid'], competitor);
    const wrapper = [
      '#!/usr/bin/env bash',
      'if [[ "$1" == "push" && ! -f "$TEST_PUSH_FLAG" ]]; then',
      '  touch "$TEST_PUSH_FLAG"',
      '  printf "NEW" > "$TEST_COMPETITOR/source-data.txt"',
      '  "$REAL_GIT" -C "$TEST_COMPETITOR" add source-data.txt',
      '  "$REAL_GIT" -C "$TEST_COMPETITOR" commit -m "fresh intelligence source"',
      '  "$REAL_GIT" -C "$TEST_COMPETITOR" push origin HEAD:refs/heads/main',
      'fi',
      'exec "$REAL_GIT" "$@"',
    ].join('\n') + '\n';
    write(bin, 'git', wrapper);
    fs.chmodSync(path.join(bin, 'git'), 0o755);
    call('node', ['generate-intelligence-hub.js'], runner);
    const env = {
      ...process.env, GITHUB_ACTIONS: 'true', GITHUB_WORKSPACE: runner,
      REAL_GIT: realGit, TEST_COMPETITOR: competitor, TEST_PUSH_FLAG: triggered,
      PATH: bin + path.delimiter + process.env.PATH
    };
    const p = cp.spawnSync('bash', [script], { cwd: runner, env, encoding: 'utf8', timeout: 20000 });
    assert.equal(p.status, 0, p.stderr + '\n' + p.stdout);
    assert.equal(fs.existsSync(triggered), true, 'conflicting first push must occur');
    assert.match(p.stdout + p.stderr, /fast-forward push \(attempt 2\)/);
    call(realGit, ['fetch', 'origin', 'main'], seed);
    const remoteSource = call(realGit, ['show', 'FETCH_HEAD:source-data.txt'], seed);
    const remoteOutput = call(realGit, ['show', 'FETCH_HEAD:api/intel/vendors.json'], seed);
    assert.equal(remoteSource, 'NEW');
    assert.equal(remoteOutput, 'NEW-generated');
    const subject = call(realGit, ['show', '-s', '--format=%s', 'FETCH_HEAD'], seed);
    assert.match(subject, /Regenerate intelligence hub against reviewed main/);
    assert.equal(call(realGit, ['rev-parse', 'HEAD^'], runner),
      call(realGit, ['rev-parse', 'HEAD'], competitor));
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('non-GitHub local workspace fails before any Git or generated changes', () => {
  const p = cp.spawnSync('bash', [script], {
    encoding: 'utf8', cwd: os.tmpdir(),
    env: { ...process.env, GITHUB_ACTIONS: 'false', GITHUB_WORKSPACE: os.tmpdir() }
  });
  assert.equal(p.status, 1);
  assert.match(p.stderr + p.stdout, /Unsafe Publishing Context/);
});
