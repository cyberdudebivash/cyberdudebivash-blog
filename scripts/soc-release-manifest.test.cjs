'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const {
  APPROVAL_SCHEMA, MANIFEST_SCHEMA, buildManifest, verifyRelease, digestPaths, digestSecretNames, MAX_ATTESTATION_AGE_MS,
  MAX_APPROVAL_AGE_MS, DEFAULT_CONTROL_PATHS,
} = require('./soc-release-manifest.cjs');

const SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);
const NOW = Date.parse('2026-11-13T00:30:00.000Z');
const FEED_AT = '2026-11-13T00:10:00.000Z';                       // 20 minutes old at NOW
const ROLLBACK = '0f1e2d3c-4b5a-4968-8776-655443322110';
const SECRETS = ['CLOUDFLARE_API_TOKEN', 'RAZORPAY_KEY_SECRET', 'CDB_SOC_APPROVED_RELEASE_SHA'];

function write(root, rel, text) {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

function fixture(feedGeneratedAt = FEED_AT) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cdb-release-manifest-'));
  write(root, 'dist-public/index.html', '<html>home</html>');
  write(root, 'dist-public/soc.html', '<html>soc</html>');
  write(root, 'dist-public/runtime-state.js', 'var RS = 1;');
  write(root, 'dist-public/live-intel.json', JSON.stringify({ generatedAt: feedGeneratedAt, totalPublished: 7454, items: [] }));
  write(root, 'dist-public/api/intel/live.json', JSON.stringify({ generated: feedGeneratedAt, total_published: 7454, items: [] }));
  write(root, 'workers/entry.js', 'export default { fetch() { return new Response("ok"); } };');
  write(root, 'workers/lib/router.js', 'export const route = 1;');
  write(root, 'wrangler.jsonc', '{ "name": "cyberdudebivash-blog", "d1_databases": [{ "binding": "DB" }] }');
  write(root, 'migrations/0001_init.sql', 'CREATE TABLE t (id TEXT);');
  for (const f of DEFAULT_CONTROL_PATHS) write(root, f, `// release-control file ${f}\n`);
  return root;
}

function approvalFor(manifest, over = {}) {
  const c = manifest.components;
  return {
    schema: APPROVAL_SCHEMA,
    source_sha: manifest.source_sha,
    manifest_digest: manifest.manifest_digest,
    components: Object.fromEntries(Object.entries(c).map(([k, v]) => [k, v.digest])),
    secret_names_digest: digestSecretNames(SECRETS),
    target_environment: 'production',
    approved_by: 'release-owner',
    approved_at: new Date(NOW - 10 * 60 * 1000).toISOString(),
    rollback_version_id: ROLLBACK,
    financial_attestation: { sha256: 'c'.repeat(64), attested_at: new Date(NOW - 30 * 60 * 1000).toISOString() },
    ...over,
  };
}

function observedFor(root, over = {}) {
  return {
    manifest: buildManifest({ root, sourceSha: SHA }),
    sourceSha: SHA,
    targetEnvironment: 'production',
    secretNames: SECRETS,
    ...over,
  };
}

function run(root, mutate, approvalOver, observedOver) {
  const approved = buildManifest({ root, sourceSha: SHA });
  const approval = approvalFor(approved, approvalOver);
  if (mutate) mutate(root);
  return verifyRelease({ approval, observed: observedFor(root, observedOver), now: NOW });
}

test('CONTROL: an unmodified tree matching a complete approval passes, and is explicitly not deploy authorization', () => {
  const root = fixture();
  const r = run(root);
  assert.deepEqual(r, { status: 'PASS_NOT_DEPLOY_AUTHORIZATION', codes: [] });
});

test('wrong SHA: an approval for a different commit never matches this tree', () => {
  const root = fixture();
  const approved = buildManifest({ root, sourceSha: OTHER_SHA });
  const r = verifyRelease({ approval: approvalFor(approved), observed: observedFor(root), now: NOW });
  assert.equal(r.status, 'HOLD');
  assert.ok(r.codes.includes('WRONG_SHA'));
});

test('wrong SHA: checked-out HEAD differs from the approved SHA', () => {
  const root = fixture();
  const r = run(root, null, null, { sourceSha: OTHER_SHA });
  assert.ok(r.codes.includes('WRONG_SHA'));
});

test('modified Worker code after approval is rejected', () => {
  const r = run(fixture(), (root) => write(root, 'workers/lib/router.js', 'export const route = 2; // changed'));
  assert.ok(r.codes.includes('WORKER_CODE_MODIFIED'));
  assert.ok(r.codes.includes('MANIFEST_DIGEST_MISMATCH'));
  assert.equal(r.status, 'HOLD');
});

test('a new Worker file after approval is rejected', () => {
  const r = run(fixture(), (root) => write(root, 'workers/lib/extra.js', 'export const x = 1;'));
  assert.ok(r.codes.includes('WORKER_CODE_MODIFIED'));
});

test('modified frontend after approval is rejected', () => {
  const r = run(fixture(), (root) => write(root, 'dist-public/runtime-state.js', 'var RS = 2; // tampered'));
  assert.ok(r.codes.includes('ASSETS_MODIFIED'));
  assert.ok(!r.codes.includes('FEED_MODIFIED'));
});

test('modified source feed inside an already approved artifact is rejected, by name', () => {
  const r = run(fixture(), (root) => write(root, 'dist-public/live-intel.json',
    JSON.stringify({ generatedAt: FEED_AT, totalPublished: 9999, items: [{ id: 'CVE-2026-0001', cisaKev: true }] })));
  assert.ok(r.codes.includes('FEED_MODIFIED'));
  assert.ok(r.codes.includes('ASSETS_MODIFIED'));
});

test('the API feed copy is covered too', () => {
  const r = run(fixture(), (root) => write(root, 'dist-public/api/intel/live.json', '{"items":["swapped"]}'));
  assert.ok(r.codes.includes('FEED_MODIFIED'));
});

test('changed D1 migration, and an added or removed migration, are rejected', () => {
  for (const mutate of [
    (root) => write(root, 'migrations/0001_init.sql', 'CREATE TABLE t (id TEXT, extra TEXT);'),
    (root) => write(root, 'migrations/0002_new.sql', 'DROP TABLE t;'),
    (root) => fs.rmSync(path.join(root, 'migrations/0001_init.sql')),
  ]) {
    const r = run(fixture(), mutate);
    assert.ok(r.codes.includes('MIGRATIONS_CHANGED'), r.codes.join());
  }
});

test('changed Wrangler config (bindings, routes, vars) is rejected', () => {
  const r = run(fixture(), (root) => write(root, 'wrangler.jsonc',
    '{ "name": "cyberdudebivash-blog", "d1_databases": [{ "binding": "DB" }], "r2_buckets": [{ "binding": "NEW" }] }'));
  assert.ok(r.codes.includes('CONFIG_OR_BINDINGS_CHANGED'));
});

test('a different secret-name set is rejected; an unpinned or unverifiable set is rejected', () => {
  const root = fixture();
  assert.ok(run(root, null, null, { secretNames: [...SECRETS, 'NEW_SECRET'] }).codes.includes('SECRETS_SET_CHANGED'));
  assert.ok(run(root, null, null, { secretNames: SECRETS.slice(1) }).codes.includes('SECRETS_SET_CHANGED'));
  assert.ok(run(root, null, { secret_names_digest: undefined }).codes.includes('SECRETS_SET_NOT_PINNED'));
  assert.ok(run(root, null, null, { secretNames: undefined }).codes.includes('SECRETS_SET_UNVERIFIABLE'));
  assert.equal(run(root, null, null, { secretNames: [...SECRETS].reverse() }).status, 'PASS_NOT_DEPLOY_AUTHORIZATION');
});

test('unapproved target environment is rejected, whichever side names it', () => {
  const root = fixture();
  for (const env of ['staging', 'preview', 'production ', '', undefined, 'PRODUCTION']) {
    assert.ok(run(root, null, null, { targetEnvironment: env }).codes.includes('TARGET_ENVIRONMENT_NOT_APPROVED'), String(env));
  }
  assert.ok(run(root, null, { target_environment: 'staging' }, { targetEnvironment: 'staging' })
    .codes.includes('TARGET_ENVIRONMENT_NOT_APPROVED'));
});

test('invalid artifact digests are rejected (wrong length, case, type, non-hex)', () => {
  const root = fixture();
  const approved = buildManifest({ root, sourceSha: SHA });
  for (const bad of ['', 'abc', 'g'.repeat(64), 'A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 123, null]) {
    const approval = approvalFor(approved);
    approval.components.assets = bad;
    const r = verifyRelease({ approval, observed: observedFor(root), now: NOW });
    assert.ok(r.codes.includes('INVALID_DIGEST_FORMAT'), String(bad));
    assert.equal(r.status, 'HOLD');
  }
  const approval = approvalFor(approved, { manifest_digest: 'not-a-digest' });
  assert.ok(verifyRelease({ approval, observed: observedFor(root), now: NOW }).codes.includes('INVALID_DIGEST_FORMAT'));
});

test('a tampered manifest document (digest not recomputable) is rejected', () => {
  const root = fixture();
  const approved = buildManifest({ root, sourceSha: SHA });
  const observed = observedFor(root);
  observed.manifest.components.worker.digest = 'd'.repeat(64);       // claim a digest the tree does not have
  const r = verifyRelease({ approval: approvalFor(approved), observed, now: NOW });
  assert.ok(r.codes.includes('MANIFEST_DIGEST_MISMATCH'));
  assert.ok(r.codes.includes('WORKER_CODE_MODIFIED'));
});

test('missing or malformed rollback target is rejected', () => {
  const root = fixture();
  for (const bad of [undefined, null, '', 'latest', 'previous', 'not-a-uuid', ROLLBACK.toUpperCase(), 42]) {
    assert.ok(run(root, null, { rollback_version_id: bad }).codes.includes('ROLLBACK_TARGET_MISSING_OR_INVALID'), String(bad));
  }
});

test('missing, malformed or stale financial attestation is rejected', () => {
  const root = fixture();
  assert.ok(run(root, null, { financial_attestation: undefined }).codes.includes('FINANCIAL_ATTESTATION_MISSING'));
  assert.ok(run(root, null, { financial_attestation: {} }).codes.includes('FINANCIAL_ATTESTATION_MISSING'));
  assert.ok(run(root, null, { financial_attestation: { sha256: 'short', attested_at: new Date(NOW).toISOString() } })
    .codes.includes('FINANCIAL_ATTESTATION_MISSING'));
  assert.ok(run(root, null, { financial_attestation: { sha256: 'c'.repeat(64), attested_at: 'yesterday' } })
    .codes.includes('FINANCIAL_ATTESTATION_MISSING'));
  const stale = new Date(NOW - MAX_ATTESTATION_AGE_MS - 1000).toISOString();
  assert.ok(run(root, null, { financial_attestation: { sha256: 'c'.repeat(64), attested_at: stale } })
    .codes.includes('FINANCIAL_ATTESTATION_STALE'));
  const future = new Date(NOW + 60 * 60 * 1000).toISOString();
  assert.ok(run(root, null, { financial_attestation: { sha256: 'c'.repeat(64), attested_at: future } })
    .codes.includes('FINANCIAL_ATTESTATION_STALE'));
  const edge = new Date(NOW - MAX_ATTESTATION_AGE_MS + 1000).toISOString();
  assert.equal(run(root, null, { financial_attestation: { sha256: 'c'.repeat(64), attested_at: edge } }).status,
    'PASS_NOT_DEPLOY_AUTHORIZATION');
});

test('a stale, future-dated or unreadable feed fails the 180-minute genuine-report gate at deploy time', () => {
  const stale = new Date(NOW - 181 * 60 * 1000).toISOString();
  assert.ok(run(fixture(stale)).codes.includes('FEED_NOT_FRESH'));
  const future = new Date(NOW + 60 * 60 * 1000).toISOString();
  assert.ok(run(fixture(future)).codes.includes('FEED_NOT_FRESH'));
  const root = fixture();
  write(root, 'dist-public/live-intel.json', 'not json');
  assert.ok(run(root).codes.includes('FEED_NOT_FRESH'));
  const justInside = new Date(NOW - 179 * 60 * 1000).toISOString();
  assert.equal(run(fixture(justInside)).status, 'PASS_NOT_DEPLOY_AUTHORIZATION');
});

test('a malformed approval or missing evidence fails closed instead of throwing', () => {
  const root = fixture();
  const observed = observedFor(root);
  for (const approval of [undefined, null, [], {}, { schema: 'other' }, 'x']) {
    assert.deepEqual(verifyRelease({ approval, observed, now: NOW }),
      { status: 'HOLD', codes: ['APPROVAL_OR_EVIDENCE_INVALID'] });
  }
  assert.equal(verifyRelease({ approval: approvalFor(observed.manifest), observed: undefined, now: NOW }).status, 'HOLD');
  assert.equal(verifyRelease({ approval: approvalFor(observed.manifest), observed, now: 'garbage' }).status, 'HOLD');
});

test('several independent problems are all reported, none masks another', () => {
  const r = run(fixture(), (root) => {
    write(root, 'workers/entry.js', 'changed');
    write(root, 'migrations/0002_new.sql', 'x');
  }, { rollback_version_id: 'latest', financial_attestation: undefined }, { targetEnvironment: 'staging' });
  for (const c of ['WORKER_CODE_MODIFIED', 'MIGRATIONS_CHANGED', 'ROLLBACK_TARGET_MISSING_OR_INVALID',
    'FINANCIAL_ATTESTATION_MISSING', 'TARGET_ENVIRONMENT_NOT_APPROVED']) assert.ok(r.codes.includes(c), c);
});

test('manifests are deterministic: same bytes give the same digest regardless of creation order or location', () => {
  const a = fixture();
  const b = fs.mkdtempSync(path.join(os.tmpdir(), 'cdb-release-manifest-'));
  // Recreate the same tree in reverse order in another directory.
  const rels = ['migrations/0001_init.sql', 'wrangler.jsonc', 'workers/lib/router.js', 'workers/entry.js',
    'dist-public/api/intel/live.json', 'dist-public/live-intel.json', 'dist-public/runtime-state.js',
    'dist-public/soc.html', 'dist-public/index.html', ...[...DEFAULT_CONTROL_PATHS].reverse()];
  for (const rel of rels) write(b, rel, fs.readFileSync(path.join(a, rel), 'utf8'));
  assert.deepEqual(buildManifest({ root: a, sourceSha: SHA }), buildManifest({ root: b, sourceSha: SHA }));
  assert.deepEqual(buildManifest({ root: a, sourceSha: SHA }), buildManifest({ root: a, sourceSha: SHA }));
  assert.notEqual(buildManifest({ root: a, sourceSha: SHA }).manifest_digest,
    buildManifest({ root: a, sourceSha: OTHER_SHA }).manifest_digest);
});

test('tree digest equals the operator-reproducible `find | sort | sha256sum | sha256sum`', { skip: process.platform === 'win32' }, () => {
  const root = fixture();
  write(root, 'dist-public/zz.txt', 'last');
  write(root, 'dist-public/Ab.txt', 'upper-case sorts before lower-case by byte');
  const mine = digestPaths(path.join(root, 'dist-public'), ['.']);
  assert.equal(buildManifest({ root, sourceSha: SHA }).components.assets.digest, mine.digest);
  const sh = cp.execFileSync('sh', ['-c',
    'cd dist-public && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum'],
  { cwd: root, env: { ...process.env, LC_ALL: 'C' }, encoding: 'utf8' }).split(/\s+/)[0];
  assert.equal(mine.digest, sh);
  // Independent recomputation of the documented format.
  const rel = ['Ab.txt', 'api/intel/live.json', 'index.html', 'live-intel.json', 'runtime-state.js', 'soc.html', 'zz.txt'];
  const lines = rel.map((f) => `${crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'dist-public', f))).digest('hex')}  ./${f}\n`).join('');
  assert.equal(mine.digest, crypto.createHash('sha256').update(lines).digest('hex'));
});

test('a symlink inside the release tree is refused (it could point outside the reviewed bytes)', { skip: process.platform === 'win32' }, () => {
  const root = fixture();
  fs.symlinkSync('/etc/hostname', path.join(root, 'dist-public/link.txt'));
  assert.throws(() => buildManifest({ root, sourceSha: SHA }), /SYMLINK_IN_RELEASE_TREE/);
});

test('secret-name digest is order-insensitive, value-free, and rejects malformed input', () => {
  assert.equal(digestSecretNames(['b', 'a']), digestSecretNames(['a', 'b', 'a']));
  assert.notEqual(digestSecretNames(['a']), digestSecretNames(['a', 'b']));
  for (const bad of [undefined, null, 'a', [1], [''], {}]) assert.equal(digestSecretNames(bad), null);
});

test('CLI: build then verify passes; a changed file turns verify into HOLD with exit code 2', () => {
  const root = fixture();
  const cli = path.join(__dirname, 'soc-release-manifest.cjs');
  const out = path.join(root, 'release-manifest.json');
  cp.execFileSync('node', [cli, 'build', '--sha', SHA, '--root', root, '--out', out]);
  const manifest = JSON.parse(fs.readFileSync(out, 'utf8'));
  const approvalFile = path.join(root, 'approval.json');
  const secretsFile = path.join(root, 'secrets.json');
  fs.writeFileSync(approvalFile, JSON.stringify(approvalFor(manifest, {
    financial_attestation: { sha256: 'c'.repeat(64), attested_at: new Date().toISOString() },
  })));
  fs.writeFileSync(secretsFile, JSON.stringify(SECRETS));
  // The fixture feed timestamp is fixed in the past, so refresh it relative to the real clock first.
  write(root, 'dist-public/live-intel.json', JSON.stringify({ generatedAt: new Date().toISOString(), totalPublished: 1 }));
  const fresh = buildManifest({ root, sourceSha: SHA });
  fs.writeFileSync(out, JSON.stringify(fresh));
  fs.writeFileSync(approvalFile, JSON.stringify(approvalFor(fresh, {
    financial_attestation: { sha256: 'c'.repeat(64), attested_at: new Date().toISOString() },
  })));
  const args = ['verify', '--manifest', out, '--approval', approvalFile, '--sha', SHA, '--target', 'production',
    '--secrets', secretsFile, '--root', root];
  const ok = cp.spawnSync('node', [cli, ...args], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /NOT DEPLOY AUTHORIZATION/);
  write(root, 'workers/entry.js', 'export default {};');
  const bad = cp.spawnSync('node', [cli, ...args], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /WORKER_CODE_MODIFIED/);
  assert.match(bad.stderr, /SUPPLIED_MANIFEST_DOES_NOT_MATCH_TREE/);
});

// ─── Phase 6: release-control files, approver / approval time, substitution ─────────────────────────────

test('schema v2: a v1 approval or manifest is refused rather than silently accepted', () => {
  assert.equal(MANIFEST_SCHEMA, 'cdb-soc-release-manifest/v2');
  assert.equal(APPROVAL_SCHEMA, 'cdb-soc-release-approval/v2');
  const root = fixture();
  const approved = buildManifest({ root, sourceSha: SHA });
  const v1 = approvalFor(approved, { schema: 'cdb-soc-release-approval/v1' });
  const r = verifyRelease({ approval: v1, observed: observedFor(root), now: NOW });
  assert.equal(r.status, 'HOLD');
  assert.deepEqual(r.codes, ['APPROVAL_OR_EVIDENCE_INVALID']);
});

test('release-control files are digested: every default path is a real file in this repository', () => {
  const repoRoot = path.resolve(__dirname, '..');
  for (const f of DEFAULT_CONTROL_PATHS) {
    assert.ok(fs.existsSync(path.join(repoRoot, f)), `${f} must exist, or the control digest silently covers nothing`);
  }
  assert.ok(DEFAULT_CONTROL_PATHS.includes('.github/workflows/cloudflare-production-deploy.yml'));
  assert.ok(DEFAULT_CONTROL_PATHS.includes('scripts/soc-release-manifest.cjs'));
});

test('an unreviewed change to ANY release-control file after approval is rejected, by name', () => {
  for (const f of DEFAULT_CONTROL_PATHS) {
    const r = run(fixture(), (root) => write(root, f, `// patched after approval\nprocess.exit(0);\n`));
    assert.equal(r.status, 'HOLD', f);
    // the component is named, and (as for every component) the approved manifest digest no longer matches
    assert.deepEqual(r.codes, ['MANIFEST_DIGEST_MISMATCH', 'RELEASE_CONTROL_MODIFIED'], f);
  }
});

test('a missing release-control file makes the manifest unbuildable instead of being skipped', () => {
  const root = fixture();
  fs.rmSync(path.join(root, DEFAULT_CONTROL_PATHS[0]));
  assert.throws(() => buildManifest({ root, sourceSha: SHA }));
});

test('approver and approval time are required, well-formed, not future-dated and not stale', () => {
  const codesFor = (over) => run(fixture(), null, over).codes;
  assert.deepEqual(codesFor({ approved_by: undefined }), ['APPROVAL_IDENTITY_MISSING']);
  for (const bad of ['', ' ', 'a b', '../x', 'x'.repeat(101), '<script>', 42, null]) {
    assert.deepEqual(codesFor({ approved_by: bad }), ['APPROVAL_IDENTITY_MISSING'], JSON.stringify(bad));
  }
  assert.deepEqual(codesFor({ approved_at: undefined }), ['APPROVAL_TIMESTAMP_INVALID']);
  for (const bad of ['', 'yesterday', 12345, null, '2026-13-45T00:00:00Z']) {
    assert.deepEqual(codesFor({ approved_at: bad }), ['APPROVAL_TIMESTAMP_INVALID'], JSON.stringify(bad));
  }
  assert.deepEqual(codesFor({ approved_at: new Date(NOW + 60 * 60 * 1000).toISOString() }), ['APPROVAL_TIMESTAMP_INVALID']);
  assert.deepEqual(codesFor({ approved_at: new Date(NOW - MAX_APPROVAL_AGE_MS - 1000).toISOString() }), ['APPROVAL_STALE']);
  assert.deepEqual(codesFor({ approved_at: new Date(NOW - MAX_APPROVAL_AGE_MS + 60000).toISOString() }), []);
});

test('a newer publisher commit cannot silently replace an approved artifact: regenerated feed bytes at the same SHA are rejected', () => {
  const r = run(fixture(), (root) => {
    write(root, 'dist-public/live-intel.json', JSON.stringify({ generatedAt: '2026-11-13T00:25:00.000Z', totalPublished: 7466, items: [] }));
    write(root, 'dist-public/api/intel/live.json', JSON.stringify({ generated: '2026-11-13T00:25:00.000Z', total_published: 7466, items: [] }));
  });
  assert.equal(r.status, 'HOLD');
  assert.ok(r.codes.includes('FEED_MODIFIED'));
  assert.ok(r.codes.includes('ASSETS_MODIFIED'));   // the feeds are also inside the asset tree
  assert.ok(r.codes.includes('MANIFEST_DIGEST_MISMATCH'));
});

test('artifact substitution after approval: rebuilding a consistent manifest over swapped bytes still fails against the approval', () => {
  const root = fixture();
  const approved = buildManifest({ root, sourceSha: SHA });
  const approval = approvalFor(approved);
  write(root, 'dist-public/soc.html', '<html>substituted</html>');
  write(root, 'workers/entry.js', 'export default { fetch() { return new Response("evil"); } };');
  const rebuilt = buildManifest({ root, sourceSha: SHA });           // internally consistent, but not the approved bytes
  const r = verifyRelease({ approval, observed: { ...observedFor(root), manifest: rebuilt }, now: NOW });
  assert.equal(r.status, 'HOLD');
  assert.deepEqual(r.codes, ['ASSETS_MODIFIED', 'MANIFEST_DIGEST_MISMATCH', 'WORKER_CODE_MODIFIED']);
});

test('a manifest whose control digest was edited to hide a change is not recomputable', () => {
  const root = fixture();
  const approved = buildManifest({ root, sourceSha: SHA });
  const approval = approvalFor(approved);
  write(root, DEFAULT_CONTROL_PATHS[0], '# patched\n');
  const forged = buildManifest({ root, sourceSha: SHA });
  forged.components.control.digest = approved.components.control.digest;   // claim "unchanged"
  const r = verifyRelease({ approval, observed: { ...observedFor(root), manifest: forged }, now: NOW });
  assert.equal(r.status, 'HOLD');
  assert.ok(r.codes.includes('MANIFEST_DIGEST_MISMATCH'));
});

test('CLI: build includes the control component; a changed control file turns verify into HOLD (exit 2)', { skip: process.platform === 'win32' }, () => {
  const root = fixture();
  const out = path.join(root, 'manifest.json');
  const bin = path.resolve(__dirname, 'soc-release-manifest.cjs');
  assert.equal(cp.spawnSync(process.execPath, [bin, 'build', '--sha', SHA, '--root', root, '--out', out]).status, 0);
  const manifest = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.ok(manifest.components.control.digest && manifest.components.control.files === DEFAULT_CONTROL_PATHS.length);
  const approvalFile = path.join(root, 'approval.json');
  fs.writeFileSync(approvalFile, JSON.stringify(approvalFor(manifest, { approved_at: new Date().toISOString() })));
  fs.writeFileSync(path.join(root, 'secrets.json'), JSON.stringify(SECRETS));
  write(root, DEFAULT_CONTROL_PATHS[1], '// changed\n');
  const verify = cp.spawnSync(process.execPath, [bin, 'verify', '--manifest', out, '--approval', approvalFile, '--sha', SHA,
    '--target', 'production', '--secrets', path.join(root, 'secrets.json'), '--root', root], { encoding: 'utf8' });
  assert.equal(verify.status, 2);
  assert.match(verify.stderr, /RELEASE_CONTROL_MODIFIED/);
});
