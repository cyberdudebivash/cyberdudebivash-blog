'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const yaml = fs.readFileSync(path.join(root, '.github/workflows/soc-historical-backup-offline-proof.yml'), 'utf8');
const {classify, isReviewedOperationalPath, deployPaths} = require('../scripts/production-drift-policy.cjs');
const deployYaml = fs.readFileSync(path.join(root, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');
const check = files => classify({
  status:'ahead', base_commit:{sha:'a'.repeat(40)}, merge_base_commit:{sha:'a'.repeat(40)},
  ahead_by:1, behind_by:0, total_commits:1, commits:[{sha:'b'.repeat(40)}],
  files:files.map(filename=>({filename,status:'modified'}))
}, 'a'.repeat(40), 'b'.repeat(40), deployPaths(deployYaml));

test('manual-only confirmed workflow has no scheduled, PR or push trigger', () => {
  assert.match(yaml, /on:\s*\n\s*workflow_dispatch:/);
  assert.doesNotMatch(yaml, /^\s*(schedule|push|pull_request|pull_request_target):/m);
  assert.ok(yaml.includes('APPROVAL_CONFIRMATION: ' + String.fromCharCode(36) + '{{ inputs.confirmation }}'));
  assert.ok(yaml.includes('P0 fail closed on invalid manual owner confirmation'));
  assert.ok(yaml.includes("if [[ \"$APPROVAL_CONFIRMATION\" != 'VERIFY_HISTORICAL_BACKUP_OFFLINE' ]]; then"));
  assert.match(yaml, /Backup proof not authorized[\s\S]*?exit 2/);
  assert.ok(!yaml.split('\n').some(line => line.trim().startsWith('if:') && line.includes('inputs.confirmation')));
  assert.match(yaml, /github\.ref == 'refs\/heads\/main'/);
  assert.match(yaml, /github\.repository == 'cyberdudebivash\/cyberdudebivash-blog'/);
  assert.match(yaml, /timeout-minutes:\s*5/);
});
test('read-only minimal GitHub permissions and no public artifact uploads', () => {
  assert.match(yaml, /permissions:\s*\n\s*contents: read\s*\n\s*actions: read/);
  assert.doesNotMatch(yaml, /contents:\s*write|actions:\s*write|actions\/upload-artifact|wrangler|git push|npm publish/i);
  assert.match(yaml, /uses: actions\/checkout@v5[\s\S]*?persist-credentials: false/);
});
test('pins Nov 5 backup run, source code and exact encrypted payload bytes', () => {
  assert.match(yaml, /gh run download 42013963858/);
  assert.match(yaml, /--name customer-data-backup-42013963858/);
  assert.match(yaml, /stat -c '%s'[^]*'14302'/);
  assert.match(yaml, /80973d53b2350260f2c4b478b2ee6a8f71f4ffa86476a2a1080c16d174606438/);
  assert.match(yaml, /692ee1f2f2a8894e5782972b61d3e2f820b2581f/);
  assert.match(yaml, /0933115405f0c70c22c34cdbe19ea451486fbad0/);
});
test('backup key is only a job-step environment secret and restore is no-write', () => {
  assert.match(yaml, /BACKUP_ENCRYPTION_KEY: \$\{\{ secrets\.BACKUP_ENCRYPTION_KEY \}\}/);
  assert.match(yaml, /node scripts\/restore-customer-data\.js \\\n\s*"\$RUNNER_TEMP\/cdb-soc-p0-proof\/customer-data\.enc" >\/dev\/null 2>&1/);
  assert.doesNotMatch(yaml, /echo\s+.*BACKUP_ENCRYPTION_KEY|printenv|set -x|--confirm-production"|\s--confirm\s+--/i);
  assert.match(yaml, /unset NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS/);
  assert.match(yaml, /P0_PRODUCTION_DATA_MUTATION=false/);
});
test('reviewed operational workflow still needs manual release and unknown future secret workflow blocks', () => {
  const known = '.github/workflows/soc-historical-backup-offline-proof.yml';
  assert.equal(isReviewedOperationalPath(known), true);
  const review = check([known]);
  assert.equal(review.state,'manual_release_required');
  assert.deepEqual(review.operational,[known]);
  assert.deepEqual(review.unknown,[]);
  assert.equal(check([known,'.github/workflows/unknown-secret-copy.yml']).state,'blocked');
});
