'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const policy=require('../scripts/production-drift-policy.cjs');

test('P0 #433: SOC public integration probe remains operational, never benign',()=>{
  const file='scripts/soc-public-integration-gate.cjs';
  assert.equal(policy.isReviewedOperationalPath(file),true);
  assert.equal(policy.isKnownBenignPath(file),false);
  const source=fs.readFileSync(path.join(__dirname,'../.github/workflows/cloudflare-production-deploy.yml'),'utf8');
  const patterns=policy.deployPaths(source);
  const baseline='a'.repeat(40),head='b'.repeat(40);
  const result=policy.classify({
    status:'ahead',base_commit:{sha:baseline},merge_base_commit:{sha:baseline},
    commits:[{sha:head}],ahead_by:1,total_commits:1,behind_by:0,
    files:[{filename:file,status:'added'}],
  },baseline,head,patterns);
  assert.equal(result.state,'manual_release_required');
  assert.deepEqual(result.unknown,[]);
  assert.deepEqual(result.operational,[file]);
});

test('P0 #433: unfamiliar source scripts continue to block',()=>{
  assert.equal(policy.isReviewedOperationalPath('scripts/unreviewed-release-override.cjs'),false);
  assert.equal(policy.isKnownBenignPath('scripts/unreviewed-release-override.cjs'),false);
});
