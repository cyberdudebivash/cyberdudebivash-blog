'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const certification=fs.readFileSync(path.join(root,'.github/workflows/customer-release-certification.yml'),'utf8');
const deploy=fs.readFileSync(path.join(root,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');

test('P0 commercial certification and manual deployment reject all moderate-or-higher runtime advisories',()=>{
  const expected='npm audit --omit=dev --audit-level=moderate';
  assert.equal(certification.split(expected).length-1,1);
  assert.match(deploy,/npm audit --omit=dev --audit-level=moderate/);
  assert.doesNotMatch(certification,/npm audit --omit=dev --audit-level=critical/);
});

test('customer release security audit runs immediately after locked install, before expensive suites and GO',()=>{
  const install=certification.indexOf('npm ci --legacy-peer-deps');
  const audit=certification.indexOf('npm audit --omit=dev --audit-level=moderate');
  const issue=certification.indexOf('name: "Block release while P0 customer incidents remain open"');
  const integration=certification.indexOf('name: "Run complete Blogger evidence/syndication suite"');
  const go=certification.indexOf('CUSTOMER_RELEASE_STATUS=GO');
  assert(install>=0&&audit>install&&issue>audit&&integration>audit&&go>integration);
  const gate=certification.slice(certification.lastIndexOf('      - name:',audit),certification.indexOf('      - name:',audit+1));
  assert.doesNotMatch(gate,/\|\|\s*true|continue-on-error:|--force|npm audit fix/);
});

test('release certification stays manual-only, read-only, and blocks unresolved customer incidents',()=>{
  assert.match(certification,/on:\s*\n  workflow_dispatch:\s*\n/);
  assert.doesNotMatch(certification,/\n  schedule:|\n  push:|\n  pull_request:/);
  assert.match(certification,/permissions:\s*\n  contents: read\n  issues: read/);
  assert.match(certification,/const blockers = \[222, 360, 418, 432, 433, 434, 494\]/);
  assert.match(certification,/node scripts\/certify-soc-public-feed-parity\.cjs/);
  assert.match(certification,/node scripts\/certify-soc-s2n-api-release\.cjs --monitor-public/);
});
