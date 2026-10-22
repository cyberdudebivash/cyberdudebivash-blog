'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const drift = fs.readFileSync(path.join(root, '.github/workflows/production-drift-reconcile.yml'), 'utf8');
const deploy = fs.readFileSync(path.join(root, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');

test('read-only drift reconciler blocks a failed manual deployment and cannot retry', () => {
  const policy = fs.readFileSync(path.join(root, 'scripts/production-drift-policy.cjs'),'utf8');
  assert.match(policy, /latest\.conclusion !== 'success'/);
  assert.match(policy, /last manual production certification failed/);
  assert.match(policy, /state: 'blocked'/);
  assert.doesNotMatch(drift, /\/dispatches|actions: write/);
  assert.match(drift, /node scripts\/production-drift-policy\.cjs/);
});

test('only explicit operator dispatch can enter the production deployment job', () => {
  assert.match(deploy, /jobs:\s*\n  deploy:[\s\S]{0,350}?if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(deploy, /environment: production/);
  assert.match(drift, /permissions:\s*\n  contents: read\n  actions: read/);
  assert.doesNotMatch(drift, /curl[^\n]*-X POST|actions: write/);
});

test('route-marker certification still executes after real deployment', () => {
  assert.match(deploy, /- name: "Certify SOC 2 \+ CTI homepage command center"/);
  assert.match(deploy, /customer_route_check\s+"\/api-dashboard\.html"\s+"API Dashboard — SENTINEL APEX"/);
  assert.match(deploy, /grep -Fq "\$marker" "\$file"/);
  assert.match(deploy, /::error::Customer route \$route failed marker/);
});

test('build and authorization gates must precede read-only domain validation and Worker deploy', () => {
  const build = deploy.indexOf('name: "Build allowlisted production assets"');
  const preflight = deploy.indexOf('name: "Predeploy customer route certification parity — rendered build"');
  const credentials = deploy.indexOf('name: "Require deployment credentials"');
  const domain = deploy.indexOf('name: "P0 precondition — verify established Worker Custom Domain without DNS writes"');
  const production = deploy.indexOf('name: "Deploy Worker assets to the existing, approved domain"');
  const post = deploy.indexOf('name: "P0 postcondition — verify existing domain mapping unchanged"');
  const live = deploy.indexOf('name: "Certify live Hybrid SOC + CTI production surfaces"');
  assert.ok(build > 0 && preflight > build && credentials > preflight &&
    domain > credentials && production > domain && post > production && live > post);
  assert.match(deploy, /node scripts\/preflight-customer-route-markers\.cjs dist-public/);
  assert.doesNotMatch(deploy, /curl[^\n]+-X (?:DELETE|POST)[^\n]+dns_records/);
});
