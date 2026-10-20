'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const drift = fs.readFileSync(path.join(root, '.github/workflows/production-drift-reconcile.yml'), 'utf8');
const deploy = fs.readFileSync(path.join(root, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');

test('drift reconciler cannot auto-retry an already failed deployment/certification', () => {
  const query = drift.indexOf('last_completed="$(jq -r');
  const stop = drift.indexOf('if [ -n "$last_completed" ] && [ "$last_completed" != "success" ]');
  const guard = drift.indexOf('echo "drift=blocked" >> "$GITHUB_OUTPUT"');
  const exit = drift.indexOf('exit 0', guard);
  const dispatch = drift.indexOf('echo "drift=true" >> "$GITHUB_OUTPUT"');
  assert.ok(query > 0 && stop > query && guard > stop && exit > guard && dispatch > exit,
    'failed certification must stop automatic deployment before dispatch');
  assert.match(drift, /Production deployment certification failed/);
  assert.match(drift, /operator-reviewed/);
});

test('only explicit TRUE drift state can trigger an automatic deploy', () => {
  assert.match(drift, /if: steps\.drift\.outputs\.drift == 'true'/);
  assert.match(drift, /latest fully certified deploy/);
  assert.match(drift, /last failed deploy requiring review/);
});

test('route-marker certification still executes after real deployment', () => {
  assert.match(deploy, /- name: "Certify SOC 2 \+ CTI homepage command center"/);
  assert.match(deploy, /customer_route_check\s+"\/api-dashboard\.html"\s+"API Dashboard — SENTINEL APEX"/);
  assert.match(deploy, /grep -Fq "\$marker" "\$file"/);
  assert.match(deploy, /::error::Customer route \$route failed marker/);
});

test('actual build-marker gate occurs before credentials and DNS/Worker mutation', () => {
  const build = deploy.indexOf('name: "Build allowlisted production assets"');
  const preflight = deploy.indexOf('name: "Predeploy customer route certification parity — rendered build"');
  const credentials = deploy.indexOf('name: "Require deployment credentials"');
  const production = deploy.indexOf('name: "Retire Vercel DNS and deploy Cloudflare Custom Domain atomically"');
  assert.ok(build > 0 && preflight > build && credentials > preflight && production > credentials);
  assert.match(deploy, /node scripts\/preflight-customer-route-markers\.cjs dist-public/);
});
