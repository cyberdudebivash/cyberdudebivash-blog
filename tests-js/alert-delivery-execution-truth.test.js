'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const source = require('../scripts/alert-delivery-execution-gate.cjs');
const flags = Object.keys(source.REQUIRED_FLAGS);
const present = Object.fromEntries(flags.map(x => [x, 'true']));

test('only all five literal true presence flags permit the customer alert run', () => {
  assert.deepEqual(source.assessAlertDeliveryPrerequisites(present), { ok: true, codes: [] });
  for (const flag of flags) {
    const partial = { ...present, [flag]: 'false' };
    const r = source.assessAlertDeliveryPrerequisites(partial);
    assert.equal(r.ok, false, flag);
    assert.ok(r.codes.includes(source.REQUIRED_FLAGS[flag]), flag);
    const missing = { ...present };
    delete missing[flag];
    assert.equal(source.assessAlertDeliveryPrerequisites(missing).ok, false, flag);
  }
  for (const incorrect of [true, 1, 'TRUE', '1', '', null]) {
    assert.equal(source.assessAlertDeliveryPrerequisites({
      ...present, HAS_CF_TOKEN: incorrect
    }).ok, false);
  }
});

test('real CLI fails before any network use; error contains only stable codes', () => {
  const p = path.resolve(__dirname, '../scripts/alert-delivery-execution-gate.cjs');
  const secret = 'THIS_IS_AN_EXAMPLE_SECRET_THAT_MUST_NOT_BE_LOGGED';
  const safeEnv = { PATH: process.env.PATH || '', ...present };
  const good = spawnSync(process.execPath, [p], { encoding: 'utf8', env: safeEnv });
  assert.equal(good.status, 0);
  assert.match(good.stdout, /PASS: Required secret-presence preflight/);
  const bad = spawnSync(process.execPath, [p], {
    encoding: 'utf8',
    env: { ...safeEnv, HAS_CF_DB: 'false', CLOUDFLARE_API_TOKEN: secret }
  });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /CONFIGURATION_NOT_READY: CF_D1_DATABASE_ABSENT/);
  assert.doesNotMatch(bad.stderr + bad.stdout, /THIS_IS_AN_EXAMPLE_SECRET/);
});

test('workflow never reports successful completion when customer operations were skipped', () => {
  const yaml = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/alert-delivery.yml'), 'utf8');
  const gate = 'run: node scripts/alert-delivery-execution-gate.cjs';
  const evaluation = 'run: node scripts/evaluate-watchlist-changes.js';
  const delivery = 'run: node scripts/deliver-watchlist-notifications.js --limit=50';
  for (const text of [gate, evaluation, delivery]) {
    assert.equal(yaml.split(text).length - 1, 1, 'missing/duplicate operation ' + text);
  }
  assert.ok(yaml.indexOf(gate) < yaml.indexOf(evaluation));
  assert.ok(yaml.indexOf(evaluation) < yaml.indexOf(delivery));
  assert.doesNotMatch(yaml, /if:\s*steps\.preflight\.outputs/);
  assert.doesNotMatch(yaml, /continue-on-error:\s*true/);
  assert.match(yaml, /cron:\s*'27,57 \* \* \* \*'/);
  assert.match(yaml, /cancel-in-progress:\s*false/);
  assert.match(yaml, /persist-credentials:\s*false/);
});

test('last-step attestation rejects a skipped evaluator or delivery processor', () => {
  const yaml = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/alert-delivery.yml'), 'utf8');
  const evaluator = yaml.indexOf('id: evaluation');
  const delivery = yaml.indexOf('id: delivery');
  const attestation = yaml.indexOf('P0 record evaluated and processed delivery steps');
  assert.ok(evaluator >= 0 && delivery > evaluator && attestation > delivery);
  assert.match(yaml, /if:\s*\$\{\{ always\(\) \}\}/);
  assert.match(yaml, /EVALUATION_OUTCOME:\s*\$\{\{ steps\.evaluation\.outcome \}\}/);
  assert.match(yaml, /DELIVERY_OUTCOME:\s*\$\{\{ steps\.delivery\.outcome \}\}/);
  assert.match(yaml, /"\$EVALUATION_OUTCOME" != "success"/);
  assert.match(yaml, /"\$DELIVERY_OUTCOME" != "success"/);
  assert.match(yaml, /P0 Alert Execution Incomplete/);
  assert.match(yaml, /exit 1/);
  assert.match(yaml, /NOT proof any customer received an alert/);
  // Negative control: dropping the outcome check is forbidden even if the
  // preflight still runs and ordinary CI jobs pass.
  const unsafe = yaml.replace(/"\$DELIVERY_OUTCOME" != "success"/, '"ignored" == "ignored"');
  assert.equal(/"\$DELIVERY_OUTCOME" != "success"/.test(unsafe), false);
});

test('negative control: removal of the gate fails the acceptance contract', () => {
  const yaml = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/alert-delivery.yml'), 'utf8');
  const validate = s => s.includes('run: node scripts/alert-delivery-execution-gate.cjs') &&
    s.indexOf('run: node scripts/alert-delivery-execution-gate.cjs') <
      s.indexOf('run: node scripts/evaluate-watchlist-changes.js');
  assert.equal(validate(yaml), true);
  assert.equal(validate(yaml.replace('run: node scripts/alert-delivery-execution-gate.cjs',
    'run: echo previous-unsafe-preflight')), false);
});

test('alert runner installs lockfile-defined runtime dependencies before evaluation or delivery', () => {
  const yaml = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/alert-delivery.yml'), 'utf8');
  const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../package.json'), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../package-lock.json'), 'utf8'));
  const preflight = 'run: node scripts/alert-delivery-execution-gate.cjs';
  const install = 'npm ci --omit=dev --legacy-peer-deps --ignore-scripts --no-audit --no-fund';
  const moduleLoad = 'require(\\'js-yaml\\'); require(\\'./api/_lib/change-engine\\'); require(\\'./api/_lib/notification-dispatch\\')';
  const evaluate = 'run: node scripts/evaluate-watchlist-changes.js';
  const deliver = 'run: node scripts/deliver-watchlist-notifications.js --limit=50';
  const safe = content =>
    content.split(install).length === 2 &&
    content.indexOf(preflight) >= 0 &&
    content.indexOf(preflight) < content.indexOf(install) &&
    content.indexOf(install) < content.indexOf(moduleLoad) &&
    content.indexOf(moduleLoad) < content.indexOf(evaluate) &&
    content.indexOf(evaluate) < content.indexOf(deliver);
  assert.equal(pkg.dependencies['js-yaml'], lock.packages[''].dependencies['js-yaml']);
  assert.equal(pkg.dependencies['js-yaml'], '5.2.2');
  assert.equal(safe(yaml), true);
  // Negative controls: removal, reordering, or skipping dependency install
  // must fail this contract before any alert evaluator executes.
  assert.equal(safe(yaml.replace(install, 'echo no-runtime-install')), false);
  assert.equal(safe(yaml.replace(install, 'npm install js-yaml')), false);
  assert.equal(safe(yaml.replace(install, '').replace(evaluate, install + '\\n' + evaluate)), false);
});
