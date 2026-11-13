'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const customerRelease = path.join(root, '.github/workflows/customer-release-certification.yml');
const publisher = path.join(root, '.github/workflows/blogger-syndication.yml');
const aiSecurity = path.join(root, '.github/workflows/ai-security-intel.yml');
const requiredIssueNumbers = [222, 360, 418, 432, 433, 434, 494];

function bloggerStatePushFailsClosed(text) {
  const match = text.match(/Push failed after 3 attempts[^\r\n]*\r?\n\s*exit\s+(\d+)\b/);
  return match !== null && Number(match[1]) !== 0;
}

function aiSecurityPushFailsClosed(text) {
  return /for i in 1 2 3 4; do[\s\S]*?if \[ "\$pushed" != "true" \]; then\r?\n\s*echo [^\r\n]+\r?\n\s*exit 1\b/.test(text);
}

function customerReleaseIsFailClosed(text) {
  const match = text.match(/const\s+blockers\s*=\s*\[([\d\s,]+)\]\s*;/);
  if (!match) return false;
  const blocked = new Set((match[1].match(/\d+/g) || []).map(Number));
  if (!requiredIssueNumbers.every(n => blocked.has(n))) return false;

  const verdict = text.indexOf('CUSTOMER_RELEASE_STATUS=GO');
  const rootParity = text.indexOf('node scripts/certify-soc-public-feed-parity.cjs');
  const apiParity = text.indexOf('node scripts/certify-soc-s2n-api-release.cjs --monitor-public');
  return verdict !== -1 && rootParity !== -1 && apiParity !== -1 &&
    rootParity < verdict && apiParity < verdict;
}

test('publisher must fail the job if all state-persistence pushes fail', () => {
  assert.equal(bloggerStatePushFailsClosed(fs.readFileSync(publisher, 'utf8')), true);
});

test('negative: false-green publication ledger state is rejected', () => {
  const actual = fs.readFileSync(publisher, 'utf8');
  const unsafe = actual.replace(/(Push failed after 3 attempts[^\r\n]*\r?\n\s*)exit\s+[1-9]\d*\b/, '$1exit 0');
  assert.notEqual(unsafe, actual, 'negative fixture must modify the real script');
  assert.equal(bloggerStatePushFailsClosed(unsafe), false);
});

test('global customer release blocks known P0s and certifies all four public feeds before GO', () => {
  assert.equal(customerReleaseIsFailClosed(fs.readFileSync(customerRelease, 'utf8')), true);
});

test('negative: omitting a live P0 incident blocks global GO', () => {
  const actual = fs.readFileSync(customerRelease, 'utf8');
  const unsafe = actual.replace(/(const\s+blockers\s*=\s*\[[^\]]*),\s*433/, '$1');
  assert.notEqual(unsafe, actual, 'negative fixture must remove an incident');
  assert.equal(customerReleaseIsFailClosed(unsafe), false);
});

test('negative: removing either dual-host public certification gate blocks global GO', () => {
  const actual = fs.readFileSync(customerRelease, 'utf8');
  assert.equal(customerReleaseIsFailClosed(actual.replace('node scripts/certify-soc-public-feed-parity.cjs', 'echo disabled')), false);
  assert.equal(customerReleaseIsFailClosed(actual.replace('node scripts/certify-soc-s2n-api-release.cjs --monitor-public', 'echo disabled')), false);
});

test('AI security intelligence publisher fails closed after exhausting Git push retries', () => {
  assert.equal(aiSecurityPushFailsClosed(fs.readFileSync(aiSecurity, 'utf8')), true);
});

test('negative: AI security persistence failure cannot be green', () => {
  const actual = fs.readFileSync(aiSecurity, 'utf8');
  const unsafe = actual.replace(/(if \[ "\$pushed" != "true" \]; then\r?\n\s*echo [^\r\n]+\r?\n\s*)exit 1\b/, '$1exit 0');
  assert.notEqual(unsafe, actual, 'negative fixture must change the real failure branch');
  assert.equal(aiSecurityPushFailsClosed(unsafe), false);
});

test('P0 AI security publisher rejects non-main live runs before secret-bearing execution',()=>{
  const yaml=fs.readFileSync(aiSecurity,'utf8');
  const branch=yaml.indexOf('if [ "'+'$'+'{GITHUB_REF}" != "refs/heads/main" ]');
  const run=yaml.indexOf('if timeout 340 node ai-security-intel-engine.js');
  assert(branch>0&&run>branch);
  assert.match(yaml,/AI publisher branch blocked/);
  assert.match(yaml,/exit 2/);
});

test('P0 AI security timeout cannot bypass cleanup or become a false-green partial publication',()=>{
  const yaml=fs.readFileSync(aiSecurity,'utf8');
  const start=yaml.indexOf('if timeout 340 node ai-security-intel-engine.js; then');
  const capture=yaml.indexOf('EXIT=$?',start);
  const cleanup=yaml.indexOf('rm -f ai-security-intel.lock',start);
  const timeoutVerdict=yaml.indexOf('AI Security Publisher Timed Out',start);
  const errorExit=yaml.indexOf('exit "$EXIT"',timeoutVerdict);
  assert(start>0&&capture>start&&cleanup>capture&&timeoutVerdict>cleanup&&errorExit>timeoutVerdict);
  assert.doesNotMatch(yaml,/Pipeline timed out[^\n]*Non-fatal/);
});

test('P0 AI security Git staging and commit errors are never disguised as no change',()=>{
  const yaml=fs.readFileSync(aiSecurity,'utf8');
  const stage=yaml.indexOf('git add -A -- api/intel/ai-security.json ai-security/');
  const proof=yaml.indexOf('git diff --cached --quiet --exit-code',stage);
  const commit=yaml.indexOf('git commit -m "SENTINEL APEX AI-SEC:',stage);
  assert(stage>0&&proof>stage&&commit>proof);
  assert.doesNotMatch(yaml,/git commit -m [^\n]+\|\|\s*\{\s*echo "nothing to commit"; exit 0;/);
  assert.match(yaml,/AI publication persistence not verified/);
  assert.match(yaml,/AI staged index unavailable/);
});
