'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const customerRelease = path.join(root, '.github/workflows/customer-release-certification.yml');
const publisher = path.join(root, '.github/workflows/blogger-syndication.yml');
const requiredIssueNumbers = [222, 360, 418, 432, 433, 434, 494];

function bloggerStatePushFailsClosed(text) {
  const match = text.match(/Push failed after 3 attempts[^\r\n]*\r?\n\s*exit\s+(\d+)\b/);
  return match !== null && Number(match[1]) !== 0;
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
