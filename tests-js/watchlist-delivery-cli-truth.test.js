'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { parseLimitArg, MAX_GITHUB_DELIVERY_LIMIT } = require('../scripts/deliver-watchlist-notifications.js');

test('delivery CLI default and fixed operation ceiling are explicit', () => {
  assert.equal(MAX_GITHUB_DELIVERY_LIMIT, 100);
  assert.equal(parseLimitArg([]), undefined);
  for (const n of [1, 2, 50, 99, 100]) assert.equal(parseLimitArg(['--limit=' + n]), n);
});

test('operator batch input rejects malformed, excessive, duplicate, partial and unknown values', () => {
  for (const values of [
    ['--limit'], ['--limit='], ['--limit=0'], ['--limit=-1'], ['--limit=101'],
    ['--limit=500'], ['--limit=99999999999999999999'], ['--limit=05'],
    ['--limit=2junk'], ['--limit=2.5'], ['--limit=1e2'],
    ['--limit=+2'], ['--limit=1', '--limit=2'], ['--limit=10', '--limit'],
    ['--batch=10'], ['--help'], ['100'], ['--limit', '50']
  ]) {
    assert.throws(() => parseLimitArg(values), /Invalid/, JSON.stringify(values));
  }
});

test('invalid argument fails before reading D1 configuration or making any query', () => {
  const filename = path.resolve(__dirname, '../scripts/deliver-watchlist-notifications.js');
  const secret = 'SECRET_VALUE_MUST_NOT_LEAK';
  const p = spawnSync(process.execPath, [filename, '--limit=100000'], {
    encoding: 'utf8', env: { ...process.env, CLOUDFLARE_API_TOKEN: secret }
  });
  assert.equal(p.status, 1);
  assert.match(p.stderr, /Invalid --limit/);
  assert.doesNotMatch(p.stdout + p.stderr, /SECRET_VALUE_MUST_NOT_LEAK/);
  assert.doesNotMatch(p.stderr, /CLOUDFLARE_ACCOUNT_ID.*must be set/);
});

test('backlog age D1 failure cannot appear as successful empty queue', () => {
  const text = fs.readFileSync(path.resolve(__dirname, '../scripts/deliver-watchlist-notifications.js'), 'utf8');
  assert.match(text, /const oldestPendingAgeSeconds = await getOldestPendingAgeSeconds\(\);/);
  assert.doesNotMatch(text, /getOldestPendingAgeSeconds\(\)\.catch\(/);
  assert.match(text, /oldest_pending_delivery_age_seconds: oldestPendingAgeSeconds/);
});

test('scheduled delivery stays at its existing 50-record ceiling', () => {
  const text = fs.readFileSync(path.resolve(__dirname, '../.github/workflows/alert-delivery.yml'), 'utf8');
  assert.match(text, /node scripts\/deliver-watchlist-notifications\.js --limit=50/);
  assert.doesNotMatch(text, /deliver-watchlist-notifications\.js --limit=(?:[1-9][0-9]{2,})/);
});
