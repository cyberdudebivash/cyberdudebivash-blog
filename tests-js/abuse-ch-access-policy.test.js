'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { abuseChHeaders, authenticatedRedirectUrl } = require('../scripts/abuse-ch-access-policy.cjs');

const validKey = 'SampleTestProviderKey000000001';
const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'fetch-live-intel.js'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/sentinel-apex.yml'), 'utf8');

test('unapproved commercial provider usage fails closed even with a valid key', () => {
  assert.throws(() => abuseChHeaders({key: validKey, commercialUseApproved: 'false'}), /ABUSE_CH_COMMERCIAL_USE_NOT_APPROVED/);
  assert.throws(() => abuseChHeaders({key: validKey}), /ABUSE_CH_COMMERCIAL_USE_NOT_APPROVED/);
});

test('approved use requires a validated private key without response disclosure', () => {
  assert.throws(() => abuseChHeaders({commercialUseApproved:'true'}), /ABUSE_CH_AUTH_KEY_MISSING_OR_INVALID/);
  assert.throws(() => abuseChHeaders({key: 'abc\r\nInjected: yes', commercialUseApproved:'true'}), /ABUSE_CH_AUTH_KEY_MISSING_OR_INVALID/);
  assert.deepEqual(abuseChHeaders({key: validKey, commercialUseApproved:'true'}), {'Auth-Key': validKey});
});

test('an authenticated cross-origin redirect must not forward a provider key', () => {
  assert.throws(() => authenticatedRedirectUrl('https://threatfox-api.abuse.ch/api/v1/', 'https://example.invalid/steal', {'Auth-Key':validKey}), /ABUSE_CH_CROSS_ORIGIN_AUTH_REDIRECT_DENIED/);
  assert.throws(() => authenticatedRedirectUrl('https://urlhaus-api.abuse.ch/v1/payloads/recent/', '//example.invalid/steal', {'auth-key':validKey}), /ABUSE_CH_CROSS_ORIGIN_AUTH_REDIRECT_DENIED/);
  assert.equal(authenticatedRedirectUrl('https://threatfox-api.abuse.ch/api/v1/','/api/v2/', {'Auth-Key':validKey}), 'https://threatfox-api.abuse.ch/api/v2/');
});

test('the engine uses guarded redirect handler and validated provider access for both feeds', () => {
  assert.match(source, /authenticatedRedirectUrl\(rawUrl, res\.headers\.location, opts\.headers \|\| \{\}\)/);
  for (const name of ['fetchURLhaus','fetchThreatFox']) {
    const start = source.indexOf('async function ' + name + '(');
    assert.ok(start > 0, name);
    const end = source.indexOf('\nasync function ', start + 16);
    const block = source.slice(start, end < 0 ? source.length : end);
    assert.match(block, /abuseChHeaders\(/, name);
    assert.match(block, /process\.env\.ABUSE_CH_AUTH_KEY/, name);
    assert.match(block, /process\.env\.CDB_ABUSE_CH_COMMERCIAL_USE_APPROVED/, name);
  }
  assert.match(source, /fetchWithRetry\(CFG\.urlhausApi, \{ method:'GET', headers \}\)/);
  assert.match(source, /if \(data\.query_status === 'no_result'\) return \[\];/);
  assert.match(source, /THREATFOX_INVALID_PROVIDER_RESPONSE/);
});

test('CERT-EU RSS is pinned to published category feed, not known broken endpoint', () => {
  assert.match(source, /certEuRss:\s*'https:\/\/cert\.europa\.eu\/publications\/threat-intelligence-rss'/);
  assert.doesNotMatch(source, /publications\/threat-intelligence\/rss/);
});

test('CI only exposes owner-provisioned provider credentials and approval to bounded pipeline job', () => {
  assert.match(workflow, /ABUSE_CH_AUTH_KEY:\s*\$\{\{ secrets\.ABUSE_CH_AUTH_KEY \}\}/);
  assert.match(workflow, /CDB_ABUSE_CH_COMMERCIAL_USE_APPROVED:\s*\$\{\{ vars\.CDB_ABUSE_CH_COMMERCIAL_USE_APPROVED \}\}/);
  assert.doesNotMatch(workflow, /[A-Za-z]*Auth-Key:.*\$\{\{/);
});
