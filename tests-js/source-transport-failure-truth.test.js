'use strict';
/**
 * P0: source adapters must not turn upstream exceptions into a successful
 * empty response. runTier owns the bounded failure fallback and keeps every
 * failure in state.sourceHealth while preserving the last published corpus.
 *
 * Source-boundary regression: no real provider calls, writes, or deployment.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'fetch-live-intel.js'), 'utf8');
const adapters = Object.freeze([
  ['fetchCISAKev', 'CISA KEV'],
  ['fetchCISAAlerts', 'CISA Alerts'],
  ['fetchGitHubAdvisories', 'GitHub Advisories'],
  ['fetchURLhaus', 'URLhaus'],
  ['fetchThreatFox', 'ThreatFox'],
  ['fetchMSRC', 'MSRC'],
  ['fetchExploitDB', 'ExploitDB'],
  ['fetchPacketStorm', 'PacketStorm'],
  ['fetchFullDisclosure', 'Full Disclosure'],
]);

function functionSource(name) {
  const start = source.indexOf('async function ' + name + '(');
  assert.ok(start >= 0, 'missing source adapter ' + name);
  const next = source.indexOf('\nasync function ', start + 15);
  return source.slice(start, next === -1 ? source.length : next);
}

for (const [name, label] of adapters) {
  test(name + ' propagates failed upstream requests instead of claiming successful zero-yield', () => {
    const body = functionSource(name);
    const errorHandler = body.split('\n').find(line => line.includes('warn(`' + label + ' failed:'));
    assert.ok(errorHandler, name + ': expected explicit source-specific failure log');
    assert.match(errorHandler, /catch\s*\(e\)\s*\{[^\n]*\bthrow\s+e\s*;/);
    assert.doesNotMatch(errorHandler, /return\s*\[\s*\]/);
  });
}

test('central per-source collector catches upstream failures and records failure, not success', () => {
  const body = functionSource('runTier');
  assert.match(body, /\.then\(items\s*=>\s*\{/);
  assert.match(body, /recordSourceSuccess\(state,\s*key,\s*items\.length\)/);
  assert.match(body, /\.catch\(e\s*=>\s*\{\s*recordSourceFailure\(state,\s*key,\s*e\.message\)/);
  assert.match(body, /return\s*\[\s*\]/);
});

test('enrichment-only EPSS lookup stays optional and returns no invented score', () => {
  assert.match(functionSource('fetchEpssBatch'), /catch\s*\(e\)\s*\{[^\n]*return\s*\{\s*\}/);
});
