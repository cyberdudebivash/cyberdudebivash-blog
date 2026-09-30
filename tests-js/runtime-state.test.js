'use strict';

// Public runtime state model (runtime-state.js) and its consumers. Protects
// three production defects: (1) customer pages could sit in "VERIFYING"
// forever because no fetch had a deadline; (2) the homepage/status page called
// a feed "LIVE"/"ok" for up to 6h while the CI freshness monitor treats >180
// min as down; (3) status "AVAILABLE" was derived from a SOC 2 flag rather
// than from what actually responded.

const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const RS = require('../runtime-state.js');
const monitor = require('../scripts/check-intel-freshness.js');

const NOW = Date.parse('2026-09-30T17:00:00Z');
const minutesAgo = m => new Date(NOW - m * 60000).toISOString();
const feedAt = iso => ({ metadata: { lastPipelineRun: iso }, generatedAt: iso, items: [], stats: {} });

describe('classifier', () => {
  test('thresholds are the CI freshness monitor thresholds (single source of truth)', () => {
    assert.equal(RS.THRESHOLDS.healthyMaxMinutes, monitor.WARN_RUNTIME_MINUTES);
    assert.equal(RS.THRESHOLDS.staleAfterMinutes, monitor.DOWN_RUNTIME_MINUTES);
  });

  test('state boundaries', () => {
    const at = m => RS.classifyFeed({ ok: true, feed: feedAt(minutesAgo(m)), nowMs: NOW }).state;
    assert.equal(at(0), 'HEALTHY');
    assert.equal(at(90), 'HEALTHY');
    assert.equal(at(91), 'DEGRADED');
    assert.equal(at(180), 'DEGRADED');
    assert.equal(at(181), 'STALE');
    assert.equal(at(20 * 60), 'STALE');
  });

  test('unprovable freshness is never HEALTHY', () => {
    assert.equal(RS.classifyFeed({ ok: true, feed: { items: [] }, nowMs: NOW }).state, 'DEGRADED');
    assert.equal(RS.classifyFeed({ ok: true, feed: feedAt('not-a-date'), nowMs: NOW }).state, 'DEGRADED');
    assert.equal(RS.classifyFeed({ ok: true, feed: feedAt(minutesAgo(-30)), nowMs: NOW }).state, 'DEGRADED');
    assert.equal(RS.classifyFeed({ ok: true, feed: null, nowMs: NOW }).state, 'DEGRADED');
  });

  test('failed retrieval is UNAVAILABLE and says why', () => {
    const r = RS.classifyFeed({ ok: false, error: 'timeout', nowMs: NOW });
    assert.equal(r.state, 'UNAVAILABLE');
    assert.equal(r.reachable, false);
    assert.match(r.reason, /timeout/);
  });

  test('pipeline completion time is preferred over generation time', () => {
    const feed = { generatedAt: minutesAgo(300), metadata: { lastPipelineRun: minutesAgo(10) } };
    assert.equal(RS.classifyFeed({ ok: true, feed, nowMs: NOW }).state, 'HEALTHY');
  });

  test('the committed production feed shape classifies from its own timestamps', () => {
    const feed = JSON.parse(fs.readFileSync(path.join(ROOT, 'live-intel.json'), 'utf8'));
    const stamp = Date.parse(RS.feedTimestamp(feed));
    assert.ok(Number.isFinite(stamp), 'live-intel.json must carry a parseable pipeline timestamp');
    assert.equal(RS.classifyFeed({ ok: true, feed, nowMs: stamp + 10 * 60000 }).state, 'HEALTHY');
    assert.equal(RS.classifyFeed({ ok: true, feed, nowMs: stamp + 24 * 3600000 }).state, 'STALE');
  });
});

describe('fetchJson deadline', () => {
  test('resolves JSON on 2xx', async () => {
    const v = await RS.fetchJson('/x', { fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ a: 1 }) }) });
    assert.deepEqual(v, { a: 1 });
  });

  test('rejects non-2xx with the status', async () => {
    await assert.rejects(RS.fetchJson('/x', { fetchImpl: async () => ({ ok: false, status: 503 }) }), /http 503/);
  });

  test('a hanging request rejects with timeout and aborts the request', async () => {
    let signal;
    const hang = (_u, init) => { signal = init.signal; return new Promise(() => {}); };
    await assert.rejects(RS.fetchJson('/x', { fetchImpl: hang, timeoutMs: 20 }), /timeout/);
    assert.equal(signal.aborted, true);
  });
});

// Run the real apex-command-center.js against a minimal DOM.
function runCommandCenter(fetchImpl) {
  const els = new Map();
  const el = id => {
    if (!els.has(id)) els.set(id, { id, textContent: '', innerHTML: '', dataset: {}, addEventListener() {} });
    return els.get(id);
  };
  const rs = { ...RS, fetchJson: url => RS.fetchJson(url, { fetchImpl, timeoutMs: 25 }) };
  const window = { SentinelRuntimeState: rs, addEventListener() {}, location: { origin: 'https://blog.cyberdudebivash.in', reload() {} }, matchMedia: () => ({ matches: true }), devicePixelRatio: 1 };
  const document = { getElementById: id => (id === 'cdbSignalCanvas' ? null : el(id)) };
  const ctx = vm.createContext({ window, document, Intl, URL, Promise, setTimeout, clearTimeout, Date, Math, Number, String, Object, Array, JSON, isFinite, fetch: fetchImpl });
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'apex-command-center.js'), 'utf8'), ctx);
  return { text: id => el(id).textContent, html: id => el(id).innerHTML, state: id => el(id).dataset.state };
}
const settle = ms => new Promise(r => setTimeout(r, ms));

describe('homepage command center wiring', () => {
  test('a hanging network resolves to UNAVAILABLE instead of staying in CHECKING', async () => {
    const page = runCommandCenter(() => new Promise(() => {}));
    await settle(80);
    assert.equal(page.text('homepage-feed-state'), 'UNAVAILABLE');
    assert.equal(page.text('homepage-priority-runtime'), 'UNAVAILABLE');
    assert.match(page.html('cdb-edge-state'), /PRODUCTION EDGE · UNAVAILABLE/);
    assert.equal(page.state('cdb-runtime-pill'), 'bad');
  });

  test('a reachable but 5h-old feed reads STALE with a verified edge, never LIVE', async () => {
    const stale = { ...feedAt(new Date(Date.now() - 300 * 60000).toISOString()), totalPublished: 5, stats: { critical: 1 } };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => stale }));
    await settle(80);
    assert.equal(page.text('homepage-feed-state'), 'STALE');
    assert.match(page.text('cdb-runtime-text'), /^STALE · FEED AGE 5h 0m$/);
    assert.match(page.html('cdb-edge-state'), /PRODUCTION EDGE · VERIFIED/);
    assert.doesNotMatch(page.text('cdb-runtime-text'), /LIVE/);
  });

  test('a fresh feed reads HEALTHY', async () => {
    const fresh = { ...feedAt(new Date(Date.now() - 12 * 60000).toISOString()), totalPublished: 5, stats: {} };
    const page = runCommandCenter(async () => ({ ok: true, status: 200, json: async () => fresh }));
    await settle(80);
    assert.equal(page.text('homepage-feed-state'), 'HEALTHY');
    assert.equal(page.state('cdb-runtime-pill'), 'live');
  });
});

describe('consumer pages', () => {
  const index = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  const status = fs.readFileSync(path.join(ROOT, 'service-status.html'), 'utf8');

  test('runtime-state.js loads before the command center and is part of the public build', () => {
    const rsAt = index.indexOf('<script src="/runtime-state.js');
    const ccAt = index.indexOf('<script src="/apex-command-center.js');
    assert.ok(rsAt > 0 && ccAt > rsAt, 'runtime-state.js must precede apex-command-center.js');
    assert.ok(status.includes('<script src="/runtime-state.js'), 'status page must load the shared model');
    const { PUBLIC_ROOT_FILES } = require('../scripts/build-cloudflare-assets.js');
    assert.ok(PUBLIC_ROOT_FILES.includes('runtime-state.js'));
  });

  test('no customer page ships an unbounded VERIFYING state or a LIVE label for batch data', () => {
    for (const [name, html] of [['index.html', index], ['service-status.html', status]]) {
      assert.doesNotMatch(html, /VERIFYING/, name);
    }
    assert.doesNotMatch(fs.readFileSync(path.join(ROOT, 'apex-command-center.js'), 'utf8'), /PRODUCTION DATA LIVE/);
  });

  test('homepage does not pull intelligence through third-party CORS proxies or CSP-blocked origins', () => {
    const scripts = (index.match(/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi) || []).join('\n');
    assert.doesNotMatch(scripts, /fetch\([^)]*(?:allorigins|corsproxy|thingproxy)/i);
    assert.doesNotMatch(scripts, /fetch\(CISA_URL/);
  });

  test('status page reachability is derived from responses, not from a SOC 2 flag', () => {
    assert.doesNotMatch(status, /soc2_certified===false\?'AVAILABLE'/);
    assert.match(status, /Promise\.allSettled\(\[RS\.fetchJson\('\/api\/intel\/customer-assurance\.json'\),RS\.fetchJson\('\/live-intel\.json'\)\]\)/);
  });
});
