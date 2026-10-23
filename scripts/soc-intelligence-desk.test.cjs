'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const desk = require('../soc-intelligence-desk.js');
const runtime = require('../runtime-state.js');
const { PUBLIC_ROOT_FILES } = require('./build-cloudflare-assets.js');
const root = path.join(__dirname, '..');

test('public SOC intelligence desk assets are allowlisted and served by Cloudflare build', () => {
  for (const file of ['soc.html', 'soc-intelligence-desk.js', 'soc-intelligence-desk.css', 'runtime-state.js']) {
    assert.ok(PUBLIC_ROOT_FILES.includes(file), file + ' not public-allowlisted');
    assert.ok(fs.statSync(path.join(root, file)).isFile(), file + ' missing');
  }
  const html = fs.readFileSync(path.join(root, 'soc.html'), 'utf8');
  const runtimePos = html.indexOf('src="/runtime-state.js?');
  const deskPos = html.indexOf('src="/soc-intelligence-desk.js?');
  assert.ok(runtimePos > 0 && deskPos > runtimePos, 'freshness model must load before SOC desk');
  assert.match(html, /id="soc-intelligence-desk"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /data-desk-search/);
  assert.match(html, /data-desk-severity/);
  assert.match(html, /data-desk-exploited/);
  assert.match(html, /href="https:\/\/soc\.cyberdudebivash\.in\/soc\.html"/);
  assert.match(html, /SOC 2 alignment is not a certified SOC 2 audit/);
});

test('normalizeRecords rejects malformed feed and never promotes unrecognized severity', () => {
  assert.equal(desk.normalizeRecords({ items: 'fake' }), null);
  assert.equal(desk.normalizeRecords(null), null);
  const out = desk.normalizeRecords({ items: [
    { id: 'CVE-2026-1234', title: '<img src=x onerror=alert(1)>', threatLevel: 'critical', source: 'cisa_kev', exploited: true, link: '/posts/known.html' },
    { title: 'Evidence pending', threatLevel: 'CUSTOMER_ALERT', source: '', exploited: 'true', link: 'javascript:alert(1)' },
    { foo: 1 }
  ] });
  assert.equal(out.length, 2);
  assert.deepEqual([out[0].severity, out[1].severity], ['CRITICAL', 'UNASSESSED']);
  assert.equal(out[0].exploited, true);
  assert.equal(out[1].exploited, false);
  assert.equal(out[0].href, '/posts/known.html');
  assert.equal(out[1].href, null);
  const script = fs.readFileSync(path.join(root, 'soc-intelligence-desk.js'), 'utf8');
  assert.ok(!script.includes('innerHTML'), 'untrusted CTI text must never become HTML');
  assert.match(script, /\.textContent\s*=/);
});

test('report links restrict authority, scheme, credentials and path', () => {
  assert.equal(desk.safeRecordHref('https://blog.cyberdudebivash.in/posts/alpha.html'), '/posts/alpha.html');
  assert.equal(desk.safeRecordHref('https://soc.cyberdudebivash.in/posts/alpha.html'), '/posts/alpha.html');
  assert.equal(desk.safeRecordHref('/posts/a-b_12.html'), '/posts/a-b_12.html');
  for (const bad of [
    'javascript:alert(1)', '//evil.example/posts/alpha.html',
    'https://soc.cyberdudebivash.in.evil.example/posts/alpha.html',
    'https://soc.cyberdudebivash.in@evil.example/posts/alpha.html',
    'https://evil.example/posts/alpha.html',
    'https://blog.cyberdudebivash.in/posts/alpha.html?token=secret',
    'https://soc.cyberdudebivash.in/api/v1/customer/dashboard',
    'http://blog.cyberdudebivash.in/posts/alpha.html',
    'https://blog.cyberdudebivash.in/posts/../api.html',
  ]) assert.equal(desk.safeRecordHref(bad), null, bad);
});

test('all desk counters count only available feed items and sources, not hypothetical customer incidents', () => {
  const records = desk.normalizeRecords({ items: [
    { title: 'A', threatLevel: 'HIGH', source: 'CISA', exploited: true },
    { title: 'B', threatLevel: 'MEDIUM', source: 'cisa', exploited: false },
    { title: 'C', threatLevel: 'LOW', source: 'nvd', exploited: true }
  ] });
  assert.deepEqual(desk.metrics(records), { records: 3, exploited: 2, sources: 2 });
  assert.equal(desk.filterRecords(records, 'cisa', 'all', false).length, 2);
  assert.equal(desk.filterRecords(records, '', 'HIGH', true).length, 1);
  assert.equal(desk.filterRecords(records, '', 'LOW', false).length, 1);
  assert.equal(desk.filterRecords(records, 'NONEXISTENT', 'all', false).length, 0);
  assert.equal(desk.LIMIT, 12);
});

test('stale or missing public feed cannot be displayed as healthy runtime', () => {
  const stale = runtime.classifyFeed({ ok: true, feed: {
    generatedAt: '2026-01-01T00:00:00.000Z'
  }, nowMs: Date.parse('2026-10-23T13:00:00.000Z') });
  const unavailable = runtime.classifyFeed({ ok: false, error: 'timeout' });
  const invalid = runtime.classifyFeed({ ok: true, feed: { items: [] } });
  assert.equal(stale.state, 'STALE');
  assert.equal(unavailable.state, 'UNAVAILABLE');
  assert.equal(invalid.state, 'DEGRADED');
});

test('all data loads are bounded, manual, same-origin and without customer credentials', () => {
  const js = fs.readFileSync(path.join(root, 'soc-intelligence-desk.js'), 'utf8');
  assert.equal(desk.ENDPOINT, '/live-intel.json');
  assert.match(js, /timeoutMs:\s*8000/);
  assert.match(js, /refresh\.addEventListener\('click', fetchFeed\)/);
  assert.ok(!/setInterval\s*\(/.test(js), 'no runaway polling or Cloudflare usage');
  assert.ok(!/localStorage|Authorization:|Cookie:|\/api\/v1\/customer\//.test(js));
});
