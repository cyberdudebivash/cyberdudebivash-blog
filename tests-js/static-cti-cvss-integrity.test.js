'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generatePostHTML, generatePostCard, validateRenderedPost } = require('../fetch-live-intel.js');

function report(overrides = {}) {
  return {
    id: 'CVE-2026-112008',
    title: 'CVE-2026-112008 libmng Heap Buffer Overflow',
    desc: 'A heap buffer overflow is reported in libmng.',
    type: 'CVE_REPORT', source: 'sentinel_apex', _sources: ['sentinel_apex'],
    cvss: 6.1, priority: 37, threatLevel: 'LOW',
    vendor: 'libmng', product: 'libmng', cves: ['CVE-2026-112008'],
    cisaKev: false, exploited: false, iocs: [],
    refs: ['https://nvd.nist.gov/vuln/detail/CVE-2026-112008'],
    pubDate: '2026-10-18', sourceCount: 1,
    ...overrides,
  };
}

test('CVSS 6.1 is MEDIUM technical severity, independent of LOW editorial priority', () => {
  const { html } = generatePostHTML(report());
  assert.match(html, /CVSS 6\.1 — MEDIUM technical severity/);
  assert.match(html, /CVSS Severity<\/div>/);
  assert.match(html, /Editorial Priority \/100 \(LOW\)/);
  assert.doesNotMatch(html, /CVSS 6\.1 (?:— )?LOW/);
  assert.doesNotMatch(html, /HIGH-PRIORITY SECURITY ADVISORY/);
});

test('CVSS 7.5 is HIGH technical severity even with LOW commercial priority', () => {
  const item = report({ cvss: 7.5, priority: 31, threatLevel: 'LOW' });
  const { html } = generatePostHTML(item);
  assert.match(html, /CVSS 7\.5 — HIGH technical severity/);
  const card = generatePostCard(item, 'cve-test', item.title);
  assert.match(card, /CVSS 7\.5 — HIGH severity · Editorial priority 31\/100 \(LOW\)/);
});

test('CVSS 5.9 is MEDIUM and does not become LOW by priority-score transposition', () => {
  const { html } = generatePostHTML(report({ cvss: 5.9, priority: 36, threatLevel: 'LOW' }));
  assert.match(html, /CVSS 5\.9 — MEDIUM technical severity/);
});

test('unknown CVSS renders no numeric certainty', () => {
  const { html } = generatePostHTML(report({ cvss: null }));
  assert.match(html, /CVSS Not assigned/);
  assert.doesNotMatch(html, /CVSS null/);
});

test('no bogus Sigma or YARA based on bare CVE ID is published', () => {
  const { html } = generatePostHTML(report());
  assert.match(html, /Detection Evidence Gap/);
  assert.doesNotMatch(html, /Reference Detection Draft — Sigma/);
  assert.doesNotMatch(html, /Reference Detection Draft — YARA/);
  assert.doesNotMatch(html, /strings:\s*\$id_str/);
});

test('source-mapped ATT&CK is kept but inferred mapping is withheld', () => {
  const article = report();
  const { html } = generatePostHTML(article);
  assert.match(html, /No ATT&amp;CK technique is established/);
  assert.match(html, /NOT ESTABLISHED/);
  assert.equal(article._mitre, undefined);
  const sourced = report({
    mitreNative: { tactic: 'Initial Access', technique: 'T1190 — Exploit Public-Facing Application', sub: 'Not supplied' },
  });
  const nativeHtml = generatePostHTML(sourced).html;
  assert.match(nativeHtml, /Source-provided mapping/);
  assert.deepEqual(sourced._mitre, sourced.mitreNative);
});

test('a single source remains collected, not independently confirmed', () => {
  const { html } = generatePostHTML(report());
  assert.match(html, /1 collected/);
  assert.match(html, /does not establish independent corroboration/);
  assert.doesNotMatch(html, /1 confirmed<\/span>/);
});

test('two collected source records are not labeled independently confirmed', () => {
  const item = report({ sourceCount: 2, _sources: ['source_a', 'source_b'] });
  const html = generatePostHTML(item).html;
  const card = generatePostCard(item, 'source-test', item.title);
  assert.match(html, /2 SOURCE RECORDS/);
  assert.match(card, /2 SOURCES COLLECTED/);
  assert.doesNotMatch(html, /2x CONFIRMED/);
  assert.doesNotMatch(card, /2x CONFIRMED/);
});

test('static CVE reports include relevant commercial discovery without prices', () => {
  const { html } = generatePostHTML(report());
  assert.equal((html.match(/data-cdb-ecosystem-static-v1="true"/g) || []).length, 1);
  assert.match(html, /https:\/\/intel\.cyberdudebivash\.com/);
  assert.match(html, /https:\/\/tools\.cyberdudebivash\.com/);
  assert.match(html, /https:\/\/academy\.cyberdudebivash\.com/);
  assert.match(html, /https:\/\/www\.cyberdudebivash\.com/);
  assert.match(html, /utm_source=static_cti_report/);
  assert.doesNotMatch(html, /data-cdb-ecosystem-static-v1="true"[\s\S]*₹/);
});

test('AI reports recommend AI Security Hub rather than CVE tools', () => {
  const item = report({
    id: 'AI-ADVISORY-TEST',
    title: 'LLM agent trust-boundary assessment',
    type: 'AI_SECURITY', cvss: null, cves: [],
  });
  const { html } = generatePostHTML(item);
  assert.match(html, /AI Security Hub™/);
  assert.match(html, /utm_campaign=ai_security/);
});

test('existing publication integrity validator still accepts source-limited render', () => {
  const item = report();
  const { html } = generatePostHTML(item);
  const result = validateRenderedPost(item, html);
  assert.equal(result.pass, true, result.reasons?.join('; '));
});
