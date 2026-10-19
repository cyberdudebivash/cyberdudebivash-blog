'use strict';
// Verifies the live generator (fetch-live-intel.js) correctly consumes the
// detection engine. Requiring the generator is side-effect-free because it
// only runs the pipeline when invoked directly (require.main === module).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const GEN = path.join(__dirname, '..', '..', '..', 'fetch-live-intel.js');
const gen = require(GEN);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const RICH_ITEM = {
  id: 'CVE-2024-4577',
  title: 'PHP-CGI argument injection exploited to deploy ransomware',
  desc: 'Attackers exploited a public-facing PHP flaw, ran encoded PowerShell, '
    + 'established registry Run key persistence, and used vssadmin to delete '
    + 'volume shadow copies before ransomware encryption.',
  vendor: 'PHP', product: 'PHP-CGI', cvss: 9.8, threatLevel: 'CRITICAL',
  priority: 95, type: 'RANSOMWARE', cves: ['CVE-2024-4577'],
  detectionEvidenceVerified: true, // explicit test-only evidence admission
  iocs: [{ type: 'domain', value: 'evil-c2[.]top', source: 'vendor-advisory-fixture', confidence_score: 0.9, first_seen: '2026-07-04' }],
  refs: ['https://vendor.example/advisory'], pubDate: new Date().toISOString(),
};

test('generator exports the detection helpers', () => {
  assert.strictEqual(typeof gen.genMultiPlatformDetections, 'function');
  assert.strictEqual(typeof gen.generatePostHTML, 'function');
});

test('multi-platform section renders for a rich item', () => {
  const html = gen.genMultiPlatformDetections(RICH_ITEM, esc);
  assert.ok(html.includes('Multi-Platform Detection Engineering'));
  assert.ok(html.includes('Microsoft Defender / Sentinel (KQL)'));
  assert.ok(html.includes('Suricata'));
  // maps at least the three techniques present in the evidence text
  for (const tid of ['T1059.001', 'T1490', 'T1547.001']) assert.ok(html.includes(tid), tid);
});

test('section is omitted (empty string) when no evidence', () => {
  const html = gen.genMultiPlatformDetections(
    { id: 'X', title: 'quarterly finance review', desc: 'budget planning meeting', iocs: [] }, esc,
  );
  assert.strictEqual(html, '');
});

test('render is fully guarded against malformed items', () => {
  assert.strictEqual(gen.genMultiPlatformDetections(null, esc), '');
  assert.strictEqual(gen.genMultiPlatformDetections({}, esc), '');
  assert.strictEqual(gen.genMultiPlatformDetections({ iocs: 'not-an-array' }, esc), '');
});

test('full post embeds the section and stays well-formed', () => {
  const { html } = gen.generatePostHTML(RICH_ITEM);
  assert.ok(html.trim().startsWith('<!DOCTYPE'));
  assert.ok(html.trim().endsWith('</html>'));
  assert.ok(html.includes('Multi-Platform Detection Engineering'));
  const opens = (html.match(/<div/g) || []).length;
  const closes = (html.match(/<\/div>/g) || []).length;
  assert.strictEqual(opens, closes, 'div tags balanced');
});

// ── Analyst Memory wiring ──────────────────────────────────────────────
const { AnalystMemory } = require(path.join(__dirname, '..', 'analyst-memory'));

test('prior-intelligence section is empty for a first sighting', () => {
  const mem = new AnalystMemory();
  assert.strictEqual(gen.genPriorIntelligence(RICH_ITEM, esc, mem), '');
});

test('prior-intelligence section renders after the entity was seen', () => {
  const mem = new AnalystMemory();
  mem.ingest(RICH_ITEM, 'prior-report');           // history
  const html = gen.genPriorIntelligence(RICH_ITEM, esc, mem);
  assert.ok(html.includes('Prior Intelligence Context'));
  assert.ok(html.includes('CVE-2024-4577'));
  assert.ok(html.includes('previously observed'));
});

test('genPriorIntelligence is guarded (no memory / bad item -> empty)', () => {
  assert.strictEqual(gen.genPriorIntelligence(RICH_ITEM, esc, null), '');
  assert.strictEqual(gen.genPriorIntelligence(null, esc, new AnalystMemory()), '');
});

test('prior-intelligence section carries only recurrence, not correlation', () => {
  const mem = new AnalystMemory();
  mem.ingest({ id: 'CVE-2023-0001', title: 'APT41 LockBit against Fortinet',
    desc: 'APT41 used encoded PowerShell and vssadmin delete shadows before LockBit encryption',
    vendor: 'Fortinet', product: 'FortiOS', cves: ['CVE-2023-0001'] }, 'seed-report');
  const html = gen.genPriorIntelligence(RICH_ITEM, esc, mem);
  assert.ok(html.includes('Prior Intelligence Context'));
  // relational correlation now lives in the structured-reasoning section
  assert.ok(!html.includes('Threat Correlation Analysis'));
});

// ── Structured Reasoning (Analyst Reasoning) wiring ─────────────────────
test('structured reasoning renders the five labeled stages', () => {
  const item = { id: 'CVE-2024-4577', type: 'RANSOMWARE',
    title: 'LockBit exploits public-facing PHP',
    desc: 'exploited a public-facing app, encoded PowerShell, vssadmin delete shadows before encryption',
    vendor: 'PHP', cves: ['CVE-2024-4577'], cvss: 9.8, cisaKev: true, exploited: true,
    iocs: [{ type: 'domain', value: 'evil.top' }] };
  const html = gen.genStructuredReasoning(item, esc, new AnalystMemory());
  assert.ok(html.includes('Structured Intelligence Assessment'));
  assert.ok(html.includes('Verified Facts'));
  assert.ok(html.includes('Analyst Assessments'));
  assert.ok(html.includes('Intelligence Gaps'));
  assert.ok(html.includes('Forward Outlook'));
  assert.ok(html.includes('CONF')); // confidence labels present
});

test('structured reasoning is guarded (bad item / no engine path -> empty)', () => {
  assert.strictEqual(gen.genStructuredReasoning(null, esc, new AnalystMemory()), '');
  assert.strictEqual(gen.genStructuredReasoning({}, esc, new AnalystMemory()), '');
});

// ── Multi-Audience Products wiring ──────────────────────────────────────
test('intelligence products section renders audience briefs + API link', () => {
  const html = gen.genIntelligenceProducts(RICH_ITEM, esc, 'cve-2024-4577-php', new AnalystMemory());
  assert.ok(html.includes('Multi-Audience Intelligence Products'));
  assert.ok(html.includes('Executive Advisory'));
  assert.ok(html.includes('Board Brief'));
  assert.ok(html.includes('SOC Bulletin'));
  assert.ok(html.includes('/api/intel/products/cve-2024-4577-php.json'));
});

test('product API JSON is valid, machine-readable, and complete', () => {
  const json = gen.buildProductApiJSON(RICH_ITEM, new AnalystMemory());
  assert.ok(json.length > 0);
  const pkg = JSON.parse(json);
  assert.strictEqual(pkg.schema, 'sentinel-apex.intelligence/1.0');
  assert.strictEqual(pkg.severity, 'CRITICAL');
  assert.ok(pkg.mitre_attack.length > 0);
  assert.ok(pkg.detections.sigma.length > 0);
  assert.ok(pkg.iocs.some((i) => i.value === 'evil-c2[.]top')); // defanged in feed
});

test('products wiring is fully guarded', () => {
  assert.strictEqual(gen.genIntelligenceProducts(null, esc, 'x', new AnalystMemory()), '');
  assert.strictEqual(gen.buildProductApiJSON(null), '');
  assert.strictEqual(gen.genIntelligenceProducts({}, esc, 'x', new AnalystMemory()), '');
});

test('full post with products stays well-formed and div-balanced', () => {
  const { html } = gen.generatePostHTML(RICH_ITEM);
  assert.ok(html.includes('Multi-Audience Intelligence Products'));
  assert.ok(html.trim().endsWith('</html>'));
  assert.strictEqual((html.match(/<div/g) || []).length, (html.match(/<\/div>/g) || []).length);
});
