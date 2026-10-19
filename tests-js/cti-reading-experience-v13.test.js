'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { CSS, STYLE_ID } = require('../scripts/cti-reading-style-v13');
const { generatePostHTML, validateRenderedPost } = require('../fetch-live-intel.js');
const { renderPage } = require('../generate-cve-pages.js');

const report = {
  id:'CVE-2026-11001',title:'Source-grounded security bulletin',desc:'A security advisory needs inventory review.',
  type:'CVE_REPORT',source:'vendor',_sources:['vendor'],sourceCount:1,
  cvss:7.5,priority:32,threatLevel:'LOW',exploited:false,cisaKev:false,
  iocs:[],refs:['https://vendor.example/advisory'],pubDate:'2026-10-18',
  vendor:'Example',product:'Service',cves:['CVE-2026-11001'],
};
const cve = {
  id:'CVE-2026-11001',title:'Example vulnerability in enterprise application',
  description:'A security advisory requires exposure validation.',
  cvss:7.5,threat_level:'LOW',type:'CVE_REPORT',sources:['vendor'],
  first_seen:'2026-10-18',last_seen:'2026-10-18',
  exploited:false,cisa_kev:false,vendor:'Example',product:'Service',refs:['https://vendor.example/advisory'],
  iocs:[],
};

test('static posts receive exactly one v13 reading system after SOC cover', () => {
  const html = generatePostHTML({ ...report }).html;
  assert.match(html, /<article class="cdb-cti-reader">/);
  assert.equal((html.match(new RegExp('id="' + STYLE_ID + '"', 'g')) || []).length, 1);
  assert.ok(html.includes('id="cdb-soc-cti-v12-css"'));
  assert.ok(html.includes('id="cdb-cti-reader-v13-css"'));
  const result = validateRenderedPost({ ...report }, html);
  assert.equal(result.pass, true, (result.reasons || []).join('; '));
});

test('CVE archive generator shares identical source-independent reading stylesheet', () => {
  const html = renderPage({ ...cve });
  assert.match(html, /class="container cdb-cti-reader"/);
  assert.equal((html.match(new RegExp('id="' + STYLE_ID + '"', 'g')) || []).length, 1);
  assert.match(html, /data-cdb-soc-cti-v12="true"/);
  assert.match(html, /CVSS 7.5/);
});

test('readability rules implement accessible touch targets and contrast', () => {
  assert.match(CSS, /min-height:44px/);
  assert.match(CSS, /:focus-visible/);
  assert.match(CSS, /--cdb-read-text:#e7f1fa/);
  assert.match(CSS, /font-size:clamp\(15px/);
  assert.match(CSS, /overflow-x:auto/);
});

test('mobile and print styles have no new external dependency', () => {
  assert.match(CSS, /@media\(max-width:760px\)/);
  assert.match(CSS, /@media print/);
  assert.match(CSS, /prefers-reduced-motion/);
  assert.doesNotMatch(CSS, /@import|<script|http[s]?:\/\/|@font-face/);
});

test('v13 presentation does not change report claims or source references', () => {
  const post = generatePostHTML({ ...report }).html;
  const page = renderPage({ ...cve });
  assert.match(post, /https:\/\/vendor\.example\/advisory/);
  assert.match(page, /https:\/\/vendor\.example\/advisory/);
  assert.match(post, /not an AICPA SOC 2 Type I\/II attestation/);
  assert.match(page, /not an AICPA SOC 2 Type I\/II attestation/);
});
