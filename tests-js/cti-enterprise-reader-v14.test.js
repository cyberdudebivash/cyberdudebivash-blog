'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { CSS, STYLE_ID, renderReaderGuide } = require('../scripts/cti-enterprise-reader-v14');
const { generatePostHTML, validateRenderedPost } = require('../fetch-live-intel.js');
const { renderPage } = require('../generate-cve-pages.js');

const post = {
  id:'CVE-2026-11001', title:'Example vendor security notice',
  desc:'Review affected assets before determining exposure.',
  type:'CVE_REPORT', source:'vendor', _sources:['vendor'], sourceCount:1,
  cvss:7.5, priority:32, threatLevel:'LOW', exploited:false,cisaKev:false,
  iocs:[], refs:['https://vendor.example/advisory'],pubDate:'2026-10-18',
  vendor:'Example', product:'Service', cves:['CVE-2026-11001'],
};
const cve = {
  id:'CVE-2026-11001', title:'Example vendor security notice',
  description:'Verify exposure in owned systems.', cvss:7.5,threat_level:'LOW',
  type:'CVE_REPORT', sources:['vendor'], first_seen:'2026-10-18',
  last_seen:'2026-10-18',exploited:false,cisa_kev:false,
  vendor:'Example', product:'Service', refs:['https://vendor.example/advisory'],iocs:[],
};

test('v14 enterprise reader renders once in live dossier posts, after existing SOC cover', () => {
  const html = generatePostHTML({...post}).html;
  assert.equal((html.match(new RegExp('id="' + STYLE_ID + '"', 'g')) || []).length, 1);
  assert.equal((html.match(/data-cdb-reader-v14="true"/g) || []).length, 1);
  assert.ok(html.indexOf('data-cdb-soc-cti-v12="true"') < html.indexOf('data-cdb-reader-v14="true"'));
  assert.ok(html.indexOf('data-cdb-reader-v14="true"') < html.indexOf('Executive Summary'));
  assert.ok(html.includes('id="cdb-cti-reader-v13-css"'));
  assert.equal(validateRenderedPost({...post},html).pass, true);
});

test('standalone CVE reports receive the same v14 stylesheet and valid source shortcuts', () => {
  const html = renderPage({...cve});
  assert.equal((html.match(new RegExp('id="' + STYLE_ID + '"','g')) || []).length, 1);
  assert.match(html, /data-cdb-reader-v14="true"/);
  const guide = html.split('data-cdb-reader-v14="true"')[1].split('</section>')[0];
  for (const id of ['cdb-static-executive','cdb-static-technical','cdb-static-references']) {
    assert.ok(guide.includes('href="#' + id + '"'), id);
    assert.ok(html.includes('id="' + id + '"'), id + ' target');
  }
  assert.doesNotMatch(guide,/href="#cdb-static-response"/);
});

test('post report source and response shortcuts point to actual sections', () => {
  const html=generatePostHTML({...post}).html;
  const guide=html.split('data-cdb-reader-v14="true"')[1].split('</section>')[0];
  for (const id of ['cdb-static-executive','cdb-static-technical','cdb-static-references','cdb-static-response']) {
    assert.ok(guide.includes('href="#'+id+'"'),id);
    assert.ok(html.includes('id="'+id+'"'),id+' target');
  }
});

test('missing reference data hides broken source anchor on both surfaces', () => {
  const html=generatePostHTML({...post,refs:[]}).html;
  const archive=renderPage({...cve,refs:[]});
  const a=html.split('data-cdb-reader-v14="true"')[1].split('</section>')[0];
  const b=archive.split('data-cdb-reader-v14="true"')[1].split('</section>')[0];
  assert.doesNotMatch(a,/href="#cdb-static-references"/);
  assert.doesNotMatch(b,/href="#cdb-static-references"/);
});

test('guidance is keyboard-accessible native HTML without claims of SOC attestation', () => {
  const html=renderReaderGuide({surface:'post',hasSources:true});
  assert.match(html,/<nav class="cdb-v14-shortcuts" aria-label="Report section shortcuts">/);
  assert.match(html,/<details><summary>How to read this intelligence report<\/summary>/);
  assert.match(html,/Customer exposure remains unverified/);
  assert.match(html,/Print \/ Save as PDF/);
  assert.doesNotMatch(html,/<script|onclick|onerror|SOC 2 Type II certified|customer compromise verified/i);
  assert.throws(()=>renderReaderGuide({surface:'unsupported'}),RangeError);
});

test('enterprise typesetting respects mobile/keyboard/reduced-motion/accessibility', () => {
  assert.match(CSS, /font-size:clamp\(27px/);
  assert.match(CSS, /max-width:78ch/);
  assert.match(CSS, /min-height:44px/);
  assert.match(CSS, /:focus-visible/);
  // Blogger's global nav CSS is sticky; report shortcuts must NOT inherit it.
  assert.match(CSS, /\.cdb-v14-shortcuts\{[^}]*position:static!important/);
  assert.match(CSS, /\.cdb-v14-shortcuts\{[^}]*height:auto!important/);
  assert.match(CSS, /@media\(max-width:760px\)/);
  assert.match(CSS, /\.cdb-v14-shortcuts\{display:grid!important/);
  assert.match(CSS, /overflow-x:auto/);
  assert.match(CSS, /prefers-reduced-motion:reduce/);
  assert.match(CSS, /animation:none!important/);
});

test('print and PDF stylesheet is source-preserving and removes conversion blockers', () => {
  assert.match(CSS, /@page\{size:A4;margin:15mm 13mm\}/);
  assert.match(CSS, /@media print/);
  assert.match(CSS, /body \.sidebar/);
  assert.match(CSS, /max-height:none!important/);
  assert.match(CSS, /white-space:pre-wrap!important/);
  assert.match(CSS, /break-after:avoid-page/);
  assert.match(CSS, /table-layout:fixed/);
  assert.doesNotMatch(CSS, /@import|@font-face|https?:\/\/|<script/i);
});

test('report facts, TLP/IOC source and suppression logic not transformed by reader styling', () => {
  const html=generatePostHTML({...post}).html;
  assert.match(html,/vendor\.example\/advisory/);
  assert.match(html,/CVSS 7\.5/);
  assert.match(html,/No source-validated detection content is established/);
  assert.doesNotMatch(html,/Model confidence: 99%|customer compromise verified/i);
});

test('v14 module never inserts remote scripts or writes production state', () => {
  const html=renderReaderGuide({surface:'cve',hasSources:false});
  assert.doesNotMatch(html,/<script|<form|fetch\(|<img|<iframe/i);
  assert.doesNotMatch(html,/href="#cdb-static-references"/);
  assert.doesNotMatch(html,/href="#cdb-static-response"/);
  assert.ok(html.includes('href="#cdb-static-technical"'));
});
