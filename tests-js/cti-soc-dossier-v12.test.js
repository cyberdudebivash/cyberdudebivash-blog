'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {renderSocCtiCover,CSS}=require('../scripts/cti-soc-cover');
const {generatePostHTML,validateRenderedPost}=require('../fetch-live-intel.js');

const base={
  id:'CVE-2026-11001',title:'Source-linked libmng CVE analysis',
  desc:'Advisory describes an affected component that must be verified.',
  type:'CVE_REPORT',source:'vendor',_sources:['vendor'],sourceCount:1,
  cvss:7.5,priority:32,threatLevel:'LOW',exploited:false,cisaKev:false,
  iocs:[],refs:['https://vendor.example/advisory'],pubDate:'2026-10-18',
  vendor:'Example',product:'libmng',cves:['CVE-2026-11001'],
};
const htmlOf=overrides=>generatePostHTML({...base,...overrides}).html;
const coverOf=overrides=>renderSocCtiCover({...base,...overrides});

test('every static intelligence report gets one premium CTI and SOC evidence cover',()=>{
  const html=htmlOf();
  assert.equal((html.match(/data-cdb-soc-cti-v12="true"/g)||[]).length,1);
  assert.ok(html.includes('id="cdb-soc-cti-v12-css"'));
  assert.ok(html.includes('SENTINEL APEX™ / CYBERDUDEBIVASH® ECOSYSTEM'));
  assert.ok(html.includes('SOC ANALYST DECISION RECORD'));
  assert.ok(html.indexOf('data-cdb-soc-cti-v12')<html.indexOf('class="meta-bar"'));
});

test('CVSS and editorial priority remain separate in the cover',()=>{
  const cover=coverOf();
  assert.match(cover,/7\.5 · HIGH/);
  assert.match(cover,/32\/100 · LOW/);
  assert.match(cover,/1 collected; not corroboration/);
});

test('absent CVSS and exploit evidence never become invented scores or attack events',()=>{
  const cover=coverOf({cvss:null,priority:null,cisaKev:false,exploited:false});
  assert.match(cover,/Not assigned · UNASSESSED/);
  assert.match(cover,/Not established by this source record/);
  assert.match(cover,/Customer exposure: NOT ASSESSED/);
  assert.match(cover,/Incident determination: NOT MADE/);
  assert.match(cover,/not an AICPA SOC 2 Type I\/II attestation/);
});

test('rendered navigation links all lead to actual headings',()=>{
  const html=htmlOf();
  const links=[...html.matchAll(/<a href="(#cdb-[^"]+)">/g)].map(m=>m[1].slice(1));
  assert.ok(links.length>=5);
  for(const id of links)assert.ok(html.includes('id="'+id+'"'),'Missing '+id);
});

test('source URL scheme and HTML metacharacters are handled defensively',()=>{
  const cover=coverOf({title:'<img onerror="alert(1)">',refs:['javascript:alert(1)']});
  assert.ok(cover.includes('&lt;img'));
  assert.ok(!cover.includes('<img'));
  assert.ok(!cover.includes('href="javascript:'));
  assert.ok(!cover.includes('Open cited source'));
});

test('family-adaptive briefing changes to AI trust boundary without falsely adding CVSS',()=>{
  const cover=coverOf({type:'AI_SECURITY',cvss:null,id:'AI-ADVISORY-42'});
  assert.match(cover,/AI \/ agent trust boundaries/);
  assert.match(cover,/Not assigned · UNASSESSED/);
  assert.doesNotMatch(cover,/7\.5 · HIGH/);
});

test('new CSS remains self-contained and responsive without dynamic network dependencies',()=>{
  assert.ok(CSS.includes('@media(max-width:720px)'));
  assert.ok(CSS.includes('@media print'));
  assert.ok(!CSS.includes('@import'));
});

test('existing fail-closed rendered post gate accepts evidence-safe premium cover',()=>{
  const item={...base};
  const html=generatePostHTML(item).html;
  const result=validateRenderedPost(item,html);
  assert.equal(result.pass,true,(result.reasons||[]).join('; '));
});
