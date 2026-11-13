'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
test('P0 no static month-old Zero-Days or CVE sidebar masquerades as live',()=>{
 assert.doesNotMatch(html,/<!-- ACTIVE ZERO-DAYS FEED -->/);
 assert.doesNotMatch(html,/widget-title[^>]*>[^<]*Active Zero-Days/);
 assert.doesNotMatch(html,/widget-title[^>]*>[^<]*April 2026 Critical CVEs/);
 assert.doesNotMatch(html,/<!-- APRIL CVE FEED -->/);
 assert.match(html,/id="soc-source-freshness-navigation"/);
 assert.match(html,/first-party[\s\S]{0,220}feed proves freshness/);
 assert.match(html,/Expired or[\s\S]{0,130}unverifiable intelligence is withheld/);
});
test('P0 archived vulnerabilities are linked as ARCHIVE, never live',()=>{
 assert.match(html,/href="#live-intel-feed" class="quick-link"/);
 assert.match(html,/href="\/archive\.html" class="quick-link"/);
 assert.match(html,/Historical CVEs and incident research — archive only/);
 assert.match(html,/id="live-intel-feed"/);
 assert.match(html,/Research Archive \(Historical\)/);
 assert.match(html,/Historical static cards removed from the live dashboard/);
});
test('no new dashboard data authority, external feed fallback or paid API',()=>{
 const section=html.slice(html.indexOf('id="soc-source-freshness-navigation"'),
   html.indexOf('<!-- PRICING TEASER -->'));
 assert(section.length>0);
 assert.doesNotMatch(section,/<script|<iframe|fetch\(|https?:\/\/|api\/|data-cve=/i);
 assert.doesNotMatch(section,/CVE-2026-\d+/);
 assert.doesNotMatch(section,/\b(?:UNPATCHED|ACTIVE ZERO-DAY|CURRENT RISK RATING)\b/);
});
