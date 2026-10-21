'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { STYLE_ID, CSS, OFFERINGS, recommendationsFor, renderEcosystemShowcase } =
  require('../scripts/cti-ecosystem-showcase-v1');
const { generatePostHTML, validateRenderedPost } = require('../fetch-live-intel.js');
const { renderPage } = require('../generate-cve-pages.js');

const base = {
  id:'CVE-2026-11001', title:'Offline fictional vendor notice',
  desc:'Example advisory; no customer exposure established.',
  type:'CVE_REPORT',source:'vendor', _sources:['vendor'],sourceCount:1,
  cvss:7.5,priority:30,threatLevel:'LOW',exploited:false,cisaKev:false,
  iocs:[],refs:['https://vendor.example/advisory'],pubDate:'2026-10-20',
  vendor:'Example',product:'Example Service',cves:['CVE-2026-11001']
};
const cve = {
  id:'CVE-2026-11001',title:'Offline fictional vendor notice',
  description:'No customer exposure established.',cvss:7.5,threat_level:'LOW',
  sources:['vendor'],first_seen:'2026-10-20',last_seen:'2026-10-20',
  exploited:false,cisa_kev:false,vendor:'Example',product:'Example Service',
  refs:['https://vendor.example/advisory'],iocs:[]
};

test('CVE post: one commercial block, after the SOC response and evidence references', () => {
  const html=generatePostHTML({...base}).html;
  const a=html.indexOf('data-cdb-ecosystem-promotion="v1"');
  assert.ok(a>0);
  assert.equal((html.match(/data-cdb-ecosystem-promotion="v1"/g)||[]).length,1);
  assert.ok(a>html.indexOf('id="cdb-static-response"'));
  assert.ok(a>html.indexOf('id="cdb-static-references"'));
  assert.equal((html.match(new RegExp('id="' + STYLE_ID + '"','g'))||[]).length,1);
  assert.equal(validateRenderedPost({...base},html).pass,true);
});

test('standalone CVE dossier: one showcase after technical evidence and source references',()=>{
  const html=renderPage({...cve});
  const a=html.indexOf('data-cdb-ecosystem-promotion="v1"');
  assert.ok(a>html.indexOf('id="cdb-static-technical"'));
  assert.ok(a>html.indexOf('id="cdb-static-references"'));
  assert.equal((html.match(/data-cdb-ecosystem-promotion="v1"/g)||[]).length,1);
  assert.equal((html.match(new RegExp('id="' + STYLE_ID + '"','g'))||[]).length,1);
});

test('AI reports feature AI Hub and assessment route, not arbitrary ransomware claims',()=>{
  assert.deepEqual(recommendationsFor('AI_SECURITY'),['ai','services','labs']);
  const html=renderEcosystemShowcase({type:'AI_SECURITY'});
  const featured=html.split('class="cdb-eco-actions"')[0];
  assert.match(featured,/SENTINEL APEX AI Security Hub™/);
  assert.doesNotMatch(featured,/ransomware backup validation already completed/i);
});

test('ransomware and data-breach reports prioritize relevant defender services',()=>{
  assert.deepEqual(recommendationsFor('RANSOMWARE'),['intel','services','tools']);
  assert.deepEqual(recommendationsFor('DATA_BREACH'),['services','intel','trustx']);
  assert.deepEqual(recommendationsFor('news-report'),['intel','services','tools']);
});

test('complete offering discovery uses grounded HTTPS links only and identifies private preview',()=>{
  assert.ok(Object.keys(OFFERINGS).length>=9);
  const urls=Object.values(OFFERINGS).map(x=>x.url);
  for(const url of urls){
    assert.equal(new URL(url).protocol,'https:');
    assert.ok(url.endsWith('/')||new URL(url).pathname.length>1);
  }
  const html=renderEcosystemShowcase({type:'THREAT_ACTOR'});
  for(const url of urls)assert.ok(html.includes(url),url);
  assert.match(html,/Private preview/);
  assert.match(html,/https:\/\/www\.cyberdudebivash\.com\/ecosystem/);
  assert.match(html,/contact@cyberdudebivash\.in/);
  assert.match(html,/11 platforms · 13 services · 43 products · 2 APIs/);
  assert.match(html,/Listings do not establish current availability/);
});

test('directory discoverability covers all eleven named ecosystem platforms and corporate entry points',()=>{
  for(const key of ['gateway','intel','ai','tools','labs','research','academy','globalcti','trustx','swarms','connect']){
    assert.ok(OFFERINGS[key], 'missing platform directory entry '+key);
    assert.ok(new URL(OFFERINGS[key].url).protocol==='https:');
  }
  const html=renderEcosystemShowcase({type:'AI_SECURITY'});
  for(const name of ['CYBERDUDEBIVASH® Official Gateway','CYBERDUDEBIVASH® Connect','Global CTI Research']){
    assert.ok(html.includes(name), 'not discoverable: '+name);
  }
  assert.match(html,/Explore the complete ecosystem/);
  assert.match(html,/Availability, checkout, licensing/);
});

test('products spotlight matches threat context, without implying current SKU availability',()=>{
  const ai=renderEcosystemShowcase({type:'AI_SECURITY'});
  const ransomware=renderEcosystemShowcase({type:'RANSOMWARE'});
  const cve=renderEcosystemShowcase({type:'CVE_REPORT'});
  assert.match(ai,/AGENTGUARD PRO/);
  assert.match(ai,/TrustGov AI™/);
  assert.match(ransomware,/Fortress Lockdown/);
  assert.match(ransomware,/Ransomware IOC Blocker/);
  assert.match(cve,/QuickScan/);
  assert.match(cve,/ReconX/);
  for(const h of [ai,ransomware,cve]){
    assert.match(h,/Relevant catalog products:/);
    assert.match(h,/Explore current listings/);
    assert.doesNotMatch(h,/₹|\$\d+/);
  }
});

test('commercial message is disclosed and has no unsupported price, SLA, or readiness guarantee',()=>{
  const h=renderEcosystemShowcase({type:'CVE_REPORT'});
  for(const s of ['ECOSYSTEM PROMOTION','Commercial disclosure','written authorization',
      'A paid offering does not increase the','Availability, checkout, licensing']){
    assert.ok(h.includes(s),s);
  }
  assert.doesNotMatch(h,/₹|\$\d|99\.9%|SOC 2 Type II certified|guaranteed detection|live customer scan success/i);
  assert.doesNotMatch(h,/<script|onclick=|onerror=|onmouseover=|<img|<iframe/i);
});

test('accessibility and print use no external network resources or advertisement scripts',()=>{
  assert.match(CSS, /@media print/);
  assert.match(CSS, /@media\(max-width:600px\)/);
  assert.match(CSS, /:focus-visible/);
  assert.match(CSS, /min-height:44px/);
  assert.match(CSS, /prefers-reduced-motion/);
  assert.doesNotMatch(CSS, /@import|@font-face|https?:\/\/|<script/i);
  assert.match(renderEcosystemShowcase(),/<details class="cdb-eco-directory"><summary>/);
});

test('existing static ecosystem ID and source/IOC safety remain intact',()=>{
  const h=generatePostHTML({...base}).html;
  assert.equal((h.match(/data-cdb-ecosystem-static-v1="true"/g)||[]).length,1);
  assert.match(h,/No source-validated detection content is established/);
  assert.match(h,/vendor\.example\/advisory/);
  assert.doesNotMatch(h,/data-cdb-ecosystem-promotion="v1"[\s\S]*₹/);
});

test('ransomware and AI marketing are not injected into the editorial summary or SOC guidance',()=>{
  for(const type of ['AI_SECURITY','RANSOMWARE']){
    const h=generatePostHTML({...base,type}).html;
    const p=h.indexOf('data-cdb-ecosystem-promotion="v1"');
    const prior=h.slice(0,p);
    assert.doesNotMatch(prior,/Commercial disclosure:/);
    assert.equal((h.match(/data-cdb-ecosystem-promotion="v1"/g)||[]).length,1);
  }
});

test('commercial buyer guidance is threat-specific, accessible and separate from evidence',()=>{
  const ai=renderEcosystemShowcase({type:'AI_SECURITY'});
  const ransomware=renderEcosystemShowcase({type:'RANSOMWARE'});
  const cve=renderEcosystemShowcase({type:'CVE_REPORT'});
  for(const html of [ai,ransomware,cve]){
    assert.equal((html.match(/class="cdb-eco-buyer-path"/g)||[]).length,1);
    assert.match(html,/role="note" aria-label="Commercial next-step guidance"/);
    assert.ok(html.indexOf('cdb-eco-buyer-path') < html.indexOf('cdb-eco-cards'));
    assert.match(html,/written authorization/);
  }
  assert.match(ai,/Assess AI application and agent risks/);
  assert.match(ransomware,/Review ransomware exposure/);
  assert.match(cve,/Prioritize verified asset exposure/);
  assert.doesNotMatch(ai,/Prioritize verified asset exposure/);
  assert.match(CSS,/\.cdb-eco-buyer-path/);
  assert.match(CSS,/@media print[\s\S]*cdb-eco-buyer-path/);
});

test('enterprise enquiry CTA is relevant, bounded and free of report/user data',()=>{
  const cases=[
    ['AI_SECURITY','AI%20Security%20Assessment%20Enquiry'],
    ['RANSOMWARE','Ransomware%20Readiness%20Enquiry'],
    ['CVE_REPORT','Vulnerability%20Exposure%20Review%20Enquiry']
  ];
  for(const [type,subject] of cases){
    const html=renderEcosystemShowcase({type});
    assert.ok(html.includes('mailto:contact@cyberdudebivash.in?subject='+subject),type);
    assert.equal((html.match(/mailto:contact@cyberdudebivash.in/g)||[]).length,1);
    assert.doesNotMatch(html,/\b(?:Bearer|api_key|secret_token)\b/i);
  }
  const untrusted=renderEcosystemShowcase({type:'<img src=x onerror=alert(1)>'});
  assert.match(untrusted,/Enterprise%20Security%20Enquiry/);
  assert.doesNotMatch(untrusted,/<img|onerror=|alert\(1\)/i);
});

test('enterprise evaluation provides documented procurement steps without readiness promises',()=>{
  const html=renderEcosystemShowcase({type:'AI_SECURITY'});
  assert.equal((html.match(/class="cdb-eco-evaluation"/g)||[]).length,1);
  assert.match(html,/Enterprise evaluation pathway/);
  assert.match(html,/Confirm scope and access/);
  assert.match(html,/documented engagement/);
  assert.match(html,/excluding confidential intelligence and credentials/);
  assert.match(CSS,/\.cdb-eco-evaluation/);
  assert.match(CSS,/@media print[\s\S]*cdb-eco-evaluation/);
  assert.doesNotMatch(html,/guaranteed|100% production ready|certified SOC 2 Type II/i);
});
