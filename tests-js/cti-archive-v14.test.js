'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const {
  ARCHIVE_MARKER, STYLE_REF, decorateLegacyPost, findSourceForCve,
  inspectArchive, digest, cli,
}=require('../scripts/cti-archive-v14');
const {repairLegacyCveHtml,ROOT}=require('../scripts/build-cloudflare-assets');

const original='<!doctype html><html lang="en"><head><title>Old CVE</title><link rel="canonical" href="https://blog.cyberdudebivash.in/posts/cve-2026-77.html"></head>'+
'<body><article><div class="meta-bar">CVSS 7.5 · MEDIUM editorial priority</div>'+
'<h1 class="rh1">Source text stays unchanged</h1><p>One primary source report with no independently verified rule.</p>'+
'<a href="https://vendor.example/advisory">Vendor</a></article></body></html>';

test('presentation-only archived posts have safe notice, usable scoped stylesheet, unchanged primary narrative',()=>{
  const upgraded=decorateLegacyPost(original,'posts/cve-2026-77.html');
  assert.ok(upgraded.includes(ARCHIVE_MARKER));
  assert.ok(upgraded.includes('cdb-cti-archive-v14'));
  assert.ok(upgraded.includes(STYLE_REF));
  assert.ok(upgraded.includes('CVSS technical severity and editorial triage priority are different measures'));
  assert.ok(upgraded.includes('Source text stays unchanged'));
  assert.ok(upgraded.includes('https://vendor.example/advisory'));
  assert.ok(upgraded.includes('href="https://blog.cyberdudebivash.in/posts/cve-2026-77.html"'));
  assert.equal(decorateLegacyPost(upgraded,'posts/cve-2026-77.html'),upgraded);
});

test('already-modern and unrelated HTML are bytewise unchanged',()=>{
  assert.equal(decorateLegacyPost(original,'index.html'),original);
  const modern=original.replace('<article>','<article data-cdb-soc-cti-v12="true">');
  assert.equal(decorateLegacyPost(modern,'posts/example.html'),modern);
  const page='<html><head></head><body>homepage</body></html>';
  assert.equal(decorateLegacyPost(page,'posts/example.html'),page);
});

test('archive notice is not SOC 2 certification nor operational compromise conclusion',()=>{
  const upgraded=decorateLegacyPost(original,'posts/source.html');
  assert.match(upgraded,/not an audited SOC 2 attestation/);
  assert.match(upgraded,/has not been independently revalidated/);
  assert.match(upgraded,/not.*evidence of customer compromise/);
  assert.doesNotMatch(upgraded,/certified by an independent auditor/);
});

test('source inventory enforces exact CVE matching and minimum original source content',()=>{
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'cti-archive-v14-'));
  try{
    const dir=path.join(tmp,'api','intel','cve');
    fs.mkdirSync(dir,{recursive:true});
    const rel='cve/CVE-2026-77234.html';
    assert.equal(findSourceForCve(tmp,rel).status,'source_unavailable');
    const file=path.join(dir,'CVE-2026-77234.json');
    fs.writeFileSync(file,JSON.stringify({id:'CVE-2026-00001',title:'Valid vulnerability title',description:'A supported description for testing the source checks.'}));
    assert.equal(findSourceForCve(tmp,rel).status,'identity_conflict');
    fs.writeFileSync(file,JSON.stringify({id:'CVE-2026-77234',title:'Missing text',description:'short'}));
    assert.equal(findSourceForCve(tmp,rel).status,'source_insufficient');
    fs.writeFileSync(file,JSON.stringify({id:'CVE-2026-77234',title:'Valid vulnerability title',description:'A supported description for testing the source checks.'}));
    const s=findSourceForCve(tmp,rel);
    assert.equal(s.status,'source_eligible');
    assert.equal(s.source_sha256,digest(fs.readFileSync(file)));
  }finally{fs.rmSync(tmp,{recursive:true,force:true})}
});

test('read-only audit emits a deterministic per-file hash and no source mutations',()=>{
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'cti-manifest-v14-'));
  try{
    fs.mkdirSync(path.join(tmp,'posts'),{recursive:true});
    const file=path.join(tmp,'posts','one.html');
    fs.writeFileSync(file,original);
    const prior=digest(fs.readFileSync(file));
    const a=inspectArchive(tmp),b=inspectArchive(tmp);
    assert.equal(a.schema,'SENTINEL-APEX-CTI-ARCHIVE-V14');
    assert.equal(a.mode,'READ_ONLY_SOURCE_AUDIT');
    assert.equal(a.totals.post_presentation_candidates,1);
    assert.deepEqual(a,b);
    assert.equal(a.files[0].original_sha256,prior);
    assert.notEqual(a.files[0].staged_sha256,prior);
    assert.equal(digest(fs.readFileSync(file)),prior);
  }finally{fs.rmSync(tmp,{recursive:true,force:true})}
});

test('CLI never writes a manifest inside the repository',()=>{
  assert.throws(()=>cli(['--manifest',path.join(ROOT,'posts','audit.json')]),/outside repository/);
});

test('public CVE builder regenerates a matching old CVE from authoritative stored record',()=>{
  const id='CVE-2009-0238';
  const source=path.join(ROOT,'cve',id+'.html');
  assert.ok(fs.existsSync(source),'expected real CVE source fixture');
  const old=fs.readFileSync(source,'utf8');
  assert.match(old,/Detection rules, IOCs, and SIEM queries available/);
  const rec=findSourceForCve(ROOT,'cve/'+id+'.html');
  assert.equal(rec.status,'source_eligible');
  const next=repairLegacyCveHtml(source,old);
  assert.match(next,/data-cdb-soc-cti-v12="true"/);
  assert.match(next,/cdb-cti-reader-v13-css/);
  assert.doesNotMatch(next,/Detection rules, IOCs, and SIEM queries available/);
  assert.match(next,/https:\/\/blog\.cyberdudebivash\.in\/cve\/CVE-2009-0238\.html/);
  assert.equal(fs.readFileSync(source,'utf8'),old,'builder may not modify git source');
});

test('CVE legacy source date is reused, not replaced by build date',()=>{
  const {renderPage,sourceIsoDate}=require('../generate-cve-pages.js');
  assert.equal(sourceIsoDate('2026-04-14'),'2026-04-14');
  assert.equal(sourceIsoDate('not supplied'),null);
  const source=JSON.parse(fs.readFileSync(path.join(ROOT,'api','intel','cve','CVE-2009-0238.json'),'utf8'));
  const html=renderPage(source);
  assert.match(html, /"datePublished":"2026-04-14"/);
  assert.doesNotMatch(html, /"datePublished":"2026-06-22"/);
  assert.match(html, /SOURCE PUBLICATION DATE/);
});

test('compound primary references split into independently clickable HTTP links',()=>{
  const {renderPage,normalizeReferences}=require('../generate-cve-pages.js');
  const list=normalizeReferences([
    'https://learn.microsoft.com/example ; https://nvd.nist.gov/vuln/detail/CVE-2009-0238',
    'javascript:alert(1)', 'https://learn.microsoft.com/example',
    'https://guest:pass@example.com/private',
  ]);
  assert.deepEqual(list,['https://learn.microsoft.com/example','https://nvd.nist.gov/vuln/detail/CVE-2009-0238']);
  const source=JSON.parse(fs.readFileSync(path.join(ROOT,'api','intel','cve','CVE-2009-0238.json'),'utf8'));
  const html=renderPage(source);
  assert.match(html,/href="https:\/\/learn\.microsoft\.com\/en-us\/security-updates\/securitybulletins\/2009\/ms09-009"/);
  assert.match(html,/href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2009-0238"/);
  assert.doesNotMatch(html,/ms09-009 ; https:/);
});

test('CVE source records do not invent publication date or emit blank sitemap lastmod',()=>{
  const {renderPage}=require('../generate-cve-pages.js');
  const source={id:'CVE-2026-99999',title:'Vendor advisory for example service',description:'Vulnerability in a supported example component affecting a version.',refs:[],cvss:7.5};
  const html=renderPage(source);
  assert.doesNotMatch(html,/"datePublished"/);
  assert.doesNotMatch(html,/"dateModified"/);
  assert.match(html,/Source publication date/i);
});

test('historic CVSS HIGH and MEDIUM editorial priority are labeled as separate measures',()=>{
  const {normalizeArchiveSidebar}=require('../scripts/cti-archive-v14');
  const raw='<div class="vscore">8.1</div><div class="threat-badge">MEDIUM — 45/100</div>'+
    '<div class="vrow"><span class="vk">Sources</span><span class="vv" style="color:#00f">1 confirmed</span></div>';
  const fixed=normalizeArchiveSidebar(raw);
  assert.match(fixed,/Displayed CVSS 8\.1 \(HIGH\) · Editorial priority 45\/100 \(MEDIUM\)/);
  assert.match(fixed,/Sources<\/span><span class="vv" style="color:#00f">1 collected/);
  assert.equal(normalizeArchiveSidebar(fixed),fixed);
});

test('missing CVSS or malformed priority badge is not silently upgraded',()=>{
  const {normalizeArchiveSidebar}=require('../scripts/cti-archive-v14');
  const raw='<div class="vscore">N/A</div><div class="threat-badge">LOW — 39/100</div>';
  assert.equal(normalizeArchiveSidebar(raw),raw);
  const bad='<div class="vscore">12.5</div><div class="threat-badge">LOW — 39/100</div>';
  assert.equal(normalizeArchiveSidebar(bad),bad);
});
