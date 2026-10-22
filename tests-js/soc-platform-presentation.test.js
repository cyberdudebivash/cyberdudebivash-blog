'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const ROOT=path.join(__dirname,'..');
const {injectSocPresentation,renameUi,STYLESHEET}=require('../scripts/soc-platform-presentation.cjs');
const {injectCustomerExperience,PUBLIC_ROOT_FILES}=require('../scripts/build-cloudflare-assets.js');
function source(name){return fs.readFileSync(path.join(ROOT,name),'utf8');}
const build=html=>injectCustomerExperience(html);

test('homepage gets exactly one cross-platform SOC shell and premium SOC launch panel',()=>{
  const out=build(source('index.html'));
  assert.equal((out.match(/data-soc-platform-shell="v1"/g)||[]).length,1);
  assert.equal((out.match(/<main(?:\s[^>]*)?>/g)||[]).length,1);
  assert.equal((out.match(/id="soc-platform-command"/g)||[]).length,1);
  assert.match(out,/Hybrid SOC \+ CTI Platform/);
  assert.match(out,/Request SOC Assessment/);
  assert.match(out,/soc-platform-ui\.css/);
  assert.doesNotMatch(out,/>Research Blog \/ Intel Factory</);
  assert.doesNotMatch(out,/SENTINEL APEX Research Blog and Intel Factory home/);
  assert.doesNotMatch(out,/>This Blog</);
  assert.match(out,/SOC 2-aligned/i);
  assert.match(out,/not certified/i);
});
test('SOC identity appears on all root public pages without exposing unapproved routes',()=>{
  const names=['index.html','soc.html','about.html','products.html','pricing.html',
    'enterprise.html','customer-assurance.html','service-status.html','hunts.html',
    'contact.html','workbench.html','customer-incident-response.html'];
  for(const name of names){
    assert.ok(PUBLIC_ROOT_FILES.includes(name),name+' is not allowlisted');
    const doc=build(source(name));
    assert.equal((doc.match(/data-soc-platform-shell="v1"/g)||[]).length,1,name);
    assert.equal((doc.match(/soc-platform-ui\.css/g)||[]).length,1,name);
    assert.ok(doc.includes('href="/soc.html"'),name);
    assert.ok(doc.includes('href="/customer-assurance.html"'),name);
    assert.ok(doc.includes('href="/enterprise-onboarding.html"'),name);
    assert.doesNotMatch(doc,/data-soc-certified="true"/);
  }
});
test('navigation and titles remove legacy blog-era brand without rewriting technical origins',()=>{
  const sample='<!doctype html><html><head><title>SENTINEL APEX Research Blog / Intel Factory</title>'+
    '<meta name="description" content="An Intelligence Blog and Research Blog">'+
    '<link rel="canonical" href="https://blog.cyberdudebivash.in/foo.html"></head><body>'+
    '<header><a href="https://blog.cyberdudebivash.in/foo.html" aria-label="Research Blog home">This Blog</a></header>'+
    '<nav><a href="/intel/">Research Blog</a></nav>'+
    '<article><p>Historical analysis of how a researcher published a blog in 2024.</p></article>'+
    '</body></html>';
  const out=injectSocPresentation(sample);
  assert.match(out,/<title>SENTINEL APEX Hybrid SOC \+ CTI Platform<\/title>/);
  assert.match(out,/SOC Threat Intelligence home/);
  assert.match(out,/SENTINEL APEX SOC<\/a>/);
  assert.match(out,/Historical analysis of how a researcher published a blog in 2024/);
  assert.match(out,/<link rel="canonical" href="https:\/\/blog\.cyberdudebivash\.in\/foo\.html"/);
  assert.match(out,/href="https:\/\/blog\.cyberdudebivash\.in\/foo\.html"/);
});
test('idempotent, never inject duplicate nav or stylesheet on second application',()=>{
  const input='<!doctype html><html><head></head><body><main>CTI</main></body></html>';
  const one=injectSocPresentation(input);
  assert.equal(injectSocPresentation(one),one);
  assert.equal((one.match(/data-soc-platform-shell="v1"/g)||[]).length,1);
  assert.equal((one.match(/soc-platform-ui\.css/g)||[]).length,1);
});
test('byte-preserves HTML script, evidence links, seller and API fields',()=>{
  const script='const bill="Research Blog / Intel Factory"; const host="https://blog.cyberdudebivash.in";';
  const input='<html><head></head><body><script>'+script+'</script>'+
    '<main><pre>Research Blog / Intel Factory</pre>'+
    '<code>api.blog.cyberdudebivash.in</code><article>Historical CTI source citation: Research Blog, 2024.</article></main>'+
    '<footer><a href="https://blog.cyberdudebivash.in/pay" data-seller-of-record="CyberDudeBivash">Blog</a></footer>'+
    '</body></html>';
  const out=injectSocPresentation(input);
  assert.ok(out.includes('<script>'+script+'</script>'));
  assert.ok(out.includes('<pre>Research Blog / Intel Factory</pre>'));
  assert.ok(out.includes('<code>api.blog.cyberdudebivash.in</code>'));
  assert.ok(out.includes('Historical CTI source citation: Research Blog, 2024.'));
  assert.ok(out.includes('href="https://blog.cyberdudebivash.in/pay"'));
});
test('flagship SOC overview has real destinations, no dummy metrics, no false attestation',()=>{
  const sourceText=source('soc.html');
  for(const target of ['/intel/','/detections/','/hunts.html',
    '/customer-incident-response.html','/customer-assurance.html',
    '/enterprise-onboarding.html','/service-status.html','/pricing.html']){
    assert.ok(sourceText.includes('href="'+target+'"'),target);
  }
  assert.match(sourceText,/SOC 2 alignment is not a certified SOC 2 audit/);
  assert.doesNotMatch(sourceText,/99\.99% uptime|24\/7 staffed|SOC 2 Type II certified|Fortune 500 customer/);
  assert.match(sourceText,/<main id="main">/);
  assert.match(sourceText,/@media\(max-width:610px\)/);
  assert.match(sourceText,/prefers-reduced-motion/);
});
test('all public HTML receives the safe SOC renderer but JSON evidence is not rewritten',()=>{
  const builder=source('scripts/build-cloudflare-assets.js');
  assert.match(builder,/injectSocPresentation\(out\)/);
  assert.match(builder,/injectCustomerExperience\(html\)/);
  assert.match(builder,/fs\.copyFileSync\(src, dest\)/);
  assert.match(builder,/correctPublicIntelJson/);
  assert.equal(STYLESHEET,'/soc-platform-ui.css?v=20261022-soc1');
  assert.equal(renameUi('This Blog'),'SENTINEL APEX SOC');
  const manifest=JSON.parse(source('site.webmanifest'));
  assert.match(manifest.name,/SENTINEL APEX SOC/);
  assert.match(source('llms.txt'),/^# SENTINEL APEX SOC/m);
  assert.match(source('llms-full.txt'),/^# SENTINEL APEX SOC/m);
  assert.match(source('robots.txt'),/^# SENTINEL APEX SOC/m);
  assert.match(source('rss.xml'),/<title>SENTINEL APEX SOC — Hybrid Security Operations/);
  assert.match(source('generate-rss.js'),/SENTINEL APEX SOC — Hybrid Security Operations/);
});
