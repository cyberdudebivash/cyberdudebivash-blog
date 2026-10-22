'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CUSTOMER_SOURCE = Object.freeze([
  'index.html', 'about.html', 'terms.html', 'privacy.html', 'pricing.html', 'contact.html',
  'faq.html', 'search.html', 'api.html', 'security-disclosure.html',
  'intel/index.html', 'malware/index.html', 'breaking/index.html',
  'research/index.html', 'detections/index.html', 'ai-security/index.html',
  'ai-security/services.html', 'intelligence.html',
  'research/exploitation-velocity-index.html',
  'research/kev-exploitation-concentration-2026.html',
  'generate-intelligence-hub.js', 'build-research.js',
  'build-evi-page.js', 'build-detections-page.js',
]);
const FALSE_INCORPORATION = /\bCyberDudeBivash\s+(?:Private\s+Limited|Pvt\.?\s*Ltd\.?)\b/gi;
function checkIdentity(text) { return [...String(text).matchAll(FALSE_INCORPORATION)].length; }
function read(file) { return fs.readFileSync(path.join(ROOT, file), 'utf8'); }

test('P0 source: customer/legal routes and regenerators do not claim incorporation', () => {
  for (const file of CUSTOMER_SOURCE) {
    assert.equal(checkIdentity(read(file)), 0,
      file + ' falsely represents the operating seller as incorporated');
  }
});
test('negative controls: detect both long and abbreviated false incorporated names', () => {
  assert.equal(checkIdentity('CYBERDUDEBIVASH PRIVATE LIMITED'),1);
  assert.equal(checkIdentity('CyberDudeBivash Pvt. Ltd.'),1);
  assert.equal(checkIdentity('CyberDudeBivash ECOSYSTEM'),0);
  assert.equal(checkIdentity('SENTINEL APEX SOC'),0);
});
test('corrected seller identity retains sentence boundaries in customer legal copy', () => {
  assert.match(read('about.html'), /operated by CYBERDUDEBIVASH ECOSYSTEM\. We monitor/);
  assert.match(read('terms.html'), /Platform content is © CYBERDUDEBIVASH ECOSYSTEM\. You may quote/);
  assert.doesNotMatch(read('about.html'), /ECOSYSTEM We monitor/);
  assert.doesNotMatch(read('terms.html'), /ECOSYSTEM You may quote/);
});
test('business contact metadata retains the recognized ecosystem trading identity', () => {
  const html=read('contact.html');
  const source=html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  assert.ok(source,'structured ContactPage metadata must exist');
  const doc=JSON.parse(source[1]);
  assert.equal(doc['@type'],'ContactPage');
  assert.equal(doc.provider.name,'CYBERDUDEBIVASH ECOSYSTEM');
});
test('customer assurance and legal navigation remain intact', () => {
  const terms=read('terms.html'), privacy=read('privacy.html');
  for(const [name,document] of [['terms',terms],['privacy',privacy]]) {
    assert.match(document, /CYBERDUDEBIVASH ECOSYSTEM/i,name);
    assert.match(document, /mailto:/,name + ' must retain a contact path');
  }
  assert.match(read('contact.html'), /Enterprise Inquiry/);
});

test('P0 homepage structured data has one authoritative non-corporate organization entity', () => {
  const html=read('index.html');
  const matches=[...html.matchAll(/<script\s+type=["']application\/ld\+json["']>([\s\S]*?)<\/script>/gi)];
  assert.ok(matches.length>0,'homepage metadata missing');
  const nodes=matches.flatMap(match=>{
    const doc=JSON.parse(match[1]);
    return Array.isArray(doc['@graph']) ? doc['@graph'] : [doc];
  });
  const organizations=nodes.filter(node=>node['@id']==='https://www.cyberdudebivash.com/#organization');
  assert.equal(organizations.length,1,'duplicate legal entity schema risks inconsistent public identity');
  assert.equal(organizations[0]['@type'],'Organization');
  assert.match(organizations[0].name,/CYBERDUDEBIVASH ECOSYSTEM/);
  assert.ok(nodes.every(node=>node['@type']!=='Corporation'),
    'sole proprietorship may not be represented as incorporated');
});
test('P0 source and customer build both preserve correct seller identity', () => {
  const source=read('index.html');
  const {injectCustomerExperience}=require('../scripts/build-cloudflare-assets.js');
  const rendered=injectCustomerExperience(source);
  for(const [label,html] of [['source',source],['built',rendered]]){
    assert.equal(checkIdentity(html),0,label+' must not claim incorporated seller');
    assert.doesNotMatch(html,/"@type"\s*:\s*"Corporation"/i,label);
    assert.match(html,/CYBERDUDEBIVASH ECOSYSTEM/,label);
    assert.equal((html.match(/id="reports"/g)||[]).length,1,label+' reports landmark must be unique');
  }
});

test('P0 AI security service structured data advertises the correct sole proprietor trading name', () => {
  const html=read('ai-security/services.html');
  const blocks=[...html.matchAll(/<script\s+type=["']application\/ld\+json["']>([\s\S]*?)<\/script>/gi)]
    .map(m=>JSON.parse(m[1]));
  assert.ok(blocks.length,'service structured metadata missing');
  const services=blocks.filter(v=>v['@type']==='Service');
  assert.ok(services.length,'Service JSON-LD must exist');
  for(const service of services){
    assert.equal(service.provider?.name,'CYBERDUDEBIVASH ECOSYSTEM');
    assert.notEqual(service.provider?.['@type'],'Corporation');
  }
});
