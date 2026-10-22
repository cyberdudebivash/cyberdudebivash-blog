'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CUSTOMER_SOURCE = Object.freeze([
  'about.html', 'terms.html', 'privacy.html', 'pricing.html', 'contact.html',
  'faq.html', 'search.html', 'api.html', 'security-disclosure.html',
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
test('legal/source text preserves sentence boundaries after correcting incorporated seller name', () => {
  for (const file of ['about.html', 'terms.html']) {
    assert.doesNotMatch(read(file), /CYBERDUDEBIVASH ECOSYSTEM (?:We|You)\b/,
      file + ' has a missing sentence boundary');
  }
  assert.match(read('about.html'), /operated by CYBERDUDEBIVASH ECOSYSTEM\. We monitor/);
  assert.match(read('terms.html'), /Platform content is © CYBERDUDEBIVASH ECOSYSTEM\. You may quote/);
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
