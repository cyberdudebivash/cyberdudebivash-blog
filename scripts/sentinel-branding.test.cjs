'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { brandHtml, displayName } = require('./sentinel-branding.cjs');
const NAME = 'SENTINEL APEX AI Security Hub';

test('display branding handles marks, case and existing APEX prefixes without duplication', () => {
  assert.equal(displayName('CyberDudeBivash® SENTINEL APEX™ Tools'), 'SENTINEL APEX Tools');
  assert.equal(displayName('CYBERDUDEBIVASH&reg; AI Security Hub'), NAME);
  assert.equal(displayName('contact@cyberdudebivash.in intel.cyberdudebivash.com CYBERDUDEBIVASH-SENTINEL-APEX'), 'contact@cyberdudebivash.in intel.cyberdudebivash.com CYBERDUDEBIVASH-SENTINEL-APEX');
});
test('human-readable surfaces change while technical and seller identity remain intact', () => {
  const script = '<script>const id="CYBERDUDEBIVASH"; const payee="CYBERDUDEBIVASH";</script>';
  const html = '<html><head><title>CYBERDUDEBIVASH AI Security Hub</title><meta content="CYBERDUDEBIVASH AI Security Hub" property="og:site_name"></head><body><header><a href="https://cyberdudebivash.in/" id="CYBERDUDEBIVASH">CyberDudeBivash® AI Security Hub</a></header><p>Seller of record: CYBERDUDEBIVASH — GSTIN 21ARKPN8270G1ZP</p><pre>CYBERDUDEBIVASH</pre>'+script+'<footer>Support</footer></body></html>';
  const out = brandHtml(html, NAME);
  assert.ok(out.includes('<title>'+NAME+'</title>'));
  assert.ok(out.includes('content="'+NAME+'" property="og:site_name"'));
  assert.ok(out.includes('href="https://cyberdudebivash.in/" id="CYBERDUDEBIVASH"'));
  assert.ok(out.includes(script));
  assert.ok(out.includes('<pre>CYBERDUDEBIVASH</pre>'));
  assert.ok(out.includes('Seller of record: CYBERDUDEBIVASH — GSTIN 21ARKPN8270G1ZP'));
  assert.ok(out.includes('Powered By CYBERDUDEBIVASH'));
  assert.ok(out.includes('href="https://www.cyberdudebivash.com/"'));
  assert.equal(brandHtml(out, NAME), out);
});
test('pages without a footer gain attribution; fragments and raw code stay fragments', () => {
  const page = brandHtml('<html><head></head><body>CYBERDUDEBIVASH</body></html>', NAME);
  assert.ok(page.includes('<footer aria-label="Platform attribution">'));
  assert.equal((page.match(/data-sentinel-attribution=/g)||[]).length, 1);
  assert.equal(brandHtml('<code>CYBERDUDEBIVASH</code>', NAME), '<code>CYBERDUDEBIVASH</code>');
});
test('nested seller and beneficiary markup retains its exact identity', () => {
  const block = '<div class="m-wire-row"><span>Beneficiary</span><span><strong>CYBERDUDEBIVASH</strong> PVT LTD</span></div>';
  const html = '<html><head></head><body>'+block+'<p>CYBERDUDEBIVASH AI Security Hub</p></body></html>';
  const out = brandHtml(html, NAME);
  assert.ok(out.includes(block));
  assert.ok(out.includes('<p>'+NAME+'</p>'));
  assert.equal(brandHtml(out, NAME), out);
});
test('website schema is branded without rewriting organization and legalName', () => {
  const graph = { '@graph': [{ '@type': 'WebSite', name: 'CYBERDUDEBIVASH AI Hub' }, { '@type': 'Organization', name: 'CYBERDUDEBIVASH', legalName: 'Verified seller identity' }] };
  const out = brandHtml('<script type="application/ld+json">'+JSON.stringify(graph)+'</script>', NAME);
  const parsed = JSON.parse(out.replace(/<[^>]+>/g, ''));
  assert.equal(parsed['@graph'][0].name, NAME);
  assert.equal(parsed['@graph'][1].name, 'CYBERDUDEBIVASH');
  assert.equal(parsed['@graph'][1].legalName, 'Verified seller identity');
});
test('literal dynamic display tags change; operational/payment scripts remain byte-identical', () => {
  const ui = '<script>const template=`<span>CYBERDUDEBIVASH Ecosystem</span>`;</script>';
  assert.ok(brandHtml(ui, NAME).includes('<span>SENTINEL APEX Ecosystem</span>'));
  const payment = '<script>const payment={name:"CYBERDUDEBIVASH"};const template=`<span>CYBERDUDEBIVASH</span>`;</script>';
  assert.equal(brandHtml(payment, NAME), payment);
});
