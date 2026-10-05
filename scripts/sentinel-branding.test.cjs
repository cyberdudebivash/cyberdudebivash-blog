'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { brandHtml, displayName, canonicalPlatformName } = require('./sentinel-branding.cjs');

const NAME = "SENTINEL APEX Research Blog / Intel Factory";
const LEGACY_NAME = "CYBERDUDEBIVASH Research Blog / Intel Factory";

test('display branding handles marks, case and technical identifiers without duplication', () => {
  assert.equal(displayName('CyberDudeBivash® SENTINEL APEX™ Tools'), 'SENTINEL APEX Tools');
  assert.equal(displayName('CYBERDUDEBIVASH&reg; AI Security Hub'), 'SENTINEL APEX AI Security Hub');
  assert.equal(
    displayName('contact@cyberdudebivash.in intel.cyberdudebivash.com CYBERDUDEBIVASH-SENTINEL-APEX'),
    'contact@cyberdudebivash.in intel.cyberdudebivash.com CYBERDUDEBIVASH-SENTINEL-APEX',
  );
});

test('platform name input is canonicalized and rejects markup/control-character injection', () => {
  assert.equal(canonicalPlatformName('  '+NAME+'  '), NAME);
  for (const invalid of [
    'CYBERDUDEBIVASH '+NAME,
    'SENTINEL APEX"><script>alert(1)</script>',
    'SENTINEL APEX\nInjected',
    'SENTINEL APEX\u0000Injected',
  ]) {
    assert.throws(() => canonicalPlatformName(invalid));
  }
});

test('human-readable surfaces change while technical and seller identity remain intact', () => {
  const script = '<script>const id="CYBERDUDEBIVASH"; const payee="CYBERDUDEBIVASH";</script>';
  const html = '<html><head><title>'+LEGACY_NAME+'</title><meta content="'+LEGACY_NAME+'" property="og:site_name"></head><body><header><a href="https://cyberdudebivash.in/" id="CYBERDUDEBIVASH">'+LEGACY_NAME+'</a></header><p>Seller of record: CYBERDUDEBIVASH — GSTIN 21ARKPN8270G1ZP</p><pre>CYBERDUDEBIVASH</pre>'+script+'<footer>Support</footer></body></html>';
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

test('pages without a footer gain exactly one attribution; fragments and raw code stay fragments', () => {
  const page = brandHtml('<html><head></head><body>CYBERDUDEBIVASH</body></html>', NAME);
  assert.ok(page.includes('<footer aria-label="Platform attribution">'));
  assert.equal((page.match(/data-sentinel-attribution=/g)||[]).length, 1);
  assert.equal((page.match(/Powered By CYBERDUDEBIVASH/g)||[]).length, 1);
  assert.equal(brandHtml('<code>CYBERDUDEBIVASH</code>', NAME), '<code>CYBERDUDEBIVASH</code>');
});

test('nested seller and beneficiary markup retains its exact identity', () => {
  const block = '<div class="m-wire-row"><span>Beneficiary</span><span><strong>CYBERDUDEBIVASH</strong> PVT LTD</span></div>';
  const html = '<html><head></head><body>'+block+'<p>'+LEGACY_NAME+'</p></body></html>';
  const out = brandHtml(html, NAME);
  assert.ok(out.includes(block));
  assert.ok(out.includes('<p>'+NAME+'</p>'));
  assert.equal(brandHtml(out, NAME), out);
});

test('website schema is branded without rewriting organization and legalName', () => {
  const graph = { '@graph': [{ '@type': 'WebSite', name: LEGACY_NAME }, { '@type': 'Organization', name: 'CYBERDUDEBIVASH', legalName: 'Verified seller identity' }] };
  const out = brandHtml('<script type="application/ld+json">'+JSON.stringify(graph)+'</script>', NAME);
  const parsed = JSON.parse(out.replace(/<[^>]+>/g, ''));
  assert.equal(parsed['@graph'][0].name, NAME);
  assert.equal(parsed['@graph'][1].name, 'CYBERDUDEBIVASH');
  assert.equal(parsed['@graph'][1].legalName, 'Verified seller identity');
});

test('literal dynamic display tags change; operational/payment scripts remain byte-identical', () => {
  const ui = '<script>const template=\`<span>'+LEGACY_NAME+'</span>\`;</script>';
  assert.ok(brandHtml(ui, NAME).includes('<span>'+NAME+'</span>'));
  const payment = '<script>const payment={name:"CYBERDUDEBIVASH"};const template=\`<span>'+LEGACY_NAME+'</span>\`;</script>';
  assert.equal(brandHtml(payment, NAME), payment);
});


test('split legacy wordmarks collapse to one canonical product-family brand', () => {
  const html = '<html><head></head><body><header><span class="cdb-brand-name">CYBERDUDE<span>BIVASH</span></span><span class="cdb-platform-name">SENTINEL APEX Research Blog / Intel Factory</span></header></body></html>';
  const out = brandHtml(html, NAME);
  assert.ok(out.includes('<span class="cdb-brand-name">SENTINEL APEX</span>'));
  assert.equal((out.match(/SENTINEL APEX/g) || []).length, 1, 'exactly one product-family wordmark must remain');
  assert.ok(out.includes('<span class="cdb-platform-name">Research Blog / Intel Factory</span>'));
  assert.ok(!out.includes('CYBERDUDE<span>BIVASH</span>'));
  assert.ok(!out.includes('SENTINEL APEX SENTINEL APEX'));
  assert.equal(brandHtml(out, NAME), out);
});

test('Cloudflare asset builder cannot bypass SENTINEL APEX branding', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const builder = fs.readFileSync(path.join(__dirname, 'build-cloudflare-assets.js'), 'utf8');

  assert.ok(builder.includes("require('./sentinel-branding.cjs')"), 'Cloudflare asset builder must load the branding transformer');
  assert.ok(builder.includes("brandHtml(out, 'SENTINEL APEX Research Blog / Intel Factory')"), 'Cloudflare asset builder must apply the canonical Blog / Intel Factory identity');
});
