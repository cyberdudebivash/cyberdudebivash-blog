'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {assertHomepageIntegrity} = require('../scripts/soc-homepage-integrity');

const ROOT = path.resolve(__dirname,'..');
const index = fs.readFileSync(path.join(ROOT,'index.html'),'utf8');
const builder = fs.readFileSync(path.join(ROOT,'scripts','build-cloudflare-assets.js'),'utf8');
const publisher = fs.readFileSync(path.join(ROOT,'fetch-live-intel.js'),'utf8');

describe('P0 SOC homepage — source and publisher integrity',() => {
  test('accepts the repaired original homepage, preserving customer CTI content',() => {
    expect(assertHomepageIntegrity(index)).toBe(index);
    expect(index).not.toContain('<!-- POST 1 — FEATURED -->');
    expect(index).not.toMatch(/data-intel-auto=/);
    expect(index).toContain('class="soc-archive-navigation"');
    expect(index).toContain('https://blog.cyberdudebivash.in/');
    expect(index).toContain('customer-assurance.html');
  });

  test('requires exactly one CTI feed, enterprise service panel and report main landmark',() => {
    const spans = [
      [/<main(?:\s[^>]*)?>/g,1],
      [/<\/main>/g,1],
      [/<section class="ent-cta-block"/g,1],
      [/<div class="stats-bar">/g,1],
      [/<section class="ai-spotlight"/g,1],
      [/<div class="featured-intel-section">/g,1],
      [/id="live-intel-feed"/g,1],
      [/id="reports"/g,1],
    ];
    for(const [pattern,expected] of spans) {
      expect((index.match(pattern)||[]).length).toBe(expected);
    }
  });

  test('fails closed when duplicated scaffold or ID sneaks into source',() => {
    const append = index.replace('<!-- MAIN -->','<!-- MAIN --><!-- MAIN -->');
    expect(() => assertHomepageIntegrity(append)).toThrow('single main marker');
    const other = index.replace('id="reports"','id="reports" id="reports"');
    expect(() => assertHomepageIntegrity(other)).toThrow('single report container');
    const duplicateCTA = index.replace(
      '<section class="ent-cta-block"',
      '<section class="ent-cta-block"><section class="ent-cta-block"'
    );
    expect(() => assertHomepageIntegrity(duplicateCTA)).toThrow('single enterprise CTA');
  });

  test('rejects original fragmented CVE card text',() => {
    const corrupted = index.replace('<!-- Historical static cards removed',
      ') in the ClassDefinition UID validation regex\n<!-- Historical static cards removed');
    expect(() => assertHomepageIntegrity(corrupted)).toThrow('orphaned card tail');
  });


  test('rejects generated static cards or a missing archive link on the live homepage',() => {
    const injected = index.replace('<!-- Historical static cards removed',
      '<!-- AUTO-GENERATED: TEST -->\\n<a data-intel-auto="TEST" href="posts/old.html">Old item</a>\\n<!-- Historical static cards removed');
    expect(() => assertHomepageIntegrity(injected)).toThrow('no static generated homepage reports');
    const noArchive = index.replace('class="soc-archive-navigation"', 'class="archive-unlinked"');
    expect(() => assertHomepageIntegrity(noArchive)).toThrow('historical archive is linked separately');
  });

  test('publisher cannot silently reinsert historical report cards',() => {
    expect(publisher).not.toContain("const MARKER = '<!-- POST 1 — FEATURED -->'");
    expect(publisher).not.toContain('html.replace(MARKER,');
    expect(publisher).toContain('Live homepage verified unchanged');
  });

  test('product identity and SEO avoid unsupported live SOC and independent SOC 2 certification claims',() => {
    const title = index.match(/<title>([^<]+)<\/title>/i);
    expect(title).toBeTruthy();
    expect(title[1]).toMatch(/Threat Intelligence & SOC Readiness/i);
    expect(title[1]).not.toMatch(/SOC\s*2\s*&/i);
    expect(index).toContain('https://blog.cyberdudebivash.in/');
    expect(index).not.toContain('LIVE HYBRID SOC 2 + CTI OPERATIONS');
  });

  test('publisher and public asset builder both call same strict homepage contract',() => {
    expect(publisher).toContain("require('./scripts/soc-homepage-integrity').assertHomepageIntegrity");
    expect(builder).toContain("require('./soc-homepage-integrity').assertHomepageIntegrity");
    expect(builder).toContain("=== 'index.html'");
  });
});
