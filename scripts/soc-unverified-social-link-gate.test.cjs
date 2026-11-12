'use strict';
/**
 * First-party outbound-link defense in depth for Ahmed #015/#017 / AI Hub #1201.
 * This does not attest third-party Facebook account remediation or research closure.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ROOT = path.resolve(__dirname, '..');
const RETIRED_PAGE_ID = '61583373732736';
function htmlFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return htmlFiles(full);
    return entry.isFile() && entry.name.endsWith('.html') ? [full] : [];
  });
}
test('SOC public HTML does not link to unverified Facebook Page A', () => {
  const paths = [
    path.join(ROOT, 'index.html'),
    path.join(ROOT, 'intelligence.html'),
    ...htmlFiles(path.join(ROOT, 'posts')),
  ];
  assert.ok(paths.length >= 9, 'SOC public HTML inventory must be present');
  for (const file of paths) {
    const html = fs.readFileSync(file, 'utf8');
    assert.equal(html.includes(RETIRED_PAGE_ID), false, path.relative(ROOT, file));
  }
});
test('SOC homepage retains first-party approved identities and valid structured data', () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  assert.match(html, /https:\/\/www\.linkedin\.com\/company\/cyberdudebivash\//);
  assert.match(html, /https:\/\/www\.instagram\.com\/cyberdudebivash_official\//);
  const blocks = [...html.matchAll(/<script\b[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)];
  assert.ok(blocks.length > 0, 'structured data must remain available');
  for (const [, json] of blocks) assert.doesNotThrow(() => JSON.parse(json));
});
