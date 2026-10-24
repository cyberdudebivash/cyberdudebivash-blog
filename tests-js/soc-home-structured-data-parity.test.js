'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const SOC = 'https://soc.cyberdudebivash.in/';
const LEGACY = 'https://blog.cyberdudebivash.in/';

function homepageGraph() {
  const scripts = [...html.matchAll(/<script\s+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)];
  assert.ok(scripts.length > 0, 'homepage must contain structured data');
  const graphs = scripts.map(match => JSON.parse(match[1])).flatMap(doc => doc['@graph'] || [doc]);
  return graphs;
}

test('SOC homepage metadata and structured-data identities share canonical origin', () => {
  assert.match(html, /<link\s+rel="canonical"\s+href="https:\/\/soc\.cyberdudebivash\.in\/"/);
  assert.match(html, /<meta\s+property="og:url"\s+content="https:\/\/soc\.cyberdudebivash\.in\/"/);
  const graph = homepageGraph();
  const website = graph.find(node => node['@type'] === 'WebSite');
  const collection = graph.find(node => node['@type'] === 'CollectionPage');
  const founder = graph.find(node => node['@type'] === 'Person');
  assert.ok(website && collection && founder, 'required structured-data nodes missing');
  assert.equal(website['@id'], SOC + '#website');
  assert.equal(website.url, SOC);
  assert.equal(website.potentialAction.target.urlTemplate, SOC + 'search.html?q={search_term_string}');
  assert.equal(collection['@id'], SOC + '#soc-cti');
  assert.equal(collection.url, SOC);
  assert.equal(founder['@id'], SOC + '#founder');
  assert.equal(founder.url, SOC + 'about.html');
  const organization = graph.find(node => node['@type'] === 'Organization');
  assert.ok(organization, 'publisher organization missing');
  assert.equal(organization.founder['@id'], founder['@id']);
  for (const node of graph) {
    assert.ok(!String(node['@id'] || '').startsWith(LEGACY), 'legacy hostname remains in entity identity');
  }
});

test('SOC command center points to SOC host; legacy asset links are not blanket rewritten', () => {
  assert.match(html, /<a\s+href="https:\/\/soc\.cyberdudebivash\.in\/"[^>]*>SOC Command Center<\/a>/);
  assert.doesNotMatch(html, /<a\s+href="https:\/\/blog\.cyberdudebivash\.in"[^>]*>SOC Command Center<\/a>/);
  // Asset URLs are intentionally not moved until SOC-host asset parity is verified.
  assert.match(html, /og-sentinel-apex-intel-factory-v1\.jpg/);
});
