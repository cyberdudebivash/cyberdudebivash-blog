'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const trust = require('../pricing-trust.js');
const runtime = require('../runtime-state.js');

const root = path.resolve(__dirname, '..');
const now = Date.parse('2026-11-06T16:00:00.000Z');
const feed = minutes => {
  const stamp = new Date(now - minutes * 60000).toISOString();
  return {generatedAt: stamp, metadata: {generated: stamp, lastPipelineRun: new Date(now).toISOString()},
    totalPublished: 7189, items: Array(150).fill(null)};
};

test('healthy pricing evidence requires a genuinely fresh publication timestamp', () => {
  const r = trust.assess(feed(40), runtime, now);
  assert.equal(r.state, 'HEALTHY');
  assert.equal(r.published, 7189);
});

test('a fresh heartbeat cannot launder a stale intelligence snapshot', () => {
  const r = trust.assess(feed(14 * 24 * 60), runtime, now);
  assert.equal(r.state, 'STALE');
  assert.match(r.message, /historical published reports/);
});

test('age between healthy and stale is explicitly degraded', () => {
  assert.equal(trust.assess(feed(150), runtime, now).state, 'DEGRADED');
});

test('invalid, conflicted, future or missing source timestamps never become healthy', () => {
  const conflict = feed(30); conflict.metadata.generated = new Date(now - 60 * 60000).toISOString();
  const missing = feed(20); delete missing.generatedAt;
  const future = feed(-15);
  const invalidCount = feed(10); invalidCount.totalPublished = 0;
  for (const value of [conflict, missing, future, invalidCount, null]) {
    assert.notEqual(trust.assess(value, runtime, now).state, 'HEALTHY');
  }
});

test('renderer only writes textContent; untrusted source text never becomes HTML', () => {
  const values = {};
  const mk = id => values[id] = {textContent:'',attrs:{},setAttribute(name,value){this.attrs[name]=value;}};
  for (const id of ['stat-threats','stat-cves','pricing-feed-status','pricing-feed-message','pricing-evidence']) mk(id);
  trust.render({state:'DEGRADED',published:null,generatedAt:null,message:'<img src=x onerror=alert(1)>'},
    {getElementById(id){return values[id]}});
  assert.equal(values['pricing-feed-message'].textContent,'<img src=x onerror=alert(1)>');
  assert.equal(values['pricing-evidence'].attrs['data-state'],'DEGRADED');
});

test('pricing page removes invented KPI fallbacks and preserves canonical checkout', () => {
  const pricing = fs.readFileSync(path.join(root,'pricing.html'),'utf8');
  const build = fs.readFileSync(path.join(root,'scripts/build-cloudflare-assets.js'),'utf8');
  assert.doesNotMatch(pricing,/4,200\+|890\+|&lt;80ms|Production-Ready Threat Intelligence/);
  assert.match(pricing,/id="pricing-evidence"[^>]*role="status"[^>]*aria-live="polite"/);
  assert.match(pricing,/<script src="\/runtime-state\.js" defer><\/script>/);
  assert.match(pricing,/<script src="\/pricing-trust\.js" defer><\/script>/);
  assert.match(build,/'pricing-trust\.js'/);
  assert.match(pricing,/https:\/\/intel\.cyberdudebivash\.com\/upgrade\.html\?plan=pro/);
  assert.doesNotMatch(pricing,/action=stats/);
});
