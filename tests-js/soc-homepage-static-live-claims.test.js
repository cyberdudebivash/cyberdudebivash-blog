'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {assertHomepageIntegrity}=require('../scripts/soc-homepage-integrity');
const index=fs.readFileSync(path.resolve(__dirname,'../index.html'),'utf8');

test('P0 homepage publishes no static claim that a category is currently live',()=>{
  assert.doesNotMatch(index,/<div\b[^>]*class=["'][^"']*\bfi-badge\b[^"']*\blive-badge\b[^"']*["'][^>]*>\s*(?:&#9679;|●)?\s*LIVE\s*<\/div>/i);
  assert.doesNotMatch(index,/<div\b[^>]*class=["'][^"']*\bfi-desc\b[^"']*["'][^>]*>[^<]*\b(?:updated live|real-time breaking)\b/i);
  assert.match(index,/id="cdb-live-badge"[^>]*hidden/);
  assert.doesNotThrow(()=>assertHomepageIntegrity(index));
});

test('P0 integrity build rejects accidentally reintroduced unverified LIVE badge',()=>{
  const changed=index.replace('&#9679; VERIFY FEED','&#9679; LIVE');
  assert.notEqual(changed,index);
  assert.throws(()=>assertHomepageIntegrity(changed),/no unauthenticated static LIVE assertion/);
});

test('P0 integrity build rejects absolute claims of live updates in static category cards',()=>{
  const changed=index.replace('Cybersecurity news archive; verify latest feed status',
    'Top cybersecurity news updated live');
  assert.notEqual(changed,index);
  assert.throws(()=>assertHomepageIntegrity(changed),/no unauthenticated static LIVE assertion/);
});
