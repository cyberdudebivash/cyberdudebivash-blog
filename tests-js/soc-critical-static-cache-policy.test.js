'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {HEADERS_FILE_CONTENT}=require('../scripts/build-cloudflare-assets.js');

const blocks=HEADERS_FILE_CONTENT.split(/\n\s*\n/)
  .map(s=>s.split('\n').map(x=>x.trim()).filter(Boolean))
  .filter(x=>x.length&&!x[0].startsWith('#'));
const matches=(pattern,path)=>{
  if(!pattern.includes('*'))return pattern===path;
  const i=pattern.indexOf('*');
  const p=pattern.slice(0,i),s=pattern.slice(i+1);
  return path.startsWith(p)&&path.endsWith(s)&&path.length>=p.length+s.length;
};
function effectiveHeaders(path){
  const current=new Map();
  const trace=[];
  for(const block of blocks){
    if(!matches(block[0],path))continue;
    for(const rule of block.slice(1)){
      if(/^!\s/.test(rule)){
        const key=rule.slice(2).trim().toLowerCase();
        current.delete(key);
        trace.push({pattern:block[0],kind:'detach',key});
      }else{
        const i=rule.indexOf(':');
        assert(i>0,rule);
        const key=rule.slice(0,i).trim().toLowerCase();
        const value=rule.slice(i+1).trim();
        const seen=current.get(key)||[];
        seen.push(value);
        current.set(key,seen);
        trace.push({pattern:block[0],kind:'set',key,value});
      }
    }
  }
  return {current,trace};
}
const CRITICAL_HTML=['/','/index.html','/soc.html','/intel/index.html',
 '/breaking/index.html','/malware/index.html','/ai-security/index.html',
 '/service-status.html','/customer-assurance.html','/api-dashboard.html'];
const CRITICAL_SCRIPTS=['/runtime-state.js','/apex-command-center.js',
 '/live-feed-widget.js','/auto-intel-engine.js','/soc-intelligence-desk.js',
 '/soc-global-incidents.js','/soc-global-incidents-loader.js',
 '/apex-command-center.css','/soc-platform-ui.css','/soc-cti-console.css'];
const CRITICAL_JSON=['/live-intel.json','/api/intel/live.json',
 '/api/intel/top-threats.json','/api/intel/iocs.json',
 '/api/intel/ransomware.json','/api/intel/customer-assurance.json',
 '/api/intel/service-assurance.json','/api/intel/cti-delivery-acceptance.json'];

test('P0 critical SOC pages, scripts and public feeds never inherit 24h SWR or duplicate cache directives',()=>{
  for(const path of [...CRITICAL_HTML,...CRITICAL_SCRIPTS,...CRITICAL_JSON]){
    const {current}=effectiveHeaders(path);
    assert.deepEqual(current.get('cache-control'),
      ['public, max-age=60, must-revalidate'],path);
    const directives=current.get('cache-control').join(',');
    assert.doesNotMatch(directives,/stale-while-revalidate|max-age=600|max-age=3600/);
    assert(!current.get('cache-control').some(x=>/no-store/.test(x)),path+' should not force unbounded uncached edge reads');
  }
});

test('P0 overridden broad rules must explicitly DETACH earlier cache controls before setting exact values',()=>{
  for(const path of [...CRITICAL_SCRIPTS, ...CRITICAL_JSON.filter(p=>p.startsWith('/api/intel/')),
    ...CRITICAL_HTML.filter(p=>p!=='/')]){
    const {trace}=effectiveHeaders(path);
    const cache=trace.filter(e=>e.key==='cache-control');
    const broad=cache.find(x=>x.kind==='set'&&x.pattern.includes('*'));
    assert.ok(broad,path+' must match a broad original cache rule');
    const later=cache.filter(x=>x.kind==='detach');
    assert.equal(later.length,1,path+' must detach prior conflicting policy');
    assert(trace.some(x=>x.kind==='set'&&x.key==='cache-control'&&x.pattern===path));
  }
});

test('P0 unrelated low-risk static content keeps the existing caching/cost strategy',()=>{
  for(const [path,expected] of [
    ['/posts/historical-report.html','public, max-age=3600, stale-while-revalidate=86400'],
    ['/analytics-engine.js','public, max-age=600, stale-while-revalidate=86400'],
    ['/apex-v13.css','public, max-age=600, stale-while-revalidate=86400'],
    ['/api/intel/products/sample.json','public, max-age=600, stale-while-revalidate=3600']
  ]){
    assert.deepEqual(effectiveHeaders(path).current.get('cache-control'),[expected],path);
  }
});

test('Cloudflare _headers stays within documented rule-count and per-line limits',()=>{
  assert(blocks.length<=100,'Cloudflare Workers static assets max 100 header blocks');
  assert(HEADERS_FILE_CONTENT.split('\n').every(line=>line.length<=2000),'line exceeds Cloudflare limit');
  // Cloudflare _headers do not affect Worker-produced protected API routes.
  assert.equal(effectiveHeaders('/api/v1/customer/dashboard').current.has('cache-control'),false);
});

test('P0 current home page references versioned UI and data-verification scripts',()=>{
  const fs=require('node:fs');
  const path=require('node:path');
  const html=fs.readFileSync(path.join(__dirname,'..','index.html'),'utf8');
  for(const asset of ['live-feed-widget.js','runtime-state.js','apex-command-center.js']){
    assert(html.includes('/'+asset+'?v=20261113-soc-p0-1'),
      asset+' must be cache-busted after the combined P0 rollout');
  }
});
