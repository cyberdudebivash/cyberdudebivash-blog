'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {VERIFIED_RSS_URLS,mayRetry,verifyRssPayload}=require('../scripts/rss-source-health-policy.cjs');
test('Talos and Rapid7 RSS use observed XML endpoints, not retired 404 paths',()=>{
 assert.equal(VERIFIED_RSS_URLS.talos,'https://blog.talosintelligence.com/rss/');
 assert.equal(VERIFIED_RSS_URLS.rapid7,'https://www.rapid7.com/blog/rss/');
 const engine=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
 assert.match(engine,/talosBlogRss:\s*VERIFIED_RSS_URLS\.talos/);
 assert.match(engine,/rapid7BlogRss:\s*VERIFIED_RSS_URLS\.rapid7/);
 assert.doesNotMatch(engine,/blog\.talosintelligence\.com\/feeds\/posts\/default/);
 assert.doesNotMatch(engine,/www\.rapid7\.com\/blog\/feed\//);
});
test('do not immediately retry retired, forbidden or rate-limited endpoints',()=>{
 for(const code of [400,401,403,404,405,410,422,429])
   assert.equal(mayRetry(Error('HTTP '+code+' — source')),false,String(code));
 for(const msg of ['HTTP 500 — source','HTTP 503 — source','Timeout: source','ECONNRESET'])
   assert.equal(mayRetry(Error(msg)),true);
});
test('valid empty RSS or Atom is genuinely empty, not a phantom threat',()=>{
 assert.deepEqual(verifyRssPayload('<rss version="2.0"><channel></channel></rss>',[]),[]);
 assert.deepEqual(verifyRssPayload('<feed xmlns="http://www.w3.org/2005/Atom"></feed>',[]),[]);
});
test('valid parsed feed retains original source items unchanged',()=>{
 const items=[{title:'Incident',link:'https://example.test/item',pubDate:'2026-10-26'}];
 assert.equal(verifyRssPayload('<rss><item><title>Incident</title></item></rss>',items),items);
});
test('reject disguised HTML errors, malformed feed data and unparseable items',()=>{
 for(const xml of ['<html><body>401 unauthorized</body></html>','{"error":"forbidden"}','',
   '<rss><item><title>Missing link</title></item></rss>'])
   assert.throws(()=>verifyRssPayload(xml,[]),/RSS_/);
 assert.throws(()=>verifyRssPayload('<rss></rss>',null),/RSS_PARSER_RESULT_INVALID/);
 assert.throws(()=>verifyRssPayload('x'.repeat(8*1024*1024+1),[]),/RSS_PAYLOAD_MISSING_OR_OVERSIZED/);
});
test('runtime propagates broken fetch to per-source health rather than successful empty results',()=>{
 const s=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
 assert.match(s,/if \(!mayRetry\(e\)\) throw e;/);
 assert.match(s,/verifyRssPayload\(raw, parseRSS\(raw\)\)/);
 assert.match(s,/catch\(e\) \{ warn\(\x60\$\{source\} failed: \$\{e\.message\}\x60\); throw e; \}/);
 assert.match(s,/recordSourceFailure\(state, key,/);
});
