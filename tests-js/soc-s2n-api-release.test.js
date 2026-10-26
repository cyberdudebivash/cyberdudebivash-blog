'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {validateBundle,verifyPublic,TARGETS}=require('../scripts/certify-soc-s2n-api-release.cjs');
const time=Date.parse('2026-10-26T13:15:00.000Z');
const moment='2026-10-26T12:30:00.000Z';
function fixture(){
  const ids=Array.from({length:12},(_,i)=>({id:'CVE-2026-'+String(10000+i)}));
  return {
   state:{lastRun:moment,lastReportGeneratedAt:moment,totalPublished:6548,
     lastIngestion:{reportsGenerated:15}},
   rootSource:{generatedAt:moment,totalPublished:6548,
     metadata:{lastPipelineRun:moment},items:ids},
   apiSource:{generated:moment,total_published:6548,items:ids},
   rootAsset:{generatedAt:moment,totalPublished:6548,
     metadata:{lastPipelineRun:moment},items:structuredClone(ids)},
   apiAsset:{generated:moment,total_published:6548,items:structuredClone(ids)},
   nowMs:time
  };
}
const verdict=change=>{const x=fixture();if(change)change(x);return validateBundle(x);};
test('P0 actual reconciled 6548 internal report ledger and four source/build feeds pass offline',()=>{
 assert.deepEqual(verdict(),{status:'PASS',codes:[]});
});
test('P0 past real 6533/6527 source drift cannot be deployed with fresh heartbeat',()=>{
 assert(verdict(x=>{x.rootSource.totalPublished=6527;x.apiSource.total_published=6527;}).codes
   .includes('AUTHORITATIVE_LEDGER_NOT_FINAL'));
});
test('P0 source fixed but Cloudflare API bundle left at older report count must HOLD',()=>{
 assert(verdict(x=>x.apiAsset.total_published=6527).codes.includes('API_REPORT_LEDGER_DIVERGENCE'));
});
test('P0 source root and bundled root timestamp, item window or counter drift blocks',()=>{
 assert(verdict(x=>x.rootAsset.totalPublished=6500).status==='HOLD');
 assert(verdict(x=>x.rootAsset.items.pop()).status==='HOLD');
 assert(verdict(x=>x.rootAsset.generatedAt='2026-10-26T12:29:00Z').status==='HOLD');
});
test('P0 CVSS build corrections may edit values but not add, reorder or replace report identities',()=>{
 assert.equal(verdict(x=>x.apiAsset.items[0].cvss=9.1).status,'PASS');
 assert(verdict(x=>x.apiAsset.items.reverse()).codes.includes('API_BUILD_REPORT_IDENTITY_DIVERGENCE'));
 assert(verdict(x=>x.apiAsset.items[0].id='FAKE-REPORT').codes.includes('API_BUILD_REPORT_IDENTITY_DIVERGENCE'));
});
test('P0 no synthetic recent API metadata when genuine report or runtime is stale',()=>{
 assert(verdict(x=>x.state.lastReportGeneratedAt='2026-10-25T05:51:00Z').status==='HOLD');
 assert(verdict(x=>x.apiAsset.generated='2026-10-26T13:15:00Z').codes.includes('API_BUILD_TIMESTAMP_DIVERGENCE'));
 assert(verdict(x=>x.apiSource.generated='2026-10-25T05:51:00Z').codes.includes('API_RUNTIME_TIMESTAMP_DIVERGENCE'));
});
test('P0 two independently fetched public API assets must exactly match approved bytes',async()=>{
 const bytes=Buffer.from(JSON.stringify(fixture().apiAsset));
 const visited=[];
 const out=await verifyPublic({assetBytes:bytes,fetchImpl:async url=>{
   visited.push(url);
   return new Response(Buffer.from(bytes),{status:200,headers:{'content-type':'application/json'}});
 }});
 assert.equal(out.status,'PASS');
 assert.deepEqual(visited,[TARGETS.soc,TARGETS.blog]);
 const modified=await verifyPublic({assetBytes:bytes,fetchImpl:async url=>
  new Response(url===TARGETS.soc?Buffer.from(bytes):Buffer.from(JSON.stringify({...fixture().apiAsset,extra:'stale'})),{
   status:200,headers:{'content-type':'application/json'}})});
 assert.equal(modified.status,'FAIL');
 assert.equal(modified.results[1].reason,'PUBLIC_S2N_API_SHA256_MISMATCH');
});
test('P0 unavailable or rate-limited public S2N API never certifies GO',async()=>{
 assert.equal((await verifyPublic({assetBytes:Buffer.from('{}'),fetchImpl:async()=>{
   throw Error('network');
 }})).status,'INCONCLUSIVE');
 assert.equal((await verifyPublic({assetBytes:Buffer.from('{}'),fetchImpl:async()=>new Response('{}',{
   status:429,headers:{'content-type':'application/json'}})})).status,'INCONCLUSIVE');
});
test('P0 workflow must check both feeds BEFORE Worker mutation and AFTER deployment',()=>{
 const w=fs.readFileSync(path.join(__dirname,'..','.github/workflows/cloudflare-production-deploy.yml'),'utf8');
 const build=w.indexOf('npm run build:cloudflare');
 const pre=w.indexOf('node scripts/certify-soc-s2n-api-release.cjs --predeploy');
 const deploy=w.indexOf('npx wrangler deploy --config wrangler.jsonc');
 const post=w.indexOf('node scripts/certify-soc-s2n-api-release.cjs --release-asset');
 assert(build>=0&&pre>build&&deploy>pre&&post>deploy);
 assert.match(w,/github.event_name == 'workflow_dispatch'/);
});
