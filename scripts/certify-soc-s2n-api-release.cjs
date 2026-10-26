#!/usr/bin/env node
'use strict';
/**
 * P0 S2N API release safety, independent of the homepage feed.
 * No network during --predeploy. Two fixed read-only GETs after an expressly
 * authorized Worker release. No provider API, customer PII or Cloudflare write.
 */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {check:checkLedger}=require('./assert-publication-ledger.cjs');
const {predeployGate,boundedJson}=require('./certify-soc-public-feed-parity.cjs');
const TARGETS=Object.freeze({
  soc:'https://soc.cyberdudebivash.in/api/intel/live.json',
  blog:'https://blog.cyberdudebivash.in/api/intel/live.json'
});
const MAX_BYTES=8*1024*1024,MAX_SKEW_MS=15*60*1000;
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const validItems=x=>Array.isArray(x)&&x.length>=1&&x.length<=10000&&
  x.every(y=>y&&typeof y.id==='string'&&y.id.length>0&&y.id.length<=160);

function validateBundle({state,rootSource,apiSource,rootAsset,apiAsset,nowMs=Date.now()}={}){
  const errors=new Set();
  const push=x=>errors.add(x);
  const receipt=checkLedger({state,widget:rootSource,api:apiSource});
  if(receipt.status!=='PASS')push('AUTHORITATIVE_LEDGER_NOT_FINAL');
  const sourceGate=predeployGate({source:rootSource,asset:rootAsset,state,nowMs});
  if(sourceGate.status!=='PASS')push('ROOT_RELEASE_'+sourceGate.reason);
  if(!apiSource||!apiAsset||!validItems(apiSource.items)||!validItems(apiAsset.items))
    push('API_SOURCE_OR_BUILD_SHAPE_INVALID');
  else{
    if(!Number.isSafeInteger(apiSource.total_published)||
       apiSource.total_published!==apiAsset.total_published||
       apiAsset.total_published!==rootAsset?.totalPublished ||
       apiSource.total_published!==state?.totalPublished)
      push('API_REPORT_LEDGER_DIVERGENCE');
    if(apiSource.generated!==apiAsset.generated)push('API_BUILD_TIMESTAMP_DIVERGENCE');
    const created=Date.parse(apiSource.generated||'');
    const runtime=Date.parse(state?.lastRun||'');
    if(!Number.isFinite(created)||!Number.isFinite(runtime)||
       Math.abs(runtime-created)>MAX_SKEW_MS)push('API_RUNTIME_TIMESTAMP_DIVERGENCE');
    const a=apiSource.items.map(x=>x.id);
    const b=apiAsset.items.map(x=>x.id);
    // The public build is permitted to apply approved CVSS corrections, but
    // NEVER silently add/remove/reorder real intelligence report identities.
    if(JSON.stringify(a)!==JSON.stringify(b))push('API_BUILD_REPORT_IDENTITY_DIVERGENCE');
  }
  return {status:errors.size?'HOLD':'PASS',codes:[...errors].sort()};
}
async function verifyPublic({assetBytes,fetchImpl=globalThis.fetch,timeoutMs=10000}={}){
  if(!Buffer.isBuffer(assetBytes)||assetBytes.length===0||assetBytes.length>MAX_BYTES||
     typeof fetchImpl!=='function')
    return {status:'HOLD',results:[],reason:'RELEASE_ASSET_UNAVAILABLE'};
  const expected=hash(assetBytes),results=[];
  for(const [host,url] of Object.entries(TARGETS)){
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),timeoutMs);
    let value;
    try{
      const response=await fetchImpl(url,{method:'GET',redirect:'manual',cache:'no-store',
        headers:{Accept:'application/json','Cache-Control':'no-cache'},signal:controller.signal});
      const parsed=await boundedJson(response);
      if(parsed.status!=='OK')value={status:parsed.status,reason:parsed.reason};
      else if(hash(parsed.bytes)!==expected)
        value={status:'FAIL',reason:'PUBLIC_S2N_API_SHA256_MISMATCH'};
      else value={status:'PASS',reason:'PUBLIC_S2N_API_EXACT_ASSET'};
    }catch(_){value={status:'INCONCLUSIVE',reason:'PUBLIC_S2N_API_READ_UNAVAILABLE'};}
    finally{clearTimeout(timer);}
    results.push({host,...value});
  }
  return {status:results.some(x=>x.status==='FAIL')?'FAIL':
     results.some(x=>x.status==='INCONCLUSIVE')?'INCONCLUSIVE':'PASS',results};
}
function loadBundle(root){
  const read=p=>JSON.parse(fs.readFileSync(path.join(root,p),'utf8'));
  return {
    state:read('intel-state.json'),rootSource:read('live-intel.json'),
    apiSource:read('api/intel/live.json'),rootAsset:read('dist-public/live-intel.json'),
    apiAsset:read('dist-public/api/intel/live.json')
  };
}
if(require.main===module){
  const mode=process.argv[2];
  if(process.argv.length!==3||!['--predeploy','--release-asset'].includes(mode)){
    console.error('HOLD: USAGE --predeploy|--release-asset');process.exitCode=2;
  }else{
    try{
      const root=path.join(__dirname,'..'),validation=validateBundle(loadBundle(root));
      if(validation.status!=='PASS'){
        console.error(JSON.stringify(validation));process.exitCode=2;
      }else if(mode==='--predeploy'){
        console.log('PASS: S2N SOURCE_LEDGER_AND_APPROVED_BUILD_CONCORDANT');
      }else{
        const bytes=fs.readFileSync(path.join(root,'dist-public/api/intel/live.json'));
        verifyPublic({assetBytes:bytes}).then(result=>{
          console.log(JSON.stringify(result));
          process.exitCode=result.status==='PASS'?0:result.status==='FAIL'?2:3;
        }).catch(()=>{console.error('INCONCLUSIVE: S2N_API_PUBLIC_VERIFICATION_UNAVAILABLE');process.exitCode=3;});
      }
    }catch(_){console.error('HOLD: S2N_RELEASE_SOURCE_OR_BUILD_UNAVAILABLE');process.exitCode=2;}
  }
}
module.exports={TARGETS,validateBundle,verifyPublic,MAX_BYTES};
