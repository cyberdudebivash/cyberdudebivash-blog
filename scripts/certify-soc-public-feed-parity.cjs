'use strict';
/**
 * Read-only SOC/CTI delivery parity. A passing page-availability smoke test
 * is never proof that the Cloudflare-bound static asset has been updated.
 * Run after an operator-approved deploy, not as a substitute for that deploy.
 * Exit 0 PASS; 2 FAIL (provable stale/drift); 3 INCONCLUSIVE (network/rate limit).
 */
const fs=require('node:fs');
const crypto=require('node:crypto');
const path=require('node:path');
const TARGETS=Object.freeze({
  soc:'https://soc.cyberdudebivash.in/live-intel.json',
  blog:'https://blog.cyberdudebivash.in/live-intel.json',
});
const MAX_BYTES=8*1024*1024, STALE_MINUTES=180, FUTURE_MINUTES=5;
const CROSS_RUNTIME_MINUTES=15;
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function inspect(feed,nowMs=Date.now()) {
  if(!feed||typeof feed!=='object'||Array.isArray(feed)||!Array.isArray(feed.items)||feed.items.length<10)
    return {ok:false,reason:'INVALID_FEED_SHAPE'};
  const timestamp=feed.metadata?.lastPipelineRun||feed.metadata?.generated||feed.generatedAt||null;
  const date=typeof timestamp==='string'?Date.parse(timestamp):NaN;
  if(!Number.isFinite(date))return {ok:false,reason:'INVALID_PIPELINE_TIMESTAMP'};
  const total=feed.totalPublished;
  if(!Number.isSafeInteger(total)||total<feed.items.length)
    return {ok:false,reason:'INVALID_TOTAL_PUBLISHED'};
  if(date>nowMs+FUTURE_MINUTES*60000)return {ok:false,reason:'FUTURE_PIPELINE_TIMESTAMP'};
  return {ok:true,iso:new Date(date).toISOString(),ts:date,
    ageMinutes:Math.max(0,Math.floor((nowMs-date)/60000)),
    totalPublished:total,items:feed.items.length};
}

function assess(reference,delivered,nowMs=Date.now(),options={}) {
  const src=inspect(reference,nowMs),live=inspect(delivered,nowMs);
  if(!src.ok)return {status:'FAIL',reason:'SOURCE_'+src.reason,src,live};
  if(!live.ok)return {status:'FAIL',reason:'LIVE_'+live.reason,src,live};
  if(src.ageMinutes>STALE_MINUTES)return {status:'FAIL',reason:'SOURCE_PIPELINE_STALE',src,live};
  // A fresh heartbeat is not proof that the intelligence publisher emitted a
  // recent report. Authoritative source state must independently prove both.
  if(options.sourceState!==undefined){
    const state=options.sourceState||{};
    const ran=typeof state.lastRun==='string'?Date.parse(state.lastRun):NaN;
    const reported=typeof state.lastReportGeneratedAt==='string'?Date.parse(state.lastReportGeneratedAt):NaN;
    if(!Number.isFinite(ran)||!Number.isFinite(reported))
      return {status:'FAIL',reason:'SOURCE_REPORT_EVIDENCE_MISSING',src,live};
    if(Math.abs(src.ts-ran)>CROSS_RUNTIME_MINUTES*60000)
      return {status:'FAIL',reason:'SOURCE_STATE_RUNTIME_MISMATCH',src,live};
    if(reported>nowMs+FUTURE_MINUTES*60000||reported>ran+FUTURE_MINUTES*60000)
      return {status:'FAIL',reason:'SOURCE_REPORT_TIMESTAMP_FUTURE',src,live};
    if(nowMs-reported>STALE_MINUTES*60000)
      return {status:'FAIL',reason:'SOURCE_INTEL_CONTENT_STALE',src,live};
  }
  if(live.ageMinutes>STALE_MINUTES)return {status:'FAIL',reason:'PUBLIC_PIPELINE_STALE',src,live};
  // A public artifact 5+ minutes behind authoritative checked-in source is an
  // unshipped/bypassed release, even when both clocks happen to look healthy.
  if(src.ts-live.ts>FUTURE_MINUTES*60000)
    return {status:'FAIL',reason:'PUBLIC_SOURCE_DEPLOYMENT_DRIFT',src,live};
  if(live.totalPublished<src.totalPublished)
    return {status:'FAIL',reason:'PUBLIC_CORPUS_BEHIND_SOURCE',src,live};
  // Release certification is about the exact build artifact, not a plausible
  // timestamp or count. Different bytes at the public hostname are drift.
  if(options.expectedBytes!==undefined){
    if(!Buffer.isBuffer(options.expectedBytes)||!Buffer.isBuffer(options.publicBytes))
      return {status:'FAIL',reason:'PUBLIC_ASSET_BYTES_UNAVAILABLE',src,live};
    if(sha256(options.expectedBytes)!==sha256(options.publicBytes))
      return {status:'FAIL',reason:'PUBLIC_ASSET_SHA256_MISMATCH',src,live};
  }
  return {status:'PASS',reason:'PUBLIC_SOURCE_FRESHNESS_AND_CORPUS_VERIFIED',src,live};
}

async function boundedJson(response) {
  if(response.status===429)return {status:'INCONCLUSIVE',reason:'PUBLIC_RATE_LIMITED'};
  if(response.status!==200)return {status:'FAIL',reason:'PUBLIC_HTTP_'+response.status};
  if(!/^application\/(?:json|[a-z0-9.+-]+\+json)(?:\s*;|$)/i.test(response.headers.get('content-type')||''))
    return {status:'FAIL',reason:'PUBLIC_CONTENT_TYPE_INVALID'};
  const n=Number(response.headers.get('content-length'));
  if(Number.isFinite(n)&&n>MAX_BYTES)return {status:'FAIL',reason:'PUBLIC_BODY_OVERSIZE'};
  if(!response.body||typeof response.body.getReader!=='function')
    return {status:'INCONCLUSIVE',reason:'PUBLIC_STREAM_UNAVAILABLE'};
  const reader=response.body.getReader();let size=0;const chunks=[];
  try {
    while(true){
      const next=await reader.read();if(next.done)break;
      size+=next.value.byteLength;
      if(size>MAX_BYTES)return {status:'FAIL',reason:'PUBLIC_BODY_OVERSIZE'};
      chunks.push(Buffer.from(next.value));
    }
  } finally {await reader.cancel().catch(()=>{});reader.releaseLock();}
  const bytes=Buffer.concat(chunks,size);
  try{return {status:'OK',data:JSON.parse(bytes.toString('utf8')),bytes};}
  catch(_){return {status:'FAIL',reason:'PUBLIC_JSON_INVALID'};}
}

async function check({expected,expectedBytes,sourceState,fetchImpl=globalThis.fetch,nowMs=Date.now(),timeoutMs=10000}={}) {
  if(!expected||typeof fetchImpl!=='function')throw new Error('EXPECTED_SOURCE_AND_FETCH_REQUIRED');
  const results=[];
  for(const [name,url] of Object.entries(TARGETS)){
    const c=new AbortController();const timer=setTimeout(()=>c.abort(),timeoutMs);
    let result;
    try{
      const response=await fetchImpl(url,{method:'GET',redirect:'manual',cache:'no-store',signal:c.signal,headers:{Accept:'application/json','Cache-Control':'no-cache'}});
      const read=await boundedJson(response);
      result=read.status==='OK'?assess(expected,read.data,nowMs,{sourceState,expectedBytes,publicBytes:read.bytes}):read;
    }catch(_){result={status:'INCONCLUSIVE',reason:'PUBLIC_READ_UNAVAILABLE'};}
    finally{clearTimeout(timer);}
    // Do not log feed bodies or customer-auth data.
    results.push({host:name,url,status:result.status,reason:result.reason,
      sourceTimestamp:result.src?.iso||null,publicTimestamp:result.live?.iso||null,
      sourcePublished:result.src?.totalPublished??null,publicPublished:result.live?.totalPublished??null,
      publicAgeMinutes:result.live?.ageMinutes??null});
  }
  const status=results.some(r=>r.status==='FAIL')?'FAIL':results.some(r=>r.status==='INCONCLUSIVE')?'INCONCLUSIVE':'PASS';
  return {status,checkedAt:new Date(nowMs).toISOString(),results,
    notes:'No deployment, publishing, credential, billing or customer mutation performed.'};
}

if(require.main===module){
  try{
    const releaseMode=process.argv.length===3&&process.argv[2]==='--release-asset';
    if(!releaseMode&&process.argv.length!==2)
      throw new Error('USAGE: node scripts/certify-soc-public-feed-parity.cjs [--release-asset]');
    const root=path.join(__dirname,'..');
    const bytes=fs.readFileSync(path.join(root,releaseMode?'dist-public/live-intel.json':'live-intel.json'));
    const expected=JSON.parse(bytes.toString('utf8'));
    const state=releaseMode?JSON.parse(fs.readFileSync(path.join(root,'intel-state.json'),'utf8')):undefined;
    check({expected,expectedBytes:releaseMode?bytes:undefined,sourceState:state}).then(result=>{
      process.stdout.write(JSON.stringify(result,null,2)+'\n');
      process.exitCode=result.status==='PASS'?0:result.status==='FAIL'?2:3;
    }).catch(()=>{console.error('INCONCLUSIVE: DELIVERY_CERTIFICATION_UNAVAILABLE');process.exitCode=3;});
  }catch(_){console.error('FAIL: AUTHORITATIVE_SOURCE_UNAVAILABLE');process.exitCode=2;}
}
module.exports={TARGETS,MAX_BYTES,STALE_MINUTES,inspect,assess,boundedJson,check};
