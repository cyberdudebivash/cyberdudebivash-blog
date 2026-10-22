#!/usr/bin/env node
'use strict';

/**
 * P0 SOC static release-parity gate.
 * Read-only: limited public GETs against the known SOC hostname.
 * Compares deployed plain + release-SHA routes with approved dist-public HTML.
 * No secrets, customer telemetry, POST, deployment or DNS operations.
 */
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');

const ORIGIN='https://blog.cyberdudebivash.in';
const MAX_HTML=3_000_000;
const ROUTES=Object.freeze([
  {path:'/', markers:['SENTINEL APEX SOC']},
  {path:'/soc.html',markers:['SENTINEL APEX SOC','Hybrid SOC']},
  {path:'/soc-readiness-assessment.html',markers:['Request a Scoped Proposal','SOC Readiness','contact@cyberdudebivash.in']},
  {path:'/about.html',markers:['CYBERDUDEBIVASH ECOSYSTEM'],legal:true},
  {path:'/terms.html',markers:['CYBERDUDEBIVASH ECOSYSTEM'],legal:true},
  {path:'/privacy.html',markers:['CYBERDUDEBIVASH ECOSYSTEM'],legal:true},
  {path:'/security-disclosure.html',markers:['CYBERDUDEBIVASH ECOSYSTEM'],legal:true},
  {path:'/contact.html',markers:['CYBERDUDEBIVASH ECOSYSTEM'],legal:true},
]);
const badCompany=/\bCyberDudeBivash\s+(?:Private\s+Limited|Pvt\.?\s*Ltd\.?)\b/i;
const personalPanStructured=/"propertyID"\s*:\s*"PAN"/i;
const BLOCKED_COPY=/\b(?:SOC 2 Type II certified|24\/7 managed SOC is live)\b/i;
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
function assess(spec,result){
  const errors=[];
  const fail=(code,predicate)=>{if(!predicate)errors.push(code)};
  if(!spec||typeof spec.path!=='string'||!result||
     !Number.isSafeInteger(result.status)||typeof result.body!=='string'){
    return ['RESPONSE_INVALID'];
  }
  fail('HTTP_NOT_200',result.status===200);
  fail('NOT_HTML',typeof result.type==='string'&&/^text\/html(?:;|$)/i.test(result.type));
  fail('BODY_EMPTY_OR_OVERSIZE',result.body.length>0&&Buffer.byteLength(result.body,'utf8')<=MAX_HTML);
  if(result.status!==200)return [...new Set(errors)].sort();
  for(const marker of spec.markers||[]){
    if(!result.body.includes(marker))errors.push('REQUIRED_MARKER_MISSING');
  }
  fail('SOFT_404',!/<title[^>]*>\s*(?:404|not found)\b/i.test(result.body));
  fail('UNSUPPORTED_COMMERCIAL_CLAIM',!BLOCKED_COPY.test(result.body));
  if(spec.legal){
    fail('FALSE_INCORPORATION_CLAIM',!badCompany.test(result.body));
  }
  if(spec.path==='/'){
    fail('PERSONAL_PAN_METADATA',!personalPanStructured.test(result.body));
  }
  if(spec.path==='/soc-readiness-assessment.html'){
    fail('ENQUIRY_LINK_MISSING',result.body.includes('mailto:contact@cyberdudebivash.in?subject='));
    fail('FALSE_CHECKOUT',!/href=["'][^"']*(?:checkout|buy\.html)/i.test(result.body));
    fail('SERVICE_BOUNDARY_MISSING',result.body.includes('not an active 24/7 monitoring service'));
    fail('CANONICAL_INCORRECT',result.body.includes('href="'+ORIGIN+spec.path+'"'));
  }
  return [...new Set(errors)].sort();
}
function compareBuildLive(spec,local,served){
  const localErrors=assess(spec,{status:200,type:'text/html',body:local});
  const liveErrors=assess(spec,served);
  const errors=[...localErrors.map(c=>'BUILD_'+c),...liveErrors.map(c=>'LIVE_'+c)];
  if(typeof served?.body==='string' && local!==served.body) errors.push('BUILD_VS_LIVE_BYTES_DIFFER');
  return {ok:errors.length===0,codes:[...new Set(errors)].sort(),
    localSha:sha(local),liveSha:typeof served?.body==='string'?sha(served.body):null};
}
function localAssetPath(dist,route){
  const name=route==='/'?'index.html':route.slice(1);
  if(!/^[a-z0-9][a-z0-9._/-]*\.html$/.test(name) || name.includes('..'))throw Error('ASSET_PATH_INVALID');
  return path.resolve(dist,name);
}
async function boundedFetch(url){
  const response=await fetch(url,{redirect:'manual',cache:'no-store',headers:{'Cache-Control':'no-cache','Accept':'text/html'},signal:AbortSignal.timeout(20000)});
  const type=response.headers.get('content-type')||'';
  const reader=response.body?.getReader();
  if(!reader)return {status:response.status,type,body:''};
  let size=0;const chunks=[];
  try{
    for(;;){
      const part=await reader.read();
      if(part.done)break;
      size+=part.value.byteLength;
      if(size>MAX_HTML)throw Error('HTTP_BODY_OVERSIZE');
      chunks.push(Buffer.from(part.value));
    }
  }finally{reader.releaseLock()}
  return {status:response.status,type,body:Buffer.concat(chunks).toString('utf8')};
}
async function run({dist='dist-public',releaseSha}={}){
  if(!/^[a-f0-9]{40}$/.test(releaseSha||''))throw Error('RELEASE_SHA_REQUIRED');
  const summaries=[];
  for(const spec of ROUTES){
    const expected=fs.readFileSync(localAssetPath(dist,spec.path),'utf8');
    const originUrl=new URL(spec.path,ORIGIN);
    if(originUrl.origin!==ORIGIN)throw Error('ORIGIN_POLICY_FAILED');
    // Plain route catches stale cache; release SHA route checks rollout consistency.
    const plain=await boundedFetch(originUrl);
    const withSha=new URL(originUrl);
    withSha.searchParams.set('release_sha',releaseSha);
    const tagged=await boundedFetch(withSha);
    const a=compareBuildLive(spec,expected,plain),b=compareBuildLive(spec,expected,tagged);
    const errors=[...new Set([...a.codes.map(c=>'PLAIN_'+c),...b.codes.map(c=>'SHA_QUERY_'+c)])].sort();
    summaries.push({route:spec.path,pass:errors.length===0,codes:errors,
      expectedSha:a.localSha,plainSha:a.liveSha,querySha:b.liveSha});
  }
  return summaries;
}
if(require.main===module){
  const shaArg=process.argv.find(arg=>arg.startsWith('--release-sha='))?.slice('--release-sha='.length);
  run({releaseSha:shaArg}).then(summaries=>{
    for(const s of summaries){
      console.log((s.pass?'PASS':'HOLD')+' '+s.route+' '+(s.codes.join(',')||'EXACT_BUILD_AND_LIVE_PARITY')+
        ' built='+s.expectedSha+' plain='+s.plainSha+' tagged='+s.querySha);
    }
    if(summaries.some(s=>!s.pass))process.exitCode=1;
  }).catch(e=>{
    // Never print fetch body, redirect or credential-rich URLs.
    const permitted=['RELEASE_SHA_REQUIRED','ASSET_PATH_INVALID','ORIGIN_POLICY_FAILED','HTTP_BODY_OVERSIZE'];
    const message=permitted.includes(e.message)?e.message:'READ_ONLY_PROBE_FAILED';
    console.error('HOLD SOC_RELEASE_PARITY '+message);process.exitCode=1;
  });
}
module.exports={ROUTES,assess,compareBuildLive,localAssetPath};
