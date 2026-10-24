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

const ORIGIN='https://soc.cyberdudebivash.in';
const MAX_HTML=3_000_000;
const ROUTES=Object.freeze([
  {path:'/', markers:['SENTINEL APEX SOC'],legal:true},
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
// SEO identity is owned by the SOC customer hostname, not the legacy CTI
// origin. A body-injected or duplicate tag must never satisfy release parity.
function seoAttribute(tag,name){
  const match=tag.match(new RegExp('(?:^|\\s)'+name+'\\s*=\\s*(?:"([^"]*)"|\\x27([^\\x27]*)\\x27)','i'));
  return match ? (match[1] ?? match[2]) : null;
}
function seoTags(head,element){
  return head.match(new RegExp('<'+element+'\\b[^>]*>','gi'))||[];
}
// Inspect customer-visible copy; scripts, metadata and comments cannot
// establish or refute a legal/service claim in the rendered body.
function visibleCopy(html){
  const body=html.match(/<body\\b[^>]*>([\\s\\S]*?)<\\/body\\s*>/i)?.[1]||'';
  return body.replace(/<!--[\\s\\S]*?-->/g,' ')
    .replace(/<(?:script|style|template|noscript)\\b[^>]*>[\\s\\S]*?<\\/(?:script|style|template|noscript)\\s*>/gi,' ')
    .replace(/<[^>]+>/g,' ').replace(/&nbsp;|&#160;/gi,' ')
    .replace(/\\s+/g,' ').trim();
}
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
  const heads=result.body.match(/<head\b[^>]*>[\s\S]*?<\/head\s*>/gi)||[];
  const bodyOffset=result.body.search(/<body\b/i);
  const head=heads.length===1 &&
    (bodyOffset<0||result.body.indexOf(heads[0])<bodyOffset)?heads[0]:'';
  fail('DOCUMENT_HEAD_MISSING_OR_AMBIGUOUS',Boolean(head));
  const expected=ORIGIN+spec.path;
  const canonical=seoTags(head,'link')
    .filter(tag=>(seoAttribute(tag,'rel')||'').toLowerCase().split(/\s+/).includes('canonical'))
    .map(tag=>seoAttribute(tag,'href'));
  const ogUrls=seoTags(head,'meta')
    .filter(tag=>(seoAttribute(tag,'property')||'').toLowerCase()==='og:url')
    .map(tag=>seoAttribute(tag,'content'));
  fail('CANONICAL_INCORRECT',canonical.length===1&&canonical[0]===expected);
  fail('OG_URL_INCORRECT',ogUrls.length===1&&ogUrls[0]===expected);
  fail('UNSUPPORTED_COMMERCIAL_CLAIM',!BLOCKED_COPY.test(result.body));
  if(spec.legal){
    fail('FALSE_INCORPORATION_CLAIM',!badCompany.test(result.body));
    fail('INCORPORATED_STRUCTURED_IDENTITY',!/["']@type["']\s*:\s*["']Corporation["']/i.test(result.body));
  }
  if(spec.path==='/about.html'){
    const copy=visibleCopy(result.body);
    fail('UNVERIFIED_CONTINUOUS_MONITORING_COPY',
      !/\\bwe monitor\\b.{0,160}\\baround the clock\\b/i.test(copy));
    fail('RETIRED_SOCIAL_IDENTITY',
      !/\\bX\\s*\\/\\s*Twitter\\s*:\\s*@cdbsentinelapex\\b/i.test(copy));
  }
  if(spec.path==='/terms.html'){
    fail('LEGACY_VISIBLE_LEGAL_HOST',
      !/\\bblog\\.cyberdudebivash\\.in\\b/i.test(visibleCopy(result.body)));
  }
  if(spec.path==='/'){
    fail('PERSONAL_PAN_METADATA',!personalPanStructured.test(result.body));
  }
  if(spec.path==='/soc-readiness-assessment.html'){
    fail('ENQUIRY_LINK_MISSING',result.body.includes('mailto:contact@cyberdudebivash.in?subject='));
    fail('FALSE_CHECKOUT',!/href=["'][^"']*(?:checkout|buy\.html)/i.test(result.body));
    fail('SERVICE_BOUNDARY_MISSING',result.body.includes('not an active 24/7 monitoring service'));
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
module.exports={ORIGIN,ROUTES,assess,compareBuildLive,localAssetPath};
