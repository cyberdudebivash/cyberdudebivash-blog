#!/usr/bin/env node
'use strict';
/**
 * Read-only inventory of the currently deployed SOC Cloudflare Worker.
 * Does NOT deploy, rollback, create a domain, publish, mutate DNS or expose
 * account IDs, tokens, full Worker version IDs, tenant data or raw API bodies.
 * Even PASS does not certify rollback, customer acceptance, or release GO.
 */
const crypto=require('node:crypto');
const WORKER='cyberdudebivash-blog';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const ACCOUNT=/^[a-f0-9]{32}$/i;
const MAX_BYTES=256*1024;
const FUTURE_SKEW_MS=5*60*1000;
const digest=id=>crypto.createHash('sha256').update(id).digest('hex').slice(0,16);
function classifyDeployment(body,nowMs=Date.now()){
  if(!body||body.success!==true||!Array.isArray(body.result?.deployments))
    return {ok:false,code:'DEPLOYMENT_RESPONSE_INVALID'};
  const newest=body.result.deployments[0];
  if(!newest||!UUID.test(newest.id||'')||!UUID.test(newest.versions?.[0]?.version_id||''))
    return {ok:false,code:'ACTIVE_DEPLOYMENT_UNAVAILABLE'};
  if(!Array.isArray(newest.versions)||newest.versions.length!==1||
     newest.versions[0].percentage!==100)
    return {ok:false,code:'ACTIVE_VERSION_TRAFFIC_SPLIT_OR_INVALID'};
  const timestamp=Date.parse(newest.created_on||'');
  if(!Number.isFinite(timestamp)||!Number.isFinite(nowMs)||timestamp>nowMs+FUTURE_SKEW_MS)
    return {ok:false,code:'DEPLOYMENT_TIMESTAMP_INVALID'};
  if(body.result.deployments.length>10)
    return {ok:false,code:'DEPLOYMENT_PAGE_UNBOUNDED'};
  return {ok:true,code:'ACTIVE_WORKER_DEPLOYMENT_READ',
    versionId:newest.versions[0].version_id,
    createdAt:newest.created_on};
}
async function boundedJson(response){
  if(!response.ok)throw Error('CLOUDFLARE_READ_HTTP_FAILURE');
  if(!response.body||typeof response.body.getReader!=='function')
    throw Error('CLOUDFLARE_READ_EMPTY');
  const reader=response.body.getReader(),parts=[];let size=0;
  try {
    for(;;){
      const next=await reader.read();
      if(next.done)break;
      size+=next.value.byteLength;
      if(size>MAX_BYTES)throw Error('CLOUDFLARE_READ_OVERSIZED');
      parts.push(Buffer.from(next.value));
    }
  } finally { reader.releaseLock(); }
  try{return JSON.parse(Buffer.concat(parts).toString('utf8'));}
  catch{throw Error('CLOUDFLARE_READ_JSON_INVALID');}
}
async function inventory({token,accountId,fetchImpl=globalThis.fetch,nowMs=Date.now()}={}){
  if(typeof token!=='string'||token.length<16||!ACCOUNT.test(accountId||'')||
     typeof fetchImpl!=='function')throw Error('CLOUDFLARE_READ_CONTEXT_MISSING');
  const api='https://api.cloudflare.com/client/v4/accounts/'+accountId+
    '/workers/scripts/'+WORKER;
  const request=async url=>{
    // The only Cloudflare network verbs in this module are GET.
    const response=await fetchImpl(url,{method:'GET',redirect:'error',
      signal:AbortSignal.timeout(15000),
      headers:{Authorization:'Bearer '+token,Accept:'application/json'}});
    return boundedJson(response);
  };
  const body=await request(api+'/deployments?page=1&per_page=10');
  const found=classifyDeployment(body,nowMs);
  if(!found.ok)throw Error(found.code);
  // Prove that the actually serving version is still readable as a candidate.
  // This does NOT validate rollback behavior or authorize a rollback.
  const version=await request(api+'/versions/'+found.versionId);
  if(!version||version.success!==true||!version.result||
     version.result.id!==found.versionId)
    throw Error('ACTIVE_VERSION_NOT_READABLE');
  return {ok:true,code:'ACTIVE_VERSION_READABLE_NOT_ROLLBACK_TESTED',
    versionFingerprint:digest(found.versionId),createdAt:found.createdAt,
    rollbackVerified:false,productionReleaseAuthorized:false};
}
if(require.main===module){
  inventory({token:process.env.CLOUDFLARE_API_TOKEN,
    accountId:process.env.CLOUDFLARE_ACCOUNT_ID}).then(result=>{
    console.log('PASS: '+result.code+' fingerprint='+result.versionFingerprint+
      ' rollback_tested=false deploy_authorized=false');
  }).catch(err=>{
    const safe=new Set(['CLOUDFLARE_READ_CONTEXT_MISSING',
      'CLOUDFLARE_READ_HTTP_FAILURE','CLOUDFLARE_READ_EMPTY',
      'CLOUDFLARE_READ_OVERSIZED','CLOUDFLARE_READ_JSON_INVALID',
      'DEPLOYMENT_RESPONSE_INVALID','ACTIVE_DEPLOYMENT_UNAVAILABLE',
      'ACTIVE_VERSION_TRAFFIC_SPLIT_OR_INVALID','DEPLOYMENT_TIMESTAMP_INVALID',
      'DEPLOYMENT_PAGE_UNBOUNDED','ACTIVE_VERSION_NOT_READABLE']);
    console.error('HOLD: '+(safe.has(err.message)?err.message:'CLOUDFLARE_DEPLOYMENT_EVIDENCE_UNAVAILABLE'));
    process.exitCode=2;
  });
}
module.exports={classifyDeployment,inventory,WORKER};
