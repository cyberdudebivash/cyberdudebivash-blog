#!/usr/bin/env node
'use strict';

/**
 * P0: read-only precondition for ROUTINE Worker content release.
 * Cloudflare Custom Domains can create DNS and TLS resources during setup.
 * Refuse any deployment until the expected domain is already bound to the
 * expected Worker. Initial DNS/hostname migration is a separate change.
 * Never prints account IDs, tokens, hostnames beyond the approved constant,
 * or raw Cloudflare API bodies.
 */
const HOSTNAME='blog.cyberdudebivash.in';
const WORKER='cyberdudebivash-blog';
const accountIdPattern=/^[a-f0-9]{32}$/i;

function classifyDomainBinding(body){
  if(!body||typeof body!=='object'||body.success!==true||!Array.isArray(body.result)){
    return {ok:false,code:'DOMAIN_API_RESPONSE_INVALID'};
  }
  const info=body.result_info;
  if(info && (typeof info!=='object' ||
      (info.total_pages!==undefined && info.total_pages!==1) ||
      (info.total_count!==undefined && info.total_count>100))){
    return {ok:false,code:'DOMAIN_LIST_NOT_COMPLETE'};
  }
  const exact=body.result.filter(item=>item &&
    typeof item==='object' && item.hostname===HOSTNAME);
  if(exact.length!==1){
    return {ok:false,code:exact.length>1?'DOMAIN_DUPLICATE':'DOMAIN_NOT_ESTABLISHED'};
  }
  const domain=exact[0];
  if(domain.service!==WORKER){
    return {ok:false,code:'DOMAIN_WRONG_WORKER'};
  }
  if(domain.enabled!==true){
    return {ok:false,code:'DOMAIN_NOT_ENABLED'};
  }
  if(typeof domain.id!=='string'||domain.id.length<1){
    return {ok:false,code:'DOMAIN_ID_MISSING'};
  }
  return {ok:true,code:'DOMAIN_MAPPING_ESTABLISHED'};
}
async function readBounded(response,maxBytes=262144){
  if(!response.body)throw new Error('DOMAIN_API_EMPTY_BODY');
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{
    for(;;){
      const next=await reader.read();
      if(next.done)break;
      size+=next.value.byteLength;
      if(size>maxBytes)throw new Error('DOMAIN_API_RESPONSE_TOO_LARGE');
      chunks.push(Buffer.from(next.value));
    }
  }finally{reader.releaseLock();}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
async function verify({token,accountId}){
  if(typeof token!=='string'||token.length<16 ||
    typeof accountId!=='string'||!accountIdPattern.test(accountId)){
    throw new Error('CLOUDFLARE_READ_CONTEXT_MISSING');
  }
  // Cloudflare Workers Domains List — exact, documented read-only endpoint.
  // Hostname filter narrows the reply; independent strict client-side match.
  const endpoint=new URL('https://api.cloudflare.com/client/v4/accounts/'+accountId+'/workers/domains');
  endpoint.searchParams.set('hostname',HOSTNAME);
  const response=await fetch(endpoint,{
    method:'GET',redirect:'error',signal:AbortSignal.timeout(15000),
    headers:{Authorization:'Bearer '+token,Accept:'application/json'},
  });
  if(!response.ok)throw new Error('CLOUDFLARE_DOMAIN_API_HTTP_FAILURE');
  const body=await readBounded(response);
  const classification=classifyDomainBinding(body);
  if(!classification.ok)throw new Error(classification.code);
  return classification;
}
if(require.main===module){
  verify({token:process.env.CLOUDFLARE_API_TOKEN,
    accountId:process.env.CLOUDFLARE_ACCOUNT_ID}).then(()=>{
    console.log('PASS: EXISTING_CLOUDFLARE_WORKER_DOMAIN_VERIFIED — routine release may proceed without DNS migration');
  }).catch(err=>{
    const safe=new Set(['CLOUDFLARE_READ_CONTEXT_MISSING','CLOUDFLARE_DOMAIN_API_HTTP_FAILURE',
      'DOMAIN_API_EMPTY_BODY','DOMAIN_API_RESPONSE_TOO_LARGE','DOMAIN_API_RESPONSE_INVALID',
      'DOMAIN_LIST_NOT_COMPLETE','DOMAIN_DUPLICATE','DOMAIN_NOT_ESTABLISHED','DOMAIN_WRONG_WORKER',
      'DOMAIN_NOT_ENABLED','DOMAIN_ID_MISSING']);
    const code=safe.has(err.message)?err.message:'CLOUDFLARE_DOMAIN_VERIFICATION_FAILED';
    console.error('HOLD: '+code+' — preserve current DNS; separate approved cutover required');
    process.exitCode=1;
  });
}
module.exports={classifyDomainBinding,verify,HOSTNAME,WORKER};
