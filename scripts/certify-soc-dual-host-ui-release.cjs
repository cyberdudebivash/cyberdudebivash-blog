#!/usr/bin/env node
'use strict';
/**
 * P0 POSTDEPLOY ONLY: prove critical customer UI bytes are identical to the
 * approved dist-public build on BOTH SOC and blog Worker Custom Domains.
 * This is read-only GET; no cache purge, DNS, deploy, customer action or writes.
 * Root/S2N feed freshness and authorization are independent mandatory gates.
 */
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const HOSTS=Object.freeze(['soc.cyberdudebivash.in','blog.cyberdudebivash.in']);
const ASSETS=Object.freeze([
  {url:'/soc-intelligence-desk.js',file:'soc-intelligence-desk.js',type:'javascript'},
  {url:'/runtime-state.js',file:'runtime-state.js',type:'javascript'},
  {url:'/apex-command-center.js',file:'apex-command-center.js',type:'javascript'},
  {url:'/soc-cti-console.css',file:'soc-cti-console.css',type:'css'},
  {url:'/soc.html',file:'soc.html',type:'html'}
]);
const SHA=/^[a-f0-9]{40}$/i;
const MAX_BYTES=2*1024*1024;
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
function expectedAssets(root=path.resolve(__dirname,'..','dist-public'),readFile=fs.readFileSync){
  return ASSETS.map(asset=>{
    const file=path.join(root,asset.file);
    const content=readFile(file);
    if(!Buffer.isBuffer(content)||content.length<40||content.length>MAX_BYTES)
      throw Error('RELEASE_BUILD_ASSET_INVALID');
    return {...asset,digest:hash(content)};
  });
}
function classifyResponse({status,contentType,body,digest,expectedType}={}){
  if(status!==200)return {ok:false,code:'PUBLIC_UI_HTTP_NOT_200'};
  if(!Buffer.isBuffer(body)||body.length<40||body.length>MAX_BYTES)
    return {ok:false,code:'PUBLIC_UI_RESPONSE_INVALID'};
  const MIME={
    javascript:/^(?:text\/javascript|application\/javascript|application\/x-javascript)(?:\s*;|\s*$)/i,
    css:/^text\/css(?:\s*;|\s*$)/i,
    html:/^text\/html(?:\s*;|\s*$)/i
  };
  if(typeof contentType!=='string'||
     !Object.prototype.hasOwnProperty.call(MIME,expectedType)||
     !MIME[expectedType].test(contentType))
    return {ok:false,code:'PUBLIC_UI_TYPE_INVALID'};
  if(!/^[a-f0-9]{64}$/.test(digest||''))return {ok:false,code:'SOURCE_BUILD_DIGEST_INVALID'};
  if(hash(body)!==digest)return {ok:false,code:'PUBLIC_UI_BUILD_BYTES_MISMATCH'};
  return {ok:true,code:'PUBLIC_UI_BUILD_EXACT'};
}

async function boundedBytes(response){
  const reader=response.body?.getReader();
  if(!reader)throw Error('PUBLIC_UI_BODY_MISSING');
  const parts=[];let size=0;
  try{
    for(;;){
      const next=await reader.read();
      if(next.done)break;
      size+=next.value.byteLength;
      if(size>MAX_BYTES)throw Error('PUBLIC_UI_BODY_TOO_LARGE');
      parts.push(Buffer.from(next.value));
    }
  }finally{reader.releaseLock();}
  return Buffer.concat(parts);
}
async function certify({releaseSha,root,fetchImpl=globalThis.fetch,readFile=fs.readFileSync}={}){
  if(!SHA.test(releaseSha||'')||typeof fetchImpl!=='function')
    return {status:'HOLD',code:'RELEASE_SHA_OR_NETWORK_INVALID'};
  let assets;
  try{assets=expectedAssets(root,readFile);}
  catch{return {status:'HOLD',code:'RELEASE_BUILD_ASSET_INVALID'};}
  const checked=[];
  for(const host of HOSTS){
    for(const asset of assets){
      const url=new URL('https://'+host+asset.url);
      url.searchParams.set('release_sha',releaseSha);
      let result={ok:false,code:'PUBLIC_UI_NETWORK_UNAVAILABLE'};
      // Propagation can be eventual. Bounded attempts, no synthetic fallback.
      for(let attempt=0;attempt<3;attempt++){
        try{
          const response=await fetchImpl(url,{method:'GET',redirect:'error',
            signal:AbortSignal.timeout(12000),headers:{'Cache-Control':'no-cache',Accept:'*/*'}});
          const body=await boundedBytes(response);
          const contentType=response.headers.get('content-type');
          result=classifyResponse({status:response.status,contentType,body,digest:asset.digest,expectedType:asset.type});
          if(result.ok)break;
        }catch(e){
          result={ok:false,code:e.message==='PUBLIC_UI_BODY_TOO_LARGE'?
            'PUBLIC_UI_BODY_TOO_LARGE':'PUBLIC_UI_NETWORK_UNAVAILABLE'};
        }
      }
      checked.push({hostname:host,asset:asset.file,status:result.ok?'PASS':'FAIL',code:result.code});
    }
  }
  return {status:checked.every(x=>x.status==='PASS')?'PASS_NOT_RELEASE_AUTHORIZATION':'HOLD',
    checks:checked.length,codes:[...new Set(checked.filter(x=>x.status!=='PASS').map(x=>x.code))].sort()};
}
if(require.main===module){
  certify({releaseSha:process.env.GITHUB_SHA}).then(result=>{
    console.log(JSON.stringify(result));
    if(result.status!=='PASS_NOT_RELEASE_AUTHORIZATION')process.exitCode=2;
  }).catch(()=>{
    console.error('HOLD: SOC_DUAL_HOST_UI_CERTIFICATION_UNAVAILABLE');
    process.exitCode=2;
  });
}
module.exports={ASSETS,HOSTS,MAX_BYTES,classifyResponse,expectedAssets,certify};
