'use strict';

/**
 * SENTINEL APEX SOC -- INTERNAL, vendor-neutral evidence proxy client.
 * No HTTP route, vendor account, DNS, Cloudflare binding, or customer enabled.
 *
 * Sources are OPERATOR-PINNED at service construction; event identities only
 * select an opaque query parameter, never a host/path or authorization token.
 * The customer-managed evidence proxy MUST independently authenticate source
 * ownership and return byte-for-byte originally hashed content with all three
 * identity headers. A native EDR/SIEM connector is NOT implemented here.
 */
const {isIP}=require('node:net');

const TENANT=/^[a-z0-9_-]{3,64}$/;
const CONNECTOR=/^[A-Za-z0-9_.:-]{1,128}$/;
const SOURCE=/^[A-Za-z0-9_.:-]{1,128}$/;

class SocPinnedEvidenceError extends Error {
  constructor(code) {super(code);this.name='SocPinnedEvidenceError';this.code=code;}
}
function deny(code){throw new SocPinnedEvidenceError(code);}
const own=(x,k)=>Object.prototype.hasOwnProperty.call(x,k);
function shape(value,keys){
  return value && typeof value==='object' && !Array.isArray(value) &&
    Object.keys(value).length===keys.length && keys.every(k=>own(value,k));
}
function trustedEndpoint(value){
  if(typeof value!=='string' || value.length>512 || value.length<14)
    deny('SOURCE_ENDPOINT_INVALID');
  let u;
  try {u=new URL(value);}catch(_){deny('SOURCE_ENDPOINT_INVALID');}
  const host=u.hostname.toLowerCase();
  if(u.protocol!=='https:' || !host || u.username || u.password ||
     u.hash || u.search || u.port ||
     isIP(host)!==0 ||
     !/^[a-z0-9.-]+$/.test(host) || !host.includes('.') ||
     host.startsWith('.') || host.endsWith('.') ||
     host==='localhost' || host.endsWith('.localhost') ||
     host.endsWith('.local') || host.endsWith('.internal') ||
     host.endsWith('.invalid') ||
     !u.pathname.startsWith('/') || u.pathname==='/' ||
     u.pathname.length>160 || u.pathname.includes('//') ||
     u.pathname.includes('%') ||
     /\/(?:\.|\.\.)(?:\/|$)/.test(u.pathname) ||
     u.toString()!==value)
    deny('SOURCE_ENDPOINT_INVALID');
  return value;
}
function checkScope({tenantId,connectorId,sourceEventId}={}){
  if(typeof tenantId!=='string' || !TENANT.test(tenantId) ||
     typeof connectorId!=='string' || !CONNECTOR.test(connectorId) ||
     typeof sourceEventId!=='string' || !SOURCE.test(sourceEventId))
    deny('SOURCE_SCOPE_INVALID');
}
function validateBinding(b){
  if(!shape(b,['tenantId','connectorId','endpoint']) ||
     typeof b.tenantId!=='string' || !TENANT.test(b.tenantId) ||
     typeof b.connectorId!=='string' || !CONNECTOR.test(b.connectorId))
    deny('SOURCE_BINDING_INVALID');
  return Object.freeze({
    tenantId:b.tenantId,connectorId:b.connectorId,
    endpoint:trustedEndpoint(b.endpoint),
  });
}
function tokenValue(value){
  // Tokens are opaque, server-managed and never emitted in errors/results.
  if(typeof value!=='string' || value.length<32 || value.length>4096 ||
     !/^[\x21-\x7e]+$/.test(value))
    deny('SOURCE_CREDENTIAL_UNAVAILABLE');
  return value;
}
function responseScope(r,scope) {
  if(!r || !r.headers || typeof r.headers.get!=='function')
    deny('SOURCE_RESPONSE_INVALID');
  if(r.headers.get('x-soc-tenant-id')!==scope.tenantId ||
     r.headers.get('x-soc-connector-id')!==scope.connectorId ||
     r.headers.get('x-soc-source-event-id')!==scope.sourceEventId)
    deny('SOURCE_RESPONSE_IDENTITY_MISMATCH');
}
async function readLimited(response,maxBytes,signal) {
  const header=response.headers.get('content-length');
  if(header!==null &&
      (!/^\d{1,8}$/.test(header) ||
       Number(header)<1 || Number(header)>maxBytes))
    deny('SOURCE_BODY_OVERSIZE');
  if(!response.body || typeof response.body.getReader!=='function')
    deny('SOURCE_STREAM_REQUIRED');
  const reader=response.body.getReader();
  const chunks=[];
  let total=0;
  try {
    while(true){
      if(signal.aborted)deny('SOURCE_FETCH_TIMEOUT');
      const next=await reader.read();
      if(next.done)break;
      if(!(next.value instanceof Uint8Array))deny('SOURCE_STREAM_INVALID');
      total+=next.value.byteLength;
      if(total>maxBytes)deny('SOURCE_BODY_OVERSIZE');
      chunks.push(Buffer.from(next.value));
    }
    if(total<1)deny('SOURCE_BODY_EMPTY');
    return Buffer.concat(chunks,total);
  }finally {
    // The AbortController drives cancellation of a real fetch stream. Never
    // indefinitely await a provider-controlled cancel() promise.
    try{const p=reader.cancel();if(p && typeof p.catch==='function')p.catch(()=>{});}
    catch(_){}
    try{reader.releaseLock();}catch(_){}
  }
}

/**
 * bindings: immutable exact tenant+connector -> operator-pinned HTTPS endpoint.
 * resolveToken: trusted secret manager hook (tenantId, connectorId) -> bearer.
 * fetcher: native Workerd fetch; test injection supported (NO public wiring).
 */
function createSocPinnedEvidenceProxy({
  bindings,resolveToken,fetcher=globalThis.fetch,
  maxBytes=262144,timeoutMs=6000,
}={}){
  if(!Array.isArray(bindings) || !bindings.length || bindings.length>32 ||
     typeof resolveToken!=='function' || typeof fetcher!=='function' ||
     !Number.isSafeInteger(maxBytes) || maxBytes<1 || maxBytes>1048576 ||
     !Number.isSafeInteger(timeoutMs) || timeoutMs<100 || timeoutMs>30000)
    deny('SOURCE_PROXY_NOT_CONFIGURED');

  const map=new Map();
  for(const raw of bindings){
    const b=validateBinding(raw);
    const id=JSON.stringify([b.tenantId,b.connectorId]);
    if(map.has(id))deny('SOURCE_BINDING_DUPLICATE');
    map.set(id,b);
  }
  async function readAuthorizedEvent(scope) {
    if(!shape(scope,['tenantId','connectorId','sourceEventId','signal']))
      deny('SOURCE_SCOPE_INVALID');
    checkScope(scope);
    const binding=map.get(JSON.stringify([scope.tenantId,scope.connectorId]));
    if(!binding)deny('SOURCE_NOT_ENROLLED');
    if(!scope.signal || typeof scope.signal.addEventListener!=='function' ||
       typeof scope.signal.aborted!=='boolean')
      deny('SOURCE_ABORT_SIGNAL_REQUIRED');
    if(scope.signal.aborted)deny('SOURCE_FETCH_ABORTED');

    const controller=new AbortController();
    const abort=()=>controller.abort();
    scope.signal.addEventListener('abort',abort,{once:true});
    let timer;
    const deadline=new Promise((_,reject)=>{
      timer=setTimeout(()=>{
        controller.abort();
        reject(new SocPinnedEvidenceError('SOURCE_FETCH_TIMEOUT'));
      },timeoutMs);
    });
    const work=async()=>{
      let token;
      try { token=tokenValue(await resolveToken(binding.tenantId,binding.connectorId)); }
      catch(_){deny('SOURCE_CREDENTIAL_UNAVAILABLE');}
      if(controller.signal.aborted)deny('SOURCE_FETCH_ABORTED');
      const u=new URL(binding.endpoint);
      u.searchParams.set('event_id',scope.sourceEventId);
      let response;
      try{
        response=await fetcher(u.toString(),{
          method:'GET',redirect:'error',cache:'no-store',
          signal:controller.signal,
          headers:{
            Accept:'application/octet-stream',
            Authorization:'Bearer '+token,
          },
        });
      }catch(_){deny('SOURCE_FETCH_UNAVAILABLE');}
      if(!response || response.status!==200)
        deny('SOURCE_HTTP_NOT_ACCEPTED');
      if(response.url && response.url!==u.toString())
        deny('SOURCE_REDIRECT_REJECTED');
      if(!response.headers || typeof response.headers.get!=='function')
        deny('SOURCE_RESPONSE_INVALID');
      if(response.headers.get('content-type')!=='application/octet-stream' ||
         (response.headers.get('content-encoding') &&
          response.headers.get('content-encoding')!=='identity'))
        deny('SOURCE_CONTENT_TYPE_REJECTED');
      responseScope(response,scope);
      const payloadBytes=await readLimited(response,maxBytes,controller.signal);
      return Object.freeze({
        tenantId:binding.tenantId,connectorId:binding.connectorId,
        sourceEventId:scope.sourceEventId,payloadBytes,
      });
    };
    try{return await Promise.race([work(),deadline]);}
    catch(error){
      if(error instanceof SocPinnedEvidenceError)throw error;
      deny('SOURCE_FETCH_UNAVAILABLE');
    }finally{
      clearTimeout(timer);
      scope.signal.removeEventListener('abort',abort);
      controller.abort();
    }
  }
  return Object.freeze({readAuthorizedEvent});
}
module.exports={createSocPinnedEvidenceProxy,SocPinnedEvidenceError};
