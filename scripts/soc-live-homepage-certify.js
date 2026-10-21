'use strict';

/**
 * Read-only SENTINEL APEX live-HTML gate. NO production writes, authentication,
 * migration, payment, GitHub deployment or DNS mutation.
 *
 * Manual operator command:
 *    node scripts/soc-live-homepage-certify.js
 *    node scripts/soc-live-homepage-certify.js --soc
 *
 * Exit: 0 PASS, 2 FAIL, 3 INCONCLUSIVE.
 * This gate checks the HTML that a single public edge returned, NOT the exact
 * Worker deployment SHA, CTI source freshness or global edge propagation.
 */
const crypto=require('node:crypto');
const {assertHomepageIntegrity}=require('./soc-homepage-integrity');

const ENDPOINTS=Object.freeze({
  blog:'https://blog.cyberdudebivash.in/',
  soc:'https://soc.cyberdudebivash.in/',
});
const MAX_BYTES=3*1024*1024;
const TIMEOUT_MS=12000;

function inspectResponseBody(html,{url=ENDPOINTS.blog,httpStatus=200,contentType='text/html'}={}) {
  const body=String(html);
  const digest=crypto.createHash('sha256').update(body,'utf8').digest('hex');
  const title=(body.match(/<title>([^<]*)<\/title>/i)||[])[1]||null;
  const result={
    checkedUrl:url,httpStatus,htmlBytes:Buffer.byteLength(body,'utf8'),
    contentSha256:digest,title,
    count:{
      mainOpen:(body.match(/<main(?:\s[^>]*)?>/gi)||[]).length,
      mainClose:(body.match(/<\/main\s*>/gi)||[]).length,
      reportIds:(body.match(/\bid=["']reports["']/gi)||[]).length,
      liveFeedIds:(body.match(/\bid=["']live-intel-feed["']/gi)||[]).length,
      enterpriseCtas:(body.match(/<section\b[^>]*class=["'][^"']*\bent-cta-block\b/gi)||[]).length,
      generatedCards:(body.match(/data-intel-auto=/g)||[]).length,
    },
    gates:['HTTP 200','HTML content type','single SOC/CTI homepage structure','accurate product title'],
    limitations:['not a deployment SHA attestation','not a CTI feed freshness check','not a multi-region edge probe'],
  };
  if(httpStatus===429)return {...result,status:'INCONCLUSIVE',reason:'EDGE_RATE_LIMITED'};
  if(httpStatus!==200)return {...result,status:'FAIL',reason:'HTTP_STATUS_UNEXPECTED'};
  if(typeof contentType!=='string'||!/^text\/html(?:\s*;|$)/i.test(contentType))
    return {...result,status:'FAIL',reason:'NOT_HTML'};
  if(!body||result.htmlBytes>MAX_BYTES)return {...result,status:'FAIL',reason:'BODY_SIZE_INVALID'};
  try{assertHomepageIntegrity(body,'public edge HTML');}
  catch(_){return {...result,status:'FAIL',reason:'HOMEPAGE_INTEGRITY_FAILED'};}
  return {...result,status:'PASS',reason:'STRUCTURE_AND_BRANDING_MATCH'};
}

async function readBounded(response) {
  const length=response.headers.get('content-length');
  if(length && Number(length)>MAX_BYTES)throw new Error('PUBLIC_HTML_TOO_LARGE');
  if(!response.body||typeof response.body.getReader!=='function')
    throw new Error('PUBLIC_HTML_STREAM_REQUIRED');
  const chunks=[];let size=0;
  const reader=response.body.getReader();
  try {
    while(true){
      const next=await reader.read();
      if(next.done)break;
      size+=next.value.byteLength;
      if(size>MAX_BYTES)throw new Error('PUBLIC_HTML_TOO_LARGE');
      chunks.push(next.value);
    }
  }finally {
    await reader.cancel().catch(()=>{});
    reader.releaseLock();
  }
  const bytes=Buffer.concat(chunks.map(chunk=>Buffer.from(chunk)),size);
  return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
}

async function certifyLiveHomepage({
  target='blog',fetcher=globalThis.fetch,timeoutMs=TIMEOUT_MS,
}={}) {
  if(!Object.hasOwn(ENDPOINTS,target))throw new Error('APPROVED_ENDPOINT_REQUIRED');
  if(typeof fetcher!=='function')throw new Error('FETCH_REQUIRED');
  const url=ENDPOINTS[target];
  const checkedAt=new Date().toISOString();
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),timeoutMs);
  try{
    const response=await fetcher(url,{
      method:'GET',redirect:'manual',cache:'no-store',
      signal:controller.signal,headers:{Accept:'text/html'},
    });
    if(!response||typeof response.status!=='number')
      throw new Error('HTTP_RESPONSE_INVALID');
    if(response.status===429) {
      return {status:'INCONCLUSIVE',reason:'EDGE_RATE_LIMITED',
        checkedUrl:url,httpStatus:429,checkedAt};
    }
    // Refuse to follow redirects silently: unexpected host/content cannot pass.
    if(response.status!==200)
      return {status:'FAIL',reason:'HTTP_STATUS_UNEXPECTED',
        checkedUrl:url,httpStatus:response.status,checkedAt};
    const type=response.headers.get('content-type')||'';
    if(!/^text\/html(?:\s*;|$)/i.test(type))
      return {status:'FAIL',reason:'NOT_HTML',checkedUrl:url,httpStatus:200,checkedAt};
    const body=await readBounded(response);
    return {...inspectResponseBody(body,{url,httpStatus:200,contentType:type}),checkedAt};
  }catch(_){
    return {status:'INCONCLUSIVE',reason:'EDGE_READ_FAILED',
      checkedUrl:url,checkedAt};
  }finally {clearTimeout(timer);}
}

if(require.main===module) {
  const args=process.argv.slice(2);
  if(args.some(x=>!['--soc'].includes(x))||args.length>1){
    process.stderr.write('Usage: node scripts/soc-live-homepage-certify.js [--soc]\n');
    process.exitCode=2;
  }else {
    certifyLiveHomepage({target:args.includes('--soc')?'soc':'blog'})
      .then(result=>{
        process.stdout.write(JSON.stringify(result,null,2)+'\n');
        process.exitCode=result.status==='PASS'?0:result.status==='FAIL'?2:3;
      })
      .catch(()=>{
        process.stderr.write('Live certification could not initialize\n');
        process.exitCode=3;
      });
  }
}

module.exports={ENDPOINTS,inspectResponseBody,certifyLiveHomepage};
