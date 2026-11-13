'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {certify,classifyResponse,ASSETS,HOSTS}=require('../scripts/certify-soc-dual-host-ui-release.cjs');
const sha='a'.repeat(40);
const body=Buffer.from('console.log("verified approved release source asset '+ 'a'.repeat(80) +'");');
const digest=crypto.createHash('sha256').update(body).digest('hex');
const readFile=()=>body;
function fetchFixture(onCall){
  const seen=[];
  return {seen,fetchImpl:async(url,opts)=>{
    seen.push({url:String(url),method:opts.method,redirect:opts.redirect});
    const changed=onCall?.(new URL(url),seen.length)||{};
    const data=changed.body||body;
    const asset=ASSETS.find(a=>a.url===new URL(url).pathname);
    const mime=asset.type==='javascript'?'application/javascript':asset.type==='css'?'text/css':'text/html';
    return new Response(data,{status:changed.status||200,
      headers:{'content-type':changed.contentType||mime}});
  }};
}
test('classification demands actual approved build bytes and HTTP 200',()=>{
 assert.deepEqual(classifyResponse({status:200,contentType:'application/javascript',body,digest,expectedType:'javascript'}),
   {ok:true,code:'PUBLIC_UI_BUILD_EXACT'});
 for(const x of [
   {status:404,contentType:'application/javascript',body,digest,expectedType:'javascript'},
   {status:200,contentType:'application/json',body,digest,expectedType:'javascript'},
   {status:200,contentType:'text/html',body,digest,expectedType:'javascript'},
   {status:200,contentType:'application/javascript',body:Buffer.from('404:'+body),digest,expectedType:'javascript'},
   {status:200,contentType:'application/javascript',body,digest:'garbage',expectedType:'javascript'},
 ]){
  assert.equal(classifyResponse(x).ok,false);
 }
});
test('both exact deployed Worker hosts serve FIVE approved asset byte digests',async()=>{
 const f=fetchFixture();
 const r=await certify({releaseSha:sha,root:'/fixture',fetchImpl:f.fetchImpl,readFile});
 assert.equal(r.status,'PASS_NOT_RELEASE_AUTHORIZATION');
 assert.equal(r.checks,10);
 assert.deepEqual(f.seen.map(x=>new URL(x.url).hostname),
   [...Array(5).fill(HOSTS[0]),...Array(5).fill(HOSTS[1])]);
 assert.deepEqual(f.seen.slice(0,5).map(x=>new URL(x.url).pathname),ASSETS.map(a=>a.url));
 assert(f.seen.every(x=>x.method==='GET'&&x.redirect==='error'));
 assert(f.seen.every(x=>new URL(x.url).searchParams.get('release_sha')===sha));
});
test('no stale legacy SOC hostname is accepted when blog is current',async()=>{
 const f=fetchFixture(url=>url.hostname===HOSTS[0]&&url.pathname==='/soc-intelligence-desk.js'?
   {body:Buffer.from('old release '+'x'.repeat(100))}:{});
 const result=await certify({releaseSha:sha,root:'/fixture',readFile,fetchImpl:f.fetchImpl});
 assert.equal(result.status,'HOLD');
 assert(result.codes.includes('PUBLIC_UI_BUILD_BYTES_MISMATCH'));
 assert.equal(f.seen.length,12,'only one bad file is retried three times');
});
test('both hosts fail on HTML fallback, absent asset and invalid credentials',async()=>{
 for(const error of [{status:404},{contentType:'text/html',body:Buffer.from('stale html'+'x'.repeat(100))}]){
  const f=fetchFixture(url=>url.pathname==='/runtime-state.js'?error:{});
  const r=await certify({releaseSha:sha,root:'/fixture',readFile,fetchImpl:f.fetchImpl});
  assert.equal(r.status,'HOLD');
 }
 assert.equal((await certify({releaseSha:'not-a-sha',root:'/fixture',readFile})).status,'HOLD');
 assert.equal((await certify({releaseSha:sha,root:'/fixture',readFile:()=>{throw Error('missing')}})).status,'HOLD');
});
test('postdeploy gate exists AFTER Wrangler and feed parity, never before or on push',()=>{
 const workflow=fs.readFileSync(path.resolve(__dirname,'../.github/workflows/cloudflare-production-deploy.yml'),'utf8');
 const deploy=workflow.indexOf('      - name: "Deploy Worker assets to the existing, approved domain"');
 const root=workflow.indexOf('      - name: "P0 deployed feed integrity — exact asset and report-age parity"');
 const api=workflow.indexOf('      - name: "P0 deployed S2N live API exact bytes on both hostnames"');
 const ui=workflow.indexOf('      - name: "P0 SOC dual-host UI exact build-byte parity — postdeploy"');
 assert(deploy>0&&root>deploy&&api>root&&ui>api);
 assert.match(workflow,/node scripts\/certify-soc-dual-host-ui-release\.cjs/);
 assert.match(workflow,/if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
 const slice=workflow.slice(ui,workflow.indexOf('      - name:',ui+12));
 assert.doesNotMatch(slice,/wrangler|createWorkflowDispatch|curl -X|dns_records/);
});
