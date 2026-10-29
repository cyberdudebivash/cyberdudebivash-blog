'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');

process.env.UPSTASH_REDIS_REST_URL='https://redis.invalid';
process.env.UPSTASH_REDIS_REST_TOKEN='DISPOSABLE_UNIT_TEST_ONLY';
const redis=require('../api/_lib/redis');
const {buildSnapshot}=require('../scripts/backup-customer-data');
const {applySnapshot}=require('../scripts/restore-customer-data');

function wire(t,fn) {
  const old=global.fetch,calls=[];
  global.fetch=async(url,opt={})=>{
    const req={url,method:opt.method||'GET',headers:opt.headers||{},
      body:opt.body?JSON.parse(opt.body):null};
    calls.push(req);
    return await fn(req,calls.length);
  };
  t.after(()=>{global.fetch=old;});
  return calls;
}
const ok=(result='OK')=>({ok:true,json:async()=>({result})});
const bad=error=>({ok:true,json:async()=>({error})});

test('P0 HMSET: customer hash fields go in one atomic Upstash POST, never a URL',async t=>{
  const requests=wire(t,()=>ok());
  const key='user:key:disposable', token='SENSITIVE_DISPOSABLE_TOKEN_NOT_REAL';
  assert.equal(await redis.hmset(key,{email:'nobody@example.invalid',tier:'pro',downloadToken:token}),'OK');
  assert.equal(requests.length,1);
  const req=requests[0];
  assert.equal(req.url,'https://redis.invalid');
  assert.equal(req.method,'POST');
  assert.equal(req.headers['Content-Type'],'application/json');
  assert.equal(req.headers.Authorization,'Bearer DISPOSABLE_UNIT_TEST_ONLY');
  assert.deepEqual(req.body,[
    'HMSET',key,'email','nobody@example.invalid','tier','pro','downloadToken',token
  ]);
  assert(!req.url.includes('nobody@example.invalid'));
  assert(!req.url.includes(token));
});
test('P0 HMSET: large customer metadata is body encoded; no oversized URL path',async t=>{
  const requests=wire(t,()=>ok());
  const large='L'.repeat(18000);
  await redis.hmset('product:purchase:isolated',{purchaseId:'isolated',contentPath:large});
  assert.equal(requests[0].url,'https://redis.invalid');
  assert.equal(requests[0].body[5],large);
});
test('P0 HMSET: preserve prior String(value) semantics and Redis OK receipt',async t=>{
  const requests=wire(t,()=>ok());
  assert.equal(await redis.hmset('subscription:disposable',{count:4,active:true,unset:null}),'OK');
  assert.deepEqual(requests[0].body,[
    'HMSET','subscription:disposable','count','4','active','true','unset','null'
  ]);
});
test('P0 HMSET: malformed key/hash or empty field rejects before network request',async t=>{
  const requests=wire(t,()=>{throw Error('network must not be invoked')});
  for(const args of [
    ['',{}],['key',{}],['key',null],['key',[]],['key','bad'],['key',{'':'v'}],
    [null,{title:'a'}]
  ]){
    await assert.rejects(redis.hmset(...args),/SOC_REDIS_HMSET_INVALID_FIELDS/);
  }
  assert.deepEqual(requests,[]);
});
test('P0 HMSET: transport and provider errors cannot produce success receipts',async t=>{
  const responses=[
    {ok:false,status:503},
    bad('WRONGTYPE'),
    {ok:true,json:async()=>({result:0})},
    {ok:true,json:async()=>({result:'OK',error:'DENIED'})},
    {ok:true,json:async()=>({})},
    {ok:true,json:async()=>null}
  ];
  const calls=wire(t,(req,n)=>responses[n-1]);
  for(let i=0;i<responses.length;i++){
    await assert.rejects(redis.hmset('user:key:isolated',{tier:'pro'}),
      /Redis HMSET HTTP 503|SOC_REDIS_HMSET_NOT_CONFIRMED/);
  }
  assert.equal(calls.length,responses.length);
});
test('P0 HMSET: backup restore uses actual POST adapter and preserves payment audit writes',async t=>{
  const requests=wire(t,req=>{
    if(req.method==='POST')return ok();
    const command=new URL(req.url).pathname.split('/').filter(Boolean)[0];
    if(command==='SET')return ok();
    if(command==='ZADD')return {ok:true,json:async()=>({result:1})};
    throw Error('UNEXPECTED_COMMAND');
  });
  const snapshot=buildSnapshot({
    hashes:{'user:key:uid-1':{email:'u@example.invalid',tier:'pro'}},
    strings:{'user:id:uid-1':'uid-1'},
    auditLog:[['{"event":"disposable"}','1700000000123']]
  });
  const result=await applySnapshot(redis,snapshot);
  assert.deepEqual(result,{hashesWritten:1,stringsWritten:1,auditEntriesWritten:1});
  assert.equal(requests[0].method,'POST');
  assert.deepEqual(requests[0].body,['HMSET','user:key:uid-1','email','u@example.invalid','tier','pro']);
  assert.equal(requests[1].method,'GET');
  assert.equal(requests[2].method,'GET');
});
test('P0 HMSET: rejected restore hash write blocks subsequent customer lookup and audit changes',async t=>{
  const requests=wire(t,req=>{
    if(req.method==='POST')return bad('READONLY');
    throw Error('Must not attempt downstream changes');
  });
  const snapshot=buildSnapshot({
    hashes:{'user:key:uid-1':{tier:'pro'}},
    strings:{'user:id:uid-1':'uid-1'},
    auditLog:[['event','1700000000000']]
  });
  await assert.rejects(applySnapshot(redis,snapshot),/SOC_REDIS_HMSET_NOT_CONFIRMED/);
  assert.equal(requests.length,1);
  assert.equal(requests[0].method,'POST');
});
