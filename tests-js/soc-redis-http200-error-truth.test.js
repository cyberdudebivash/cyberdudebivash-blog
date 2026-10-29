'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');

// Independent per-file worker environment, no live Redis credentials.
process.env.UPSTASH_REDIS_REST_URL='https://redis.invalid';
process.env.UPSTASH_REDIS_REST_TOKEN='DISPOSABLE_UNIT_TEST_NOT_A_SECRET';
const redis=require('../api/_lib/redis');
const {fetchAll,buildSnapshot}=require('../scripts/backup-customer-data');
const {applySnapshot}=require('../scripts/restore-customer-data');

function fixture(t, impl){
  const original=global.fetch,calls=[];
  global.fetch=async (url,opts={})=>{
    const parts=opts.method==='POST' ? JSON.parse(opts.body) :
      new URL(url).pathname.split('/').filter(Boolean).map(decodeURIComponent);
    calls.push({url,opts,parts});
    return impl(parts,calls.length,opts);
  };
  t.after(()=>{global.fetch=original;});
  return calls;
}
const yes=(result)=>({ok:true,json:async()=>({result})});
const rejected=(error)=>({ok:true,json:async()=>({error})});
test('P0: HTTP 200 Redis error is not mistaken for successful GET/SET/KEYS/HMSET/ZADD',async t=>{
  const calls=fixture(t,()=>rejected('WRONGTYPE or authorization rejected'));
  for(const cb of [
    ()=>redis.get('user:id:001'),
    ()=>redis.set('user:id:001','test'),
    ()=>redis.keys('user:key:*'),
    ()=>redis.hmset('user:key:001',{tier:'pro'}),
    ()=>redis.zadd('audit:payment:log',1700000000000,'event')
  ]){
    await assert.rejects(cb(),/SOC_REDIS_COMMAND_SERVER_REJECTED/);
  }
  assert.deepEqual(calls.map(x=>x.parts[0]),['GET','SET','KEYS','HMSET','ZADD']);
});
test('P0: valid Redis null GET result and error:null responses keep their documented meaning',async t=>{
  fixture(t,(parts,n)=>n===1?yes(null):{ok:true,json:async()=>({error:null,result:'OK'})});
  assert.equal(await redis.get('nonexistent'),null);
  assert.equal(await redis.set('isolated','value'),'OK');
});
test('P0: malformed, absent and ambiguous provider replies fail closed',async t=>{
  const values=[null,{},[],{error:'ERR invalid command'},'garbage',
    {result:0,error:'NO_PERMISSION'},{error:null}];
  fixture(t,(parts,n)=>({ok:true,json:async()=>values[n-1]}));
  for(const value of values){
    await assert.rejects(redis.get('isolated'),/SOC_REDIS_COMMAND_SERVER_REJECTED/);
  }
});
test('P0: HTTP transport failure still fails before success handling',async t=>{
  fixture(t,()=>({ok:false,status:429,json:async()=>({result:'OK'})}));
  await assert.rejects(redis.set('isolated','value'),/Redis HTTP 429/);
});
test('P0: a rejected KEYS response cannot silently produce a zero-record customer backup',async t=>{
  const calls=fixture(t,parts=>{
    if(parts[0]==='KEYS')return rejected('ERR no permission');
    throw Error('Audit data must not be read after backup KEYS failed');
  });
  await assert.rejects(fetchAll(redis),/SOC_REDIS_COMMAND_SERVER_REJECTED/);
  assert.deepEqual(calls.map(x=>x.parts[0]),['KEYS']);
});
test('P0: restore refuses to report hash recovery after an HTTP-200 HMSET rejection',async t=>{
  const calls=fixture(t,parts=>{
    if(parts[0]==='HMSET')return rejected('ERR readonly');
    throw Error('No further restore data can be written');
  });
  const snap=buildSnapshot({
    hashes:{'user:key:disposable':{tier:'pro',email:'x@example.invalid'}},
    strings:{'user:id:disposable':'disposable'},
    auditLog:[['{"event":"DISPOSABLE"}','1700000000000']]
  });
  await assert.rejects(applySnapshot(redis,snap),/SOC_REDIS_COMMAND_SERVER_REJECTED/);
  assert.deepEqual(calls.map(x=>x.parts[0]),['HMSET']);
});
test('P0: non-atomic pipeline surfaces any failed or ambiguous operation receipt',async t=>{
  const cases=[
    [{result:'OK'},{error:'WRONGTYPE'}],
    [{result:'OK'}],
    {error:'ERR'},
    [{result:'OK'},{result:null,error:'REJECTED'}],
    [{result:'OK'},{}]
  ];
  fixture(t,(parts,n)=>({ok:true,json:async()=>cases[n-1]}));
  for(const item of cases){
    await assert.rejects(redis.pipeline([['SET','a','1'],['DEL','b']]),
      /SOC_REDIS_PIPELINE_PARTIAL_FAILURE/);
  }
});
test('P0: valid pipeline may contain a documented null Redis result',async t=>{
  fixture(t,()=>({ok:true,json:async()=>[{result:'OK',error:null},{result:null}]}));
  assert.deepEqual(await redis.pipeline([['SET','a','1'],['GET','absent']]),['OK',null]);
});
