'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const pending=require('../api/_lib/pending-tier-registration');
const SCRIPT=fs.readFileSync(path.join(__dirname,'../api/v1/auth.js'),'utf8');
const KEY='user:pending:tier:buyer_example.com';
const RAW=JSON.stringify({tier:'pro',activatedAt:'2026-10-01T00:00:00Z',transactionId:'disposable-payment'});
function fixture({failLookup=false,failCleanup=false,newPaymentDuringWrite=false,pendingValue=RAW}={}){
  const calls=[],values=new Map(pendingValue?[[KEY,pendingValue]]:[]);
  const redis={
    get:async key=>{calls.push(['get',key]);return values.get(key)||null;},
    hmset:async(key,data)=>{calls.push(['hmset',key,{...data}]);return 'OK';},
    set:async(key,value)=>{
      calls.push(['set',key,value]);
      if(failLookup&&key.startsWith('user:id:'))throw Error('DISPOSABLE_WRITE_FAILURE');
      values.set(key,value);
      if(newPaymentDuringWrite&&key.startsWith('user:id:'))values.set(KEY,JSON.stringify({
        tier:'enterprise',transactionId:'newer-disposable-payment'
      }));
      return 'OK';
    },
    eval:async(script,keys,args)=>{
      calls.push(['eval',script,keys,args]);
      if(failCleanup)throw Error('DISPOSABLE_CLEANUP_FAILURE');
      assert.match(script,/redis\.call\("GET", KEYS\[1\]\)/);
      assert.match(script,/current ~= ARGV\[1\]/);
      assert.match(script,/redis\.call\("DEL", KEYS\[1\]\)/);
      const existing=values.get(keys[0]);
      if(existing!==args[0])return 0;
      values.delete(keys[0]);
      return 1;
    },
    incr:async()=>1
  };
  const middleware={
    authenticate:async()=>null,
    respond:(res,status,value)=>{res.statusCode=status;res.body=value;return value;},
    apiError:(res,status,code,message)=>{res.statusCode=status;res.body={error:{code,message}};return res.body;},
    successResponse:(res,value)=>{res.statusCode=200;res.body=value;return value;},
    corsHeaders:()=>({}),
    generateApiKey:()=> 'disposable_generated_key',
    hashKey:()=> 'fake-api-key-hash',
    RATE_LIMITS:{free:100}
  };
  const security={
    guardRequest:async()=>true,globalIpRateLimit:async()=>true,
    assertFieldWhitelist:()=>null,
    sanitize:(v,n)=>String(v).slice(0,n),
    validateEmail:v=>v==='buyer@example.com',
    safeError:()=> 'Registration unavailable'
  };
  const modules={
    crypto, '../_lib/redis':redis,'../_lib/middleware':middleware,
    '../_lib/security':security,'../_lib/resend':{canSendEmail:()=>false},
    '../_lib/pending-tier-registration':pending
  };
  const module={exports:{}};
  vm.runInNewContext(SCRIPT,{module,require:key=>{
    if(!Object.prototype.hasOwnProperty.call(modules,key))throw Error('UNEXPECTED_MODULE '+key);
    return modules[key];
  },console:{warn:(...args)=>calls.push(['warn',...args])},Date,Buffer,process:{
    env:{}
  }},{filename:'auth.js',timeout:2000});
  async function register(){
    const res={};
    await module.exports({method:'POST',query:{action:'register'},body:{email:'buyer@example.com',plan:'free'}},res);
    return res;
  }
  return {calls,values,register};
}
test('P0 preregistration tier is consumed ONLY after hash/email/reverse lookup persist',async()=>{
  const x=fixture();
  const res=await x.register();
  assert.equal(res.statusCode,201);
  assert.equal(res.body.user.tier,'pro');
  assert.equal(res.body.user.tier_activated_by,'manual_payment');
  const ordered=x.calls.map(v=>v[0]==='set'?'set:'+v[1].split(':').slice(0,2).join(':'):v[0]);
  const position=name=>ordered.indexOf(name);
  assert(position('hmset')>=0);
  assert(position('hmset')<position('set:user:email'));
  assert(position('set:user:email')<position('set:user:id'));
  assert(position('set:user:id')<position('eval'));
  assert.equal(x.values.has(KEY),false);
  const record=x.calls.find(v=>v[0]==='hmset')[2];
  assert.equal(record.tier,'pro');
  assert.equal(record.subscriptionId,'disposable-payment');
});
test('P0 failed reverse lookup preserves paid tier for authorized registration retry',async()=>{
  const x=fixture({failLookup:true});
  const res=await x.register();
  assert.equal(res.statusCode,500);
  assert.equal(res.body.error.code,'REGISTRATION_FAILED');
  assert.equal(x.values.get(KEY),RAW);
  assert(!x.calls.some(c=>c[0]==='eval'));
});
test('P0 concurrent newer payment is never deleted by registration of older payment',async()=>{
  const x=fixture({newPaymentDuringWrite:true});
  const res=await x.register();
  assert.equal(res.statusCode,201);
  assert.equal(res.body.user.tier,'pro');
  assert.equal(JSON.parse(x.values.get(KEY)).tier,'enterprise');
  assert.equal(x.calls.filter(c=>c[0]==='eval').length,1);
});
test('P0 cleanup outage does not conceal a successfully created one-time API key',async()=>{
  const x=fixture({failCleanup:true});
  const res=await x.register();
  assert.equal(res.statusCode,201);
  assert.equal(res.body.api_key,'disposable_generated_key');
  assert.equal(x.values.get(KEY),RAW);
  assert.equal(x.calls.filter(c=>c[0]==='warn').length,1);
  assert(!JSON.stringify(x.calls.find(c=>c[0]==='warn')).includes('disposable-payment'));
});
test('P0 empty or invalid pending payment never triggers tier consumption',async()=>{
  const x=fixture({pendingValue:JSON.stringify({tier:'random-untrusted'})});
  const res=await x.register();
  assert.equal(res.statusCode,201);
  assert.equal(res.body.user.tier,'free');
  assert.equal(x.calls.filter(c=>c[0]==='eval').length,0);
});
test('atomic compare-delete rejects invalid input and ambiguous Redis receipts',async()=>{
  const redis={eval:async()=>null};
  await assert.rejects(pending.consumePendingTierAfterRegistration(redis,KEY,RAW),/SOC_PENDING_TIER_CLEANUP_UNVERIFIED_RECEIPT/);
  await assert.rejects(pending.consumePendingTierAfterRegistration(redis,'user:email:bad',RAW),/INVALID_ARGUMENT/);
  await assert.rejects(pending.consumePendingTierAfterRegistration(redis,KEY,''),/INVALID_ARGUMENT/);
});
