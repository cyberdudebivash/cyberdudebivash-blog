'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {
  buildSnapshot,fetchAll,encryptSnapshot,decryptSnapshot,
  MAX_PENDING_TIER_TTL_SECONDS
}=require('../scripts/backup-customer-data');
const {validateSnapshot,applySnapshot}=require('../scripts/restore-customer-data');
const PENDING='user:pending:tier:disposable_example.com';
const RAW=JSON.stringify({tier:'pro',transactionId:'synthetic-payment-id'});
const KEY='a'.repeat(64);
function backupRedis({seconds=90*86400}={}){
  const calls=[];
  return {calls,
    keys:async p=>{calls.push(['keys',p]);return p==='user:pending:tier:*'?[PENDING]:[];},
    get:async key=>{calls.push(['get',key]);return RAW;},
    ttl:async key=>{calls.push(['ttl',key]);return seconds;},
    hgetall:async()=>{throw Error('NO_HASH_EXPECTED');},
    zrevrange:async()=>[]
  };
}
function target(){
  const calls=[];
  return {calls,
    hmset:async(...xs)=>{calls.push(['hmset',...xs]);return 'OK';},
    set:async(...xs)=>{calls.push(['set',...xs]);return 'OK';},
    setex:async(...xs)=>{calls.push(['setex',...xs]);return 'OK';},
    zadd:async(...xs)=>{calls.push(['zadd',...xs]);return 1;}
  };
}
const snapshot=({expiry,createdAt}={})=>{
  const ss=buildSnapshot({hashes:{},strings:{[PENDING]:RAW},auditLog:[],
    ...(expiry!==undefined?{pendingTierExpiry:{[PENDING]:expiry}}:{})});
  if(createdAt)ss.createdAt=createdAt;
  return ss;
};
test('backup captures original short-lived pending-paid entitlement expiration, not timeless value',async()=>{
  const fake=backupRedis({seconds:600});
  const before=Date.now();
  const data=await fetchAll(fake);
  const after=Date.now();
  const exp=Date.parse(data.pendingTierExpiry[PENDING]);
  assert(exp>=before+600000 && exp<=after+600000);
  assert.equal(data.strings[PENDING],RAW);
  assert.equal(fake.calls.filter(c=>c[0]==='ttl').length,1);
  const ss=buildSnapshot(data);
  const restored=decryptSnapshot(encryptSnapshot(ss,KEY),KEY);
  assert.equal(restored.pendingTierExpiry[PENDING],ss.pendingTierExpiry[PENDING]);
});
test('backup refuses absent, negative, zero, noninteger or overlong Redis TTL evidence',async()=>{
  for(const seconds of [-2,-1,0,null,'100',1.25,MAX_PENDING_TIER_TTL_SECONDS+1]){
    await assert.rejects(fetchAll(backupRedis({seconds})),/SOC_BACKUP_PENDING_TIER_TTL_UNVERIFIED/);
  }
});
test('legacy encrypted snapshot with pending entitlement but no original expiry fails before ANY restore write',async()=>{
  const legacy=snapshot();delete legacy.pendingTierExpiry;
  assert.throws(()=>validateSnapshot(legacy),/SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED/);
  const redis=target();
  await assert.rejects(applySnapshot(redis,legacy),/SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED/);
  assert.equal(redis.calls.length,0);
});
test('valid payment pending snapshot restores via SETEX with REMAINING TTL, never plain SET',async()=>{
  const expiresAt=new Date(Date.now()+200000).toISOString();
  const ss=snapshot({expiry:expiresAt});
  assert.deepEqual(validateSnapshot(ss).strings,[[PENDING,RAW,Date.parse(expiresAt)]]);
  const redis=target();
  const result=await applySnapshot(redis,ss);
  assert.deepEqual(result,{hashesWritten:0,stringsWritten:1,auditEntriesWritten:0});
  assert.equal(redis.calls.length,1);
  assert.equal(redis.calls[0][0],'setex');
  assert.equal(redis.calls[0][1],PENDING);
  assert(redis.calls[0][2]>0 && redis.calls[0][2]<=200);
  assert.equal(redis.calls[0][3],RAW);
});
test('expired pending payment is skipped; nonpending customer lookup remains recoverable',async()=>{
  const expired=new Date(Date.now()-2000).toISOString();
  const ss=snapshot({expiry:expired});
  ss.strings['user:id:disposable']='disposable-key-hash';
  const redis=target();
  const result=await applySnapshot(redis,ss);
  assert.deepEqual(result,{hashesWritten:0,stringsWritten:1,auditEntriesWritten:0,expiredPendingTiers:1});
  assert.deepEqual(redis.calls,[['set','user:id:disposable','disposable-key-hash']]);
});
test('untrusted expiry extension and unrelated expiry metadata are rejected before writes',async()=>{
  const ss=snapshot({expiry:new Date(Date.now()+95*86400*1000).toISOString()});
  await assert.rejects(applySnapshot(target(),ss),/SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED/);
  const wrong=snapshot({expiry:new Date(Date.now()+180000).toISOString()});
  wrong.pendingTierExpiry['user:email:intruder']='2099-01-01T00:00:00.000Z';
  await assert.rejects(applySnapshot(target(),wrong),/SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED/);
  const malformed=snapshot({expiry:'tomorrow'});
  await assert.rejects(applySnapshot(target(),malformed),/SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED/);
});
test('tampered type or absent native TTL does not certify an encrypted customer recovery',async()=>{
  const noTtl=backupRedis();
  noTtl.ttl=undefined;
  await assert.rejects(fetchAll(noTtl),/redis\.ttl is not a function/);
  const malformed=snapshot({expiry:new Date(Date.now()+200000).toISOString()});
  malformed.pendingTierExpiry=[];
  await assert.rejects(applySnapshot(target(),malformed),/SOC_RESTORE_PENDING_TIER_TTL_UNVERIFIED/);
});
