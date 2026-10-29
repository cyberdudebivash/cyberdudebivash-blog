'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const {buildSnapshot,encryptSnapshot,decryptSnapshot,fetchAll,
  normalizeHashRecord,normalizeAuditLog}=require('../scripts/backup-customer-data');
const {applySnapshot,validateSnapshot}=require('../scripts/restore-customer-data');
const KEY='a'.repeat(64);
const CREATED='2026-10-29T10:00:00.000Z';
function log() {const calls=[];return {
 calls,
 hmset:async(...xs)=>{calls.push(['hmset',...xs]);return 1;},
 set:async(...xs)=>{calls.push(['set',...xs]);return 'OK';},
 zadd:async(...xs)=>{calls.push(['zadd',...xs]);return 1;}
};}
function snapshot(change={}){
 return {...buildSnapshot({hashes:{'user:key:uid-1':{email:'u@example.com',tier:'pro'}},
 strings:{'user:id:uid-1':'uid-1','user:email:u@example.com':'uid-1'},
 auditLog:[['{"event":"PAYMENT"}','1700000000123']]}),createdAt:CREATED,...change};
}
test('native HGETALL and ZREVRANGE WITHSCORES flat arrays normalize to exact fields/pairs',async()=>{
 const redis={
  keys:async pattern=>pattern==='user:key:*'?['user:key:uid-1']:[],
  hgetall:async key=>{assert.equal(key,'user:key:uid-1');return ['email','u@example.com','tier','pro'];},
  get:async()=>null,
  zrevrange:async(key,start,stop,scores)=>{
   assert.deepEqual([key,start,stop,scores],['audit:payment:log',0,-1,true]);
   return ['{"event":"PAYMENT"}','1700000000123','{"event":"REFUND"}','1700000000456'];
  }
 };
 const data=await fetchAll(redis);
 assert.deepEqual(data.hashes['user:key:uid-1'],{email:'u@example.com',tier:'pro'});
 assert.deepEqual(data.auditLog,[
  ['{"event":"PAYMENT"}','1700000000123'],
  ['{"event":"REFUND"}','1700000000456']
 ]);
});
test('historical v1 flattened hash and audit arrays can decrypt and restore without numeric hash keys',async()=>{
 const old=snapshot({
   hashes:{'user:key:uid-1':['email','u@example.com','tier','pro']},
   auditLog:['{"event":"PAYMENT"}','1700000000123']
 });
 const encrypted=encryptSnapshot(old,KEY);
 const recovered=decryptSnapshot(encrypted,KEY);
 const redis=log();
 const result=await applySnapshot(redis,recovered);
 assert.deepEqual(result,{hashesWritten:1,stringsWritten:2,auditEntriesWritten:1});
 const h=redis.calls.find(x=>x[0]==='hmset');
 assert.deepEqual(h,['hmset','user:key:uid-1',{email:'u@example.com',tier:'pro'}]);
 assert(!Object.keys(h[2]).some(k=>k==='0'||k==='1'));
 assert.deepEqual(redis.calls.filter(x=>x[0]==='zadd'),
   [['zadd','audit:payment:log',1700000000123,'{"event":"PAYMENT"}']]);
});
test('backup audit log provider failure propagates and cannot be represented as an empty log',async()=>{
 const redis={keys:async()=>[],zrevrange:async()=>{throw Error('AUDIT_READ_FAILED');}};
 await assert.rejects(fetchAll(redis),/AUDIT_READ_FAILED/);
});
test('missing, odd, duplicate and malformed native HGETALL fields fail closed',()=>{
 for(const raw of [null,[],['only'],['name','a','name','b'],['name',null],
   ['','value'],{valid:'value',bad:42}]){
  assert.throws(()=>normalizeHashRecord(raw),/SOC_BACKUP_INVALID_HASH_RESPONSE/);
 }
});
test('malformed audit score, shape, and missing member fail closed',()=>{
 for(const raw of [null,['only'],[['member']],['member','not-a-score'],
  [['',1]],[['m1',Infinity]],['m1',1,['m2',2]]]){
  assert.throws(()=>normalizeAuditLog(raw),/SOC_BACKUP_INVALID_AUDIT_RESPONSE/);
 }
});
test('restore validates entire schema and scope before first write, even if an early entry is valid',async()=>{
 for(const bad of [
  snapshot({schemaVersion:2}),
  snapshot({hashes:{'user:key:uid-1':{email:'safe'},'admin:secret':{key:'bad'}}}),
  snapshot({strings:{'user:email:u@example.com':'uid-1','payment:intent:123':'override'}}),
  snapshot({hashes:{'user:key:uid-1':['email','a','tier']}}),
  snapshot({auditLog:[['PAYMENT','invalid-score']]}),
  snapshot({auditLog:null}),
  snapshot({strings:{'user:id:uid-1':1}})
 ]){
  const redis=log();
  await assert.rejects(applySnapshot(redis,bad));
  assert.deepEqual(redis.calls,[]);
 }
});
test('empty payment audit trail is allowed only after successful readable result; nullable Redis strings skipped',async()=>{
 const redis=log();
 const ss=snapshot({strings:{'user:email:u@example.com':null},auditLog:[]});
 const result=await applySnapshot(redis,ss);
 assert.deepEqual(result,{hashesWritten:1,stringsWritten:0,auditEntriesWritten:0});
 assert.deepEqual(redis.calls.map(x=>x[0]),['hmset']);
});
test('payment audit entries replay with original scores and preserve order without duplicate-adding writes',async()=>{
 const redis=log();
 const result=await applySnapshot(redis,snapshot({auditLog:[
  ['entry-1','1700000000000'],['entry-2','1700000000001']
 ]}));
 assert.equal(result.auditEntriesWritten,2);
 assert.deepEqual(redis.calls.filter(x=>x[0]==='zadd'),[
  ['zadd','audit:payment:log',1700000000000,'entry-1'],
  ['zadd','audit:payment:log',1700000000001,'entry-2']
 ]);
});
test('restore CLI dry run verifies historical snapshot without Redis credentials or writes',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'cdb-soc-restore-'));
 try{
  const loc=path.join(root,'disposable.enc');
  fs.writeFileSync(loc,encryptSnapshot(snapshot({hashes:{
    'user:key:uid-1':['email','u@example.com','tier','pro']
  }}),KEY),'utf8');
  const r=spawnSync(process.execPath,['scripts/restore-customer-data.js',loc],{
    cwd:path.join(__dirname,'..'),encoding:'utf8',timeout:10000,
    env:{PATH:process.env.PATH,HOME:root,BACKUP_ENCRYPTION_KEY:KEY}
  });
  assert.equal(r.status,0,r.stderr);
  assert.match(r.stdout,/Dry run only/);
  assert.match(r.stdout,/1 audit entries/);
  assert.doesNotMatch(r.stdout,/Wrote .* into Redis/);
 }finally{fs.rmSync(root,{force:true,recursive:true});}
});
