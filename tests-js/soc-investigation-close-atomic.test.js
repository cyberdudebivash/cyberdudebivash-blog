'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {InvestigationManager}=require('../api/_lib/investigation-manager');
const {atomicCloseInvestigation,CLOSE_INVESTIGATION_SCRIPT}=require('../api/_lib/investigation-closure-atomic');

const RECORD={id:'inv-1',assignee:'alice',status:'in_progress',version:5,priority:3};
const LEAD={id:'lead-1',role:'lead_analyst'};
const DATE=new Date('2026-10-29T13:45:00.000Z');
function fixture(){
  const calls=[];
  const redis={
    hgetall:async()=>{calls.push(['hgetall']);return Object.entries(RECORD).flat().map(String);},
    hset:async()=>{calls.push(['hset']);},
    zadd:async()=>{calls.push(['zadd']);},
    zrem:async()=>{calls.push(['zrem']);},
    eval:async(...args)=>{calls.push(['eval',...args]);return ['OK','6'];}
  };
  const manager=new InvestigationManager(redis,null,null);
  manager.recordInvestigationAudit=async()=>{calls.push(['audit']);};
  return {calls,redis,manager};
}
test('P0 close: verified lead uses a single atomic compare-and-swap; no separate writes',async()=>{
  const {calls,redis}=fixture();
  const out=await atomicCloseInvestigation({
    redis,investigation:RECORD,closureReason:'Containment complete',
    recommendations:['Rotate exposed token'],caller:LEAD,now:DATE
  });
  assert.deepEqual(out,{closed:true,investigationId:'inv-1',version:6,
    closedAt:'2026-10-29T13:45:00.000Z'});
  assert.deepEqual(calls.map(x=>x[0]),['eval']);
  const [,script,keys,args]=calls[0];
  assert.equal(script,CLOSE_INVESTIGATION_SCRIPT);
  assert.deepEqual(keys,[
    'investigation:inv-1','investigations:by:status:in_progress',
    'investigations:by:status:closed','investigation:audit:inv-1'
  ]);
  assert.deepEqual(args.slice(0,8),[
    'in_progress','5','alice','2026-10-29T13:45:00.000Z',
    'Containment complete','["Rotate exposed token"]','6','inv-1'
  ]);
  assert.equal(JSON.parse(args[9]).actor,'lead-1');
  assert.equal(JSON.parse(args[9]).version,6);
});
test('P0 close: missing or untrusted caller denied before any record read or Redis write',async()=>{
  for(const who of [undefined,null,{}, {id:'bob',role:'analyst'},
    {id:'customer',role:'customer_admin'},{id:'bad id',role:'soc_admin'}]){
    const {calls,manager,redis}=fixture();
    await assert.rejects(manager.closeInvestigation('inv-1','Closed',[],who),
      /SOC_INVESTIGATION_CLOSE_AUTHORIZATION_REQUIRED/);
    assert.deepEqual(calls,[]);
    await assert.rejects(atomicCloseInvestigation({
      redis,investigation:RECORD,closureReason:'Closed',caller:who,now:DATE}),
      /SOC_INVESTIGATION_CLOSE_AUTHORIZATION_REQUIRED/);
    assert.deepEqual(calls,[]);
  }
});
test('P0 close: manager passes verified caller but performs no independent hset/index writes',async()=>{
  const {calls,manager}=fixture();
  manager.getInvestigation=async id=>{
    calls.push(['get',id]);return {...RECORD};
  };
  const out=await manager.closeInvestigation('inv-1','Finished',[],LEAD);
  assert.equal(out.closed,true);
  assert.deepEqual(calls.map(x=>x[0]),['get','eval']);
});
test('P0 close: invalid terminal or incomplete records fail before any EVAL',async()=>{
  for(const patch of [
    {status:'closed'},{status:'archived'},{status:'bad'},{version:NaN},
    {version:0},{version:Number.MAX_SAFE_INTEGER},{assignee:'bad owner'},
    {id:'bad id'}]){
    const {calls,redis}=fixture();
    await assert.rejects(atomicCloseInvestigation({redis,investigation:{...RECORD,...patch},
      closureReason:'Finished',caller:LEAD,now:DATE}),/SOC_INVESTIGATION_CLOSE_INVALID_RECORD/);
    assert.deepEqual(calls,[]);
  }
});
test('P0 close: invalid reason or recommendations fail before any Redis mutation',async()=>{
  for(const [reason,recommendations] of [
    ['',[]],['   ',[]],[null,[]],['x'.repeat(2049),[]],
    ['Fine',{}],['Fine',Array(65).fill('ok')],
    ['Fine',[null]],['Fine',['']],['Fine',['x'.repeat(4097)]]
  ]){
    const {calls,redis}=fixture();
    await assert.rejects(atomicCloseInvestigation({redis,investigation:RECORD,
      closureReason:reason,recommendations,caller:LEAD,now:DATE}));
    assert.deepEqual(calls,[]);
  }
});
test('P0 close: stale CAS, wrongtype and indeterminate replies never claim success',async()=>{
  for(const result of [null,{},['HOLD_STALE_RECORD'],['HOLD_INDEX_TYPE'],
    ['HOLD_INCOMPLETE_RECORD'],['HOLD_TERMINAL_RECORD'],['OK','5']]){
    const {calls,redis}=fixture();
    redis.eval=async(...args)=>{calls.push(['eval',...args]);return result;};
    await assert.rejects(atomicCloseInvestigation({redis,investigation:RECORD,
      closureReason:'Finished',caller:LEAD,now:DATE}),
      /SOC_INVESTIGATION_CLOSE_NOT_COMMITTED/);
    assert.deepEqual(calls.map(x=>x[0]),['eval']);
  }
});
test('P0 close: no EVAL transport and invalid clock fail closed',async()=>{
  const {redis,calls}=fixture();
  await assert.rejects(atomicCloseInvestigation({redis:{},
    investigation:RECORD,closureReason:'Finished',caller:LEAD,now:DATE}),
    /SOC_INVESTIGATION_CLOSE_ATOMIC_REDIS_UNAVAILABLE/);
  await assert.rejects(atomicCloseInvestigation({redis,
    investigation:RECORD,closureReason:'Finished',caller:LEAD,now:new Date(NaN)}),
    /SOC_INVESTIGATION_CLOSE_INVALID_TIME/);
  assert.deepEqual(calls,[]);
});
test('P0 close: type and CAS checks precede all Lua HSET/index/audit mutations',()=>{
  for(const token of ["HOLD_RECORD_TYPE","HOLD_INDEX_TYPE","HOLD_STALE_RECORD",
    "HMGET","redis.call('HSET'","redis.call('ZREM'",
    "redis.call('ZADD',KEYS[3]","redis.call('ZADD',KEYS[4]","return {'OK',ARGV[7]}"]){
    assert(CLOSE_INVESTIGATION_SCRIPT.includes(token),token);
  }
  const firstMutation=CLOSE_INVESTIGATION_SCRIPT.indexOf("redis.call('HSET'");
  for(const token of ["HOLD_RECORD_TYPE","HOLD_INDEX_TYPE","HOLD_STALE_RECORD"]){
    assert(CLOSE_INVESTIGATION_SCRIPT.indexOf(token)<firstMutation,token);
  }
});
test('P0 close: existing metadata-only edits retain old behavior and status/priority fail closed',async()=>{
  const {manager,calls}=fixture();
  await assert.rejects(manager.updateInvestigation('inv-1',{status:'closed'},LEAD),
    /SOC_INVESTIGATION_STATUS_TRANSITION_NOT_READY/);
  await assert.rejects(manager.updateInvestigation('inv-1',{priority:'CRITICAL'},LEAD),
    /SOC_INVESTIGATION_PRIORITY_TRANSITION_NOT_READY/);
  assert.equal(calls.filter(x=>['hset','zadd','zrem','eval'].includes(x[0])).length,0);
});
