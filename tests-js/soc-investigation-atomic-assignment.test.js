'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const cp=require('node:child_process');
const {InvestigationManager}=require('../api/_lib/investigation-manager');
const {atomicReassign,REASSIGN_SCRIPT}=require('../api/_lib/investigation-assignment-atomic');

const CASE={id:'inv1',assignee:'alice',status:'open',priority:3,version:4,title:'Before',description:'Current'};
const LEAD={id:'lead1',role:'lead_analyst'};
function fixture(){
  const calls=[];
  const redis={
    async hgetall(){calls.push(['hgetall']);return Object.entries(CASE).flat().map(String);},
    async hset(){calls.push(['hset']);},
    async zadd(){calls.push(['zadd']);},
    async zrem(){calls.push(['zrem']);},
    async eval(script,keys,args){calls.push(['eval',script,keys,args]);return ['OK','5'];}
  };
  const manager=new InvestigationManager(redis);
  manager.recordInvestigationAudit=async()=>{calls.push(['audit']);};
  return {redis,manager,calls};
}
test('reassignment: authenticated internal lead uses one atomic CAS instead of split writes',async()=>{
  const {manager,calls}=fixture();
  const result=await manager.updateInvestigation('inv1',{assignee:'bob',title:'After'},LEAD);
  assert.equal(result.assignee,'bob');
  assert.equal(result.title,'After');
  assert.equal(result.version,5);
  assert.deepEqual(calls.map(x=>x[0]),['hgetall','eval']);
  const [,script,keys,args]=calls[1];
  assert.equal(script,REASSIGN_SCRIPT);
  assert.deepEqual(keys,[
    'investigation:inv1','investigations:assigned:alice',
    'investigations:assigned:bob','investigation:audit:inv1'
  ]);
  assert.equal(args[0],'alice');
  assert.equal(args[1],'bob');
  assert.equal(args[2],'4');
  assert.equal(args[3],'open');
  assert.equal(args[6],'inv1');
  assert.equal(args[8],'1');
  assert.equal(args[9],'After');
  assert.equal(JSON.parse(args[10]).actor,'lead1');
});
test('no verified lead identity: all reassignment attempts fail before Redis EVAL',async()=>{
  for(const identity of [undefined,null,{}, {id:'analyst1',role:'analyst'},
    {id:'lead1',role:'unknown'},{id:'lead1',role:'customer_admin'}]){
    const {manager,calls}=fixture();
    await assert.rejects(manager.updateInvestigation('inv1',{assignee:'bob'},identity),
      /SOC_INVESTIGATION_REASSIGNMENT_NOT_READY/);
    assert.deepEqual(calls.map(x=>x[0]),['hgetall']);
  }
});
test('unchanged assignments keep existing metadata update and audit; no EVAL',async()=>{
  const {manager,calls}=fixture();
  const out=await manager.updateInvestigation('inv1',{assignee:'alice',title:'Safe'},LEAD);
  assert.equal(out.title,'Safe');
  assert.deepEqual(calls.map(x=>x[0]),['hgetall','hset','audit']);
});
test('invalid owner, terminal record or malformed metadata fail before atomic command',async()=>{
  for(const [recordPatch,updates] of [
    [{status:'closed'},{assignee:'bob'}],
    [{status:'archived'},{assignee:'bob'}],
    [{assignee:'bad owner'},{assignee:'bob'}],
    [{},{assignee:'bad owner'}],
    [{version:NaN},{assignee:'bob'}],
    [{},{assignee:'bob',description:42}],
    [{},{assignee:'bob',title:'x'.repeat(4097)}]
  ]){
    const {redis,calls}=fixture();
    const source={...CASE,...recordPatch};
    await assert.rejects(atomicReassign({redis,investigation:source,updates,caller:LEAD}));
    assert.deepEqual(calls,[]);
  }
});
test('missing EVAL transport and indeterminate CAS reply fail closed',async()=>{
  const source={...CASE};
  await assert.rejects(atomicReassign({redis:{},investigation:source,
    updates:{assignee:'bob'},caller:LEAD}),/SOC_INVESTIGATION_ATOMIC_REDIS_NOT_AVAILABLE/);
  for(const v of [['HOLD_STALE_RECORD'],['HOLD_INDEX_TYPE'],null,{},['OK','4']]){
    const {manager,redis,calls}=fixture();
    redis.eval=async(...args)=>{calls.push(['eval',...args]);return v;};
    await assert.rejects(manager.updateInvestigation('inv1',{assignee:'bob'},LEAD),
      /SOC_INVESTIGATION_ATOMIC_REASSIGNMENT_NOT_COMMITTED/);
    assert.deepEqual(calls.map(x=>x[0]),['hgetall','eval']);
  }
});
test('status and priority remain independently fail closed even in lead reassignment',async()=>{
  for(const changes of [{assignee:'bob',status:'closed'},{assignee:'bob',priority:'CRITICAL'}]){
    const {manager,calls}=fixture();
    await assert.rejects(manager.updateInvestigation('inv1',changes,LEAD),
      /SOC_INVESTIGATION_(STATUS|PRIORITY)_TRANSITION_NOT_READY/);
    assert.deepEqual(calls.map(x=>x[0]),['hgetall']);
  }
});
test('Lua source compares current record state and validates types before all writes',()=>{
  for(const marker of [
    "HMGET", "ARGV[1]", "ARGV[3]", "ARGV[4]",
    "HOLD_STALE_RECORD", "HOLD_TERMINAL_CASE", "HOLD_INDEX_TYPE",
    "redis.call('HSET'", "redis.call('ZREM'", "redis.call('ZADD'",
    "KEYS[4]", "return {'OK', ARGV[6]}"
  ]) assert(REASSIGN_SCRIPT.includes(marker),marker);
  const firstWrite=REASSIGN_SCRIPT.indexOf("redis.call('HSET'");
  assert(REASSIGN_SCRIPT.indexOf('HOLD_INDEX_TYPE')<firstWrite);
  assert(REASSIGN_SCRIPT.indexOf('HOLD_STALE_RECORD')<firstWrite);
});
test('Upstash REST EVAL transport uses POST JSON and rejects server errors',()=>{
  const script=[
    "process.env.UPSTASH_REDIS_REST_URL='https://test.invalid';",
    "process.env.UPSTASH_REDIS_REST_TOKEN='fake-private-test-token';",
    "global.fetch=async (u,o)=>{",
    " const b=JSON.parse(o.body);",
    " if (u!=='https://test.invalid'||o.method!=='POST'||b[0]!=='EVAL'||b[2]!=='1'||b[3]!=='record'||b[4]!=='value') throw Error('BAD_REQUEST');",
    " return {ok:true,json:async()=>({result:['OK','5']})};",
    "};",
    "require('./api/_lib/redis').eval('return ARGV[1]',['record'],['value']).then(v=>{if(v[0]!=='OK')throw Error('BAD_RESULT')}).catch(e=>{console.error(e);process.exitCode=1});"
  ].join('\n');
  const r=cp.spawnSync(process.execPath,['-e',script],{cwd:path.join(__dirname,'..'),encoding:'utf8',timeout:7000});
  assert.equal(r.status,0,r.stderr||r.error?.message);
  const source=fs.readFileSync(path.join(__dirname,'..','api/_lib/redis.js'),'utf8');
  assert.match(source,/Redis EVAL HTTP/);
  assert.match(source,/SOC_REDIS_EVAL_SERVER_REJECTED/);
});
test('route supplies the authenticated server caller, not a request body role',()=>{
  const s=fs.readFileSync(path.join(__dirname,'..','api/v1/workbench/investigations.js'),'utf8');
  assert.match(s,/const caller = await requireAnalyst\(req, res, fail\)/);
  assert.match(s,/updateInvestigation\(id, body, caller\)/);
  assert.doesNotMatch(s,/updateInvestigation\(id,\s*body,\s*body\./);
});
