'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {InvestigationManager}=require('../api/_lib/investigation-manager');
const {atomicCreateInvestigation,CREATE_SCRIPT}=require('../api/_lib/investigation-create-atomic');

const AT=new Date('2026-11-11T00:20:00.000Z');
const BASE={
  id:'a'.repeat(32),title:'SOC investigation',description:'Verified event',
  priority:4,status:'open',assignee:'analyst_a',createdBy:'analyst_a',
  createdAt:AT.toISOString(),updatedAt:AT.toISOString(),
  linkedIntelligence:'["ioc-1"]',linkedEntities:'[]',
  caseCount:0,evidenceCount:0,noteCount:0,version:1
};
function fixture(result=['OK',BASE.id]){
  const calls=[];
  const redis={
    async eval(...args){calls.push(['eval',...args]);return result;},
    async hset(...args){calls.push(['hset',...args]);},
    async expire(...args){calls.push(['expire',...args]);},
    async zadd(...args){calls.push(['zadd',...args]);}
  };
  return {calls,redis};
}
test('P0 create stores record, TTL, all indexes and audit in one EVAL',async()=>{
  const {calls,redis}=fixture();
  const record=await atomicCreateInvestigation({redis,investigation:BASE,now:AT});
  assert.equal(record,BASE);
  assert.deepEqual(calls.map(x=>x[0]),['eval']);
  const [,script,keys,args]=calls[0];
  assert.equal(script,CREATE_SCRIPT);
  assert.deepEqual(keys,[
    'investigation:'+BASE.id,'investigations:all',
    'investigations:by:status:open','investigations:by:priority:4',
    'investigations:assigned:analyst_a','investigation:audit:'+BASE.id
  ]);
  const pairs=JSON.parse(args[0]);
  const fields=Object.fromEntries(Array.from({length:pairs.length/2},(_,i)=>[pairs[2*i],pairs[2*i+1]]));
  assert.equal(fields.id,BASE.id);
  assert.equal(fields.version,'1');
  assert.equal(fields.priority,'4');
  assert.deepEqual(JSON.parse(fields.linkedIntelligence),['ioc-1']);
  assert.equal(args[1],String(AT.getTime()));
  assert.equal(args[2],BASE.id);
  assert.equal(args[4],'1');
  assert.equal(JSON.parse(args[3]).actor,'analyst_a');
});

test('P0 create: unassigned index receives no writes',async()=>{
  const {redis,calls}=fixture();
  const data={...BASE,assignee:'unassigned'};
  await atomicCreateInvestigation({redis,investigation:data,now:AT});
  assert.equal(calls[0][3][4],'0');
});

test('P0 create: incomplete or untrusted payload is rejected before Redis',async()=>{
  for(const patch of [
    {id:'invalid'},{title:''},{title:'a'.repeat(4097)},
    {adminOverride:true},
    {description:null},{description:'d'.repeat(16385)},
    {assignee:'bad owner'},{createdBy:'bad owner'},
    {priority:0},{priority:9},{priority:'4'},{status:'closed'},
    {version:2},{caseCount:1},{linkedIntelligence:'not-json'},
    {linkedIntelligence:'[123]'},{linkedIntelligence:'["x"]'.repeat(101)},
    {linkedEntities:'["unapproved"]'}, {createdAt:'2099-01-01T00:00:00Z'}
  ]){
    const {redis,calls}=fixture();
    await assert.rejects(atomicCreateInvestigation({
      redis,investigation:{...BASE,...patch},now:AT
    }),/SOC_INVESTIGATION_CREATE_(INVALID_RECORD|INVALID_LINKS|INVALID_CLOCK)/);
    assert.deepEqual(calls,[]);
  }
});

test('P0 create: invalid Redis transport or EVAL receipt never claims success',async()=>{
  await assert.rejects(atomicCreateInvestigation({redis:{},investigation:BASE,now:AT}),
    /SOC_INVESTIGATION_CREATE_ATOMIC_REDIS_UNAVAILABLE/);
  for(const response of [null,{},['HOLD_RECORD_EXISTS'],['HOLD_INDEX_TYPE'],
    ['HOLD_INVALID_FIELDS'],['OK','other-id']]){
    const {redis,calls}=fixture(response);
    await assert.rejects(atomicCreateInvestigation({redis,investigation:BASE,now:AT}),
      /SOC_INVESTIGATION_CREATE_NOT_COMMITTED/);
    assert.equal(calls.length,1);
  }
  const {redis,calls}=fixture();
  redis.eval=async(...args)=>{calls.push(['eval',...args]);throw Error('EVAL_TIMEOUT');};
  await assert.rejects(atomicCreateInvestigation({redis,investigation:BASE,now:AT}),/EVAL_TIMEOUT/);
  assert.equal(calls.length,1,'do not auto-retry unknown commit');
});

test('P0 create: Lua preflights WRONGTYPE before any HSET/ZADD/EXPIRE',()=>{
  for(const marker of ["HOLD_RECORD_EXISTS","HOLD_INDEX_TYPE","HOLD_INVALID_FIELDS",
    "redis.call('HSET'","redis.call('EXPIRE'","redis.call('ZADD'","return {'OK',ARGV[3]}"]){
    assert(CREATE_SCRIPT.includes(marker),marker);
  }
  const firstWrite=CREATE_SCRIPT.indexOf("redis.call('HSET'");
  for(const marker of ['HOLD_RECORD_EXISTS','HOLD_INDEX_TYPE','HOLD_INVALID_FIELDS']){
    assert(CREATE_SCRIPT.indexOf(marker)<firstWrite,marker);
  }
  assert.equal((CREATE_SCRIPT.match(/redis\.call\('ZADD'/g)||[]).length,5,
    'global, status, priority, conditional owner and audit indexes');
});

test('P0 manager uses EVAL only; never separately indexes an uncommitted case',async()=>{
  const {redis,calls}=fixture(['OK',null]);
  redis.eval=async(script,keys,args)=>{calls.push(['eval',script,keys,args]);return ['OK',args[2]];};
  const manager=new InvestigationManager(redis,null,null);
  manager.recordInvestigationAudit=async()=>{throw Error('UNEXPECTED_SPLIT_AUDIT');};
  const record=await manager.createInvestigation('T','D','HIGH','analyst_a',['ioc-1'],'analyst_a');
  assert.equal(record.priority,4);
  assert.equal(record.status,'open');
  assert.deepEqual(calls.map(x=>x[0]),['eval']);
});
