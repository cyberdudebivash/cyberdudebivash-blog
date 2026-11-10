'use strict';
const {atomicCreateInvestigation,CREATE_SCRIPT}=require('../investigation-create-atomic');

const now=new Date('2026-11-11T00:20:00.000Z');
const record=Object.freeze({
  id:'a'.repeat(32),title:'Test case',description:'Observed event',
  priority:4,status:'open',assignee:'analyst_a',createdBy:'analyst_a',
  createdAt:now.toISOString(),updatedAt:now.toISOString(),
  linkedIntelligence:'[]',linkedEntities:'[]',
  caseCount:0,evidenceCount:0,noteCount:0,version:1
});

test('P0 customer SOC worklist create is a single atomic Redis EVAL',async()=>{
  const calls=[];
  const redis={eval:async(script,keys,args)=>{calls.push([script,keys,args]);return ['OK',args[2]];}};
  const result=await atomicCreateInvestigation({redis,investigation:record,now});
  expect(result.id).toBe(record.id);
  expect(calls).toHaveLength(1);
  expect(calls[0][0]).toBe(CREATE_SCRIPT);
  expect(calls[0][1]).toEqual([
    'investigation:'+record.id,'investigations:all',
    'investigations:by:status:open','investigations:by:priority:4',
    'investigations:assigned:analyst_a','investigation:audit:'+record.id
  ]);
  expect(JSON.parse(calls[0][2][0])).toContain('title');
});

test('P0 creation fails closed on stale or ambiguous Redis reply',async()=>{
  for(const answer of [null,{},['HOLD_INDEX_TYPE'],['HOLD_RECORD_EXISTS'],['OK','not-the-id']]){
    const redis={eval:async()=>answer};
    await expect(atomicCreateInvestigation({redis,investigation:record,now}))
      .rejects.toThrow('SOC_INVESTIGATION_CREATE_NOT_COMMITTED');
  }
});

test('P0 creation rejects invalid record before touching Redis',async()=>{
  const evalFn=jest.fn(async()=>['OK',record.id]);
  for(const patch of [{title:''},{assignee:'client forged owner'},{status:'closed'},{priority:0},{adminOverride:true}]){
    await expect(atomicCreateInvestigation({
      redis:{eval:evalFn},investigation:{...record,...patch},now
    })).rejects.toThrow('SOC_INVESTIGATION_CREATE_INVALID_RECORD');
  }
  expect(evalFn).not.toHaveBeenCalled();
});

test('P0 Lua guards all keys before the first mutation',()=>{
  const firstWrite=CREATE_SCRIPT.indexOf("redis.call('HSET'");
  expect(firstWrite).toBeGreaterThan(0);
  for(const check of ['HOLD_RECORD_EXISTS','HOLD_INDEX_TYPE','HOLD_INVALID_FIELDS']){
    expect(CREATE_SCRIPT.indexOf(check)).toBeLessThan(firstWrite);
  }
  expect(CREATE_SCRIPT).toContain("redis.call('EXPIRE'");
  expect(CREATE_SCRIPT).toContain("redis.call('ZADD',KEYS[6]");
});
