'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { InvestigationManager } = require('../api/_lib/investigation-manager');

function fixture() {
  const reads = [], writes = [];
  const records = {
    root: {id:'root',assignee:'alice',status:'open',linkedIntelligence:'["ioc-1"]'},
    good: {id:'good',assignee:'alice',status:'open',linkedIntelligence:'[]'},
    closed: {id:'closed',assignee:'alice',status:'closed',linkedIntelligence:'[]'},
    otherOwner: {id:'otherOwner',assignee:'bob',status:'open',linkedIntelligence:'[]'}
  };
  const redis = {
    hgetall: async key => {
      reads.push(['hgetall',key]);
      const x=records[key.slice('investigation:'.length)];
      return x ? Object.entries({...x,priority:'3',version:'1'}).flat() : [];
    },
    zrange: async (...args) => {
      reads.push(['zrange',...args]);
      assert.equal(args[0],'intelligence:in:investigations:ioc-1');
      return ['root','good','otherOwner','closed','good'];
    },
    hset: async (...args) => {writes.push(['hset',...args]);},
    zadd: async (...args) => {writes.push(['zadd',...args]);},
    zrem: async (...args) => {writes.push(['zrem',...args]);}
  };
  return {manager:new InvestigationManager(redis),reads,writes,records};
}

test('P0: no implicit global owner scope and no Redis operations for missing scope',async()=>{
  const {manager,reads,writes}=fixture();
  for(const value of [undefined,{},null,[],{assignee:''},{assignee:'unassigned'}]){
    await assert.rejects(manager.getRelatedInvestigations('root',20,value),
      /SOC_RELATED_INVESTIGATION_OWNER_SCOPE_REQUIRED/);
  }
  assert.deepEqual(reads,[]);
  assert.deepEqual(writes,[]);
});

test('P0: requested owner must also own the source investigation, before related lookups',async()=>{
  const {manager,reads,writes}=fixture();
  await assert.rejects(manager.getRelatedInvestigations('root',20,{assignee:'bob'}),
    /SOC_RELATED_INVESTIGATION_OWNER_SCOPE_MISMATCH/);
  assert.deepEqual(reads,[['hgetall','investigation:root']]);
  assert.deepEqual(writes,[]);
});

test('P0: only current owner records returned, duplicates removed and root excluded',async()=>{
  const {manager,writes}=fixture();
  const out=await manager.getRelatedInvestigations('root',20,{assignee:'alice'});
  assert.deepEqual(out.map(x=>x.id),['good','closed']);
  assert.deepEqual(writes,[]);
});

test('P0: status filter is ANDed with current owner, never a global fallback',async()=>{
  const {manager,writes}=fixture();
  const out=await manager.getRelatedInvestigations('root',20,
    {assignee:'alice',status:'closed'});
  assert.deepEqual(out.map(x=>x.id),['closed']);
  assert.deepEqual(writes,[]);
});

test('P0: malformed status and unbounded limits fail before Redis reads',async()=>{
  const {manager,reads,writes}=fixture();
  for(const lim of [0,-1,51,Infinity,NaN,1.5,'20']){
    await assert.rejects(manager.getRelatedInvestigations('root',lim,{assignee:'alice'}),
      /SOC_RELATED_INVESTIGATION_LIMIT_INVALID/);
  }
  await assert.rejects(manager.getRelatedInvestigations('root',20,{assignee:'alice',status:'NOT_REAL'}),
    /SOC_RELATED_INVESTIGATION_STATUS_INVALID/);
  assert.deepEqual(reads,[]);
  assert.deepEqual(writes,[]);
});

test('P0: missing source case fails closed before querying related index',async()=>{
  const {manager,reads,writes}=fixture();
  await assert.rejects(manager.getRelatedInvestigations('missing',20,{assignee:'alice'}),
    /Investigation not found/);
  assert.deepEqual(reads,[['hgetall','investigation:missing']]);
  assert.deepEqual(writes,[]);
});

test('P0: existing reassignment and status/priority transition guards remain active',async()=>{
  const {manager,writes}=fixture();
  await assert.rejects(manager.updateInvestigation('root',{assignee:'bob'}),
    /SOC_INVESTIGATION_REASSIGNMENT_NOT_READY/);
  await assert.rejects(manager.updateInvestigation('root',{status:'closed'}),
    /SOC_INVESTIGATION_STATUS_TRANSITION_NOT_READY/);
  await assert.rejects(manager.updateInvestigation('root',{priority:'CRITICAL'}),
    /SOC_INVESTIGATION_PRIORITY_TRANSITION_NOT_READY/);
  assert.deepEqual(writes,[]);
});
