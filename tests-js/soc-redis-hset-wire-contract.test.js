'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
// Isolated Node --test file. Never uses real Upstash or Cloudflare credentials.
process.env.UPSTASH_REDIS_REST_URL = 'https://redis.invalid';
process.env.UPSTASH_REDIS_REST_TOKEN = 'UNIT_TEST_ONLY_NOT_A_SECRET';
const redis = require('../api/_lib/redis');
const {InvestigationManager} = require('../api/_lib/investigation-manager');

function fakeTransport(t) {
  const oldFetch = global.fetch;
  const calls = [];
  let failWrites = false;
  global.fetch = async url => {
    const parts = new URL(url).pathname.split('/').filter(Boolean).map(decodeURIComponent);
    calls.push(parts);
    if (failWrites && parts[0] === 'HSET') return {ok:false,status:503};
    return {ok:true,json:async()=>({result:1})};
  };
  t.after(()=>{global.fetch=oldFetch;});
  return {calls,fail:()=>{failWrites=true;}};
}
function hsets(calls) {return calls.filter(x=>x[0]==='HSET');}
function asFields(parts) {
  assert.equal(parts[0],'HSET');
  assert.equal(parts.length%2,0,'HSET+key+N alternating pairs expected');
  const raw=parts.slice(2),obj={};
  for(let i=0;i<raw.length;i+=2) obj[raw[i]]=raw[i+1];
  return obj;
}
test('P0: createInvestigation sends all investigation fields in one valid HSET',async t=>{
  const {calls}=fakeTransport(t);
  const manager=new InvestigationManager(redis,null,null);
  manager.recordInvestigationAudit=async()=>{};
  const investigation=await manager.createInvestigation('Title','Description','HIGH','alice',['ioc-1'],'analyst');
  const cmds=hsets(calls);
  assert.equal(cmds.length,1);
  assert.equal(cmds[0][1],'investigation:'+investigation.id);
  const fields=asFields(cmds[0]);
  assert.equal(fields.title,'Title');
  assert.equal(fields.assignee,'alice');
  assert.equal(fields.priority,'4');
  assert.equal(fields.status,'open');
  assert.equal(fields.version,'1');
  assert.deepEqual(JSON.parse(fields.linkedIntelligence),['ioc-1']);
  assert(!cmds[0].includes('undefined'));
  assert(calls.some(x=>x[0]==='EXPIRE'&&x[1]==='investigation:'+investigation.id));
  assert(calls.some(x=>x[0]==='ZADD'&&x[1]==='investigations:assigned:alice'));
});
test('P0: metadata-only update sends title, description, version and timestamp',async t=>{
  const {calls}=fakeTransport(t);
  const manager=new InvestigationManager(redis,null,null);
  manager.getInvestigation=async()=>({id:'inv1',assignee:'alice',priority:3,status:'open',version:1});
  manager.recordInvestigationAudit=async()=>{};
  const result=await manager.updateInvestigation('inv1',{title:'New title',description:'Text'});
  assert.equal(result.version,2);
  assert.equal(hsets(calls).length,1);
  const fields=asFields(hsets(calls)[0]);
  assert.equal(fields.title,'New title');
  assert.equal(fields.description,'Text');
  assert.equal(fields.version,'2');
  assert.match(fields.updatedAt,/^\d{4}-/);
  assert(!calls.some(x=>x[0]==='ZADD'||x[0]==='ZREM'));
});
test('P0: classic single-field HSET remains compatible; JSON values do not become object Object',async t=>{
  const {calls}=fakeTransport(t);
  await redis.hset('case:1','status','open');
  await redis.hset('case:1',['priority',3,'summary',{test:true},'labels',['a','b']]);
  assert.deepEqual(asFields(hsets(calls)[0]),{status:'open'});
  assert.deepEqual(asFields(hsets(calls)[1]),{
    priority:'3',summary:'{"test":true}',labels:'["a","b"]'
  });
});
test('P0: malformed or incomplete fields never reach Redis',t=>{
  const {calls}=fakeTransport(t);
  for(const args of [
    ['case',[]],['case',['title','x','version']],['case',['',1]],
    ['case',['title',undefined]],['case',['priority',NaN]],['case',42],
    ['case','title'],['case',['status','open'],'unexpected']
  ]) {
    assert.throws(()=>redis.hset(...args),/SOC_REDIS_HSET_INVALID_FIELDS/);
  }
  assert.deepEqual(calls,[]);
});
test('P0: HTTP failure stops create before expiry, indexes, and audit',async t=>{
  const {calls,fail}=fakeTransport(t);fail();
  const manager=new InvestigationManager(redis,null,null);
  manager.recordInvestigationAudit=async()=>{throw Error('AUDIT_NOT_ALLOWED');};
  await assert.rejects(manager.createInvestigation('T','D','HIGH','alice'),/Redis HTTP 503/);
  assert.deepEqual(calls.map(x=>x[0]),['HSET']);
});
