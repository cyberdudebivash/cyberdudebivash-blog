'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { InvestigationManager } = require('../api/_lib/investigation-manager');

function fixture() {
  const writes = [];
  const redis = {
    async hgetall() {
      return ['id','inv-1','assignee','alice','title','Original','status','open',
        'priority','3','version','1'];
    },
    async hset(...args) { writes.push(['hset',...args]); return 1; },
    async zadd(...args) { writes.push(['zadd',...args]); return 1; },
    async zrem(...args) { writes.push(['zrem',...args]); return 1; },
  };
  const manager = new InvestigationManager(redis);
  manager.recordInvestigationAudit = async () => { writes.push(['audit']); };
  return { manager, writes };
}

test('P0 #462: changed status fails before all Redis writes', async () => {
  const { manager, writes } = fixture();
  await assert.rejects(
    manager.updateInvestigation('inv-1',{ status:'in_progress',title:'Must not persist' }),
    /SOC_INVESTIGATION_STATUS_TRANSITION_NOT_READY/
  );
  assert.deepEqual(writes, []);
});

test('P0 #462: changed priority fails before all Redis writes', async () => {
  const { manager, writes } = fixture();
  await assert.rejects(
    manager.updateInvestigation('inv-1',{ priority:'CRITICAL',title:'Must not persist' }),
    /SOC_INVESTIGATION_PRIORITY_TRANSITION_NOT_READY/
  );
  assert.deepEqual(writes, []);
});

test('P0 #462: status and priority unchanged permit title update', async () => {
  const { manager, writes } = fixture();
  const record = await manager.updateInvestigation('inv-1',{
    status:'open',priority:'MEDIUM',title:'Permitted'
  });
  assert.equal(record.title,'Permitted');
  assert.equal(writes.filter(x=>x[0]==='hset').length,1);
  assert.equal(writes.filter(x=>x[0]==='audit').length,1);
  assert.equal(writes.filter(x=>x[0]==='zadd'||x[0]==='zrem').length,0);
});

test('P0 #462: title-only update remains permitted', async () => {
  const { manager, writes } = fixture();
  const record = await manager.updateInvestigation('inv-1',{title:'Renamed'});
  assert.equal(record.title,'Renamed');
  assert.equal(writes.filter(x=>x[0]==='hset').length,1);
});

test('P0 #455: existing owner transfer guard stays effective', async () => {
  const { manager, writes } = fixture();
  await assert.rejects(manager.updateInvestigation('inv-1',{assignee:'bob'}),
    /SOC_INVESTIGATION_REASSIGNMENT_NOT_READY/);
  assert.deepEqual(writes,[]);
});
