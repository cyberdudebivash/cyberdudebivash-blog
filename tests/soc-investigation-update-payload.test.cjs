'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { InvestigationManager } = require('../api/_lib/investigation-manager');

function fixture() {
  const writes = [];
  const record = {
    id: 'case-1', assignee: 'analyst-a', priority: '3', version: '1',
    linkedIntelligence: '[]', linkedEntities: '[]',
  };
  const redis = {
    async hgetall(key) {
      assert.equal(key, 'investigation:case-1');
      return Object.entries(record).flat();
    },
    async hset(...args) { writes.push(args); },
    async zadd(...args) { writes.push(args); },
    async zrem(...args) { writes.push(args); },
  };
  return { manager: new InvestigationManager(redis, null, null), writes };
}

for (const payload of [null, undefined, [], 'invalid', 7]) {
  test('reject malformed update payload without mutation: ' + String(payload), async () => {
    const { manager, writes } = fixture();
    await assert.rejects(manager.updateInvestigation('case-1', payload), {
      name: 'TypeError', message: 'SOC_INVESTIGATION_INVALID_UPDATES',
    });
    assert.equal(writes.length, 0);
  });
}

test('reject reassignment before mutation', async () => {
  const { manager, writes } = fixture();
  await assert.rejects(manager.updateInvestigation('case-1', { assignee: 'analyst-b' }),
    /SOC_INVESTIGATION_REASSIGNMENT_NOT_READY/);
  assert.equal(writes.length, 0);
});

test('unchanged assignee permits metadata update', async () => {
  const { manager, writes } = fixture();
  // Avoid external audit dependency: this test verifies the Redis mutation boundary.
  manager.recordInvestigationAudit = async () => {};
  const result = await manager.updateInvestigation('case-1', {
    assignee: 'analyst-a', title: 'Updated title',
  });
  assert.equal(result.assignee, 'analyst-a');
  assert.equal(result.title, 'Updated title');
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], 'investigation:case-1');
});

test('metadata-only update preserves assignee', async () => {
  const { manager, writes } = fixture();
  manager.recordInvestigationAudit = async () => {};
  const result = await manager.updateInvestigation('case-1', { description: 'New detail' });
  assert.equal(result.assignee, 'analyst-a');
  assert.equal(result.description, 'New detail');
  assert.equal(writes.length, 1);
});

test('Redis update failure propagates without claiming success', async () => {
  const { manager, writes } = fixture();
  manager.redis.hset = async (...args) => {
    writes.push(args);
    throw new Error('INJECTED_REDIS_WRITE_FAILURE');
  };
  let auditCalls = 0;
  manager.recordInvestigationAudit = async () => { auditCalls += 1; };
  await assert.rejects(manager.updateInvestigation('case-1', { title: 'Cannot commit' }),
    /INJECTED_REDIS_WRITE_FAILURE/);
  assert.equal(writes.length, 1);
  assert.equal(auditCalls, 0);
});

test('unassignment is rejected before Redis mutation', async () => {
  const { manager, writes } = fixture();
  await assert.rejects(manager.updateInvestigation('case-1', { assignee: 'unassigned' }),
    /SOC_INVESTIGATION_REASSIGNMENT_NOT_READY/);
  assert.equal(writes.length, 0);
});
