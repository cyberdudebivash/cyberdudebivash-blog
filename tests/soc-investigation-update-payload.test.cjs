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
