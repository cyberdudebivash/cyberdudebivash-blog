'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { InvestigationManager } = require('../api/_lib/investigation-manager');

function fixture(assignee = 'alice') {
  const calls = [];
  const redis = {
    hgetall: async key => {
      assert.equal(key, 'investigation:inv-1');
      return ['id', 'inv-1', 'assignee', assignee, 'title', 'Original',
        'priority', '3', 'version', '1'];
    },
    hset: async (...args) => { calls.push(['hset', ...args]); return 1; },
    zadd: async (...args) => { calls.push(['zadd', ...args]); return 1; },
    zrem: async (...args) => { calls.push(['zrem', ...args]); return 1; },
  };
  const manager = new InvestigationManager(redis);
  manager.recordInvestigationAudit = async () => { calls.push(['audit']); };
  return { manager, calls };
}

test('P0 #455: cross-analyst reassignment fails before any Redis mutation', async () => {
  const { manager, calls } = fixture('alice');
  await assert.rejects(
    manager.updateInvestigation('inv-1', { assignee: 'bob', title: 'Should not persist' }),
    /SOC_INVESTIGATION_REASSIGNMENT_NOT_READY/
  );
  assert.deepEqual(calls, []);
});

test('P0 #455: reassignment to unassigned also fails closed', async () => {
  const { manager, calls } = fixture('alice');
  await assert.rejects(
    manager.updateInvestigation('inv-1', { assignee: 'unassigned' }),
    /SOC_INVESTIGATION_REASSIGNMENT_NOT_READY/
  );
  assert.deepEqual(calls, []);
});

test('P0 #455: unchanged assignee and ordinary metadata updates remain permitted', async () => {
  const { manager, calls } = fixture('alice');
  const updated = await manager.updateInvestigation('inv-1', {
    assignee: 'alice', title: 'Permitted',
  });
  assert.equal(updated.assignee, 'alice');
  assert.equal(updated.title, 'Permitted');
  assert.equal(calls.filter(x => x[0] === 'hset').length, 1);
  assert.equal(calls.filter(x => x[0] === 'audit').length, 1);
  assert.equal(calls.filter(x => x[0] === 'zadd' || x[0] === 'zrem').length, 0);
});

test('P0 #455: omitted assignee does not block title-only updates', async () => {
  const { manager, calls } = fixture('alice');
  const updated = await manager.updateInvestigation('inv-1', { title: 'Renamed' });
  assert.equal(updated.title, 'Renamed');
  assert.equal(calls.filter(x => x[0] === 'hset').length, 1);
});
