'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { InvestigationManager } = require('../api/_lib/investigation-manager');

function harness(ids, records) {
  const reads = [];
  const redis = {
    async zrevrange(key, start, stop) {
      reads.push({ key, start, stop });
      return ids;
    },
  };
  const manager = new InvestigationManager(redis, {}, {});
  manager.getInvestigation = async id => records[id] || null;
  return { manager, reads };
}

test('P0: a stale former-assignee index never exposes the reassigned investigation', async () => {
  const { manager, reads } = harness(['own', 'foreign', 'deleted'], {
    own: { id: 'own', assignee: 'analyst-a', status: 'open' },
    foreign: { id: 'foreign', assignee: 'analyst-b', status: 'open' },
  });
  const result = await manager.listInvestigations({ assignee: 'analyst-a' }, 20);
  assert.deepEqual(result.map(r => r.id), ['own']);
  assert.deepEqual(reads, [{ key: 'investigations:assigned:analyst-a', start: 0, stop: 19 }]);
});

test('P0: assignee scope always takes precedence over status index selection', async () => {
  const { manager, reads } = harness(['own-open', 'own-closed', 'foreign-open'], {
    'own-open': { id: 'own-open', assignee: 'analyst-a', status: 'open' },
    'own-closed': { id: 'own-closed', assignee: 'analyst-a', status: 'closed' },
    'foreign-open': { id: 'foreign-open', assignee: 'analyst-b', status: 'open' },
  });
  const result = await manager.listInvestigations({ assignee: 'analyst-a', status: 'open' }, 10);
  assert.deepEqual(result.map(r => r.id), ['own-open']);
  assert.equal(reads[0].key, 'investigations:assigned:analyst-a');
});

test('P0: stale status-index members are filtered against current stored status', async () => {
  const { manager, reads } = harness(['open', 'closed'], {
    open: { id: 'open', assignee: 'analyst-a', status: 'open' },
    closed: { id: 'closed', assignee: 'analyst-a', status: 'closed' },
  });
  const result = await manager.listInvestigations({ status: 'open' }, 5);
  assert.deepEqual(result.map(r => r.id), ['open']);
  assert.equal(reads[0].key, 'investigations:by:status:open');
});

test('P0: an index read failure propagates rather than returning an empty success', async () => {
  const { manager } = harness([], {});
  manager.redis.zrevrange = async () => { throw new Error('REDIS_UNAVAILABLE'); };
  await assert.rejects(manager.listInvestigations({ assignee: 'analyst-a' }), /REDIS_UNAVAILABLE/);
});
