'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createOutbox } = require('../api/_lib/soc-notification-outbox');

const event = Object.freeze({ event_id: 'event-receipt-test' });
const watchers = Object.freeze([{ ownerId: 'owner-1', watchlistId: 'watchlist-1' }]);

function fixture(receipts) {
  const pending = [...receipts];
  const writes = [];
  const d1 = {
    query: async () => [],
    runMutationWithChanges: async (sql, params) => {
      writes.push({ sql, params });
      return pending.shift();
    },
  };
  return {
    outbox: createOutbox({ d1, enabled: true, now: () => 1700000000000 }),
    writes,
  };
}

test('staging accepts a verified one-row insert', async () => {
  const { outbox, writes } = fixture([1]);
  assert.deepEqual(await outbox.stageEventFanout({ event, watchers }), { staged: 1, created: 1 });
  assert.equal(writes.length, 1);
});

test('staging accepts a verified zero-row conflict without counting a new intent', async () => {
  const { outbox, writes } = fixture([0]);
  assert.deepEqual(await outbox.stageEventFanout({ event, watchers }), { staged: 1, created: 0 });
  assert.equal(writes.length, 1);
});

for (const [label, receipt] of [
  ['missing', undefined], ['null', null], ['NaN', NaN],
  ['infinite', Infinity], ['negative', -1], ['multi-row', 2],
  ['fractional', 0.5], ['string', '1'], ['boolean', true],
]) {
  test(`staging rejects ${label} mutation receipt before reporting success`, async () => {
    const { outbox, writes } = fixture([receipt]);
    await assert.rejects(
      outbox.stageEventFanout({ event, watchers }),
      /SOC_OUTBOX_STAGE_RECEIPT_INVALID/,
    );
    assert.equal(writes.length, 1);
  });
}

test('partial fanout with a later ambiguous receipt rejects rather than reporting success', async () => {
  const { outbox, writes } = fixture([1, 2]);
  await assert.rejects(
    outbox.stageEventFanout({
      event,
      watchers: [...watchers, { ownerId: 'owner-2', watchlistId: 'watchlist-2' }],
    }),
    /SOC_OUTBOX_STAGE_RECEIPT_INVALID/,
  );
  assert.equal(writes.length, 2);
});
