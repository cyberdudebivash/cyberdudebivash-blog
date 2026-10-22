'use strict';

jest.mock('../redis', () => {
  const { createFakeRedis } = require('../__fixtures__/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});
// This file's "notification dispatch integration" describe block exercises
// notification-store.js indirectly (via change-engine.js's own dispatch
// call) -- that store is D1-backed, not Redis-backed, as of the
// Cloudflare-Only Alert Runtime tranche.
jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

let fakeCves = {};
let fakeCampaigns = {};
let fakeGraph = { nodes: {}, edges: [] };
let fakeReportsIndex = { reports: [] };

jest.mock('../intel', () => ({
  getCVEDetail: (id) => (global.__fakeCves[id] ? { found: true, item: global.__fakeCves[id] } : { found: false, item: null }),
  getCampaignDetail: (id) => (global.__fakeCampaigns[id] ? { found: true, campaign: global.__fakeCampaigns[id] } : { found: false, campaign: null }),
  loadGraph: () => global.__fakeGraph,
  loadJSON: () => global.__fakeReportsIndex,
  PATHS: { reportsIndex: 'REPORTS_INDEX_PATH' },
}));

const store = require('../watchlist-store');
const engine = require('../change-engine');

function resetFakes() {
  fakeCves = {}; fakeCampaigns = {}; fakeGraph = { nodes: {}, edges: [] }; fakeReportsIndex = { reports: [] };
  global.__fakeCves = fakeCves;
  global.__fakeCampaigns = fakeCampaigns;
  global.__fakeGraph = fakeGraph;
  global.__fakeReportsIndex = fakeReportsIndex;
}

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  global.__fakeD1ForTest._reset();
  resetFakes();
});

async function watchCve(ownerId, cveId, name = 'L') {
  const wl = await store.createWatchlist({ ownerId, name });
  await store.addEntity(wl.watchlist.id, ownerId, 'cve', cveId);
  return wl.watchlist.id;
}

describe('evaluateEntity — baseline (Phase 52)', () => {
  test('first observation establishes a baseline snapshot with zero events', async () => {
    fakeCves['CVE-2026-1111'] = { cvss: 8.1, threat_level: 'high', cisa_kev: false, exploited: false };
    await watchCve('usr_a', 'CVE-2026-1111');

    const intel = require('../intel');
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-1111', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('baseline_established');
    expect(outcome.events).toEqual([]);

    const snapshot = await engine.loadSnapshot('cve', 'CVE-2026-1111');
    expect(snapshot).not.toBeNull();
    expect(snapshot.state.cvss).toBe(8.1);
  });
});

describe('evaluateEntity — unchanged vs changed', () => {
  test('re-evaluating identical canonical state produces unchanged, zero events', async () => {
    fakeCves['CVE-2026-2222'] = { cvss: 7.0, threat_level: 'high', cisa_kev: false, exploited: false };
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-2222', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    const second = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-2222', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(second.status).toBe('unchanged');
    expect(second.events).toEqual([]);
  });

  test('a real KEV addition produces one persisted, matched event', async () => {
    fakeCves['CVE-2026-3333'] = { cvss: 9.1, threat_level: 'critical', cisa_kev: false, exploited: false };
    const watchlistId = await watchCve('usr_a', 'CVE-2026-3333');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-3333', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCves['CVE-2026-3333'] = { ...fakeCves['CVE-2026-3333'], cisa_kev: true };
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-3333', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('changed');
    // cisa_kev flipping true fires BOTH CVE_KEV_ADDED and
    // CVE_ACTIVE_EXPLOITATION_CONFIRMED (classifyExploitation() derives
    // exploitation status from cisa_kev) -- two distinct, correctly
    // evidenced facts changed together, matching the mandate's own
    // north-star example (KEV and Active Exploitation shown as separate
    // line items for the same underlying update).
    expect(outcome.events).toHaveLength(2);
    const kevEvent = outcome.events.find(e => e.change_type === 'CVE_KEV_ADDED');
    expect(kevEvent).toBeDefined();

    const page = await store.getOwnerFeedPage('usr_a', { limit: 10, cursor: 0 });
    expect(page.eventIds.sort()).toEqual(outcome.events.map(e => e.event_id).sort());
    const persisted = await engine.getEventById(kevEvent.event_id);
    expect(persisted.entity_id).toBe('CVE-2026-3333');
  });
});

describe('idempotency and replay safety (Phase 31/32/70)', () => {
  test('evaluating the exact same before/after pair twice does not duplicate the customer feed entry', async () => {
    fakeCves['CVE-2026-4444'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_a', 'CVE-2026-4444');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-4444', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCves['CVE-2026-4444'] = { ...fakeCves['CVE-2026-4444'], cisa_kev: true };
    const firstChange = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-4444', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    const pageAfterFirstChange = await store.getOwnerFeedPage('usr_a', { limit: 10, cursor: 0 });
    expect(pageAfterFirstChange.total).toBe(firstChange.events.length);

    // Re-run evaluation again with the SAME (now-current) state -- this is
    // "unchanged" from here, so it must not add any further feed entries.
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-4444', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    const pageAfterReplay = await store.getOwnerFeedPage('usr_a', { limit: 10, cursor: 0 });
    expect(pageAfterReplay.total).toBe(firstChange.events.length);
  });

  // Real Promise.all concurrency (Phase 55-59), not a simulated sequential
  // claim: two logically-concurrent calls racing to persist the exact same
  // event_id (e.g. an overlapping evaluation run) must not double-store it,
  // and exactly one of the two must observe itself as the actual creator.
  test('two concurrent persistEventIfNew calls for the same event_id do not duplicate storage, and exactly one call wins', async () => {
    const event = {
      event_id: 'evt_race_1', entity_type: 'cve', entity_id: 'CVE-2026-9001',
      observed_at: new Date().toISOString(), change_type: 'CVE_KEV_ADDED',
    };
    const [first, second] = await Promise.all([
      engine.persistEventIfNew({ ...event }),
      engine.persistEventIfNew({ ...event }),
    ]);
    const createdFlags = [first.created, second.created].sort();
    expect(createdFlags).toEqual([false, true]);

    const stored = await engine.getEventById('evt_race_1');
    expect(stored.entity_id).toBe('CVE-2026-9001');
    expect(global.__fakeD1ForTest._dump().changeEvents.size).toBe(1);
  });
});

describe('catastrophic data-loss protection (Phase 72)', () => {
  test('a canonical load failure on a previously-known entity leaves the snapshot untouched and emits nothing', async () => {
    fakeCves['CVE-2026-5555'] = {
      cvss: 8.8, threat_level: 'high', cisa_kev: true, exploited: true,
    };
    fakeGraph.nodes['CVE-2026-5555'] = { id: 'CVE-2026-5555', type: 'CVE', name: 'CVE-2026-5555' };
    fakeGraph.nodes['campaign:x'] = { id: 'campaign:x', type: 'Campaign', name: 'campaign:x' };
    fakeGraph.edges.push({ source: 'CVE-2026-5555', target: 'campaign:x', relationship: 'includes', confidence: 0.9, sources: [], first_seen: null });

    await watchCve('usr_a', 'CVE-2026-5555');
    const intel = require('../intel');
    const baseline = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5555', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(baseline.status).toBe('baseline_established');
    const snapshotBefore = await engine.loadSnapshot('cve', 'CVE-2026-5555');
    expect(snapshotBefore.state.campaign_ids).toEqual(['campaign:x']);

    // Simulate an upstream outage / catastrophic drop: the entity can no
    // longer be found at all.
    delete fakeCves['CVE-2026-5555'];
    const outage = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5555', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outage.status).toBe('load_failed');
    expect(outage.events).toEqual([]);

    const snapshotAfterOutage = await engine.loadSnapshot('cve', 'CVE-2026-5555');
    expect(snapshotAfterOutage).toEqual(snapshotBefore); // untouched, not overwritten with empty state

    // Recovery: canonical data comes back with the SAME real facts as
    // before the outage. Because the snapshot was never corrupted by the
    // outage, this must be "unchanged", NOT a flood of "new" relationship
    // events (which is exactly what would happen if the outage had
    // incorrectly overwritten the snapshot with an empty state).
    fakeCves['CVE-2026-5555'] = { cvss: 8.8, threat_level: 'high', cisa_kev: true, exploited: true };
    const recovered = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5555', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(recovered.status).toBe('unchanged');
    expect(recovered.events).toEqual([]);
  });
});

describe('global event / customer match separation (Phase 67/68)', () => {
  test('100 customers watching the same CVE produce ONE diff and ONE stored event, fanned out to every watcher', async () => {
    fakeCves['CVE-2026-6666'] = { cvss: 6.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    const owners = Array.from({ length: 25 }, (_, i) => `usr_${i}`);
    for (const owner of owners) await watchCve(owner, 'CVE-2026-6666');

    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-6666', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    fakeCves['CVE-2026-6666'] = { ...fakeCves['CVE-2026-6666'], cisa_kev: true };
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-6666', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    // cisa_kev flipping fires 2 distinct events (see the note in the
    // preceding describe block) -- the point under test here is that each
    // one was computed ONCE and fanned out by reference, not recomputed
    // or duplicated per watcher.
    const eventIds = outcome.events.map(e => e.event_id).sort();

    for (const owner of owners) {
      const page = await store.getOwnerFeedPage(owner, { limit: 10, cursor: 0 });
      expect(page.eventIds.sort()).toEqual(eventIds);
    }

    // Exactly as many event objects were written as distinct changes
    // detected -- never one per watcher (25 watchers, still just N events).
    const changeEvents = global.__fakeD1ForTest._dump().changeEvents;
    expect(changeEvents.size).toBe(outcome.events.length);
  });
});

describe('evaluateWatchedEntities — bounded, cursor-resumable batch (Phase 48/51/67)', () => {
  test('only entities that are actually watched are evaluated -- an unwatched entity is never touched', async () => {
    fakeCves['CVE-2026-7777'] = { cvss: 5.0 }; // watched
    fakeCves['CVE-2026-8888'] = { cvss: 5.0 }; // NOT watched
    await watchCve('usr_a', 'CVE-2026-7777');

    const results = await engine.evaluateWatchedEntities({ batchLimit: 200 });
    expect(results.watched_entities_total).toBe(1);
    expect(results.evaluated).toBe(1);
    const untouchedSnapshot = await engine.loadSnapshot('cve', 'CVE-2026-8888');
    expect(untouchedSnapshot).toBeNull();
  });

  test('baseline run over multiple watched entities does not flood events, and touches last_evaluated_at', async () => {
    fakeCves['CVE-2026-0001'] = { cvss: 5.0 };
    fakeCves['CVE-2026-0002'] = { cvss: 6.0 };
    fakeCves['CVE-2026-0003'] = { cvss: 7.0 };
    const wl = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(wl.watchlist.id, 'usr_a', 'cve', 'CVE-2026-0001');
    await store.addEntity(wl.watchlist.id, 'usr_a', 'cve', 'CVE-2026-0002');
    await store.addEntity(wl.watchlist.id, 'usr_a', 'cve', 'CVE-2026-0003');

    const results = await engine.evaluateWatchedEntities({ batchLimit: 200 });
    expect(results.baseline).toBe(3);
    expect(results.changed).toBe(0);
    expect(results.events_created).toBe(0);
    expect(results.watchlists_touched).toBe(1);

    const after = await store.getWatchlist(wl.watchlist.id, 'usr_a');
    expect(after.watchlist.last_evaluated_at).not.toBeNull();
  });

  test('batchLimit bounds a single run, and the cursor advances so a second run covers the rest', async () => {
    for (let i = 0; i < 5; i++) {
      fakeCves[`CVE-2026-${1000 + i}`] = { cvss: 5.0 };
      await watchCve('usr_a', `CVE-2026-${1000 + i}`, `L${i}`);
    }
    const first = await engine.evaluateWatchedEntities({ batchLimit: 2 });
    expect(first.evaluated).toBe(2);
    const second = await engine.evaluateWatchedEntities({ batchLimit: 2 });
    expect(second.evaluated).toBe(2);
    const third = await engine.evaluateWatchedEntities({ batchLimit: 2 });
    expect(third.evaluated).toBe(2); // wraps back around, not stuck

    // Across the 3 bounded runs (6 evaluations of a 5-entity set), every
    // entity was reached at least once.
    const snapshots = await Promise.all(
      [1000, 1001, 1002, 1003, 1004].map(n => engine.loadSnapshot('cve', `CVE-2026-${n}`))
    );
    expect(snapshots.every(s => s !== null)).toBe(true);
  });

  test('zero watched entities is a clean no-op, not an error', async () => {
    const results = await engine.evaluateWatchedEntities({});
    expect(results.watched_entities_total).toBe(0);
    expect(results.evaluated).toBe(0);
  });
});


describe('SOC bounded keyset watchlist sweep (migration 0017)', () => {
  test('bounded sweep deduplicates watchers, advances and wraps', async () => {
    for (let i = 1; i <= 5; i++) {
      const id = 'CVE-2026-' + String(i).padStart(4, '0');
      fakeCves[id] = { cvss: 5.0 };
      await watchCve('usr_a', id, 'L' + i);
    }
    await watchCve('usr_b', 'CVE-2026-0001', 'Duplicate watcher');
    const first = await engine.evaluateWatchedEntities({ batchLimit: 2, boundedScan: true });
    const second = await engine.evaluateWatchedEntities({ batchLimit: 2, boundedScan: true });
    const third = await engine.evaluateWatchedEntities({ batchLimit: 2, boundedScan: true });
    expect([first.evaluated, second.evaluated, third.evaluated]).toEqual([2, 2, 1]);
    expect([first.watched_entities_total, second.watched_entities_total]).toEqual([null, null]);
    for (let i = 1; i <= 5; i++) {
      expect(await engine.loadSnapshot('cve', 'CVE-2026-' + String(i).padStart(4, '0'))).not.toBeNull();
    }
    const wrapped = await engine.evaluateWatchedEntities({ batchLimit: 2, boundedScan: true });
    expect(wrapped.evaluated).toBe(2);
  });

  test('empty bounded database window never evaluates or writes', async () => {
    const out = await engine.evaluateWatchedEntities({ batchLimit: 10, boundedScan: true });
    expect(out.evaluated).toBe(0);
    expect(out.watched_entities_total).toBe(0);
  });

  test('invalid Cron batch sizes are blocked before database access', async () => {
    for (const batchLimit of [0, 11, 200, -1, 1.5, NaN, Infinity, '10']) {
      await expect(engine.evaluateWatchedEntities({ batchLimit, boundedScan: true }))
        .rejects.toThrow('batchLimit 1..10');
    }
  });

  test('index scanner returns no more than the fixed raw SQL window', async () => {
    const all = global.__fakeD1ForTest._dump().watchlistEntities;
    for (let i = 1; i <= 300; i++) {
      all.push({ watchlist_id: 'wl_test', entity_type: 'cve',
        entity_id: 'CVE-2026-' + String(i).padStart(4, '0') });
    }
    expect((await store.getWatchedEntityWindow()).length).toBe(128);
    expect((await store.getWatchedEntityWindow({
      after: { entityType: 'cve', entityId: 'CVE-2026-0200' }, rowLimit: 20
    })).map(e => e.entityId)).toEqual(
      Array.from({ length: 20 }, (_, i) => 'CVE-2026-' + String(i + 201).padStart(4, '0'))
    );
    await expect(store.getWatchedEntityWindow({ rowLimit: 129 })).rejects.toThrow('1..128');
    await expect(store.getWatchedEntityWindow({ after: { entityType: 'cve' } }))
      .rejects.toThrow('Invalid SOC watchlist keyset cursor');
  });
});

describe('schema version change (Phase 30)', () => {
  test('a stored snapshot from an older schema version is treated as if no snapshot existed -- re-baselined, zero events, never a false mass-change', async () => {
    fakeCves['CVE-2026-1212'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_a', 'CVE-2026-1212');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-1212', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    // Simulate a future schema bump by corrupting the stored snapshot's
    // own version tag directly (the real production trigger for this
    // path -- WATCHABLE_STATE_SCHEMA_VERSION itself changing -- can't be
    // exercised without editing source, so this reaches the same branch
    // the same way a real version bump would: prior.schema_version !==
    // the module's current constant).
    const snapshotRow = global.__fakeD1ForTest._dump().entitySnapshots.get('cve|CVE-2026-1212');
    snapshotRow.schema_version = '0.9-old';

    fakeCves['CVE-2026-1212'] = { ...fakeCves['CVE-2026-1212'], cisa_kev: true }; // a real change too, to prove it's suppressed by the re-baseline
    const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-1212', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('baseline_established');
    expect(outcome.events).toEqual([]);

    const newSnapshot = await engine.loadSnapshot('cve', 'CVE-2026-1212');
    expect(newSnapshot.schema_version).not.toBe('0.9-old');
  });
});

describe('defensive branch: unsupported entity type reaching the engine directly', () => {
  test('evaluateEntity never crashes on a type watchlist-store.js would already reject', async () => {
    const intel = require('../intel');
    const outcome = await engine.evaluateEntity({ entityType: 'malware', entityId: 'x', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('unsupported_type');
    expect(outcome.events).toEqual([]);
  });
});

describe('campaign evaluation', () => {
  test('a campaign change is detected the same way as a CVE change', async () => {
    fakeCampaigns['campaign:x'] = {
      campaign_id: 'campaign:x', severity: 'high', confidence: 0.6, last_seen: '2026-08-01',
      threat_actors: [], shared_cves: [], has_kev: false, has_exploited: false, has_ransomware: false,
    };
    const wl = await store.createWatchlist({ ownerId: 'usr_a', name: 'L' });
    await store.addEntity(wl.watchlist.id, 'usr_a', 'campaign', 'campaign:x');
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'campaign', entityId: 'campaign:x', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCampaigns['campaign:x'] = { ...fakeCampaigns['campaign:x'], has_ransomware: true };
    const outcome = await engine.evaluateEntity({ entityType: 'campaign', entityId: 'campaign:x', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    expect(outcome.status).toBe('changed');
    expect(outcome.events[0].change_type).toBe('CAMPAIGN_RANSOMWARE_FLAG_ADDED');
  });
});

describe('notification dispatch integration (Alert Delivery v1)', () => {
  const notify = require('../notification-store');

  test('a genuinely new event enqueues a pending delivery for a watcher with notifications enabled', async () => {
    fakeCves['CVE-2026-5001'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_notify', 'CVE-2026-5001');
    await notify.updatePreferences('usr_notify', { email_override: 'alerts@example.com' });
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5001', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    fakeCves['CVE-2026-5001'] = { ...fakeCves['CVE-2026-5001'], cisa_kev: true };
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5001', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    // A KEV flip legitimately fires TWO events (CVE_KEV_ADDED and
    // CVE_ACTIVE_EXPLOITATION_CONFIRMED, since classifyExploitation()
    // derives exploitation status from the same cisa_kev field) -- this
    // is documented, correct platform behavior from the watchlist v1
    // round's own change-detector tests, not a bug here. One pending-
    // delivery record is created per (owner, event_id), so two distinct
    // events for the same owner correctly produce two records.
    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(2);
    expect(due.every(r => r.owner_id === 'usr_notify')).toBe(true);
    expect(due.every(r => r.channel === 'email')).toBe(true);
    expect(new Set(due.map(r => r.event_id)).size).toBe(2); // distinct events, not a duplicate enqueue
  });

  test('a watcher with no notification channels enabled gets nothing enqueued (existing default-off-for-webhook, on-but-unresolvable-for-email posture)', async () => {
    fakeCves['CVE-2026-5002'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_silent', 'CVE-2026-5002');
    // No preferences ever set for usr_silent, and no user:id/user:key
    // account record exists in this fake redis for it either -- email
    // defaults "on" but has no resolvable target, so nothing is enqueued.
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5002', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
    fakeCves['CVE-2026-5002'] = { ...fakeCves['CVE-2026-5002'], cisa_kev: true };
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5002', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    const due = await notify.getDuePendingDeliveries(10);
    expect(due).toHaveLength(0);
  });

  test('a baseline-only run (no real change) never enqueues a notification', async () => {
    fakeCves['CVE-2026-5003'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    await watchCve('usr_notify2', 'CVE-2026-5003');
    await notify.updatePreferences('usr_notify2', { email_override: 'a@example.com' });
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5003', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex }); // baseline only

    expect(await notify.getDuePendingDeliveries(10)).toHaveLength(0);
  });

  test('a notification-dispatch failure never prevents the feed fan-out that already succeeded', async () => {
    // dispatchNewEvent is enqueue-only and error-swallowed at the call
    // site (see change-engine.js) -- simulate a hard failure by breaking
    // notification-store's write mid-flight and confirm the watcher's
    // feed entry (the pre-existing, load-bearing behavior) is still
    // written. Was a broken redis.hget before the Cloudflare-Only Alert
    // Runtime tranche; then a broken global d1.query after Alert Delivery
    // v1 moved notification-store onto D1. As of the Cloudflare-Only
    // Runtime Completion v2 tranche, change-engine.js's OWN snapshot/event
    // persistence also moved onto the same shared D1 client (see
    // watchable-state/change-detector D1 migration), so breaking
    // d1.query globally now fails evaluateEntity's own loadSnapshot()
    // before it ever reaches dispatch -- too broad to isolate a
    // notification-store-specific failure anymore. Breaking
    // notify.enqueuePendingDelivery() directly (the exact call
    // dispatchNewEvent makes -- see notification-dispatch.js) is the
    // precise equivalent failure-injection point in the new design
    // (email_override is already set below, so getOwnerAccountEmail()'s
    // own lookup is short-circuited and never even reached).
    fakeCves['CVE-2026-5004'] = { cvss: 5.0, threat_level: 'medium', cisa_kev: false, exploited: false };
    const wlId = await watchCve('usr_resilient', 'CVE-2026-5004');
    await notify.updatePreferences('usr_resilient', { email_override: 'a@example.com' });
    const intel = require('../intel');
    await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5004', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });

    const originalEnqueue = notify.enqueuePendingDelivery;
    notify.enqueuePendingDelivery = async () => { throw new Error('simulated notification-store failure'); };
    try {
      fakeCves['CVE-2026-5004'] = { ...fakeCves['CVE-2026-5004'], cisa_kev: true };
      const outcome = await engine.evaluateEntity({ entityType: 'cve', entityId: 'CVE-2026-5004', intel, graph: fakeGraph, reportsIndexData: fakeReportsIndex });
      expect(outcome.status).toBe('changed'); // detection + persistence + feed fan-out all still succeeded
      const feed = await store.getOwnerFeedPage('usr_resilient', { limit: 10, cursor: 0 });
      expect(feed.eventIds.length).toBeGreaterThan(0);
    } finally {
      notify.enqueuePendingDelivery = originalEnqueue;
    }
  });
});
