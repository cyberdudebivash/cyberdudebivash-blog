'use strict';
// Regression test: CISA KEV additions were silently dropped by fetchCISAKev().
//
// Root cause (confirmed against real publisher job logs, run 41744466181 at
// 2026-11-04T00:07:43Z, which logged "CISA KEV: fetching (since 2026-11-03)..."
// then "CISA KEV: 0 items." while the live catalog released 2026-11-03T20:00Z
// held an entry with dateAdded 2026-11-03):
//
//   CISA's KEV schema publishes `dateAdded` as a calendar DATE ("YYYY-MM-DD").
//   `new Date("2026-11-03")` is midnight UTC. The adapter compared that against
//   a TIMESTAMP watermark from watermarkStart() (min(lastFetch, now - 4h)), so
//   any entry added earlier in the same UTC day than the cutoff instant compared
//   as "older than the cutoff" and was discarded. A KEV entry is published
//   during the day, so every incremental run saw it only after midnight had
//   already fallen behind the cutoff: the adapter returned [] for the entire
//   incremental path and only produced records on a cold start (no lastFetch).
//
// Fix under test: a date-granularity source is compared at date granularity,
// i.e. against the start of the cutoff's UTC day. Re-seen same-day entries are
// harmless: isPublished()/writeLiveIntel() dedupe by id (see
// watermark-lookback-floor.test.js).
//
// All fixture records are SYNTHETIC (CVE-2099-*). No network is used: the
// https transport is stubbed and the clock is frozen.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const { fetchCISAKev } = require(path.join(__dirname, '..', 'fetch-live-intel.js'));

const MIN = 60000;
const HOUR = 3600000;

function kevEntry(id, dateAdded) {
  return {
    cveID: id, vendorProject: 'SyntheticVendor', product: 'SyntheticProduct',
    vulnerabilityName: 'Synthetic test vulnerability (not real intelligence)',
    dateAdded, shortDescription: 'SYNTHETIC FIXTURE', requiredAction: 'none',
    dueDate: '2099-12-31', knownRansomwareCampaignUse: 'Unknown', notes: '',
  };
}

/** Stub https.request so fetchUrl() receives `body` with `status`; counts calls. */
function stubTransport(t, body, status = 200) {
  return t.mock.method(https, 'request', (_options, cb) => {
    const req = new EventEmitter();
    req.write = () => {};
    req.destroy = () => {};
    req.end = () => setImmediate(() => {
      const res = new EventEmitter();
      res.statusCode = status;
      res.headers = {};
      res.setEncoding = () => {};
      res.resume = () => {};
      cb(res);
      res.emit('data', body);
      res.emit('end');
    });
    return req;
  });
}

const catalog = (vulns) => JSON.stringify({ title: 'SYNTHETIC KEV-shaped fixture', catalogVersion: 'test', vulnerabilities: vulns });
const freezeClock = (t, iso) => t.mock.timers.enable({ apis: ['Date'], now: Date.parse(iso) });
const stateWith = (lastFetch) => ({ sourceFetchState: lastFetch ? { cisa_kev: { lastFetch } } : {} });
const ids = (items) => items.map((i) => i.id).sort();

test('an entry added earlier today is returned when the previous fetch was 30 minutes ago', async (t) => {
  const now = '2026-11-04T15:14:42Z';
  freezeClock(t, now);
  stubTransport(t, catalog([kevEntry('CVE-2099-0001', '2026-11-04')]));
  const items = await fetchCISAKev(stateWith(Date.parse(now) - 30 * MIN));
  assert.deepEqual(ids(items), ['CVE-2099-0001']);
});

test('exact production scenario: first run after a 20:00Z release returns the same-day entry', async (t) => {
  // Real run 41744466181: now=2026-11-04T00:07:43Z, previous success 2026-11-03T19:16Z.
  freezeClock(t, '2026-11-04T00:07:43Z');
  stubTransport(t, catalog([kevEntry('CVE-2099-0002', '2026-11-03')]));
  const items = await fetchCISAKev(stateWith(Date.parse('2026-11-03T19:16:00Z')));
  assert.deepEqual(ids(items), ['CVE-2099-0002']);
  assert.equal(items[0].source, 'cisa_kev');
  assert.equal(items[0].cisaKev, true);
  assert.equal(items[0].exploited, true, 'KEV membership is confirmed exploitation per CISA');
  assert.equal(items[0].cvss, null, 'unknown severity must stay unknown, never defaulted');
  assert.equal(items[0].pubDate, '2026-11-03', 'the provider date is preserved, not rewritten');
});

test('the window is not over-widened: entries from a day before the cutoff day are not returned', async (t) => {
  const now = '2026-11-04T15:14:42Z';
  freezeClock(t, now);
  stubTransport(t, catalog([
    kevEntry('CVE-2099-0003', '2026-11-03'),
    kevEntry('CVE-2099-0004', '2026-11-02'),
    kevEntry('CVE-2099-0005', '2026-11-04'),
  ]));
  const items = await fetchCISAKev(stateWith(Date.parse(now) - 30 * MIN));
  assert.deepEqual(ids(items), ['CVE-2099-0005']);
});

test('a longer outage widens the window to the day of the last successful fetch', async (t) => {
  const now = '2026-11-04T15:14:42Z';
  freezeClock(t, now);
  stubTransport(t, catalog([
    kevEntry('CVE-2099-0006', '2026-11-01'),
    kevEntry('CVE-2099-0007', '2026-11-02'),
    kevEntry('CVE-2099-0008', '2026-11-03'),
  ]));
  const lastFetch = Date.parse('2026-11-02T08:00:00Z'); // 2.3 days before now
  const items = await fetchCISAKev(stateWith(lastFetch));
  assert.deepEqual(ids(items), ['CVE-2099-0007', 'CVE-2099-0008']);
});

test('cold start (no previous fetch) uses the 7-day lookback, day-granular', async (t) => {
  freezeClock(t, '2026-11-04T15:14:42Z');
  stubTransport(t, catalog([
    kevEntry('CVE-2099-0009', '2026-10-27'),   // older than the 7-day window
    kevEntry('CVE-2099-0010', '2026-10-28'),   // boundary day: included (date granularity)
    kevEntry('CVE-2099-0011', '2026-11-01'),
  ]));
  const items = await fetchCISAKev(stateWith(null));
  assert.deepEqual(ids(items), ['CVE-2099-0010', 'CVE-2099-0011']);
});

test('malformed or missing dateAdded is skipped without throwing; valid entries still returned', async (t) => {
  const now = '2026-11-04T15:14:42Z';
  freezeClock(t, now);
  const bad1 = kevEntry('CVE-2099-0012', 'not-a-date');
  const bad2 = kevEntry('CVE-2099-0013', '');
  const bad3 = kevEntry('CVE-2099-0014', undefined);
  stubTransport(t, catalog([bad1, bad2, bad3, kevEntry('CVE-2099-0015', '2026-11-04')]));
  const items = await fetchCISAKev(stateWith(Date.parse(now) - 30 * MIN));
  assert.deepEqual(ids(items), ['CVE-2099-0015']);
});

test('a successful fetch ratchets the watermark to now (unchanged behaviour)', async (t) => {
  const now = '2026-11-04T15:14:42Z';
  freezeClock(t, now);
  const state = stateWith(Date.parse(now) - 3 * HOUR);
  stubTransport(t, catalog([]));
  assert.deepEqual(await fetchCISAKev(state), []);
  assert.equal(state.sourceFetchState.cisa_kev.lastFetch, Date.parse(now));
});

test('a failed fetch fails closed and leaves the watermark untouched (unchanged behaviour)', async (t) => {
  const now = '2026-11-04T15:14:42Z';
  freezeClock(t, now);
  const previous = Date.parse(now) - 3 * HOUR;
  const state = stateWith(previous);
  stubTransport(t, 'forbidden', 403); // 403 is never retried: no real sleeping in this test
  await assert.rejects(() => fetchCISAKev(state), /HTTP 403/);
  assert.equal(state.sourceFetchState.cisa_kev.lastFetch, previous, 'watermark must not advance on failure');
});
