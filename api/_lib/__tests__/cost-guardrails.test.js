'use strict';

// Application-level cost guardrails (docs/operations/CLOUDFLARE-COST-GUARDRAILS.md).
// These limits keep a bug or a hostile query from turning into runaway
// Worker CPU, bundle size, D1 reads or request volume. Each assertion pins a
// limit that, if raised or removed, must be a reviewed decision.

const fs = require('fs');
const path = require('path');
const store = require('../ioc-engine/store');
const { queryFeed } = require('../ioc-engine/feed');
const config = require('../../../config/ioc-sources.json');
const { searchDocuments } = require('../search-index');

const ROOT = path.join(__dirname, '..', '..', '..');

describe('IOC feed (bundled into the Worker)', () => {
  test('feed cap is configured at the 600 hard limit and cannot exceed it', () => {
    expect(store.FEED_CAP_HARD_LIMIT).toBe(600);
    expect(config.feed_cap).toBeLessThanOrEqual(store.FEED_CAP_HARD_LIMIT);
  });

  test('a config raising feed_cap above the hard limit still publishes at most 600 and fails the gate', () => {
    const st = store.emptyStore();
    const now = '2026-10-01T00:00:00.000Z';
    for (let i = 0; i < 700; i++) {
      const v = `evil${i}.top`;
      st.indicators[`domain|${v}`] = {
        id: store.indicatorId('domain', v), type: 'domain', value: v, status: 'ACTIVE', confidence: 'HIGH',
        last_seen: now, first_seen: now, sources: ['threatfox'], observations: [],
      };
    }
    const raised = { ...config, feed_cap: 5000 };
    const feed = store.buildFeed(st, raised, {}, now);
    expect(feed.items.length).toBe(600);
    expect(store.validateFeed(feed, raised).join('\n')).toMatch(/exceeds hard limit 600/);
  });

  test('per-source caps are set and bounded', () => {
    for (const s of config.sources) {
      expect(s.per_source_cap).toBeGreaterThan(0);
      expect(s.per_source_cap).toBeLessThanOrEqual(300);
      expect(s.max_bytes).toBeLessThanOrEqual(25000000);
      expect(s.timeout_ms).toBeLessThanOrEqual(30000);
    }
  });

  test('API page size is capped at 200 regardless of the requested limit', () => {
    const items = Array.from({ length: 600 }, (_, i) => ({ id: String(i), type: 'url' }));
    expect(queryFeed(items, { limit: '99999999' }).items).toHaveLength(200);
    expect(queryFeed(items, { page: '99999999' }).items).toHaveLength(0);
  });
});

describe('search and D1-backed lists', () => {
  test('unified search caps limit at 100', () => {
    const docs = Array.from({ length: 300 }, (_, i) => ({ id: `cve:${i}`, type: 'cve', name: `CVE-2026-${1000 + i} test` }));
    const out = searchDocuments({ documents: docs }, 'test', { limit: 99999999, tier: 'enterprise' });
    expect(out.results.length).toBeLessThanOrEqual(100);
  });

  test.each([
    ['api/_lib/premium-commerce-store.js', /function clampLimit\(value, fallback = 50, max = 100\)/],
    ['api/_lib/notification-store.js', /Math\.min\(limit, 200\)/],
    ['api/_lib/watchlist-store.js', /Math\.min\(limit, 100\)/],
    ['api/v1/notifications.js', /Math\.min\(parseInt\(req\.query\.limit, 10\) \|\| 50, 200\)/],
    ['api/v1/watchlists.js', /Math\.min\(parseInt\(req\.query\.limit, 10\) \|\| 20, 100\)/],
  ])('%s keeps its list limit cap', (file, re) => {
    expect(fs.readFileSync(path.join(ROOT, file), 'utf8')).toMatch(re);
  });
});

describe('client polling', () => {
  test('live feed widget refreshes no faster than every 15 minutes and not from hidden tabs', () => {
    const src = fs.readFileSync(path.join(ROOT, 'live-feed-widget.js'), 'utf8');
    const m = /REFRESH_MS:\s*(\d+)\s*\*\s*(\d+)\s*\*\s*(\d+)/.exec(src);
    expect(m).not.toBeNull();
    expect(Number(m[1]) * Number(m[2]) * Number(m[3])).toBeGreaterThanOrEqual(15 * 60 * 1000);
    expect(src).toMatch(/if \(document\.hidden\) return;/);
  });
});
