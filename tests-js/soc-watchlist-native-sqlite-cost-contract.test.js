'use strict';

// Cloudflare cost preflight: offline native SQLite, ZERO production D1 calls.
// This tests the real migration SQL and the exact production query constants,
// not a fake D1 stub or a rewritten approximation.
// IMPORTANT: SQLITE EXPLAIN is not proof of Cloudflare D1 billable rows_read.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const {
  SOC_WATCH_WINDOW_FIRST_SQL,
  SOC_WATCH_WINDOW_SEEK_SQL,
  SOC_CRON_MEMBERSHIP_PROBE_SQL,
  SOC_CRON_ACTIVE_WATCHERS_SQL,
  SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS,
  GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS
} = require('../api/_lib/watchlist-store');

const root = path.resolve(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const migration = read('migrations/0002_watchlists_change_detection.sql');
const cursorMigration = read('migrations/0017_soc_bounded_watchlist_eval.sql');
const now = '2026-10-22T00:00:00.000Z';

function seededDatabase() {
  const db = new DatabaseSync(':memory:');
  db.exec(migration);
  db.exec(cursorMigration);
  const watch = db.prepare(
    'INSERT INTO watchlists (id, owner_id, name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)'
  );
  const entity = db.prepare(
    'INSERT INTO watchlist_entities (watchlist_id, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?)'
  );
  db.exec('BEGIN');
  try {
    for (let n = 1; n <= 1500; n++) {
      const id = 'unrelated-' + String(n);
      watch.run(id, 'usr_unrelated', 'Test', 'active', now, now);
      entity.run(id, 'cve', 'CVE-2026-' + String(n).padStart(4, '0'), now);
    }
    // 11 different watchlists for the same entity; mostly paused still
    // counts towards the guard. This must be rejected before joined reads.
    for (let n = 1; n <= 11; n++) {
      const id = 'heavy-' + n;
      watch.run(id, 'usr_heavy_' + n, 'Heavy', n === 1 ? 'active' : 'paused', now, now);
      entity.run(id, 'cve', 'CVE-2026-9001', now);
    }
    // Exactly 10 memberships, only 7 active.
    for (let n = 1; n <= 10; n++) {
      const id = 'bounded-' + n;
      watch.run(id, 'usr_bounded_' + n, 'Bounded', n <= 7 ? 'active' : 'paused', now, now);
      entity.run(id, 'cve', 'CVE-2026-9002', now);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    db.close();
    throw err;
  }
  return db;
}

function explain(db, sql, args) {
  return db.prepare('EXPLAIN QUERY PLAN ' + sql).all(...args).map(r => r.detail);
}

test('production SQLite migrations provision exact expected reverse index and independent keyset', () => {
  const db = seededDatabase();
  try {
    const indexes = db.prepare('PRAGMA index_list(watchlist_entities)').all().map(r => r.name);
    assert.ok(indexes.includes('idx_watchlist_entities_reverse'));
    const cursor = db.prepare("PRAGMA table_info(watchlist_eval_keyset_state)").all().map(r => r.name);
    assert.deepEqual(cursor, ['id', 'entity_type', 'entity_id']);
    const oldCursor = db.prepare("PRAGMA table_info(watchlist_eval_state)").all().map(r => r.name);
    assert.deepEqual(oldCursor, ['id', 'cursor']);
  } finally { db.close(); }
});

test('raw membership preflight uses indexed equality seek and detects 11-member rejection', () => {
  const db = seededDatabase();
  try {
    const sql = SOC_CRON_MEMBERSHIP_PROBE_SQL;
    assert.equal(SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS, 10);
    const plan = explain(db, sql, ['cve', 'CVE-2026-9001', 11]).join('\n');
    assert.match(plan, /SEARCH watchlist_entities USING INDEX idx_watchlist_entities_reverse/);
    const heavy = db.prepare(sql).all('cve', 'CVE-2026-9001', 11);
    assert.equal(heavy.length, 11);
    assert.ok(heavy.length > SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS);
    const normal = db.prepare(sql).all('cve', 'CVE-2026-9002', 11);
    assert.equal(normal.length, 10);
    assert.ok(normal.length <= SOC_CRON_MAX_WATCHLIST_MEMBERSHIPS);
  } finally { db.close(); }
});

test('active watcher join uses indexed membership search and primary-key watchlist join', () => {
  const db = seededDatabase();
  try {
    const sql = SOC_CRON_ACTIVE_WATCHERS_SQL;
    const plan = explain(db, sql, ['cve', 'CVE-2026-9002', 11]).join('\n');
    assert.match(plan, /SEARCH we USING INDEX idx_watchlist_entities_reverse/);
    assert.match(plan, /SEARCH w USING INDEX sqlite_autoindex_watchlists_1/);
    const active = db.prepare(sql).all('cve', 'CVE-2026-9002', 11);
    assert.equal(active.length, 7);
    assert.equal(new Set(active.map(r => r.watchlist_id)).size, 7);
    const mostlyPaused = db.prepare(sql).all('cve', 'CVE-2026-9001', 11);
    assert.equal(mostlyPaused.length, 1);
    // This single result alone must NEVER override the 11-member raw
    // preflight, which correctly rejects the expensive popular entity.
    assert.equal(db.prepare(SOC_CRON_MEMBERSHIP_PROBE_SQL)
      .all('cve', 'CVE-2026-9001', 11).length, 11);
  } finally { db.close(); }
});

test('bounded first and continuation index windows obey 128 raw row ceiling', () => {
  const db = seededDatabase();
  try {
    const firstPlan = explain(db, SOC_WATCH_WINDOW_FIRST_SQL, [128]).join('\n');
    assert.match(firstPlan, /USING COVERING INDEX idx_watchlist_entities_reverse/);
    const seekPlan = explain(db, SOC_WATCH_WINDOW_SEEK_SQL, ['cve', 'CVE-2026-1000', 128]).join('\n');
    assert.match(seekPlan, /SEARCH watchlist_entities USING COVERING INDEX idx_watchlist_entities_reverse/);
    const first = db.prepare(SOC_WATCH_WINDOW_FIRST_SQL).all(128);
    const seek = db.prepare(SOC_WATCH_WINDOW_SEEK_SQL).all('cve', 'CVE-2026-1000', 128);
    assert.equal(first.length, 128);
    assert.equal(seek.length, 128);
    assert.ok(seek.every(row => row.entity_id > 'CVE-2026-1000'));
    assert.equal(db.prepare(SOC_WATCH_WINDOW_FIRST_SQL).all(0).length, 0);
  } finally { db.close(); }
});

test('negative control: removing reverse index breaks indexed-seek acceptance', () => {
  const db = seededDatabase();
  try {
    db.exec('DROP INDEX idx_watchlist_entities_reverse');
    const plan = explain(db, SOC_CRON_MEMBERSHIP_PROBE_SQL, ['cve', 'CVE-2026-9002', 11]).join('\n');
    assert.doesNotMatch(plan, /USING INDEX idx_watchlist_entities_reverse/);
    const afterDrop = explain(db, SOC_WATCH_WINDOW_SEEK_SQL, ['cve', 'CVE-2026-1000', 128]).join('\n');
    assert.doesNotMatch(afterDrop, /idx_watchlist_entities_reverse/);
  } finally { db.close(); }
});

test('keyset cursor remains isolated from legacy numeric publisher cursor', () => {
  const db = seededDatabase();
  try {
    db.prepare('INSERT INTO watchlist_eval_state(id,cursor) VALUES (1,?)').run(13);
    db.prepare('INSERT INTO watchlist_eval_keyset_state(id,entity_type,entity_id) VALUES (1,?,?)')
      .run('cve', 'CVE-2026-9002');
    assert.equal(db.prepare('SELECT cursor FROM watchlist_eval_state WHERE id=1').get().cursor, 13);
    assert.equal(db.prepare('SELECT entity_id FROM watchlist_eval_keyset_state WHERE id=1').get().entity_id,
      'CVE-2026-9002');
  } finally { db.close(); }
});


test('legacy GitHub publisher now limits raw index rows before any cursor or event mutation', () => {
  const db = seededDatabase();
  try {
    assert.equal(GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS, 1024);
    const sql = SOC_WATCH_WINDOW_FIRST_SQL;
    const plan = explain(db, sql, [GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS + 1]).join('\n');
    assert.match(plan, /USING COVERING INDEX idx_watchlist_entities_reverse/);
    assert.doesNotMatch(sql, /DISTINCT|COUNT\s*\(|OFFSET/i);
    const rows = db.prepare(sql).all(GITHUB_WATCHLIST_MAX_RAW_MEMBERSHIPS + 1);
    assert.equal(rows.length, 1025);
    const source = read('api/_lib/change-engine.js');
    const store = read('api/_lib/watchlist-store.js');
    assert.match(source, /await store\.getBoundedLegacyWatchedEntityKeys\(\)/);
    assert.doesNotMatch(source, /await store\.getAllWatchedEntityKeys\(\)/);
    assert.match(store, /GITHUB_WATCHLIST_RAW_MEMBERSHIP_BUDGET_EXCEEDED/);
    // The separate optional SOC Cron path must retain its keyset scan.
    assert.match(source, /await store\.getWatchedEntityWindow\(/);
  } finally { db.close(); }
});

test('legacy GitHub index-scan acceptance fails after removal of the covering reverse index', () => {
  const db = seededDatabase();
  try {
    db.exec('DROP INDEX idx_watchlist_entities_reverse');
    const plan = explain(db, SOC_WATCH_WINDOW_FIRST_SQL, [1025]).join('\n');
    assert.doesNotMatch(plan, /idx_watchlist_entities_reverse/);
  } finally { db.close(); }
});
