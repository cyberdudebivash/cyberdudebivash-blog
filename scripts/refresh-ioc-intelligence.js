#!/usr/bin/env node
'use strict';

/**
 * SENTINEL APEX evidence-only IOC refresh.
 *
 * Fetches each allowlisted source in config/ioc-sources.json, parses it with
 * api/_lib/ioc-engine/adapters.js, merges into the persistent store
 * (data/ioc-store.json), and publishes:
 *   data/ioc-feed.json     customer feed, bundled into the Worker, API-only
 *   api/intel/iocs.json    public value-free status summary (static asset)
 *
 * Failure model: each source is isolated (timeout, byte cap, parse errors)
 * and a failed source only marks the feed "degraded"; the stored indicators
 * from earlier runs remain and age normally. Nothing is written unless the
 * new feed passes validateFeed(); on any failure the previous files are the
 * last-known-good. Exit code: 0 when files were published (healthy or
 * degraded), 1 when nothing could be published.
 *
 * Usage: node scripts/refresh-ioc-intelligence.js [--offline <dir>] [--now <iso>]
 *   --offline <dir>  read <source-id>.<json|csv> from <dir> instead of fetching
 */

const fs = require('fs');
const path = require('path');
const { parseSource } = require('../api/_lib/ioc-engine/adapters');
const store = require('../api/_lib/ioc-engine/store');

const ROOT = path.resolve(__dirname, '..');
const PATHS = {
  config: path.join(ROOT, 'config', 'ioc-sources.json'),
  store: path.join(ROOT, 'data', 'ioc-store.json'),
  feed: path.join(ROOT, 'data', 'ioc-feed.json'),
  summary: path.join(ROOT, 'api', 'intel', 'iocs.json'),
};
const ALLOWED_HOST = /(^|\.)abuse\.ch$/;
const USER_AGENT = 'CYBERDUDEBIVASH-SENTINEL-APEX-IOC/1.0 (+https://blog.cyberdudebivash.in)';

function log(msg) { console.log(`[IOC] ${msg}`); }

/** SSRF guard: only https URLs on hosts the policy allows, from config only. */
function assertSourceUrl(url) {
  const u = new URL(url);
  if (u.protocol !== 'https:' || !ALLOWED_HOST.test(u.hostname) || u.username || u.password || u.port) {
    throw new Error('source_url_not_allowed');
  }
  return u;
}

/** Bounded fetch: timeout, byte cap, no redirects, conditional GET. */
async function fetchSource(source, cache) {
  assertSourceUrl(source.url);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Number(source.timeout_ms) || 30000);
  try {
    const headers = { 'User-Agent': USER_AGENT, Accept: 'application/json, text/csv;q=0.9' };
    if (cache && cache.etag) headers['If-None-Match'] = cache.etag;
    if (cache && cache.last_modified) headers['If-Modified-Since'] = cache.last_modified;
    const res = await fetch(source.url, { headers, redirect: 'error', signal: ctrl.signal });
    if (res.status === 304) return { notModified: true, status: 304 };
    if (!res.ok) throw new Error(`http_${res.status}`);
    const max = Number(source.max_bytes) || 25000000;
    const declared = Number(res.headers.get('content-length') || 0);
    if (declared > max) throw new Error('response_too_large');
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) { ctrl.abort(); throw new Error('response_too_large'); }
      chunks.push(value);
    }
    return {
      text: Buffer.concat(chunks.map(c => Buffer.from(c))).toString('utf8'),
      status: res.status,
      etag: res.headers.get('etag'),
      last_modified: res.headers.get('last-modified'),
      bytes: total,
    };
  } catch (e) {
    if (e && e.name === 'AbortError') throw new Error('timeout');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

function readOffline(dir, source) {
  for (const ext of ['json', 'csv']) {
    const f = path.join(dir, `${source.id}.${ext}`);
    if (fs.existsSync(f)) return { text: fs.readFileSync(f, 'utf8'), status: 200, bytes: fs.statSync(f).size };
  }
  throw new Error('offline_fixture_missing');
}

function errorClass(e) {
  const m = String((e && e.message) || e || 'error');
  return /^(timeout|response_too_large|source_url_not_allowed|offline_fixture_missing|http_\d{3}|invalid_json|unexpected_shape|missing_header|missing_column_[a-z_]+|unsupported_format)$/.test(m)
    ? m : 'fetch_error';
}

/**
 * Run one refresh. Exported for integration tests (`fetcher` is injectable).
 */
async function refresh({ now = new Date().toISOString(), fetcher, paths = PATHS } = {}) {
  const config = JSON.parse(fs.readFileSync(paths.config, 'utf8'));
  const st = store.readJsonFile(paths.store, null) || store.emptyStore();
  if (st.schema_version !== store.SCHEMA_VERSION) throw new Error('store schema_version mismatch');
  const runs = {};
  const telemetry = {};
  let anyIngested = false;

  for (const source of config.sources) {
    if (!source.enabled) continue;
    const started = Date.now();
    try {
      const r = await fetcher(source, st.http_cache[source.id]);
      if (r.notModified) {
        runs[source.id] = { state: 'not_modified', checked_at: now };
        telemetry[source.id] = { state: 'not_modified', http_status: 304, ms: Date.now() - started };
        continue;
      }
      const { candidates, tally } = parseSource(source, r.text);
      const { stats } = store.mergeCandidates(st, candidates, config.sources, now);
      st.http_cache[source.id] = { etag: r.etag || null, last_modified: r.last_modified || null };
      runs[source.id] = { state: 'ok', checked_at: now };
      telemetry[source.id] = { state: 'ok', http_status: r.status, bytes: r.bytes, ms: Date.now() - started, ...tally, merge: stats };
      anyIngested = true;
    } catch (e) {
      // Isolation: this source fails alone; its stored indicators are kept.
      runs[source.id] = { state: 'failed', checked_at: now };
      telemetry[source.id] = { state: 'failed', error: errorClass(e), ms: Date.now() - started };
    }
  }

  const okCount = Object.values(runs).filter(r => r.state !== 'failed').length;
  if (okCount > 0) st.last_success_at = now;
  store.refreshDerived(st, config.sources, now, config.revocations || []);
  const feed = store.buildFeed(st, config, runs, now);
  const problems = store.validateFeed(feed, config);
  if (problems.length) {
    return { published: false, problems: problems.slice(0, 20), telemetry, feed_status: feed.feed_status };
  }
  store.writeJsonAtomic(paths.store, st);
  store.writeJsonAtomic(paths.feed, feed);
  store.writeJsonAtomic(paths.summary, store.buildPublicSummary(feed), true);
  return { published: true, anyIngested, telemetry, feed_status: feed.feed_status };
}

async function main() {
  const args = process.argv.slice(2);
  const offIdx = args.indexOf('--offline');
  const nowIdx = args.indexOf('--now');
  const offlineDir = offIdx >= 0 ? args[offIdx + 1] : null;
  const now = nowIdx >= 0 ? new Date(args[nowIdx + 1]).toISOString() : new Date().toISOString();
  const fetcher = offlineDir ? async s => readOffline(offlineDir, s) : fetchSource;
  const result = await refresh({ now, fetcher });
  for (const [id, t] of Object.entries(result.telemetry)) log(`${id}: ${JSON.stringify(t)}`);
  const fsx = result.feed_status;
  log(`feed status=${fsx.status} indicators=${fsx.indicator_count} by_type=${JSON.stringify(fsx.by_type)} by_confidence=${JSON.stringify(fsx.by_confidence)} store=${fsx.store_size}`);
  if (!result.published) {
    log(`NOT PUBLISHED — feed failed validation; last-known-good retained: ${result.problems.join('; ')}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch(e => { console.error(`[IOC] refresh failed: ${errorClass(e)}`); process.exit(1); });
}

module.exports = { refresh, fetchSource, assertSourceUrl, readOffline, PATHS };
