/**
 * SENTINEL APEX — Cloudflare D1 Client (alert-delivery control plane)
 *
 * Mirrors redis.js's shape on purpose: a thin query primitive reachable
 * via plain fetch() from anywhere (Node, GitHub Actions, or Cloudflare
 * Workers), so notification-store.js can move onto D1 in place without
 * widening workers/lib/router.js#dispatch()'s handler signature to thread
 * `env` through ~30 unrelated Vercel-style (req,res) handlers -- confirmed
 * via a fresh read of router.js that dispatch() calls `handler(req, res)`
 * with no env param at all, which rules out a native-binding-only design.
 *
 * Two transports, chosen automatically at call time:
 *
 *   1. Native env.DB binding (Cloudflare Workers, zero HTTP round trip) --
 *      refreshed from each Worker request via setD1Binding(env.DB), mirroring
 *      workers/lib/resvg-wasm-init.js's setWasmModule() precedent exactly:
 *      module-level mutable var + explicit setter, called from
 *      workers/entry.js before the first request.
 *
 *   2. D1 REST API (Node / Vercel / GitHub Actions fallback) -- POST
 *      https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{db}/query,
 *      Bearer-token auth via CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID /
 *      CLOUDFLARE_D1_DATABASE_ID. The endpoint and its multi-statement
 *      `sql` field (semicolon-joined statements executed as one call,
 *      returning one result per statement) are confirmed current and real
 *      via a live captured example (lambrospetrou.com/articles/hurl-
 *      cloudflare-d1/) and via this repo's own `wrangler d1 execute
 *      --local` runs against migrations/0001_notification_delivery.sql --
 *      not assumed from training data.
 *
 * runMutationWithChanges() below deliberately does NOT read
 * meta.changes / meta.rows_written to learn how many rows a statement
 * affected. Those fields could not be confirmed with confidence from this
 * sandbox: Cloudflare's own API-reference pages are JS-rendered SPAs that
 * return no usable content via fetch, `wrangler d1 execute --local`'s own
 * JSON output (checked directly, including with --json) never populates
 * anything in `meta` beyond `duration`, and the one real captured REST
 * example found did not exercise a mutating statement. Rather than ship a
 * claim/idempotency mechanism resting on a field this session could not
 * verify, this file appends `SELECT changes() AS affected;` as a second
 * statement after every mutating statement that needs its own row count,
 * and reads the answer back as an ordinary query result row -- a
 * mechanism empirically verified locally before notification-store.js was
 * migrated onto it: a conditional UPDATE claim reports affected=1 then
 * affected=0 on a repeated race, INSERT...ON CONFLICT DO NOTHING reports
 * affected=1 then affected=0 on a duplicate, and DELETE reports affected=1
 * then affected=0 once the row is gone. This is portable across both
 * transports for free -- changes() is a plain SQLite function, not a
 * driver-specific extra -- and sidesteps the meta-field ambiguity
 * entirely rather than trusting it. Per the migration mandate's own
 * instruction: verify current behavior before implementing, and if a
 * property can't be confirmed, choose a stronger primitive rather than
 * ship something resting on an assumption.
 */
'use strict';

const { isCloudflareWorkers } = require('./runtime-env');

const ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID || '';
const DATABASE_ID = process.env.CLOUDFLARE_D1_DATABASE_ID || '';
const API_TOKEN = process.env.CLOUDFLARE_API_TOKEN || '';
const REST_ENDPOINT = ACCOUNT_ID && DATABASE_ID
  ? `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/d1/database/${DATABASE_ID}/query`
  : '';

let nativeBinding = null;

// Refreshed by workers/lib/router.js for each Worker request (including
// explicit null when env.DB is missing). A missing Worker D1 binding MUST
// NOT inherit prior state or trigger REST fallback. Node / GitHub Actions
// retain their explicitly configured REST transport.
function setD1Binding(db) {
  nativeBinding = db;
}

function isConfigured() {
  return Boolean(nativeBinding) || (!isCloudflareWorkers() && Boolean(REST_ENDPOINT && API_TOKEN));
}
// Only expose binding presence, never a customer database handle or token.
// Used by the Worker routing regression to verify stale bindings are gone.
function hasNativeBinding() {
  return Boolean(nativeBinding);
}

// Only warns on the Node path: at module-load time nativeBinding is
// ALWAYS null even inside a real Worker (setD1Binding() runs a moment
// later, once entry.js's top-level code executes) -- warning
// unconditionally here would fire a false positive on every Workers
// isolate boot, not just a genuinely misconfigured Node environment.
if (!isCloudflareWorkers() && !(REST_ENDPOINT && API_TOKEN)) {
  console.warn('[D1] CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_D1_DATABASE_ID / CLOUDFLARE_API_TOKEN not set — D1 REST API unavailable (Node/GitHub-Actions path only; Cloudflare Workers uses the native env.DB binding via setD1Binding() instead).');
}

// statements: [{ sql, params }, ...]. Returns one { results, success, meta }
// per statement, in order -- same shape regardless of transport.
async function exec(statements) {
  if (nativeBinding) {
    if (statements.length === 1) {
      const { sql, params } = statements[0];
      const stmt = nativeBinding.prepare(sql);
      const bound = params && params.length ? stmt.bind(...params) : stmt;
      const result = await bound.run();
      return [{ results: result.results || [], success: result.success !== false, meta: result.meta || {} }];
    }
    const prepared = statements.map(({ sql, params }) => {
      const stmt = nativeBinding.prepare(sql);
      return params && params.length ? stmt.bind(...params) : stmt;
    });
    const results = await nativeBinding.batch(prepared);
    return results.map(r => ({ results: r.results || [], success: r.success !== false, meta: r.meta || {} }));
  }

  // Workers must never silently fall back to an authenticated external
  // Cloudflare REST call when env.DB is absent. Missing native binding is a
  // release/configuration failure, not permission for extra HTTP/usage.
  if (isCloudflareWorkers()) throw new Error('D1 native binding required in Worker');
  if (!REST_ENDPOINT || !API_TOKEN) throw new Error('D1 not configured');
  // A single ;-joined sql string, one flat params array. The only
  // multi-statement caller in this file (runMutationWithChanges) always
  // pairs a statement that owns every `?` placeholder with a trailing
  // `SELECT changes()` that has none -- so whichever way D1 applies a
  // flat params array across a multi-statement string, the result is
  // identical here; this file does not depend on resolving that ambiguity.
  const sql = statements.map(s => (s.sql.trim().endsWith(';') ? s.sql.trim() : `${s.sql.trim()};`)).join(' ');
  const params = (statements[0] && statements[0].params) || [];
  const res = await fetch(REST_ENDPOINT, {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(params.length ? { sql, params } : { sql }),
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`D1 REST HTTP ${res.status}`);
  const json = await res.json();
  if (!json.success) {
    const msg = (json.errors || []).map(e => e.message).join('; ') || 'unknown error';
    throw new Error(`D1 REST error: ${msg}`);
  }
  return json.result.map(r => ({ results: r.results || [], success: r.success !== false, meta: r.meta || {} }));
}

/** One read-only statement. Returns the row array directly (mirrors redis.js's unwrapped-value convention). */
async function query(sql, params = []) {
  const [result] = await exec([{ sql, params }]);
  return result.results;
}

/** One mutating statement where the affected-row count doesn't matter (append-only log inserts, best-effort trims). */
async function run(sql, params = []) {
  const [result] = await exec([{ sql, params }]);
  return result;
}

/**
 * The claim/idempotency/completion primitive: runs one mutating
 * statement (UPDATE, DELETE, or INSERT ... ON CONFLICT DO NOTHING) and
 * returns exactly how many rows it changed, via the empirically-verified
 * SELECT changes() follow-up described in this file's header -- never via
 * meta.changes/rows_written. `sql` must be a single statement with no
 * trailing semicolon of its own.
 */
async function runMutationWithChanges(sql, params = []) {
  const results = await exec([{ sql, params }, { sql: 'SELECT changes() AS affected', params: [] }]);
  // A missing/failed receipt is not evidence of a zero-row mutation. In
  // particular, silently converting a malformed REST/native D1 response to
  // zero can make outbox claim/staging logic misclassify a committed write.
  if (!Array.isArray(results) || results.length !== 2 ||
      results.some(r => !r || r.success !== true || !Array.isArray(r.results))) {
    throw new Error('D1_MUTATION_RECEIPT_UNVERIFIED');
  }
  const rows = results[1].results;
  if (rows.length !== 1 || !rows[0] ||
      !Number.isSafeInteger(rows[0].affected) || rows[0].affected < 0) {
    throw new Error('D1_MUTATION_RECEIPT_UNVERIFIED');
  }
  return rows[0].affected;
}

module.exports = { query, run, runMutationWithChanges, setD1Binding, isConfigured, hasNativeBinding };
