# SENTINEL APEX SOC — bounded watchlist indexing / pre-revenue FinOps

**Status:** source patch for review only. Cloudflare account state unverified. No live D1 migration, Cron activation, deployment, DNS edit, payment or customer operation is part of this patch.

## Source risk and correction

PR #407 placed a hard 10-entity ceiling on the optional SOC Cron handler, but the existing getAllWatchedEntityKeys() enumeration reads the entire watchlist membership index before choosing those entities. This patch adds an independent boundedScan code path for the SOC Cron only.

- Migration 0017 creates watchlist_eval_keyset_state with an independent type/id marker and no full-table backfill; missing migration causes fail-closed errors before evaluation or delivery.
- The existing (entity_type, entity_id) covering index powers ordered range-seek queries returning no more than 128 raw membership rows per query. There is no DISTINCT, COUNT, GROUP BY, or OFFSET in the Cron candidate window.
- Duplicate memberships each consume one of the 128 window slots and are deduplicated in application code before up to 10 entities are evaluated.
- A separate numeric cursor and original full-index path remain for the existing GitHub alert-delivery workflow; its performance and cost profile are not changed or certified by this patch.
- Bounded mode returns watched_entities_total=null when the full universe is unknown, or 0 when an empty window is confirmed.
- The keyset cursor advances before evaluating entities to prevent one bad entity from wedging the sweep. It wraps to the start when no index rows remain after the saved key.
- A local SQLite EXPLAIN QUERY PLAN with 300 memberships confirmed the first window uses the covering index and later range seeks use an indexed SEARCH. This is not a representative production benchmark.

## Billing and customer-impact limitations

**DO NOT ENABLE the SOC Cron merely because this code exists.** It remains disabled unless CDB_SOC_CRON_ENABLED is the literal string true, and a deployed Cron still costs Worker invocations even while downstream processing is disabled.

128 is a query row limit, not a D1 billing hard cap. In particular, getWatchersForEntity can return all watchlists attached to an evaluated entity, and notification fan-out, history persistence, last-evaluated updates, CPU, logging, and delivery retries remain potentially expensive. Large shared watches can produce many D1 reads/writes despite a small candidate window. Concurrent Cron runs can also repeat work. Cloudflare account-wide usage from every platform remains unverified.

Before an authorized enablement: verify account-wide Cloudflare billing and 20% reserve; establish end-to-end fan-out and D1 rows-read/written ceilings with local native D1 tests; measure indexes at representative cardinalities; prove migration order, idempotency under simultaneous runs, customer delivery SLAs and safe rollback; obtain operator approval and confirm no unmodeled billable products.

**Decision:** SOURCE REVIEW ONLY. SOC first commercial service remains NO-GO pending hostname, origin, legal identity, customer-route and billing acceptance (#398 and #360). AI Security Hub cross-platform FinOps prerequisite is #1204. No deployment is authorized here.

## P0 Phase II — SOC scheduled watcher/event fan-out guard (PR successor to #408)

The optional `boundedScan` SOC Cron now performs **two bounded, fail-closed lookups** before evaluating an entity:

1. Read at most **11 raw watchlist memberships**, including paused memberships. If 11 are found, reject the entity without writing a snapshot, change event, feed or notification. This avoids running an unbounded active-watchlist JOIN simply to discover high fan-out. Paused memberships are deliberately counted to avoid hiding underlying D1 volume.
2. Only if the membership count is at most 10, read at most 11 active watcher rows using the existing reverse index and primary-key relationship. A concurrent over-limit result also rejects the entity. No authoritative claim is made that these queries consume only 11 billed D1 rows, particularly when the planner scans additional rows during joins; inspect D1 `meta.rows_read` and `meta.rows_written` before activation.

A successful preflight reuses the exact in-memory watchers for event fan-out and final last-evaluated updates, eliminating repeated watcher queries for each event in the optional SOC path. The **original GitHub publisher still uses `getWatchersForEntity()` as before**, and is not constrained to 10 memberships.

The optional Cron rejects an entire entity's change set **before writing any of its event IDs** when more than 2 events are detected, or when its candidate watcher-event pairs would exceed the remaining **40 pairs per run**. This preserves the event/snapshot state for a later separately authorized evaluation instead of knowingly emitting a partial subset and marking the rest already processed. Entities with no active watcher are skipped without a snapshot write. The pre-existing keyset cursor still advances before evaluating entities; blocked entities are not continuously retried or silently counted as delivered.

**These limits are protective operating controls, NOT absolute billing limits or customer SLA guarantees.** They do not cap all D1 operations: write amplification from secondary indexes, audit logs, multiple delivery channels, `owner_feed` retention, rescans after membership churn, other account Workers and scheduled triggers, or CPU/log consumption. Concurrent changes to memberships remain a race; a customer-accurate subscription snapshot, transactional outbox and per-account budget-enforcement design are required before enabling the scheduler for customer obligations. Existing GitHub-based change publishing also remains a separate cost model, not addressed here.

### Acceptance / NO-GO

- Require the native D1 query plan and representative `meta.rows_read`, `meta.rows_written` measurements, including 11+ watchers, mostly paused watchers, heavy multi-change events and concurrency.
- Run Jest `api/_lib/__tests__/change-engine.test.js`, watcher store tests and `workers/lib/router.test.js`; require passing exact-head CI.
- Reconcile a freshly observed whole-account Cloudflare bill and forecast at <=80% of each actual included allowance, including AI Hub, Threat Intel, Academy, NILACHALA, SOC, all other Workers, Queues, Logs, D1, KV, R2 and any paid add-ons. Independently verify actual plan entitlements and live schedules.
- **Keep `CDB_SOC_CRON_ENABLED` unset; no D1 migrations, deployments, schedule activation, DNS migration, plan changes, customer charges or paid service additions are authorized by this source PR.**
