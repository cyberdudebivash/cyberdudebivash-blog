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