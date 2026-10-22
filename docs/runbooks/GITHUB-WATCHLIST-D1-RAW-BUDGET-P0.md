# P0 — Legacy GitHub Watchlist D1 Budget: Raw Membership Ceiling

## Root cause

The existing GitHub Action watchlist evaluator called
`store.getAllWatchedEntityKeys()`, executing an unrestricted
`SELECT DISTINCT entity_type, entity_id FROM watchlist_entities`.
A `--batch=200` limit applied **after** the D1 query, so it did not
limit membership discovery cost. Arbitrarily many customers could watch
a common entity; DISTINCT output could be tiny even after scanning a
very large number of underlying memberships.

## Source-only containment

The legacy GitHub evaluator now uses
`getBoundedLegacyWatchedEntityKeys()`. It reads **at most 1,025 raw
membership rows** using `SOC_WATCH_WINDOW_FIRST_SQL` (index-order,
no DISTINCT, COUNT or OFFSET) against the existing
`idx_watchlist_entities_reverse` covering index.

- When raw membership count is 1,024 or fewer, the method de-duplicates
  entity pairs in JavaScript and retains the **existing GitHub numeric
  cursor** and selected-entity evaluation semantics.
- When the query returns 1,025 rows, it throws
  `GITHUB_WATCHLIST_RAW_MEMBERSHIP_BUDGET_EXCEEDED` **before** the
  numeric cursor, snapshot, event or notification is updated.
- The independent optional SOC Worker Cron keyset state, its index
  window and its disabled-by-default configuration are untouched.
- Existing D1 migration `0002` already defines the covering reverse
  index; this change **does not require a new D1 migration**.

This limit is a **hard operational capacity ceiling** on the legacy
publisher. If it is reached, GitHub should report a RED job and the
operator must preserve the alert outage evidence. Do not silently
increase the limit to unblock customers: separately design and
rehearse a native keyset/cursor publisher that preserves delivery
semantics, enforces fanout cost budgets, and requires account-wide
Cloudflare financial authorization.

## Scope limits / assertions that must not be made

The indexed-query source and offline SQLite query plan establish
bounded **raw index row retrieval** for this discovery call, not a
guarantee of native D1 `meta.rows_read` or any zero-overage invoice.
Other legacy operations, including watcher fanout, per-owner feed
updates and delivery dispatch, can still consume significant D1
operations. Entire GitHub scheduled alert delivery was not live
certified when this change was prepared; missing GitHub Actions
D1 secrets were previously observed.

This is NOT certification of payment, actual customer notification
delivery, first SOC customer service, current Cloudflare Worker Cron
state, or Cloudflare account-wide headroom.

## Acceptance and go/no-go

Run exact-head CI: existing engine integration tests, three newly added
Jest budget/cursor tests, native SQLite query-plan ceiling + negative
index-removal controls, build verification, governance, resilience and
security. Confirm the GitHub job fails explicitly for oversized
membership sets. During first reviewed release, require private
operator verification of D1 credentials and actual Cloudflare
billing-cycle balances before executing this scheduler.

**Production customer release: NO-GO.** No secret, DNS, schedule,
Cloudflare Worker, D1 migration or billing mutation is permitted by
this source-only change.
