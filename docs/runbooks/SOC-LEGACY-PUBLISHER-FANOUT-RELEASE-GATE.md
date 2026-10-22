# P0 — GitHub bridge fan-out cost-guard review

This source-only patch applies the existing indexed maximum-11 raw-membership probe and maximum-11 active-watcher JOIN to **both** scheduled evaluation paths. The legacy GitHub alert publisher previously capped its global raw index discovery at 1,025 rows but could still retrieve arbitrarily many watchers for an individual entity.

## Safety properties

- Reject more than 10 memberships (including paused) **before** persisting a new change event, feed item, notification, or snapshot.
- Skip entities with no active watchers. Enforce 2 detected events/entity and 40 fan-out pairs/evaluation run, even when the GitHub CLI allows a 200-entity batch.
- Rejected entities are intentionally **deferred**, not silently treated as successfully evaluated: the legacy numeric cursor continues advancing, and a subsequent sweep can revisit them. A repeatedly over-budget entity can remain without new alerts indefinitely. Do **not** promise complete coverage or a 30-minute SLO while this limit is in place.
- The existing change-event write/fan-out is not transactional. A crash after event persistence or during fan-out can still leave missed subscriber deliveries on replay because event IDs are idempotent. This PR does **not** solve that separate P0 gap.
- Native SQLite query-plan tests confirm the indexed probe, not actual Cloudflare billable D1 `rows_read`. Per-resource and combined paid-account usage must still be certified.

## Required approval checks

1. Offline tests, SQLite query plans and exact-head GitHub CI pass.
2. Review whether postponing popular shared entities meets *first sellable service* requirements; if not, keep release blocked and implement durable per-owner delivery reconciliation.
3. Confirm live D1 schema/index, measured `meta.rows_read` and account-wide budget, then run staged customer acceptance tests (initial baseline, change, paused watcher, retry, failure injection, idempotency).
4. Obtain explicit operator approval before deployment, migration, enabling Cron, customer enrollment or paid alert activation.

No Cloudflare credentials, migration, Cron, external delivery or production billing action is exercised by this patch.
