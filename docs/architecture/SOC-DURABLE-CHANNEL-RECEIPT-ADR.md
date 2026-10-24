# ADR (proposed): Durable per-channel SOC notification intents and receipts

**Status:** PROPOSED / NOT IMPLEMENTED / NO-GO  
**Scope:** #418, #360, #404, #400; review-only companion to draft PR #442.  
**Safety:** No live D1 migration, Worker/Cron activation, external sends, deployment, DNS or billing changes.

## Decision boundary

The existing `soc_notification_outbox` is an owner/watchlist/event *fanout* intent, not a durable record of each external notification. `notification_delivery_jobs` deletes terminal jobs, and the delivery log is trimmed. A stable job ID therefore does not establish whether a provider accepted a previous send. Draft PR #442 quarantines ambiguous replays, but cannot certify external delivery or recover all interrupted writes.

**Proposed design:** add a separate, durable per-(owner_id,event_id,channel) intent/receipt ledger. Keep it disabled until independently certified. Do not infer delivery from enqueue or from a missing queue row. External email and webhook delivery cannot be guaranteed exactly once without downstream idempotency/receipt support.

## Identity, schema, tenancy

Proposed table `soc_notification_channel_intents` (DDL requires separate reviewed migration):

| Column / constraint | Purpose |
| --- | --- |
| `owner_id, event_id, channel` composite primary key | One logical owner/event/channel delivery; duplicate watchlists cannot duplicate a send. `channel` is constrained to `email` or `webhook`. |
| `intent_id` unique opaque identifier | Stable, non-secret provider idempotency/correlation key; never regenerate on retry. |
| `source_watchlist_id`, `created_at_ms`, `updated_at_ms` | Minimal audit provenance; multiple matching watchlists do not create new channel intents. |
| `state` | `pending`, `claimed`, `accepted`, `cancelled`, `blocked`, or `provider_unknown`; `accepted` means provider accepted a request, **not** mailbox delivery. |
| `claim_token`, `lease_expires_ms`, `attempt_count`, `next_attempt_ms` | Compare-and-swap claims and bounded retry; indexes on due and expired windows. |
| `provider_request_id`, `accepted_at_ms`, `last_error_code` | Redacted acknowledgement/correlation metadata only; never store provider secrets, recipient addresses, webhook payloads, or raw response bodies. |
| `consent_version`, `channel_enabled_at_event` | Snapshot of eligible channels at event creation, subject to a **fresh disable/revocation check immediately before send**. |

Every lookup, claim, update, export and aggregate must be owner-scoped. No API may accept caller-supplied `owner_id` as authorization. Use the authenticated principal and explicit watchlist ownership check. Cross-tenant IDOR and aggregate negative tests are mandatory. Document retention and data-subject deletion behavior before migration; retention must preserve deduplication evidence for the entire possible replay horizon.

## Persistence ordering and recovery

1. **Before mutation**, validate the complete watcher set (maximum 10), unique owners/watchlists, channel eligibility and maximum 20 owner/channel intents for one event; reject over-budget work without advancing a snapshot. Do not truncate a query and silently omit watchers.
2. In one *verified* D1 atomic transaction/batch, persist the canonical change event, the complete deduplicated owner feed/fanout intents and per-channel intents, and advance the entity snapshot. If a required insert fails, roll back all writes. A SQL batch API is not assumed atomic until verified in the **native Worker D1 binding** with injected failures and actual read/write receipts.
3. The GitHub REST publisher transport may not share the same transaction boundary. It must use a recoverable two-phase event/snapshot journal with a deterministic event ID, durable `prepared` state and an idempotent recovery worker. Never advance its externally visible snapshot until all required channel intents are durably confirmed; if this invariant cannot be established, block that transport's notification release.
4. A consumer claims one channel intent using a conditional `pending -> claimed` update and a unique claim token; check consent/owner/channel status again before provider I/O. Disabled channels transition to `cancelled`, never `accepted`. Newly enabled channels do **not** retroactively receive historical events without a separately consented backfill.
5. Before a provider call, persist the stable `intent_id` as the outbound idempotency key and the irreversible-send boundary. Webhook requests should include a stable idempotency header and signed event identity; recipient implementations must prove deduplication or accept a documented at-least-once contract. For email, require a provider-specific idempotency capability or quarantine uncertain sends.
6. A verified provider acknowledgement conditionally transitions the same claim to `accepted` and stores a redacted provider request ID. Timeout, crash after send, expired claim or failure to persist acknowledgement transitions to `provider_unknown` (or is conservatively quarantined on recovery), **never automatic blind replay**. Distinguish provider acceptance from downstream delivery/bounce.
7. Retries are permitted only where a failure is provably *pre-send* or the provider has verified idempotency. Terminal `blocked` and `provider_unknown` rows require an authorized reconciliation decision with an auditable actor, reason and provider evidence.

**Critical crash boundaries to test:** before event write; after event write; after each fanout/receipt write; before snapshot advancement; after claim; after provider acceptance before acknowledgement; during acknowledgement write; during lease expiry; during duplicate scheduler execution; and during a transient D1 read failure. No test may infer successful delivery merely from a successful queue insert.

## Required acceptance evidence

- Real SQLite migration/uniqueness/transaction rollback tests, with `EXPLAIN QUERY PLAN` on bounded due/expired claims, duplicate watchlists, mixed channel opt-outs, and retention.
- Native Worker D1 transaction/failure-injection tests, `meta.rows_read`/`meta.rows_written` evidence, and GitHub REST transport journal recovery tests. No live D1 writes without separate owner approval.
- Concurrent scheduler/lease tests, provider timeout-after-acceptance, provider idempotency and webhook recipient replay tests, plus independent owner A/B cross-tenant negative tests.
- Real, consented provider receipt and bounce/failed-delivery evidence; no fabricated customer delivery or 24/7 monitoring claims.
- Account-wide Cloudflare cost model covering all active Workers/D1/KV/R2/Queues/DO/AI/logging products, current authenticated billing cycle, at least 20% projected reserve and 1.25x pace buffer. No new paid products or schedules by this ADR.
- Immutable reviewed SHA, branch/environment approval, manual release gate, canary and rollback plan; all require owner authorization.

**Release decision:** This ADR is design evidence only. Neither PR #442's green CI nor implementation of this design alone authorizes a SOC customer launch, a D1 migration, an external send, a billing change or a deployment.
