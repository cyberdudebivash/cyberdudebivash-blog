# SENTINEL APEX SOC — Durable Notification Outbox, P0 Release Gate

**Change type:** additive, source-only, feature OFF by default.
**Business service status:** NO-GO for paid or automated customer alert promises.
**Not a SOC 2 audit or certificate.** Control engineering requires implemented,
operating and independently evidenced controls across a defined audit period;
this source PR proves none of those operational outcomes.

## Failure mode and controlled mitigation

Existing watchlist change detection could persist a change event and then
fail before owner-specific notification jobs were created. A repeat evaluation
saw the already-persisted event and/or unchanged snapshot and could never
replay the missing fan-out. PR #421 reported the error but did not recover it.

New **migration 0018** creates `soc_notification_outbox`: one durable
intent per (event_id, watchlist_id, owner_id), with atomic unique-key
deduplication, explicit states, attempt limit, claim token, lease expiry,
backoff and indexed due queue. Identifiers are stored, not email addresses,
webhook credentials, signing secrets or the event payload.

**Gated evaluator** (`CDB_SOC_OUTBOX_ENABLED=true` ONLY after approval):
1. Reuse the existing maximum-ten raw watcher preflight and two
   events/entity, 40 fanout pairs/run safeguards.
2. Stage each prospective event/watchlist/owner intent in D1 BEFORE writing
   the change_event or moving the snapshot.
3. If staging or migration fails, throw before event mutation. If staging
   succeeds but event persistence fails, the pending intent remains for
   bounded retry when the event eventually appears.
4. The gated path does not directly send alerts or write the owner feed.
   The separate reconciler replays the feed insertion and durable
   notification-job enqueue. Existing feed and delivery-job keys are
   idempotent. Normal disabled production behavior is unchanged.

**Reconciler** (`scripts/reconcile-soc-notification-outbox.js`):
- Runs **only with explicit** `--apply`,
  `CDB_SOC_OUTBOX_ENABLED=true`, and
  `CDB_SOC_OUTBOX_OPERATOR_APPROVED=true`. No Cron or workflow calls it.
  Invocation with no args performs NO D1/network operation.
- Selects at most **5** due intents, using indexed pending and expired
  claim windows, with conditional atomic claim and 90-second lease.
  **Expired claims are quarantined** as `DELIVERY_STATE_AMBIGUOUS`, not
  re-dispatched: the crashed worker may have enqueued a job or reached a
  provider before its acknowledgement was recorded. This conservatively
  blocks some pre-dispatch crashes until manual review; it avoids an
  unsupported exactly-once delivery claim.
- Reads canonical event, proves watchlist belongs to the intended owner,
  is active and still includes that entity, then replays the owner feed
  and idempotently queues eligible email/webhook channels.
- A disabled channel, paused/deleted watchlist or removed membership
  yields a **skipped** terminal intent, never customer delivery.
- **Ambiguous enqueue fail-closed control:** if dispatch reports eligible
  channels but `enqueued=false`, the intent is marked `blocked` with
  `DELIVERY_STATE_AMBIGUOUS`, not `complete` and not automatically retried.
  A missing/malformed dispatch result **or a dispatch exception after a
  possible partial enqueue** is likewise blocked without automatic replay.
  An `enqueued=true` result must include nonempty recognized channel names.
  A failure to persist `complete` after dispatch is also ambiguous and
  must not be retried automatically.
  This prevents
  false-green source acceptance when a pending job already exists or a
  previously delivered terminal job has been deleted. A verified first
  enqueue can mark the *outbox intent* complete, but not external delivery.
  Operator review of durable per-channel receipts is still mandatory.
- Retries **pre-dispatch** exceptional work with bounded backoff and stable claim tokens;
  at 5 unsuccessful attempts, marks a **blocked incident** for review.
  After the dispatch boundary, including failure to persist a successful
  enqueue acknowledgement, it quarantines immediately; no automatic retry.
  Errors cause the manual CLI to fail rather than claim successful service.
- Optional `--prune-completed` removes only up to 5 completed/skipped
  intents older than 30 days. It never deletes pending, claimed or
  blocked evidence. Retention and legal scope still require approval.
- Reports only numerical metrics, never tenant IDs, payloads or secrets.

## Offline tests and control acceptance

Mandatory `node --test tests-js/soc-notification-outbox-native.test.js`
runs SQLite migration and real SQL statements on Node 22's native SQLite;
includes index plan, idempotent staging, duplicate memberships, false-green
negative gate, missing event recovery, tenant status/membership enforcement,
one-time delivery identity after partial failure, expired-lease quarantine,
bounded retry dead-letter, terminal-only retention and manual CLI safety.
Existing Jest / E2E / governance / security checks remain mandatory.

## Security / privacy / service caveats

- Staging is **not atomic with the change_events insert**. The ordering
  prevents the old missing-outbox failure for newly staged events when
  enabled, but can leave a pending orphan if event insertion never succeeds.
  Reconciliation marks repeated missing-event cases blocked; it does not
  fabricate events. Formal transactional guarantees need native D1
  review and crash/fault-injection certification.
- Retention, consent, incident management, access reviews, audit immutability,
  vendor compliance, change approvals, data geography, backup/restore,
  disaster recovery, vulnerability management and operational SOC 2 control
  performance still require evidence.
- Successful enqueue is NOT proof of email/webhook send or external receipt.
  The underlying notification_delivery_jobs table deletes terminal jobs;
  its stable delivery ID alone is NOT a durable per-channel deduplication
  ledger. A crash after an external provider accepts a send but before
  recording its receipt remains an unresolved duplicate-delivery risk.
  Do not enable customer alerts until a durable channel-intent/receipt
  design and provider-specific idempotency or documented at-least-once
  delivery policy have passed independent acceptance.
  This branch does not enable delivery providers or establish an SLA.
- This source PR does not migrate old events or recover prior customer
  omissions. That requires separate forensic reconciliation with consent
  and historical evidence.
- D1 billed `meta.rows_read`, Worker invocation/storage headroom and
  billing for ALL ecosystem properties MUST be verified privately from
  the authenticated Cloudflare account, not inferred from SQLite.
- Existing 29 unclassified drift files, manual release, domain routing,
  customer service acceptance, terms/privacy and legal seller identity
  remain separate P0 gates.

## Change and rollout gates

**No remote D1 migration or live scheduler activation** was performed.
Before GO: review PR code and all tests, document authorized Cloudflare
account-wide budget/limits, conduct bounded real D1 read-cost rehearsal,
run isolated tenant/paused/removed/fault-injection acceptance, prove
first actual recipient delivery receipts, certify purge/incident audit logs,
capture before/after manual deployment hashes, test rollback, and obtain
operator release authorization. Do not use customer traffic as a test bed.

If any precondition fails: keep feature flag OFF and customer release NO-GO.
