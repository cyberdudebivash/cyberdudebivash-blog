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
- A **confirmed explicit opt-out of both notification channels**, paused/deleted
  watchlist or removed membership yields a **skipped** terminal intent.
  Missing account email, incomplete enabled webhook, or legacy ambiguous
  `enqueued=false` without a verified `ALL_CHANNELS_DISABLED` reason
  must instead be **blocked**, never silently treated as customer opt-out.
- **Ambiguous enqueue fail-closed control:** if dispatch reports eligible
  channels but `enqueued=false`, the intent is marked `blocked` with
  `DELIVERY_STATE_AMBIGUOUS`, not `complete` and not automatically retried.
  A missing/malformed dispatch result **or a dispatch exception after a
  possible partial enqueue** is likewise blocked without automatic replay.
  An `enqueued=true` result must include nonempty recognized channel names.
  Multi-channel enqueue acknowledgements must prove **every eligible channel was newly inserted**. The underlying queue's `created=true` only means *at least one* insert succeeded; a partially pre-existing email/webhook pair is ambiguous and must be quarantined, not reported complete.
  A failure to persist `complete` after dispatch is also ambiguous and
  must not be retried automatically.
  This prevents
  false-green source acceptance when a pending job already exists or a
  previously delivered terminal job has been deleted. A verified first
  enqueue can mark the *outbox intent* complete, but not external delivery.
  Operator review of durable per-channel receipts is still mandatory.
- Persisted canonical event reads must match the claimed `event_id`, use a
  supported `cve`/`campaign` type, contain a nonempty entity ID and a
  parseable observation timestamp. An invalid event payload is **not** proof
  that a customer removed the entity: retry pre-dispatch with
  `EVENT_PAYLOAD_INVALID` and retain blocked incident evidence at the
  retry ceiling. Every entry returned in an owner-scoped entity membership
  array must have a supported type and nonempty ID; malformed arrays
  similarly retry instead of terminally skipping alerts.
- A returned owner-scoped watchlist must also carry an `id` exactly equal
  to the claimed `watchlist_id`; a missing or mismatched ID is uncertain
  dependency state, not authorization to skip, pause or dispatch. Native
  SQLite negatives cover wrong/missing identities and wrong paused IDs. Native SQLite
  negatives exercise scalar/array/wrong-event payloads, corrupt/mixed
  membership rows and later recovery. This does not certify external sends.
- Owner-scoped watchlist and entity membership checks only mark `skipped`
  for a confirmed `NOT_FOUND`, an explicitly `paused` watchlist, or an
  authenticated active list that no longer includes the event entity.
  Missing/malformed dependency responses and other error codes must **not**
  be interpreted as consent withdrawal: they retry before the outbound
  dispatch boundary with `DEPENDENCY_STATE_UNKNOWN`, then block after
  the bounded attempt ceiling. SQLite negative controls cover those
  responses, recovery and incident retention. This is not a native D1
  availability or recipient delivery certification.
- Retries **pre-dispatch** exceptional work with bounded backoff and stable claim tokens;
  at 5 unsuccessful attempts, marks a **blocked incident** for review.
  After the dispatch boundary, including failure to persist a successful
  enqueue acknowledgement, it quarantines immediately; no automatic retry.
  Errors cause the manual CLI to fail rather than claim successful service.
- **P0 replay/retention HOLD (24 October 2026):** `--prune-completed` is
  rejected before D1 access and `pruneCompleted()` fails closed. Completed
  and skipped intents are currently the only durable tombstones protecting
  deterministic event IDs from being restaged after 30-day deletion.
  Pruning them could re-create a customer alert or undo a prior opt-out.
  Do not schedule retention deletion until a reviewed canonical-event
  deduplication strategy, durable per-channel terminal receipt ledger,
  bounded privacy retention/tombstone policy, native D1 failure tests and
  owner approval exist. Indefinite tombstone retention is **not** a
  certified privacy policy; this is a temporary safety block, not GO.
- Reports only numerical metrics, never tenant IDs, payloads or secrets.

## Offline tests and control acceptance

Mandatory `node --test tests-js/soc-notification-outbox-native.test.js`
runs SQLite migration and real SQL statements on Node 22's native SQLite;
includes index plan, idempotent staging, duplicate memberships, false-green
negative gate, missing event recovery, tenant status/membership enforcement,
one-time delivery identity after partial failure, expired-lease quarantine,
bounded retry dead-letter, fail-closed retention replay negatives and manual CLI safety.
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
