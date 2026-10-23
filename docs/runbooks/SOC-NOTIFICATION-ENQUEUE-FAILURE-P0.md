# P0 SOC Alert Integrity — Notification Enqueue Failure Visibility

## Confirmed defect

The change engine persisted a newly identified threat-change event, then
performed per-watchlist feed fan-out and notification enqueue. A dispatch
exception was silently swallowed. A later replay of that same event did
not automatically re-enqueue the missing notification because idempotent
event persistence returned `created=false`.

This allowed a scheduled evaluation run to appear successful even when
one or more customer alert jobs had **never been enqueued**.

## Scope of this source correction

- Count notification enqueue exceptions for each entity evaluation without
  logging customer identifiers, provider exceptions, payloads, or secrets.
- Aggregate the count across the scheduled evaluation batch.
- Return a failed GitHub evaluation command if the count is nonzero, while
  retaining the existing feed update logic for other watchers.
- Include regression tests demonstrating both visibility and the
  **unrecovered replay limitation**.

## Critical residual risk

**This patch does not solve reliable replay or at-least-once enqueue.**
The event may have been persisted even if a notification enqueue failed.
A future evaluation can see the current fingerprint and skip new
notification creation. Manual incident reconciliation/requeue must not
invent events or send duplicate customer messages. A separately designed
bounded outbox or event-to-recipient reconciliation mechanism is necessary
to guarantee recovery, with idempotent keys, ownership checks, claims,
retention limits, backpressure, native D1 cost measurements, and privacy
controls.

This patch also cannot prove email delivery or webhook receipt: a
successfully enqueued job is not proof of an external sender or recipient.

## Production decision

- GitHub Action failed status is an honest alerting signal, **not**
  evidence that the unqueued notification was recovered.
- No additional Cron, Worker, D1 migration, Cloudflare mutation, DNS
  change, or customer delivery is authorized by this document.
- All active customer notification promises remain **NO-GO** until
  live delivery, replay safety and shared-account budget headroom are
  independently accepted.
