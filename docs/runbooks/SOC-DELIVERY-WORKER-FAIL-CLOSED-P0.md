# SENTINEL APEX SOC — Delivery Worker Financial and Health Truth Gate

## Scope

The GitHub delivery processor `scripts/deliver-watchlist-notifications.js` is
the second step of the existing (unchanged) GitHub alert-delivery workflow.
It consumes already-enqueued D1 delivery jobs; it does not create detection
events and does not attest external email/webhook receipt.

### Source hardening

- CLI `--limit=N` accepts only one exact integer in **1..100**. Without a
  limit, the existing default remains 100. The scheduled workflow explicitly
  uses `--limit=50` and remains unchanged.
- Invalid, duplicated, partial-number, overflow and unknown options fail
  **before loading the D1 client** instead of silently falling back to default.
  No secrets are printed.
- `getOldestPendingAgeSeconds()` failure now marks the job red; it may no
  longer be converted to `null` and rendered as `n/a (queue empty)`.
  A true null returned by the D1-backed store still denotes an empty queue.
- Source CI has negative controls for CLI oversize, duplicates, malformed
  numbers, secret disclosure, backlog false-green and schedule stability.

### Limits and operational hazards

The queue reader and delivery sender have independent data/cost paths.
A bounded 50-job invocation is NOT proof of an account-wide cost ceiling,
no-overage forecast, delivery SLA, customer receipt or idempotent replay.

**Outstanding P0 #418:** The change-event write path lacks an atomic,
durable per-channel outbox. The event may persist before every required
customer delivery job is enqueued, while notification enqueue failures are
currently swallowed. Merely repeating fan-out is unsafe because completed
queue rows are deleted and delivery logs are capped; repeated sends may
occur. No replay-only patch may be merged as a substitute for a verified
durable intent ledger and failure-injection certification.

### Release

Keep GitHub scheduler cadence and Worker Cron activation unchanged. Do
not change account plans, D1 schema live, billing limits, email provider,
Cloudflare domains, DNS, credentials, customer data or payment state.
Account-wide Cloudflare FinOps approval, authenticated delivery receipts,
first-service endpoint/legal parity, and operator-reviewed manual deploy
remain required. **First paid SOC launch: NO-GO.**
