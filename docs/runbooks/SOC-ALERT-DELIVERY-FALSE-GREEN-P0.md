# SOC Watchlist Alert Delivery — P0 False-Green Incident and Runbook

**Operational decision: NO-GO for claims of verified automated customer alert delivery.**

## Evidence

On **2026-10-22 17:49:56 UTC**, GitHub Actions scheduled run
[`#39826095933`](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39826095933)
reported overall success while **both** operational steps
(`Evaluate watchlist changes` and `Deliver due alerts`) had the
`skipped` conclusion.

The preflight log reported that `CLOUDFLARE_ACCOUNT_ID`,
`CLOUDFLARE_D1_DATABASE_ID` and/or `CLOUDFLARE_API_TOKEN` were not all
configured as GitHub Actions repository secrets. It did **not** establish
which individual value was absent, whether a live D1 exists, or whether
another independent alert delivery runtime was operational.

The previous workflow intentionally emitted a warning, skipped both
customer-facing steps, and exited successfully. A successful scheduler
process is not evidence that notifications were evaluated or sent.

## Source fix (no production changes)

A dedicated `scripts/alert-delivery-execution-gate.cjs` validates five
**boolean presence flags only**. It does not receive secret values or
call Redis, Cloudflare, a network endpoint or a billing API.

If any prerequisite is missing, it emits deterministic codes and exits
nonzero *before* the evaluation and delivery steps. The conditional
skip clauses have been removed; a successful job now requires that both
operations actually run and finish successfully. This is not proof that
all eligible customers received notifications, nor that customers had
matching events.

The current `27,57 * * * *` scheduler, read-only repo permission, and
serial execution remain unchanged. Existing D1 REST and Redis values
are **not** to be copied to public issues, logs, screenshots or pull requests.

An intentionally failed preflight may produce repeated red scheduled runs
until configuration is restored. These reflect the operational outage,
not a newly introduced cloud API workload. Owner should coordinate
GitHub Actions minutes/limits with existing platform financial policy;
do not add polling, schedule frequency or metered Cloudflare operations.

## Operator readiness requirements

1. Verify required secrets exist **privately** in GitHub Actions for the
   intended protected deployment environment, not only in Cloudflare Worker
   secrets. Use least privilege and rotate exposed credentials. Do not
   print, paste or commit actual values.
2. Confirm the correct account, D1 resource, network credentials, migrations,
   and operational permissions using an authorized read-only procedure.
   Do not run production SQL migrations to "fix" missing credentials.
3. Review independent Cloudflare Worker Cron availability; the GitHub
   bridge is not proof of an enabled/working Worker Cron.
4. Obtain account-wide Cloudflare billing-cycle usage and verified allowance
   headroom before enabling any additional schedules or workloads.
5. After approved configuration recovery, certify a GitHub run where the
   preflight, evaluate step and deliver step each succeed. Record job
   conclusions, bounded outcome metrics, mail/webhook transport health,
   and any actual customer acceptance evidence without PII.
6. Evaluate failure modes (expired token, denied D1 access, Redis outage,
   no recipients, retry/dead-letter) separately. Preflight checks secret
   *presence* only and must not be called production alert certification.
7. Keep first paid SOC customer offering and managed monitoring promises
   gated by SOC issue #398 and platform issue #360.

**Source PR only.** This runbook does not authorize modifying GitHub
repository secrets, live Cloudflare DNS, Worker domains, D1 databases,
billing plans, customer data, live schedules, payments or customer claims.
