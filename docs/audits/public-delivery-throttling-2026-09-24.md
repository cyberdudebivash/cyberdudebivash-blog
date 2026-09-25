# Public delivery throttling incident — 2026-09-24

| Proof before change | Evidence |
|---|---|
| Objective | Handle transient public HTTP throttling without hiding persistent delivery failures. |
| Affected files | scripts/check_blogger_public_delivery.py; .github/workflows/freshness-check.yml; tests/test_blogger_public_retry.py; this audit |
| Root cause | Run 36063705320, job 107848399115: public probe HTTP 429 at 21:49:02 UTC; local Blogger publication 21:35:55 UTC; post-recovery generator HEALTHY. Probe has no retry; alert blames recovered generator. |
| Reuse | Existing fetch/evaluate flow and freshness SLO; no publication or quality-gate changes. |
| Risk / blast radius | Low: read-only public probe and incident labeling only; three endpoints, at most three attempts each. Existing API, payment and publishing contracts unchanged. |
| Verification | Mock 429 then success, permanent 429, Retry-After numeric/date/oversized, nonretryable 401, endpoint diagnostics and alert ordering. Existing delivery checks retained. |
| Rollback | Revert the focused commit; never bypass the public delivery check. |

Requests remain bounded: 15-second HTTP timeout, maximum three attempts per endpoint, maximum 60-second wait per retry. Provider Retry-After beyond the local budget ends the check without an early retry. Persistent failure remains nonzero with no publishing recovery dispatch. No cloud services or workload cadence changes. A fresh ledger does not prove public availability. Live recovery requires a successful public probe on an actual runner.


A main-branch change to the probe or monitor triggers a read-only public-delivery canary with contents:read and no recovery dispatch. Scheduled/manual monitoring retains existing recovery behavior. Canary and scheduled runs use separate concurrency groups so a source change cannot cancel an active recovery. Seven local regression checks passed before PR creation.
