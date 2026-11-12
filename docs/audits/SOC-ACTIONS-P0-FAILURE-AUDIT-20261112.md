# SOC/CTI GitHub Actions P0 failure audit — 2026-11-12

**Status:** Source-only corrective PR #569; **PRODUCTION HOLD**.  
**Repository:** `cyberdudebivash/cyberdudebivash-blog`  
**Audit point:** 2026-11-12 ~17:10 UTC. Preserve exact run IDs and rerun checks on current main before any irreversible action.

## 1. Current production customer impact

| Owner / failure surface | Evidence | Classification | Resolution gate |
|---|---|---|---|
| SOC public root intelligence, two domains | [Production Smoke #43241381442](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43241381442) | Genuine P0; public SOC/blog `/live-intel.json` remained at 2026-10-23 04:58 UTC, 6,466 cumulative reports while source contained 7,412. The checker also flagged source publication age >180m. | Genuine publisher report+state freshness, canonical/static/S2N parity, reviewed deploy SHA, account-wide budget, owner-approved manual rollout, independent public verification. |
| SOC S2N API, two domains | Same smoke run | Genuine P0; `SOURCE_S2N_MALFORMED_OR_STALE`. This is not evidence that the published Worker is current. | Independently verify both `/api/intel/live.json` endpoints after approved release. |
| Internal native publisher cadence | [Native publisher #43203274256](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43203274256) | Genuine scheduling/reliability gap: `10:46 UTC` scheduled run generated 3 reports, 7/35 nonempty sources. Prior inspected scheduled run was at `02:44 UTC`, despite `:03/:33` cron; GitHub can delay/drop schedules. | Source `lastRun` AND `lastReportGeneratedAt` within policy window, minimum real source yield, no fabricated heartbeat. Inspect missed scheduling and capacity without creating new paid crons. |
| Intel Feed Freshness Monitor | [Freshness run #43182062247](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43182062247) | Real alert: public Blogger verification failed at that checkpoint, SOC root stale; after source recovery the public edge remained stale. Do not make the gate green by suppressing public checks. | Recent external publication evidence + SOC two-host parity. |
| Pipeline Health Certification | [Health certification #43131632732](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43131632732) | Correct fail-closed source assessment: observed source content age 193m and active coverage 9/35, not certified. | Real source update/coverage and passing classification at the time of release. |
| Blogger syndication | [Blogger publisher #43194131692](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43194131692) | Not a failed publishing job at 09:46 UTC: 4 posts marked LIVE, 0 failures, source and Blogger URL recorded. A subsequent dry window is a separate cadence/delivery SLO risk. | Separate real-publication fetch-back, homepage freshness, SLO and quality verification. |
| Production Drift Reconciler | [Drift #43252387085](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43252387085) | Diagnostic SUCCESS **not deployment**: `manual_release_required`, comparing last approved deployed SHA `365c89f34692cd94a860fbf0f95a0523f5f6f6aa` to `5098d04418761b6446f97f48568452a1cb11f13b`; 4,275 production-affecting, 205 operational, 136 nonproduction, 0 unknown (4,616 total). | Scope/impact review of giant drift; do not blindly ship unreleased changes. |
| Cloudflare production deploy | [Deploy run #43241381049](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43241381049) | Intentionally SKIPPED on push under manual-only policy, **not a workflow defect**. | Operator-signed exact-SHA workflow_dispatch only after safety gates. |
| Security, Jest, asset build | [Security #43241381245](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43241381245); [PR #568](https://github.com/cyberdudebivash/cyberdudebivash-blog/pull/568) | Recent latest verified jobs SUCCESS. Canceled superseded PR runs are not necessarily regressions. | Preserve baseline, require current-head CI. |

## 2. Defect identified and narrowly fixed in draft PR #569

`.github/workflows/sentinel-apex.yml` used:

```bash
timeout 290 node fetch-live-intel.js
EXIT_CODE=$?
```

GitHub's default `bash -e -o pipefail` shell exits before `EXIT_CODE=$?` for nonzero timeout return codes. The intended timeout classification/cleanup was unreachable. The PR wraps the process in an `if timeout ...; then ... else ... fi` status capture. Exit code 0 remains success; timeouts 124/143 preserve existing nonfatal pathway **only through the subsequent integrity/ledger/yield gates**; other codes remain fatal. A deterministic Node/Bash test runs exit 0/124/143/17 under `bash -e`. No schedule/permission change, new service or customer mutation.

## 3. Release plan and negative gates

1. Re-read protected current `main`; obtain customer-impacting patch/diff review and preserve the last known-good Worker version + rollback. **The PR does not authorize merge/deploy.**
2. Independently verify native publisher genuinely added reports and `live-intel.json`, `intel-state.json`, `api/intel/live.json` and built asset ledger are fresh and consistent, without fake timestamps or invented feed counts.
3. Capture a private Cloudflare ACCOUNT-WIDE usage/billing attestation no older than two hours, confirming 1.25× pace buffer, `<=80%` projected usage, `>=20%` reserve, and zero additional metered spend.
4. Review 4,275 production-affecting changes since the last approved deploy; classify every operational/security/backup/payment change. Do not treat an all-green source CI as release certification.
5. Obtain **explicit operator authorization for the exact current release SHA**, then use the already-guarded *manual* Cloudflare workflow, no automatic dispatch. No DNS changes.
6. Verify current intelligence, timestamp, counts and content/byte parity at FOUR URLs: both SOC/blog `/live-intel.json` and both `/api/intel/live.json`, plus authenticated customer, payment, tenancy, alert and backup/restore release canaries. Keep stale state visibly non-LIVE until successful.
7. Blogger is separate: verify live external posts and actual current theme export/restore via Blogger dashboard (not hypothetical theme API). Clear CTI assurance/false attribution separately under issue #222.

**Remaining status:** Production Smoke, public delivery freshness and managed SOC GA remain **NO-GO**. Do not close [#433](https://github.com/cyberdudebivash/cyberdudebivash-blog/issues/433) from source changes or diagnostic success.

**Observability constraints:** Public raw endpoints were not independently retrievable from the analysis browser during this checkpoint; most recent trustworthy public observations are CI logs as linked. Workflow history sample is the most recent 100 runs plus 100 failed runs, **not** exhaustive review of 32,000 historic runs.
