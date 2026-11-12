# SOC P0 Phase 4: publisher provenance, CISA KEV reconciliation and release evidence

Evidence date: 2026-11-12 (UTC). Repository: `cyberdudebivash/cyberdudebivash-blog`. Scope: `soc.cyberdudebivash.in` and the
shared feed on `blog.cyberdudebivash.in`.

**Status of this document: EVIDENCE ONLY. Nothing here deploys, approves or certifies a release.** No production write,
deployment, publisher dispatch, purge, migration, charge or notification was made by the author of this document. All
production observations are read-only `GET` requests. It contains no secret, credential, account identifier or personal data.

Confidence labels: **Verified** (observed directly from a primary source in this session) · **Partially Verified** ·
**Not Verified** · **Proposed** · **Blocked** (needs an owner-run step; not guessed).

Earlier prior-art, for the first-failing-boundary analysis, is in `SOC-P0-GITHUB-ACTIONS-RECOVERY-20261023.md` and
`SOC-FULL-TREE-PRODUCTION-DRIFT-P0.md`. Those are reference material; the statements below were re-checked against the
current repository and live GitHub run records.

---

## 0. Decision

| Platform | Decision | Why |
|---|---|---|
| SOC (`soc.` and `blog.` feed hosts) | **NO-GO** for customer production | Source is healthy and fresh; the **edge still serves the 2026-10-23 bundle** (6,466 reports). The deploy workflow is manual-only and has not run since. A release also needs an owner cost attestation, an approved exact SHA, a ≤180-minute-old report, and reviewed drift. None can be supplied from the repository. |

Highest-risk findings, in business order:

1. **Customers see a 20-day-old feed (Verified, section 4).** Persisted source is current (7,435 reports at 17:31Z); public bytes are unchanged since 2026-10-23. The 946-to-969-report gap is publication drift, not a delivery failure.
2. **The publisher was dark for about three days and the cause is now known (Verified for 5 of 20 failed runs, section 1).** A fail-closed homepage integrity gate rejected a valid run until #555 aligned it with the feed-only homepage.
3. **KEV flags were wrong in the committed feed (Verified, now corrected and re-verified by a new run, section 2).**
4. **Deployment provenance of the 2026-10-23 edge bundle is still unexplained (Not Verified).** Needs the owner-run reads in section 6.

---

## 1. Publisher forensics (4A)

### 1.1 The newest genuine runs

| Run | Trigger | Code at checkout | Result | Commit written | Feed `generatedAt` | Reports |
|---|---|---|---|---|---|---|
| [4461 / 43265767941](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43265767941) | `workflow_dispatch` by `github-actions[bot]` (freshness-monitor recovery) | `5098d044` (#568) | success, 17:05:49Z to 17:06:51Z | `e04985d3d` 17:06:44Z | 2026-11-12T17:06:23.895Z | +8, total 7,420 |
| [4463 / 43270219921](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/43270219921) | `push` of #573 (that merge changes the workflow file, which is a push trigger) | `939bbfc81` (includes #570, #571, #572, #573) | success, 17:30:48Z to 17:31:38Z | `27bd783c1` 17:31:32Z | 2026-11-12T17:31:10.468Z | +15, total 7,435 |

No run in this table was dispatched by the author of this document. Run 4462 (push of #569, 17:10:56Z) concluded `cancelled`;
the cancellation reason was not read (**Partially Verified**: the publisher workflow runs in a shared writer concurrency group).

### 1.2 Stage-by-stage timeline for the 17:30Z run (Verified from job step records and the commit)

| Stage | Result | Evidence |
|---|---|---|
| Scheduled / triggered | `push` event on `main` | run 4463 record |
| Started | 17:30:48Z on a real runner | `runner_id` non-zero |
| Ingested | 15 reports generated from live sources | commit message `+15 reports ... total=7435, 15srcs` |
| Validated | homepage precommit integrity gate, finalized-ledger gate and source-yield gate passed (**Partially Verified**: inferred from the run concluding `success`; this run's step list was not read) | run 4463 conclusion |
| Generated | `live-intel.json` `generatedAt` 17:31:10.468Z, `lastPipelineRun` 17:31:30.053Z | feed at `27bd783c1` |
| Committed | `27bd783c1` 17:31:32Z | `git log origin/main` |
| Published to GitHub `main` | yes | same |
| **Published to the edge** | **no. Deployment is manual-only (section 4).** | production probes, section 4 |

### 1.3 Why no newer artifact was persisted from 2026-11-07 to 2026-11-10 (the dark window)

The publisher listing shows 20 consecutive `failure` conclusions, runs 4429 to 4448, from 2026-11-07T21:36Z to 2026-11-10T17:50Z (68 h).
Run 4449 (schedule, 2026-11-10T19:55Z) was the first success after #555 merged at 19:46:59Z.

I inspected the job steps of five of the twenty (**Verified**) and the full log of one:

| Run | Time | Failing step | Reports persisted? |
|---|---|---|---|
| 4429 | 11-07 21:36Z | post-commit "P0 source-yield truth, block false green pipeline" | **yes**: the commit step succeeded first |
| 4430 | 11-08 01:11Z | same | yes |
| 4441 | 11-09 11:06Z | **"P0 homepage precommit integrity gate"** | **no**: commit and ledger steps skipped |
| 4444 | 11-10 02:08Z | same | no |
| 4448 | 11-10 17:50Z | same | no (13 reports generated and then discarded) |

For 4448 the gate printed `Error: P0 homepage integrity failure (publisher precommit): featured report marker exists`
(`HOMEPAGE_INTEGRITY_FAILED`, thrown at `scripts/soc-homepage-integrity.js:27`). The pipeline itself had succeeded
(15 of 35 sources returned data, "CISA KEV feed active", 13 new reports); the gate demanded a static "featured report marker"
that the feed-only homepage no longer contains. #555 ("keep SOC live homepage feed-only and unblock truthful publisher gate",
merged 2026-11-10T19:46:59Z) changed the gate, `fetch-live-intel.js` and the tests together; the next run succeeded.
**The reason the marker was missing is Partially Verified**: I read the error text and the PR title and file list, not the full diff.
The other 15 failed runs were not individually inspected (**Not Verified**); the sampled split (2 post-commit, 3 pre-commit) suggests
two failure modes and I make no claim beyond the sample.

### 1.4 Classification of your list

| Candidate cause | Verdict | Basis |
|---|---|---|
| Scheduler drop or delay | **Contributing** (Verified) | Cron is `3,33 * * * *`; the `schedule` runs in the listing (4451 to 4460) are roughly 4 to 8 hours apart. Bot self-dispatch ("recovery") fills the gaps (runs 4453, 4455, 4457, 4459, 4461 are `workflow_dispatch` by `github-actions[bot]`). |
| Runner or infrastructure failure | No (Verified) | Every sampled run was assigned a runner; step records are populated. |
| Concurrency cancellation | Not the cause of the dark window (Partially Verified) | Only run 4462 is `cancelled`, after the window. |
| Publisher failure | **Yes**, in the dark window | Section 1.3. |
| Source or CISA retrieval failure | No (Verified for 4448) | Pipeline step succeeded; "CISA KEV feed active". the abuse.ch IOC feeds report `ABUSE_CH_COMMERCIAL_USE_NOT_APPROVED`, which by its name is a licensing gate rather than an outage (the approval variable was empty in that run). |
| Integrity gate | **Yes (first failing stage for 3 of 5 sampled runs)** | `HOMEPAGE_INTEGRITY_FAILED`. Fail-closed behaviour was correct; the gate's expectation was stale. |
| Validation failure | Yes for 2 of 5 sampled runs | Post-commit source-yield gate (reason text not read: Not Verified). |
| Git push or permissions | No evidence | Commit step `success` where it ran. |
| Zero new reports | No | 13 were generated and discarded in run 4448. |
| Deployment disabled | **Yes, for the edge** | Section 4. Persisted is not published. |

---

## 2. CISA KEV reconciliation (4B)

### 2.1 Record-by-record result against the live catalog (Verified)

Authoritative catalog: CISA `known_exploited_vulnerabilities.json`, version **2026.11.10**, released 2026-11-10T19:03:29Z, **1,779** entries,
1,779 unique ids, fetched 17:32Z (the 17:13Z fetch was the same version). Membership is by exact CVE id.

| Feed | `generatedAt` | `cisaKev=true` | Flagged but **not** in the catalog | Catalog members **not** flagged | `stats.cisaKev` | Unique ids |
|---|---|---|---|---|---|---|
| Before (`0c1299450`) | 2026-11-12T10:46:31.830Z | 37 | **4**: `CVE-2026-43456` (reddit-sourced, absent from catalog), `SECURITYWEEK-6906104d8606997d`, `SECURITYWEEK-0d20c758adf2cea8`, `REDDIT_CYBER-28e83926b85eda37` (the last three are news/social article ids that can never be KEV members) | **7**: `CVE-2026-33825`, `CVE-2026-41091`, `CVE-2026-16812`, `CVE-2026-48558`, `CVE-2026-104286`, `CVE-2026-20245`, `CVE-2026-20253` | 37 | 150 |
| After (`e04985d3d`, run 4461) | 2026-11-12T17:06:23.895Z | 40 | 0 | 0 | 40 | 150 |
| After (`27bd783c1`, run 4463, first run with #570) | 2026-11-12T17:31:10.468Z | 40 | **0** | **0** | 40 | 150 |

37 − 4 + 7 = 40. In the newest feed, all 23 items from the `cisa_kev` source are in the catalog.

### 2.2 Provenance now persisted in the feed (Verified)

`27bd783c1` `live-intel.json` `metadata.kevCatalog`:

```json
{"status":"VERIFIED","catalogVersion":"2026.11.10","dateReleased":"2026-11-10T19:03:29.8375Z",
 "entries":1779,"invalidEntries":0,"duplicateEntries":0,"verifiedAt":"2026-11-12T17:31:01.348Z"}
```

The earlier run 4461 (`e04985d3d`) predates #570 (merged 17:10Z) and so correctly carries no `kevCatalog` block; it
demonstrates the corrected flags (#564) only. Run 4463 is the first run to demonstrate both.

### 2.3 Fail-closed behaviour and its tests (Verified: executed locally and in the merged CI files; production fault injection was not performed and must not be)

| Required case | Test (file: name) |
|---|---|
| Positive membership: listed id keeps or gains the flag | `kev-flag-catalog-authority`: "a record in the authoritative catalog keeps / gains cisaKev=true" |
| Negative membership: article ids can never be members | "news / social ARTICLE records can never be KEV members: the claim is cleared" |
| Unsupported claim removed, listed claim kept | "a CVE record claiming KEV that the catalog does not list is cleared, but a listed one is kept" |
| Missed member added | same positive case ("gains") |
| Retrieval failure or unknown catalog changes nothing | "an unknown catalog (null / empty / not a Set) changes nothing"; `kev-catalog-validation`: "an unparseable response fails the adapter and leaves provenance untouched" |
| Partial catalog rejected | `kev-catalog-validation`: count mismatch, tiny array, adapter "a partial catalog is not adopted" |
| Duplicates | "duplicates are de-duplicated and counted, never double-counted toward the floor" |
| Invalid id | "invalid identifiers are ignored, counted, and never become authority" |
| Historical entries older than the incremental cutoff | "the adapter keeps every catalog id (including entries older than its incremental cutoff)" |
| Retained snapshot is never falsely recertified | "a later bad catalog never downgrades or re-stamps an already verified snapshot"; "no fetch yet: provenance is UNVERIFIED with an explicit reason" |
| No new reports in a run | **Partially Verified**: only a structural test ("the live feed writer reconciles before computing stats, and fails open"); no behavioural fixture for a zero-new-report run |

Results: 10 + 15 tests, all passing, wired into `.github/workflows/test.yml`. **Not changed and Not Verified here:** the
`exploited=true` flag (139 of 150 items; 99 not in KEV) is keyword-derived legacy logic; "newly observed exploitation" and
"retracted or superseded" are not modelled in the data.

---

## 3. One freshness authority across widgets (4C)

PR #571 (merged 17:24Z) made `runtime-state.js` the single authority for what is LIVE and routed the homepage triage list
(`apex-command-center.js selectTriageFeed`) and the SOC desk (`soc-intelligence-desk.js`) through it (the live widget already used it from #563), adding
`pipelineAllowsLive` so a stale, unavailable or unverifiable pipeline exposes no record on any surface. LIVE means both
`_addedAt` ≤ 24 h (zoned date-time required) and `pubDate` ≤ 72 h. Cross-widget fixtures: `tests-js/soc-live-authority-cross-widget.test.js` (9 tests:
identical live set across the three surfaces; every disqualifying case; re-ingestion does not reset age; archive-only data yields empty
lists; stale/unavailable pipeline yields nothing; a missing shared model fails closed; no private window rule remains; global incidents are a
separate ACTIVITY category). Related JS suites 168/168; Python pin module 55/55 (local). **Hosted CI on the merge commit was still
`pending` when last read (Not Verified).**

Applied to the newest committed feed (`27bd783c1`) at 17:36Z by the merged `runtime-state.js` (**Verified**, local evaluation):
pipeline `HEALTHY` (age 4 min); **6 of 150** records LIVE; excluded `NOT_RECENTLY_INGESTED` 137 and `INVALID_TIMESTAMP` 7
(seven old `cisa_kev` rows whose `_addedAt` is the date-only `2026-04-20`, correctly fail-closed). At 19:00Z the same feed is `HEALTHY` (88 min) and at 20:20Z `DEGRADED` (168 min);
the 180-minute stale line falls at about 20:31Z. The live lists do not backfill archival rows.

Noted, not mine: #573 (merged 17:30Z) makes the scheduler heartbeat metadata-only and stops it back-filling `_addedAt` from source dates.
That matches the contract above (a re-ingested old advisory must not look newly added).

### 3.1 RSS date semantics (`updateRSS` and `generate-rss.js`)

* `fetch-live-intel.js updateRSS` stamps each new item and `lastBuildDate` with `new Date().toUTCString()` (the run instant).
  The same run writes the post with `datePublished = isoNow()` (`YYYY-MM-DD`, UTC), so the run's date **is** the post's publication date and the instant is just finer-grained. **Not a fabricated date** (Verified in source).
* `generate-rss.js` (workflow "Auto RSS Generator") rewrites the whole `rss.xml` from each post's own `datePublished` at 12:00Z of that day; #572 removed its invented fallbacks (an undated post is now excluded).
* **Observed interaction (Verified):** run 4461 wrote 8 items dated `17:06:24 GMT`; the generator commit `92e9ab963` (17:27:53Z) rewrote the file (101 insertions, 176 deletions): every item now reads `12:00:00 +0000` on its publication day and `lastBuildDate` moved **backwards** from 17:06:24 GMT to `Thu, 12 Nov 2026 12:00:00 +0000`.
* Conclusion: **no contract violation, so no code change in this PR.** Residual **Low** finding (Proposed, needs approval because it changes what feed readers see): two scheduled writers of one file use different date granularity; the same GUID changes `pubDate` within about 20 minutes; items first published earlier than 12:00Z on day D carry a `pubDate` up to 12 hours in the future until 12:00Z. Recommended: one writer, with 00:00Z (never future) or the real instant.

---

## 4. Production parity, drift and the financial gate (4F)

### 4.1 Four public endpoints (read-only `GET`, 2026-11-12T17:30:14Z to 17:30:22Z; no redirects, HTTP 200 on all four)

| URL | Bytes | `generatedAt` / `metadata.generated` | Reports | Items | SHA-256 | ETag | Cache-Control | CF |
|---|---|---|---|---|---|---|---|---|
| `https://soc.cyberdudebivash.in/live-intel.json` | 156,055 | 2026-10-23T04:58:15.799Z | 6,466 | 150 | `999a7b19d128982c89518ee60627dad5a5851ca15efb0dfbf8ab8f7bc31c69a6` | `"aeca3cf3…601ce771e"` | `public, max-age=0, must-revalidate` | HIT |
| `https://soc.cyberdudebivash.in/api/intel/live.json` | 130,250 | 2026-10-23T04:58:15.800Z | 6,466 | 100 | `1869f2efaf0b75bf0bbc3ac00bf9115c268097e192b0730b0130e16f8e345a07` | `"395b5711…0d189f3"` | `public, max-age=600, stale-while-revalidate=3600` | HIT |
| `https://blog.cyberdudebivash.in/live-intel.json` | 156,055 | identical | identical | 150 | **identical hash** | identical | identical | HIT |
| `https://blog.cyberdudebivash.in/api/intel/live.json` | 130,250 | identical | identical | 100 | **identical hash** | identical | identical | HIT |

Hashes and ETags are unchanged from the 13:12Z probe: the edge did not move in 4 h 18 min. **Source vs edge:** source feed 7,435 reports
(generated 17:31Z) against 6,466 served: **969 reports of publication drift** (not 969 missing incidents). No public build or
version endpoint exists (`/api/health`, `/api/version`, `/version.json`, `/build.json` return 404), so the deployed commit cannot be read from the edge.

### 4.2 Why the edge did not move (Verified)

`cloudflare-production-deploy.yml` is the only workflow that runs `wrangler deploy`; since #383 its job runs only for `workflow_dispatch` on `main`
(push-triggered runs conclude `skipped`). The newest successful deploy run in the repository is #758 (2026-10-22T05:47Z, commit `365c89f3`).
The served bytes correspond to source at about 2026-10-23T04:58Z, and the edge lacks `/soc-intelligence-desk.js` (shipped 2026-10-23 13:33Z; still HTTP 404 when re-probed at 17:4xZ today), so a bundle was
deployed between those times. The newest `workflow_dispatch` run of the deploy workflow in the repository is #758 (2026-10-22T05:47Z, success); **GitHub shows no deploy run in that window (Not Verified who or how).** See section 6.

### 4.3 Drift ledger (Verified)

Production Drift Reconciler run #1421 (id 43267028232, `main` `86f6e74b`, 17:13Z): decision **`manual_release_required`**, production-affecting 4,297,
operational 205, known non-production 138, **unknown 0**, comparison `verified_full_git_trees`, last approved deploy `365c89f3`. Run #1423
(id 43269493273, `4c8956f04`, 17:26Z) returns the same decision. `manual_release_required` is not proof of deployment and authorises nothing.

### 4.4 Financial gate (Blocked)

Release requires an owner-reviewed, account-wide Cloudflare cost attestation no older than 2 hours (with the 20 % reserve and pace factor in
`CLOUDFLARE-ACCOUNT-WIDE-ZERO-OVERAGE.md`). None exists in the repository and none is fabricated here. **HOLD.**

---

## 5. Immutable manual release package (prepared only; perishable; nothing is approved)

| Item | Value |
|---|---|
| Candidate SHA built | `92e9ab963288a224c0c621af5c5774841991aed8` (built 17:31Z). **`main` has already advanced** (`939bbfc81`, then publisher commits); the approved SHA must be re-taken and rebuilt immediately before release. |
| Clean install | `npm ci --legacy-peer-deps --ignore-scripts`: exit 0 |
| `npm run check:cloudflare` | exit 0 (43/43 node tests) |
| `npm run build:cloudflare` | exit 0, `dist-public/ built: 22402 files` (branding test 9/9) |
| `dist-public` manifest digest | `9e3e519f4e8ff0e504e81292b075b0f0c7e8e679ca89652bd566cbd1b3d958eb` (sha256 of the sorted `sha256sum` manifest of all 22,402 files, paths relative to `dist-public`) |
| `live-intel.json` | `dba5bb4a34c21db29372d7d9c8dddc3d1ef6be90b6e6365c3ddea9a12f4cafb8` (feed `generatedAt` 17:06:23.895Z, 7,420 reports) |
| `api/intel/live.json` | `6ddf5de2255832fd45b6473172c03a19829debb8dfdc504c58466c2e9a49ebbb` |
| `index.html` / `soc.html` | `efa04beccad66a40e07d080b24e6278deb872c3c6a188b9ae8d54e81d2ba6bf2` / `293f73b283f601c2b2a1cac9dd94ad6b6f9860ae9e86a23f732615113d438f0d` |
| `runtime-state.js` | `5f173af2eae7f773bc6b00424b220fa5b2f169e59f39c5a6eae39e69732aede9` |
| `soc-intelligence-desk.js` | `7c4523e92ebf626cbdb92af22a76bcde2095063b2f9d0aeb41c2a3a3991a66b3` |
| `apex-command-center.js` / `.css` | `ae4776937b7c4bdd1f7f7f8b6553cd9b17112a90284b5fd6cdf5421ec645e9a0` / `36fd291fce404147b6e4d19d35bc60e8746345b76491ed500a75e5902732b5e8` |
| `live-feed-widget.js` | `da0476108ed5e560e53c6c4e924718e587834e6e9fbc4bb8400541220727701f` |
| `rss.xml` | `309b900a120576b259db5c2047951b76fef10f0b30a13f371ddc0b1958a4d1b2` |
| Local predeploy gates at 17:31:47Z | `certify-soc-public-feed-parity.cjs --predeploy`: **PASS** `SOURCE_REPORT_AND_BUILT_ASSET_FRESH`; `certify-soc-s2n-api-release.cjs --predeploy`: **PASS** `SOURCE_LEDGER_AND_APPROVED_BUILD_CONCORDANT`. Both are **perishable**: the 180-minute report-age line for the 17:06Z report is about 20:06Z (for the 17:31Z report, about 20:31Z) and any newer publisher commit changes the inputs. |
| Rollback target | **Blocked**: the current Worker version id is not readable from the repository. Owner: `wrangler versions list` (section 6). |

Release procedure (unchanged, see `SOC-WINDOWS-OPERATOR-PINNED-RELEASE-PREFLIGHT.md` and the zero-overage runbook): owner takes the exact 40-character
`origin/main` SHA right after a publisher report, supplies the account-wide attestation (≤2 h), runs the local preflight, then dispatches **Cloudflare Production Deploy**
on `main` with `approved_release_sha` equal to that SHA under the protected `production` environment. The workflow re-checks the SHA before `npm ci` and again before
`wrangler deploy`; a publisher commit in between causes HOLD and the cycle repeats. Do not use the break-glass script.

**Rollback triggers:** any post-release acceptance check failing; either host disagreeing with the other; `generatedAt` older than 180 minutes at verification; a LIVE badge with a non-HEALTHY pipeline.
**Post-release acceptance (do not run without approval):** both hosts × both feeds return the new bytes and identical hashes; `generatedAt` ≤ 180 min; badge and pill agree
(LIVE only when HEALTHY); live lists contain no record older than the 24 h / 72 h windows; KEV flags equal catalog membership and `metadata.kevCatalog.status` is `VERIFIED`; `/soc-intelligence-desk.js`
returns 200; legacy host mappings unchanged; no managed-SOC staffing or SLA claim without evidence.

---

## 6. Owner-only read checklist (Blocked for the author; the Cloudflare read-only token request was declined and is not repeated)

```bash
npx wrangler deployments list --name cyberdudebivash-blog     # who/when deployed the 2026-10-23 bundle
npx wrangler versions list --name cyberdudebivash-blog        # rollback target
```

Also: confirm the `production` GitHub environment requires a reviewer; confirm no second deploy path exists outside this repository.
Results settle the one open provenance question in section 4.2 and supply the rollback target.

---

## 7. Open items, in priority order

1. Owner reads in section 6 and the cost attestation (release blockers).
2. **Proposed, needs approval:** let the release SHA check compare the release-relevant tree rather than raw `main`, so publisher-only data commits do not invalidate an approval (`main` advanced at least three times within five minutes of this package being built).
3. Public build identity (a build-time `release.json`) so the deployed commit is observable. *Proposed.*
4. One RSS writer and non-future `pubDate` (section 3.1). *Proposed.*
5. Inspect the other 15 failed publisher runs; add a behavioural zero-new-report KEV test; audit the `exploited` derivation.
6. Hosted CI on the #571/#572 merge commits was not yet read.

## 8. Reproduction

```bash
git fetch origin main && git checkout --detach <SHA>
npm ci --legacy-peer-deps --ignore-scripts && npm run check:cloudflare && npm run build:cloudflare
node scripts/certify-soc-public-feed-parity.cjs --predeploy
node scripts/certify-soc-s2n-api-release.cjs --predeploy
( cd dist-public && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum )   # manifest digest
curl -fsS https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json   # catalog for section 2
```
