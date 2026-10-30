# CYBERDUDEBIVASH SENTINEL APEX — Operational Runbooks

Incident and outage procedures. Distinct from `OPERATIONS.md`, which covers
deployment mechanics and revenue-system activation — this file is what to
do when something is actively broken. Written GEORP v1; update it when a
real incident teaches something this version got wrong, not speculatively.

---

## Backup & Restore — P0 customer-data recovery (30 October 2026)

**Current operational status: NO-GO / not yet recoverability-certified.**
The latest inspected scheduled workflow, [Customer Data Backup run #41037203567](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/41037203567), **failed during credential preflight**: `HAS_REDIS_URL=true`, `HAS_REDIS_TOKEN=true`, `HAS_BACKUP_KEY=false`. The backup and artifact-upload steps were **skipped**. This is a correct fail-closed result, not evidence of a usable new encrypted backup. Do not close [recovery incident #494](https://github.com/cyberdudebivash/cyberdudebivash-blog/issues/494) until independent backup and restore evidence exists.

**Data scope.** `scripts/backup-customer-data.js` reads the Redis customer API-key hashes (`user:key:*`), durable account lookup strings (`user:email:*` and `user:id:*`), time-limited prepaid registration tier strings (`user:pending:tier:*`), and the payment audit sorted set (`audit:payment:log`). Snapshots contain sensitive customer metadata and hashes. The current implementation encrypts with AES-256-GCM before writing an output file, then verifies the encrypted bytes can be decrypted. It does **not** guarantee a transactionally consistent point-in-time Redis snapshot.

### Owner-only secret recovery (no secrets in chat, Git, PRs, or logs)

1. In GitHub repository **Settings → Secrets and variables → Actions**, inspect availability/scope of exactly `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, and `BACKUP_ENCRYPTION_KEY`. The current workflow job declares **no GitHub environment**, so an environment-only secret is not automatically available to it. Confirm correct repository access and intentionally approved scope.
2. Recover the **original** `BACKUP_ENCRYPTION_KEY` from the authorized key custodian/vault. Its expected format is 64 hexadecimal characters (32 bytes). Do not generate a replacement merely to make CI green: historical encrypted snapshots would then be unreadable. If the original key is demonstrably irretrievable, initiate a separately approved documented recovery/rotation incident and assess historical backups before establishing a new key.
3. Make any secret correction **privately through authorized administration**. Do not expose secret values via issue comments, screenshots, shell history, workflow logs, or a pull request. Do not modify the preflight to skip the key check.
4. Before a credentialed backup attempt, obtain approval for the expected Upstash read workload and retention handling; repository CI success alone is not a cost/quotas attestation or a production customer-recovery guarantee.

### Controlled encrypted-backup acceptance

After the secret owner restores authorized prerequisites, the owner may explicitly trigger the **existing** `backup-customer-data.yml` workflow (or perform the equivalent approved private local run). No automatic new schedule or cloud deployment is required. Verify all of the following on the **same run**:

- Credential preflight **passed** and the real customer backup step **completed**; no plaintext data appeared in logs.
- The `customer-data-backup-<run_id>` encrypted artifact was uploaded successfully, is nonempty, and is retrievable within its retention window.
- The original key decrypts and authenticates the artifact **off the production service**; the snapshot schema, actual record counts, payment-audit entries, and pending-tier expiry metadata pass the current restore validator. A successful upload alone is insufficient.
- Snapshot creation time, SHA-256 of the **encrypted** artifact, secure storage location, custodian, retention/expiry date, and latest successful recoverable backup time are recorded in private operational evidence; no sensitive customer fields or secrets are attached to tickets.
- A separately approved durable encrypted-backup destination and key-escrow/rotation policy are required for longer-term recoverability. **GitHub Actions artifact retention is currently 7 days**, as declared in `.github/workflows/backup-customer-data.yml`. It is not a durable archival service.

### Restore CLI write authorization — enforced before any Redis writes

The CLI now **fails closed** for `--confirm` unless the operator provides an explicitly pinned Redis origin and an incident/change reference; an offline dry run does not need these write-authorization variables. This is defense in depth against an accidental target mismatch, **not independent proof of target isolation or formal customer-data change approval**.

To prepare private write authorization, verify the *actual* approved Upstash REST origin and compute its SHA-256 fingerprint locally without publishing the URL or token. Keep the production-origin fingerprint from a separately verified privileged source; do not invent a dummy fingerprint merely to pass the check. Both fingerprints are **SHA-256 of the exact HTTPS origin string** (e.g. generated privately via `require('node:crypto').createHash('sha256').update(origin).digest('hex')`). Only an exact lowercase HTTPS `*.upstash.io` origin with no slash, URL path, query, credentials or port suffix is accepted.

The authorized process environment must provide:

- `SOC_RESTORE_TARGET_URL_SHA256` — private independently reviewed fingerprint of the exact `UPSTASH_REDIS_REST_URL` destination.
- `SOC_RESTORE_LIVE_URL_SHA256` — separate, genuine fingerprint of the current live customer Redis origin.
- `SOC_RESTORE_APPROVAL_REF` — approved incident/change reference in `CDB-INC-YYYY-NNN` or `CDB-CHG-YYYY-NNN` format (3–8 digits after year).
- `SOC_RESTORE_MODE=isolated-rehearsal` — required for a rehearsal; target fingerprint **must differ** from the verified live fingerprint.

For an actual production disaster-recovery change only, use `SOC_RESTORE_MODE=production-break-glass` with the **same exact live and target fingerprint**, plus `SOC_RESTORE_BREAK_GLASS_CONFIRM=I_AUTHORIZE_PRODUCTION_CUSTOMER_DATA_RESTORE`. These environment controls must be combined with explicit independent owner approval, a scheduled recovery window, reconciliation, and rollback. A matching hash and approval-reference string are **operator-supplied assertions, not cryptographic proof of authority**.

The guard checks these conditions *after* offline snapshot authentication/validation but **before** loading the live Redis adapter or executing any restore command. It does not display Redis URLs, tokens, or fingerprint values. For a rehearsal, a second person or independent approved inventory must confirm the target is disposable and separate from production before `--confirm`. No scripts automatically select a sandbox or provision an isolated database.

### Isolated recovery rehearsal — mandatory before customer GO

**Critical:** `scripts/restore-customer-data.js --confirm` writes to whichever Upstash Redis endpoint is configured by `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` in the invoking environment. It does **not** automatically select a staging database, create a sandbox, or supply cross-key atomicity. **Never run `--confirm` with production credentials as a rehearsal.**

1. Provision or select an explicitly approved **disposable, isolated** Redis target. Independently verify the target's provider account, database identity, endpoint, and scope are different from live customer Redis, without revealing its token. Apply approved time/budget limits.
2. Using the original key supplied through a secure, nonlogged environment, perform the offline dry-run command: `node scripts/restore-customer-data.js /secure/path/customer-data.enc`. It must authenticate the encrypted input and validate the entire snapshot without Redis writes.
3. Only after independent destination verification, explicit owner authorization, and a clean dry run, use the isolated target credentials for the restore command: `node scripts/restore-customer-data.js /secure/path/customer-data.enc --confirm`.
4. Verify recovered account-hash fields, account lookup consistency, audit score/member fidelity, and customer entitlement correctness, including expired, revoked and refunded payment cases; record **redacted** counts and pass/fail receipts. Never invent or extend a 90-day pending-tier TTL. Historical snapshots missing trustworthy prepaid expiry metadata must fail closed and require payment-ledger reconciliation.
5. Measure end-to-end **RPO/RTO** using actual backup/restore timestamps and completeness results; document partial-write recovery/rollback because restoration is key-by-key, not atomic. Destroy the isolated rehearsal dataset according to the approved retention policy.
6. A real production restore is a separate break-glass change, requiring incident authorization, correct destination verification, write freeze/coordination where required, rollback readiness, payment reconciliation, and a written customer-impact plan. A successful rehearsal is **not** automatic permission to overwrite production Redis.

**Recovery objectives:** ≤24-hour RPO is only a *proposed target* derived from the daily schedule; it is **not achieved or certified** while scheduled backups fail. RTO is unmeasured until an isolated end-to-end rehearsal is completed. Mark both **unverified** in customer-facing SLA statements.

**Release gate:** The backup issue remains OPEN until a current encrypted snapshot is authenticated and restored into isolated native Upstash with account/tier/audit/TTL reconciliation and explicit owner acceptance. Source tests (including `tests-js/backup-restore.test.js`), successful CI, or a credential-presence flag by themselves are not recovery certification.

---

## Redis Outage / Data Loss

**Symptoms**: registration, login, tier checks, and rate limiting all fail;
`api/_lib/redis.js` logs `Redis not configured` or requests to Upstash time
out.

1. Check Upstash's own status page and dashboard first — this may be a
   provider-side outage, not something to work around locally.
2. If `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN` were rotated or
   corrupted (not a provider outage), restore them in the Cloudflare Worker secret store from the source of truth for those
   credentials, then redeploy.
3. If actual data loss occurred (not just connectivity), follow the
   **Backup & Restore** procedure above once a new/recovered Redis
   instance is reachable.
4. If no authenticated, restorable backup is available, recovery of some
   registered users' API-key records may be impossible. Do not assume
   earlier snapshots are valid or that all prior customer records are lost;
   establish the actual recovery position and disclose verified impact.

---

## API Outage

**Symptoms**: `smoke-test.yml` (runs after every push to `main`) reports a
non-200 or undersized response on a critical page; or a customer reports
`api/v1/*` endpoints failing directly.

1. Check the most recent `smoke-test.yml` run — it already checks critical
   page HTTP status and response size after selected main-branch pushes.
2. Inspect the affected Cloudflare Worker request logs and active deployment version.
3. If the failure correlates with a recent push, prefer `git revert` of
   the specific commit over `git reset` — see **Rollback** below.
4. If it's an upstream dependency (Redis, Razorpay, Resend), see
   that provider's specific section below.

---

## Payment Provider Outage (Razorpay / Gumroad)

Only Razorpay and Gumroad are authorized payment sources. If a provider is
unavailable, defer checkout and reconcile authenticated provider events after
recovery. Never grant entitlement from a redirect or an unverified reference.
Check webhook authentication failures against the Cloudflare Worker secret
store and provider configuration without printing secrets or payment payloads.
Preserve idempotency and existing paid access; do not enable manual payment
fallbacks. Verify configured product, amount and currency before reopening sales.

---

## Email Provider Outage (Resend)

The registration welcome email and newsletter capture both depend on
Resend. `resend.js`'s `sendEmail()` call in `auth.js`'s registration
handler is already `.catch(() => {})` — a Resend outage **cannot** fail a
registration; the user still gets their API key in the JSON response, they
just don't get the email copy of it. No action needed beyond monitoring
Resend's own status page; this was deliberately designed to degrade
gracefully, not to require an incident response.

---

## Report Publication Failures

1. Run `cli.py gate <report.md>` and `cli.py certify <report.md>` directly
   (`Sentinel-APEX/engine/`) to see exactly which check is failing —
   `scripts/assure.sh`'s certification stage runs this same check across
   the whole corpus and will show it too.
2. If the report renders incorrectly once published, check
   `Sentinel-APEX/renderer/`'s test suite (`node --test` from that
   directory) — this is the canonical renderer for full reports, distinct
   from `generate-cve-pages.js`'s `mdToSafeHtml()`, which only handles
   auto-generated CVE description snippets.
3. If a report is certified but not appearing at `/intelligence/`, confirm
   `Sentinel-APEX/renderer/publish-report.js` was actually run against it
   — certification and publication are two separate, manual steps (see
   `platform/open-issues.md` Issue 5's "2 of 3 reports were never
   published" finding, GCDOM v1).

---

## Intelligence Pipeline Failures

1. Check `.github/workflows/sentinel-apex.yml` and
   `intelligence-engine-ci.yml`'s most recent runs first.
2. Compare the generated artifact commit with the active Cloudflare deployment.
   A successful pipeline or merge does not establish public delivery.
3. For a data-quality issue (not a pipeline crash), check
   `platform/open-issues.md` first — several specific, evidenced defect
   classes in IOC extraction and ATT&CK mapping are already tracked there
   with their exact root causes, rather than being unknown territory.

---

## Rollback

Use the Cloudflare release and rollback procedure in `OPERATIONS.md`.
Record the current and previous known-good Worker version IDs before changing
production. Restore the verified previous version through Cloudflare deployment
controls, then reconcile source with a reviewed `git revert`. Rebuild assets
and explicitly deploy; a GitHub merge alone is not a deployment. Verify public
pages, API headers and payment callback behavior after rollback.

---

## Incident Response (general process)

1. Confirm the symptom against the specific runbook section above, if one
   exists, before assuming novel root cause.
2. Check `scripts/assure.sh`'s full output — it runs every test suite plus
   quality-gate/certification in one pass and will surface most
   engine-level regressions directly.
3. Check the relevant GitHub Actions workflow's recent run history (14
   workflows total — `gh`/GitHub UI, or the `actions_list`/`actions_get`
   MCP tools if working with Claude Code).
4. Fix at the smallest safe scope; prefer `git revert` over rewriting
   history.
5. Record what happened and why in `platform/open-issues.md` if it reveals
   a real defect, not just an environmental blip — this repo's own
   established convention for durable institutional memory.

---

## Customer Support

No ticketing system exists today — support is `mailto:bivash@cyberdudebivash.com`
and the `contact.html` form only (recorded in `platform/open-issues.md`'s
scale-readiness finding as a blocker before ~1,000 customers). Until a real
system exists:
- Registration/API-key issues: point to the FAQ (`faq.html`) first — it
  directly covers lost API keys, tiers, billing, and report access.
- Billing/payment issues: `docs/PRICING.md` and this file's payment-outage
  section above cover the two most likely root causes (stale price
  display, webhook secret mismatch).
- Anything else: no defined escalation path beyond direct email exists yet
  — this is itself the gap, not a procedure to follow.

