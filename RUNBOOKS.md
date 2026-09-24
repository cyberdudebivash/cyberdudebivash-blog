# CYBERDUDEBIVASH SENTINEL APEX — Operational Runbooks

Incident and outage procedures. Distinct from `OPERATIONS.md`, which covers
deployment mechanics and revenue-system activation — this file is what to
do when something is actively broken. Written GEORP v1; update it when a
real incident teaches something this version got wrong, not speculatively.

---

## Backup & Restore

**What's backed up and why**: registered API keys, tier assignments, and
the payment audit log exist *only* in Redis (Upstash) — unlike posts and
reports, which are git-versioned and durable by construction. Before
`scripts/backup-customer-data.js` existed, there was no export path at all
for this data (found and recorded in `platform/open-issues.md`, GPEP v1).

**Not yet active in production.** The backup workflow
(`.github/workflows/backup-customer-data.yml`) and scripts exist and are
tested, but require three GitHub Actions repository secrets that are not
yet configured — see the workflow file's own header comment for exact
names and how to generate `BACKUP_ENCRYPTION_KEY`. Until they're set, the
workflow runs on schedule, detects this, and posts a visible warning
without failing. **This is a pending activation decision, the same shape
as the registration welcome email before it was merged** — someone with
repo-secrets access needs to provision the three secrets before backups
actually start.

**Manual backup** (once secrets are configured, or run locally with the
same three env vars set):
```
BACKUP_ENCRYPTION_KEY=<key> node scripts/backup-customer-data.js [outputPath]
```

**Restore procedure** (a deliberate, human-initiated action — never
automatic):
1. Obtain the encrypted snapshot (a GitHub Actions artifact, or a locally
   run backup file) and the `BACKUP_ENCRYPTION_KEY` used to create it.
2. Dry run first — always:
   ```
   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file>
   ```
   This decrypts and prints record counts without writing anything.
3. Only after confirming the counts look right, actually write:
   ```
   BACKUP_ENCRYPTION_KEY=<key> node scripts/restore-customer-data.js <snapshot-file> --confirm
   ```

**Recovery targets** (proposed, not yet validated against a real incident):
- **RPO (Recovery Point Objective)**: ≤24 hours, matching the daily backup
  schedule. If this isn't tight enough for the business's actual risk
  tolerance, that's an Executive Decision (increase frequency), not
  something to silently assume is fine.
- **RTO (Recovery Time Objective)**: not yet measured. The restore script
  itself runs in seconds for realistic data volumes, but total incident
  time also depends on detecting the loss, obtaining the encryption key,
  and locating the right snapshot — none of which have been rehearsed.

**Validation procedure**: none has been run yet against a real or
staging Redis instance — only against fake in-memory clients in
`tests-js/backup-restore.test.js`. **Remaining validation, explicitly**: a
real dry run against a staging (not production) Redis instance, once one
exists, to confirm the KEYS-based enumeration behaves correctly at real
data volumes and the restore path is genuinely trustworthy end-to-end.

**Ownership**: whoever holds GitHub repository secrets access and the
Upstash account today — not assigned to a named role here since this is
currently a small/solo operation (see `platform/open-issues.md`'s scale
readiness finding).

**Known limitation, stated plainly**: GitHub Actions artifact retention
(90 days, set in the workflow) is a safety net, not a long-term archival
policy. If the business needs backups older than 90 days recoverable, that
needs a durable off-GitHub destination — an infrastructure decision
requiring explicit approval, not built here.

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
4. If no backup exists yet (true until the three secrets above are
   configured), registered users' API keys are unrecoverable — they would
   need to re-register. State this to affected customers plainly rather
   than guessing at a recovery that isn't possible yet.

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

