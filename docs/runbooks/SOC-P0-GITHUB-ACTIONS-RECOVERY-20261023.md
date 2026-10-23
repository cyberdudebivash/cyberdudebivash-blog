# P0 — SENTINEL APEX SOC GitHub Actions failure triage and recovery

**Audit date:** 2026-10-23 UTC. **Scope:** GitHub Actions latest 300 runs read via GitHub connector; sampled recent failures and failing job logs inspected. This is a time-bounded sample, not a claim that all 29,000+ historical runs have been repaired.

## 1. Root JS, Build Verification, and Continuous Assurance — source fix included in this PR

Observed:
- `test.yml` run [39962188565](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39962188565): `tests-js/soc-first-offer.test.js` requires old blog canonical while `soc-readiness-assessment.html` publishes SOC canonical.
- `continuous-assurance.yml` run [39962188625](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39962188625): root JS suite 607/609 passed, two failures: obsolete SOC canonical expectation; two new public files unlisted in production deployment input path graph (`soc-intelligence-desk.css`, `soc-intelligence-desk.js`).

Changes:
- Update only the test's positive canonical/OG assertion and add a negative-control rejection of legacy blog canonical.
- Add both public frontend assets to the existing production-deploy path inventory AND mandatory built-artifact verification. A regression test proves omission of either path is detected.
- Preserve `workflow_dispatch` **and** `refs/heads/main` guards on the production deploy job. Merely observing an Actions success does **not** deploy Cloudflare.

## 2. Watchlist alert delivery — configuration P0 remains RED (NO BYPASS)

Observed run [39938382549](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39938382549):
`CONFIGURATION_NOT_READY: CF_D1_DATABASE_ABSENT`. Evaluation and delivery were skipped. There is no evidence that customer watchlist alerts were delivered.

Required private operator steps:
1. Confirm the exact intended Cloudflare account, D1 database and limited-permission API token for this repository's GitHub Actions workflow. Do **not** post IDs/tokens publicly.
2. Set the missing `CLOUDFLARE_D1_DATABASE_ID` in repository Actions secrets through authenticated GitHub Settings, without changing existing database values or bypassing the readiness gate.
3. Verify `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` are present and valid, using names-only/log-safe preflight. Mere presence is insufficient.
4. Ensure a safe non-customer canary/fixture tests watchlist evaluation, atomic D1 claims, notifications outbox, and actual delivery receipt. Until then, customer alert delivery is **NOT CERTIFIED**.
5. Avoid duplicate schedules or double-delivery when both GitHub Actions and Cloudflare Cron can run; rely on evidence-backed deduplication and per-channel receipts.

## 3. Production drift reconciliation — correct protective failure

Observed [39961283044](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39961283044):
- last successful approved deploy `365c89f34692cd94a860fbf0f95a0523f5f6f6aa`
- evaluated main `5d8e8f60aea8af9f42fb20d8d655cca1709f78f6`
- 318 production-affecting, 45 known non-production and 41 unclassified changed files, using verified full Git trees.
- Fail closed on unknown paths. Do **not** convert these to documentation-only or silently mark green to suppress alerts.

Operator resolution:
- Review and explicitly classify unknown source inputs (including workflows, generation scripts, D1 migrations, state files and logs) based on their actual production effect, with regression tests.
- Retain the `manual_release_required` disposition for unshipped production changes, even after all paths are classified.
- Compare certified merged source with actual Cloudflare deployment provenance; complete authenticated API/billing checks and account-wide zero-overage preflight **before** any manual deploy.
- Never auto-dispatch Cloudflare deploy via the drift reconciler. Release and rollback remain human-controlled.

## 4. Freshness monitor — real customer-facing freshness failure, not a cosmetic test

Observed [39936386343](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39936386343):
- A generator self-heal succeeded after stale runtime, but public publication probe failed and Blogger classifier reported `BLOGGER_STALE`.
- Investigate persisted publication timestamp, public Blogger feed delivery, HTTP/content probes, cache propagation and independent website publication evidence. Do **not** rewrite timestamps or declare fresh on success of the internal generator alone.
- Preserve fail-closed publication quality and dispatch control.

## 5. Older, superseded observations

An older intelligence-hub generator job [39837287792](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39837287792) failed from a non-fast-forward push and rebase conflict in generated vendor JSON. Later intelligence-hub runs succeeded. This is a concurrent-writer reliability risk, not proof of a current outage; investigate writer coordination/rebase conflict retry separately and avoid force-pushing generated feeds.

## 6. Acceptance before closure

```bash
node --test tests-js/soc-first-offer.test.js tests-js/deploy-triggers.test.js
node --test tests-js/production-drift-safety.test.js
npm run check:cloudflare
npm run test:soc-domain
npm run test:soc-frontend
npm run build:cloudflare
node --test scripts/build-cloudflare-assets.test.js
npx wrangler deploy --dry-run --config wrangler.jsonc --outdir .wrangler-dry-run
```

Requires actual log evidence for full tests and PR head SHA. No live deployment, secret modification, workflow-dispatch/retry, payment charge or Cloudflare resource mutation is authorized by this source-only PR.
