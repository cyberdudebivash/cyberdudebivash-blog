# Production Deploy Triggers

## Invariant

Any merge to `main` that can change what `blog.cyberdudebivash.in` serves must trigger `.github/workflows/cloudflare-production-deploy.yml` on push. A backend security fix must not wait for the 30-minute drift reconciler.

## Incident that motivated this (2026-10-01)

- PR cyberdudebivash/cyberdudebivash-blog#318 changed `api/_lib/**` and `api/v1/**`. It merged at 13:28 UTC as `aea98b00`.
- The push filter listed only some front-end files, so nothing deployed.
- The fix went live at 13:30:52 UTC, as Worker version `f919bee8-8fa9-4cf5-9eb4-6f9dc6d6b39b`, only because a pipeline commit (`bf3caf66`) dispatched a deploy that included it.
- A forensic run of the coverage check against the pre-fix filter: **257 production runtime inputs were uncovered**, including the payment webhook and the premium-commerce service.

## Workflow inventory

| Workflow | Trigger | Role |
|---|---|---|
| `cloudflare-production-deploy.yml` | push to `main` (path-filtered, below), `workflow_dispatch` | Build, gate, deploy, live-certify. Concurrency group `cloudflare-production-deploy`, never cancels a running deploy. |
| `production-drift-reconcile.yml` | `*/30` schedule; completion of the intel, AI-security, CVE, RSS, hub and syndication pipelines; dispatch | Safety net: re-deploys when `main` differs from the last successful deploy |
| Pipeline workflows (`sentinel-apex.yml` and others) | schedule | Commit content with `[skip ci]` and dispatch the deploy themselves |
| `smoke-test.yml` | schedule / dispatch | Post-deploy smoke checks |
| PR checks (`test.yml`, `pricing-integrity.yml`, `continuous-assurance.yml`, …) | `pull_request` | Merge gates |

## What counts as a production runtime input

The required set is **derived, not hand-listed**, by `scripts/deploy-trigger-inputs.js`:

1. **Worker bundle.** The esbuild module graph of `wrangler.jsonc` `main` (`workers/entry.js`) is exactly what Wrangler bundles. Today it covers:
   - `workers/**` and `api/**`;
   - `Sentinel-APEX/engine-node/detection-engine.js`;
   - `data/detection-rules-canonical.json`, `data/cvss-corrections.json`, `data/ioc-feed.json`;
   - `live-intel.json`, `intel-state.json`.

   npm dependencies are represented by `package.json` and `package-lock.json`.
2. **Static-asset build.**
   - `scripts/build-cloudflare-assets.js` and the local modules it requires, including `generate-cve-pages.js`;
   - its `PUBLIC_DIRS` (`posts/**`, `cve/**`, …);
   - its `PUBLIC_ROOT_FILES`.
3. **Deploy configuration:** `wrangler.jsonc`, the package manifests and the two deploy workflows.

**Not production inputs, so they do not deploy:**
- `docs/**`, `*.md`;
- `tests/**`, `tests-js/**`;
- `reportx-canary/**` (premium reports publish through the API, not through a deploy);
- pipeline-only generators.

Premium reports reach production through `scripts/publish-premium-reports.js`, which writes to R2 and D1 and needs no Worker deploy.

## Enforcement

`tests-js/deploy-triggers.test.js` (part of the Full Assurance Pass) fails when:
- any derived input is not matched by the workflow's `push.paths`;
- the payment and webhook modules drop out of the module graph;
- a docs path (or `**`) is added to the filter, which would cause deployment storms.

The test also checks expected deploy/no-deploy decisions for representative files.

Its built-in negative controls prove that the pre-fix filter, and a filter without `api/**`, are detected. Removing any one of `api/**`, `workers/**`, `Sentinel-APEX/engine-node/**`, `posts/**` or `intel-plans.js` from the workflow fails the suite (5 of 5 detected).

**When you add a public file or a Worker dependency,** run `node scripts/deploy-trigger-inputs.js`. It prints any missing path, which you then add to the workflow.

## Deployment provenance

Every deploy now runs `wrangler deploy --tag git-<sha12> --message "commit <sha> run <id>/<attempt> event <name>"`. Each Worker version in Cloudflare therefore names its commit and workflow run.

The run's step summary records:
- commit;
- Worker version ID;
- run URL;
- trigger;
- UTC timestamp.

**Rollback target:** the previous version in Cloudflare → Workers → `cyberdudebivash-blog` → Deployments, or `npx wrangler rollback <version-id> --name cyberdudebivash-blog`.

## Merge discipline

Merge only after every required check on the PR head reaches a final green state.
- **Operator action:** in GitHub → Settings → Branches → `main`, enable "Require status checks to pass" and "Require branches to be up to date", so this is enforced rather than remembered.
- This repository cannot set branch protection itself.
