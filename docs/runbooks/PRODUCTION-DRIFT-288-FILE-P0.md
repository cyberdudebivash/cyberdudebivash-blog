# P0 Production Drift — 288-file release control evidence (2026-10-23 IST)

## Observed comparison — not an authorized deployment

GitHub compare API, last claimed successful manually approved deploy
`365c89f34692cd94a860fbf0f95a0523f5f6f6aa` to reviewed `main`
`06386bc6d62f271c6538173fb0a8483867514b75`:

| Observation | Count |
|---|---:|
| Commits ahead | 123 |
| Changed files (complete response at checkpoint) | 288 |
| Files matching production deployment paths | 215 |
| Known nonproduction paths | 44 |
| Unclassified paths | 29 |

This GitHub comparison is **not** evidence that the last manually approved
workflow reached its final live-site acceptance step, that its SHA is the
actual Cloudflare Worker version, or that the build is deployable today.
The 288-file comparison is close to GitHub's 300-file comparison ceiling:
a later incomplete/truncated response must remain fail-closed.

The prior drift policy *correctly* chose `blocked`, but incorrectly returned
**zero** production-affecting paths if any unknown path was present.
This PR preserves all three categories in the blocked result, prints the
real counts and a bounded, safe filename sample. It **does not** silently
classify unreviewed source as benign, shorten the release boundary or
alter Cloudflare.

## The 29 unclassified paths, requiring explicit operator review

### GitHub pipeline and release controls (3)
- `.github/workflows/alert-delivery.yml`
- `.github/workflows/intelligence-hub.yml`
- `.github/workflows/workflow-security-gate.yml`

### Source generators and live/customer control scripts (13)
- `build-detections-page.js`
- `build-evi-page.js`
- `build-research.js`
- `generate-intelligence-hub.js`
- `generate-rss.js`
- `scripts/alert-delivery-execution-gate.cjs`
- `scripts/audit-soc-published-ui.cjs`
- `scripts/cloudflare-account-zero-overage-gate.cjs`
- `scripts/evaluate-watchlist-changes.js`
- `scripts/publish-intelligence-hub.sh`
- `scripts/soc-live-release-parity.cjs`
- `scripts/soc-readiness-delivery-gate.cjs`
- `scripts/verify-existing-cloudflare-domain.cjs`

### Datastore, state and migration (6)
- `ai-security-intel-memory.json`
- `ai-security-intel-state.json`
- `data/ioc-store.json`
- `data/published_posts.json`
- `intel-memory.json`
- `migrations/0017_soc_bounded_watchlist_eval.sql`

### Operational file and generated run evidence (7)
- `OPERATIONS.md`
- `logs/run-20261022-073736.json`
- `logs/run-20261022-100859.json`
- `logs/run-20261022-131441.json`
- `logs/run-20261022-151526.json`
- `logs/run-20261022-180407.json`
- `logs/run-20261022-191412.json`

**Important:** The heading counts above are descriptive risk families.
Source generators are especially important because they may influence
generated static assets indirectly. Do not categorize them as inert
documentation or grant automatic deployment. The actual classification
must follow an explicit code review of their build graph and the future
deployment workflow. State, logs and migration changes require separate
privacy/data/retention and D1-migration review.

## Operator review and release decision

1. Reconfirm the repository SHA and compare completeness, including rename
   paths, changes after the checkpoint, and any diff truncation.
2. Review all unclassified source paths before any rule changes. Changing
   path taxonomy alone must NEVER authorize production deployment; the
   215 previously detected production changes still require manual
   release, verified Cloudflare billing headroom and customer parity.
3. Validate old and new Cloudflare Worker module/assets graphs and D1
   migration prerequisites from a frozen reviewed commit.
4. Verify account-wide billing headroom across all ecosystem sites and
   products; no claim of zero overage without actual authenticated billing.
5. Require operator-approved manual deployment, rollback plan, native
   Worker-domain binding and live customer-route certification.
6. Record actual customer alert execution separately. A source-green
   GitHub job cannot attest any successful delivery receipt.

**Release status:** HOLD / NO-GO.
