# Main Branch Protection

**Status re-verified 2026-10-02: NOT ENFORCED.** Still `[]`. The classic protection endpoint returns 403 without admin credentials, and this environment has no repository-administration access, so an owner must apply phase 1. Earlier status (2026-10-01): `GET /repos/cyberdudebivash/cyberdudebivash-blog/rules/branches/main` returns `[]`, so GitHub applies no rule to `main`. This repository and its CI cannot change repository settings, so an owner applies the settings below.

Verify at any time (read-only):

```bash
node scripts/verify-branch-protection.js --phase 1   # exit 0 = enforced
```

## Constraint: pipelines push directly to `main`

Six workflows commit content to `main` with `GITHUB_TOKEN` (`git push origin main`): content, intel, hub and syndication pipelines. A ruleset can grant bypass only to roles, teams, GitHub Apps and Dependabot. The `GITHUB_TOKEN` cannot be bypass-listed. A "require pull request" or "require status checks" rule would therefore reject every pipeline push and stop content publication.

Protection is staged so that it never breaks that automation.

## Required status checks (derived, not hand-listed)

`scripts/verify-branch-protection.js` derives them from the workflows: every job of the merge-gate workflow `.github/workflows/test.yml`, plus the GitGuardian app check.

| Check | Source |
|---|---|
| Jest Test Suite | `test.yml` |
| Build Verification | `test.yml` |
| End-to-End Tests | `test.yml` |
| Governance Tests | `test.yml` |
| Performance Tests | `test.yml` |
| Resilience Tests | `test.yml` |
| Coverage Verification | `test.yml` |
| GitGuardian Security Checks | GitGuardian GitHub App |

These names match the checks that reported on cyberdudebivash/cyberdudebivash-blog#320.

`npm audit + Security Validation` stays advisory, not required. Its workflow is path-filtered, and a new upstream advisory could block every merge, including an emergency fix.

**Deadlock guard.**
- `test.yml` previously ran on PRs only for some paths, so a PR touching only `workers/**`, `config/**` or HTML ran no Jest at all.
- Its `pull_request` trigger now has no path filter, so every required check reports on every PR. The `push` trigger keeps its filter.
- The repository is public, so this costs no Actions minutes.
- `scripts/__tests__/branch-protection-policy.test.js` fails if a required check ever comes from a path-filtered workflow.

## Phase 1: apply now (safe with direct pipeline pushes)

GitHub → **Settings → Rules → Rulesets → New branch ruleset**:

- Name: `main-integrity`
- Enforcement: **Active**
- Target branches: **Include default branch**
- Bypass list: **empty**
- Rules:
  - ☑ **Restrict deletions**
  - ☑ **Block force pushes**

No workflow force-pushes (checked: no `push --force`, `-f` or `--force-with-lease` in `.github/workflows/`), so pipelines are unaffected.

Verify: `node scripts/verify-branch-protection.js --phase 1` → `ENFORCED`.

## Phase 2: required checks and PR merges

Prerequisite: pipelines push through a GitHub App, which can be bypass-listed, instead of `GITHUB_TOKEN`.

1. Create a GitHub App owned by the account, installed on this repository only. Permissions: Contents read/write. No webhook. Free.
2. Store `PIPELINE_APP_ID` and `PIPELINE_APP_PRIVATE_KEY` as Actions secrets.
3. In each pushing workflow, mint a short-lived token with `actions/create-github-app-token` and use it for checkout/push. This is a separate, reviewed PR, and each pipeline must be test-dispatched once.
4. Add rules to `main-integrity`:
   - ☑ **Require a pull request before merging** (0 approvals for a single-maintainer repo; dismiss stale approvals)
   - ☑ **Require status checks to pass**, with the eight checks above
   - ☑ **Require branches to be up to date before merging**
5. Bypass list: **the pipeline GitHub App only**, mode "Always".
6. Verify: `node scripts/verify-branch-protection.js --phase 2` → `ENFORCED`.
7. Then open a docs-only PR: all eight checks report, and the merge stays blocked until they are green.

Until phase 2 is done, the merge rule ("merge only when every check on the head is green") is a human discipline. GitHub does not enforce it.

## Emergency bypass

There is no casual bypass. For a production-down fix that cannot wait for CI:

1. A repository admin temporarily sets the ruleset to **Disabled**, recording the reason in the PR.
2. Merge, watch the deploy, and confirm live.
3. Re-enable immediately, and confirm `--phase 2` → `ENFORCED`.
4. Run the full CI on `main` afterwards and fix anything red as the next change.
