# SENTINEL APEX SOC — Complete Production Drift Evidence (P0)

**Decision authority:** release engineering evidence only. Neither GitHub CI nor this monitor deploys Cloudflare, authorizes billing, applies D1 migrations, validates external customer notifications, or grants SOC 2 compliance.

## Confirmed failure mode

The last recorded operator-approved production deployment commit is
`365c89f34692cd94a860fbf0f95a0523f5f6f6aa`.
Against `main` commit `1f5df3aec105d3e8c167f53462fc3bbf388ed655`,
GitHub Compare reported 151 commits, an `ahead` relationship, and
**exactly 300 changed files**. The 300-file Compare result is not a
complete release diff. The drift monitor correctly blocked and printed
`comparison incomplete, divergent, or truncated`.

The original 288- and 289-file summaries (including 29 unclassified
paths) are historical snapshots and must not be treated as current.

## Approved read-only inventory algorithm

1. Pin the checked-out main SHA and last successful operator-dispatched
   release baseline SHA. Never accept an automated skipped push workflow
   as evidence of deployment.
2. Validate the original Compare ancestry: exact base SHA, merge-base,
   head commit, no commits behind, identical ahead/total counts, complete
   list of fewer than 250 commits.
3. For a Compare result at the 300-file ceiling, fetch each **immutable
   Git tree SHA from its validated commit object**, recursively. Do not
   trust the mutable `main` ref inside the tree request.
4. Require exact SHA match, `truncated:false`, a complete nonempty tree,
   unique paths, accepted object types/modes, valid 40-character object
   IDs, and bounded entry counts. If any property is missing, **HOLD**.
5. Compute the complete blob/submodule difference by path and mode +
   object SHA. Renames conservatively appear as a removed old path and an
   added new path. A changed symlink or executable bit is a change.
6. Apply **the same** strict path taxonomy derived from the real production
   deployment workflow. Any unclassified file means `blocked`. Even
   with zero unknown files, production paths mean
   `manual_release_required`, **not deployed**.
7. Display verified full-tree provenance and actual counts without
   truncating the source inventory. The user-facing summary may bound
   listed filenames while retaining totals and historical evidence.
8. The branch source tests include >300 files, new and removed paths,
   executable mode changes, divergent histories, truncation, malformed
   entries, and tree SHA forgery negative controls.

## Current remaining customer release blockers

- Actual Cloudflare custom-domain binding and full page/API parity remain
  unverified. The planned `soc.cyberdudebivash.in` hostname is **not**
  proven reachable by CI source tests.
- The scheduled GitHub Actions alert workflow failed closed with
  `CONFIGURATION_NOT_READY: CF_D1_DATABASE_ABSENT`. Do not enable it
  without checking available shared-account D1 headroom.
- Default-disabled D1 outbox migration 0018 remains unapplied to live
  D1. It has only source/offline SQLite acceptance and no external
  recipient delivery receipt or production rollback rehearsal.
- Account-wide Cloudflare Workers, D1, R2, KV, queues and other billable
  services must be attested via the separate current-cycle budget gate.
  Never infer bill-free use from localhost tests.
- Seller authorization, privacy/retention policies, signed customer scope,
  legal terms, incident response, backup/recovery, and actual delivery
  acceptance require explicit operator and customer evidence.
- SOC 2 is a control framework and audit/attestation effort; it must not
  be presented as certified, audited or independently compliant without
  formal evidence.

**GO decision:** not established. Operator-approved manual release with
verified runtime, tenant isolation, data and billing headroom, production
drift review and customer-delivery receipts remains necessary.
