# Intelligence Hub Publisher — P0 Non-Fast-Forward Race Recovery

## Incident evidence
GitHub Actions Intelligence Hub Generator run [#39837287792](https://github.com/cyberdudebivash/cyberdudebivash-blog/actions/runs/39837287792), on October 22, 2026, completed generation and validation, but its push was rejected as non-fast-forward. The source moved while the generator ran. The retry performed `git pull --rebase`; its new generated JSON conflicted with updated vendor, collection and timeline output on the remote. After aborting, identical stale pushes failed two more times. The workflow exited 1, leaving publication unverified.

## Source-only remediation
- `scripts/publish-intelligence-hub.sh` runs ONLY in the repository's ephemeral GitHub Actions checkout on branch `main`.
- Each generated commit is pushed with `git push origin HEAD:refs/heads/main`, never force.
- At most three attempts. After the first non-fast-forward rejection, fetch the current remote SHA and verify that the previous base is an ancestor of current remote. If it has NOT advanced, the failure is not a supported race; fail rather than loop.
- **Only after validating a clean ephemeral workspace** reset the runner to fetched `main`, rerun generator syntax + intelligence hub unit tests, regenerate all output, revalidate required artifact presence, and recommit the allowed generated paths.
- If regenerated files match latest main, finish without a redundant commit. If history diverges, credentials deny push, output is missing, or three attempts are exhausted, fail closed.
- This does NOT grant CI authority to bypass branch protection, modify production Cloudflare data, force-push, or alter unrelated upstream source commits.

## Offline CI evidence
New `tests-js/intelligence-hub-publish-race.test.js` creates a temporary bare Git remote and two clones, injects a competing upstream change on the first push, and checks that the final remote retains the competitor's source while generated JSON corresponds to the **new** source. Negative controls reject non-GitHub workspace execution and force/rebase commands. The test uses local Git and Node only, no Cloudflare or external API.

## Operator acceptance
Exact-head CI required before merge. The existing GitHub Actions schedule remains unchanged. This change reduces failed publishing caused by a narrow class of concurrent main updates; it is not proof of live customer SOC service, current intel freshness, Worker availability, or account-wide billing reserve. Keep platform first-service NO-GO until independently certified.
