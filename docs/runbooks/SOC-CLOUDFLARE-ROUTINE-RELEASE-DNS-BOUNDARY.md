# P0: SENTINEL APEX SOC — routine releases must not migrate DNS

**Effective:** 22 October 2026  
**Scope:** Both existing Worker Custom Domains declared in `wrangler.jsonc` — `blog.cyberdudebivash.in` and `soc.cyberdudebivash.in` — must be verified as already bound to `cyberdudebivash-blog` before a routine deploy.  
**Status:** operational precondition; not evidence of a completed deployment.

## Separation of duties

A routine Worker content release is **not** a DNS, TLS or domain cutover. The target Cloudflare Worker Custom Domain must already exist, be enabled, and be bound to the exact expected Worker. Before invoking Wrangler, the production workflow performs **two read-only, hostname-filtered** `GET /accounts/{account_id}/workers/domains?hostname=<approved hostname>` requests, one for `blog.` and one for `soc.`. Both must pass strict hostname, service, enabled and list-completeness validation. A passing `blog.` mapping alone is not sufficient. It repeats that check after deploy.

**Read-only API pagination safety:** Cloudflare Workers Domains `result_info.total_count` measures the account-wide domain inventory *without search parameters*. It is not an appropriate threshold for the single-hostname query. Validate the returned page and filtered-record count, require exactly one matching hostname and Worker, and reject inconsistent/unfiltered responses. A large unrelated Cloudflare domain inventory must not block a valid existing Worker binding. This is a source-level precondition only; it does not prove actual live routing or certificate health.

**No routine workflow step may delete, create, restore or overwrite DNS records.** Older code attempted to delete a legacy Vercel CNAME and restore it only on Wrangler failure. Such behavior is removed. If Cloudflare reports that the domain is missing, disabled, mapped to the wrong Worker, duplicated or uncertain, the release must **HOLD** before any deployment.

Cloudflare's Worker Custom Domain mechanism automatically manages DNS/TLS during setup; consequently domain *creation or migration* requires a separate written, owner-approved change with advance DNS inventory, customer impact review, coordinated Worker/domain provisioning, exact rollback instructions and post-change verification. Do **not** bypass the routine precondition to force a deploy.

## Operator release sequence

1. Read-only: capture current Cloudflare zone and Worker Custom Domain mapping, previous Worker version, DNS records and TLS; keep records in restricted storage. The routine workflow requires a minimum-scoped account token able to read Worker domains and to deploy the Worker; never publish the token or account ID.
2. Confirm the environment `production` requires an authorized reviewer and only main-branch deployment. Note that code cannot independently certify repository/environment admin settings.
3. Verify release artifact SHA, `npm ci --legacy-peer-deps --ignore-scripts`, focused CI, `npm run build:cloudflare` and source-route checks.
4. Confirm `scripts/verify-existing-cloudflare-domain.cjs` passes. A failed prerequisite is **HOLD**, not a reason to delete DNS.
5. Obtain explicit release authorization. Invoke the guarded manual `workflow_dispatch` from `main` only if GitHub Actions is operational and billing permits; otherwise follow the separately approved local operator procedure with identical preconditions. No recurring or scheduled auto-release is allowed.
6. After Worker deployment, revalidate the Worker domain, legacy DNS conflicts, eight customer route markers, source/build/served SHA-256 parity, mailto reachability, legal identity, mobile layout and rollback readiness. **Any failed check means customer release is NOT certified.**
7. Record exact Worker version and commit, change approver, operator, timestamp, production proof, unsuccessful checks, rollback disposition, and customer availability decision.

## Out-of-scope migration workflow

If `blog.` is still served by a legacy Vercel CNAME, the routine content-deploy workflow MUST stop without changing DNS. A separate domain migration change must document target Worker, certificate readiness, DNS TTL and propagation, temporary outage risk, rollback under partial failures, routing rules and monitoring. Do not treat a successful Worker upload as confirmation that public traffic reaches the new Worker.

**SOC cutover is not authorized by a routine release.** Because the current Wrangler manifest already lists `soc.cyberdudebivash.in` as a Custom Domain, the routine release must fail **before** Wrangler if that existing mapping cannot be independently proven. A missing/incorrect SOC binding requires a separately approved cutover or a separately reviewed configuration change; do not silently create, restore or remove domain mappings during a content release.

**Operational decision:** source-level tests and a read-only domain query do not authorize customer SOC services, billing, enterprise SLAs or SOC 2 assurance claims.
