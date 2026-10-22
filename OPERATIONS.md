# Production operations

Effective 2026-09-24. This is the current deployment runbook; older migration
inventories describe historical states and are not deployment instructions.

## Ownership

| Surface | Source/runtime |
|---|---|
| blog.cyberdudebivash.in | This repository; Cloudflare Worker entry workers/entry.js and allowlisted static assets |
| cti.cyberdudebivash.in | Blogger; Python pipeline and blogger-syndication workflow in this repository |
| intel.cyberdudebivash.com | Separate CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM repository and Cloudflare gateway |

The operator has retired Vercel. No deployment, secrets, scheduler, rollback or
routing operation should use that provider. The Node request/response adapter
remains required by the Cloudflare router and existing API handlers.

## Release gate

From a clean checkout of the reviewed commit, using the locked dependencies:

```powershell
npm ci --ignore-scripts --no-fund --legacy-peer-deps
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
# STRICT P0: Account-wide zero-overage evidence is mandatory, including
# every Worker/Pages, D1, R2, KV, Queues and logging workload in the same account.
# Set these two variables through private, operator-approved controls only:
#   CLOUDFLARE_ACCOUNT_ID
#   CDB_CF_ACCOUNT_BUDGET_ATTESTATION (fresh, owner-reviewed JSON)
node scripts/cloudflare-account-zero-overage-gate.cjs
if ($LASTEXITCODE -ne 0) { throw 'HOLD: Shared Cloudflare account budget and headroom unverified' }
npm run check:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'Cloudflare security gate failed' }
npm run test:ci
if ($LASTEXITCODE -ne 0) { throw 'Application regression gate failed' }
npm run build:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'Asset build failed' }
npx --no-install wrangler deploy --dry-run
if ($LASTEXITCODE -ne 0) { throw 'Worker bundle validation failed' }
```

Use existing Python/Blogger evidence CI for publication changes. Do not publish
or relax evidence gates to test a hosting cleanup.

## Authenticated deployment

A successful local dry-run, clean GitHub PR or static build never overrides
the account-wide budget HOLD. Release snapshots must be no older than 2 hours,
show zero forecast variable-usage overage, and retain a 20% safety reserve
across account-wide Workers requests/CPU, D1, KV, R2, Queues and logs.
Unmodeled billable services (including a possibly active visitors Durable
Object or Workers AI fallback) require explicit verified costing before
attesting them as zero. See
`docs/runbooks/CLOUDFLARE-ACCOUNT-WIDE-ZERO-OVERAGE.md` and P0 #404.
Do not paste credentials, raw usage or private approval receipts into issues.

Before deploying, identify the existing Worker, its account, current version,
production route/custom-domain configuration, D1 database identity and R2
binding in the authenticated Cloudflare account. Record current plan limits
and actual usage. The checked-in wrangler.jsonc now specifies the intended
`blog.cyberdudebivash.in` Custom Domain and D1 database name, but a
checked-in route declaration does **not** prove that the live Cloudflare
account already has an enabled matching Worker domain. Do not invent D1
database IDs, create replacement storage, or use a routine content release to
migrate DNS. Require the read-only
`node scripts/verify-existing-cloudflare-domain.cjs` check and the separate
legacy DNS conflict check **before** any Wrangler mutation. Preserve existing
production bindings and record rollback identity.

Set runtime secrets through the Worker secret store; keep Blogger/pipeline
credentials in GitHub Actions secrets. Do not expose either in build output.
Review pending D1 migrations separately; this hosting removal does not require
schema changes, a new scheduler, a resource upgrade or a quota increase.

After those preconditions and the release gate pass, deploy with the existing
production Wrangler configuration. Record the resulting Worker version ID and
commit, then verify public pages, feed freshness, static and API response
headers, route aliases, protected endpoints and authenticated payment callback
canaries. A smoke test of existing live pages is not commit-specific deployment
proof. A GitHub merge is not proof of deployment.

## Rollback

Record the previous known-good Cloudflare version before release. Restore it
through the existing Worker deployment controls if a release fails; verify
public routes and customer access. Reconcile source with a reviewed git revert,
rebuild assets and deploy explicitly. Do not reset main, change DNS or restore
the retired provider. Reconcile payment events without duplicating entitlements.

## Payments and incident handling

Razorpay and Gumroad are the only authorized payment sources. Confirm products,
amounts, currency, provider authentication, duplicate-event behavior, refund
handling and actual delivery before enabling an offer. Provider redirects are
not proof of payment. Treat revenue as unverified until captured transaction
records establish it. Do not enable manual payment fallback or a paid service.

See RUNBOOKS.md for incident procedures. Check active Worker logs and deployment
identity when HTTP behavior differs from source. For Blogger, trace a published
post ID and permalink through API fetch-back, public feed and both homepage
variants; internal feed success is insufficient.
