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

Before deploying, identify the existing Worker, its account, current version,
production route/custom-domain configuration, D1 database identity and R2
binding in the authenticated Cloudflare account. Record current plan limits
and actual usage. The checked-in wrangler.jsonc intentionally has no production
route or D1 database_id. Do not invent these values or create replacement
resources. Use the existing validated production configuration and bindings.

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
