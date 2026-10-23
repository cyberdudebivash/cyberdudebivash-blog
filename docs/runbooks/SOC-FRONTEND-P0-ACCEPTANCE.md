# SENTINEL APEX SOC — Premium Frontend P0 Acceptance

**Change scope:** SOC overview intelligence desk, shared sitewide navigation, public CTI export, and build regression controls. No changes to customer authentication, commerce, D1/R2, Worker code, routes, DNS, providers, or billing. The public first-party feed is not customer telemetry and does **not** establish managed SOC delivery or SOC 2 attestation.

## Source and security controls
- `/soc.html` presents a polished intelligence desk. It reads only `/live-intel.json` using the existing bounded `SentinelRuntimeState.fetchJson` model.
- The page shows the **timestamp-derived freshness state** (HEALTHY / DEGRADED / STALE / UNAVAILABLE); if fetch or validation fails, it removes previous records and numbers and shows UNAVAILABLE. Do not classify a successful HTTP request as fresh intelligence.
- Record counts apply **only to the current available feed sample**, capped at 100; no fabricated alert, analyst, SLA, customer, incident or telemetry statistics.
- Record text uses `textContent`; report links require HTTPS to SOC/blog and a strict public `/posts/*.html` path. Unverified links are not rendered as clickable.
- Analyst filters stay client-side. CSV export contains only filtered public feed records, maximum 100, with spreadsheet formula injection protection. No customer information or credentials are accessed, transmitted or stored.
- No interval polling, timers for server activity, database writes, new storage, analytics beacons, vendors, Workers, D1 queries or Cloudflare cron settings. The only page data request is one same-origin public static feed fetch on load or a direct user-triggered refresh. Blob URL revocation timer is browser-local only.
- Global navigation presents the SOC Intelligence Desk while retaining existing services and historic pages.

## Required offline gates

From a **clean, detached audit worktree** at this PR's verified head SHA:

```powershell
npm ci --no-audit --no-fund
npm run test:soc-frontend
npm run check:cloudflare
npm run test:soc-domain
npm run build:cloudflare
node --test scripts/build-cloudflare-assets.test.js
npx wrangler deploy --dry-run --config wrangler.jsonc --outdir .wrangler-dry-run
```

Fail the release if any exit code is nonzero, or if the PR head moves after testing. These are **offline** checks; `--dry-run` is mandatory.

## Manual acceptance matrix

| Surface | Test | Pass condition |
| --- | --- | --- |
| Desktop `/soc.html` | 1440px and 1280px | No clipped metrics/nav; four metrics fit; report cards readable |
| Tablet | 768px | Controls reflow; status/freshness readable |
| Mobile | 320px and 390px | One-column dashboard; no horizontal body overflow; controls ≥44px |
| Keyboard | Tab, Shift+Tab, Enter, Space | Every interactive control usable; visible focus; export disabled until records |
| Screen reader | Status, form labels, results | Labels, polite runtime status, result counts understandable |
| Reduced motion/high contrast | OS preferences | No required animation; borders and state legible |
| Fresh feed fixture | Valid <90-minute timestamp | HEALTHY only when runtime classifier verifies it |
| Old/missing timestamp | 4+ hours, invalid, future clock skew | STALE / DEGRADED (never HEALTHY) |
| Fetch failure | Offline / timeout / non-2xx / invalid JSON | UNAVAILABLE, no prior metrics or records remain |
| Filtering | Search, severity, exploitation | Only feed-backed matches appear; no fake absent-threat claims |
| CSV | Quoted titles, formulas, zero results | No executable spreadsheet formulas; export disabled when empty |
| Internal routes | Links on all pages, public reports | Same-origin SOC report links; legacy webhook/API paths untouched |
| Dual host | SOC and blog baseline checks | Existing 2×26 public acceptance remains green |
| Performance | Low-end mobile/slow 4G | No new third-party JS or critical layout shift; inspect LCP/INP manually |

## Release/rollback controls

1. No merging before automated and hands-on acceptance. Existing PRs and merged releases are **not** live deployment evidence.
2. Verify account-wide Cloudflare Workers/Pages/D1/R2 usage headroom across the entire CYBERDUDEBIVASH ecosystem and the current deployed Worker identity.
3. Before deploying, capture the current Cloudflare deployment version, route mappings, both custom domains, and a documented rollback route.
4. Only a separate explicitly authorized local Windows/WSL manual deployment may be used; never automatic GitHub Actions deployment while billing is blocked.
5. Repeat dual-host baseline, browser acceptance and payment/auth route compatibility checks after any deployment. Confirm no change to webhook destinations and no unexpected checkout acceptance.
6. Roll back on customer auth failures, billing callback regression, missing assets, broken CSP, stale feed displayed as LIVE, or unbudgeted Cloudflare usage.

**Definition of done:** Premium frontend source, generated artifacts, accessibility/performance and dual-host customer-safety gates all passed with evidence. This is not SOC 2 certification or a complete commercial onboarding/fulfillment sign-off.
