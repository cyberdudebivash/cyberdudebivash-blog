# SENTINEL APEX SOC — Blog-to-SOC domain cutover runbook

**Change state:** PLANNED ONLY / not authorized for production execution.
**Source:** \`https://blog.cyberdudebivash.in\`
**Target:** \`https://soc.cyberdudebivash.in\`
**Production Worker:** existing \`cyberdudebivash-blog\`
**Existing deployment config:** \`wrangler.jsonc\`, \`workers/entry.js\`, \`workers/lib/route-table.js\`
**Change owner:** an authenticated Cloudflare/DNS operator with explicit approval.

## 0. Hard preconditions

- Resolve all P0 release gates in \`docs/architecture/SENTINEL-APEX-SOC-TRANSFORMATION-2026-10-21.md\`. In particular, **do not expose tenant/client SOC dashboards while auth is analyst-key-based and resources are globally indexed**.
- Verify zone \`cyberdudebivash.in\` ownership, actual Cloudflare account/zone, current \`blog.\` record, existing Worker custom domain, D1 database ID, R2 bucket ID, service binding, environment secrets, rollback Worker version, current usage/cost limits. Preserve deployment evidence. Do not invent Cloudflare resource IDs or make new paid resources.
- Establish the exact production public artifact manifest for HTML, CTI reports, \`/posts/*\`, \`/cve/*\`, \`/api/*\`, \`rss.xml\`, \`sitemap.xml\`, \`robots.txt\`, OG assets, authenticated endpoints, webhooks and checkout. Back up configuration and rollback instructions (not secret values).
- Enumerate URLs and hardcoded \`blog.cyberdudebivash.in\` values in HTML templates, generated reports, CSS CSP/connect-src, email templates, API CORS, service configurations, JSON feeds, webhooks, sitemap, RSS, schema.org, OG/Twitter cards, Search Console and external ecosystem links.
- Record traffic/search baseline and user acceptance against the current domain. Preserve stable CTI post URLs and search intent.

## 1. Gate A — Technical build/canary

On a clean reviewed commit, without spending or deploying:

\`\`\`powershell
$ErrorActionPreference = 'Stop'
npm ci --ignore-scripts --no-fund --legacy-peer-deps
if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
npm run check:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'Cloudflare runtime checks failed' }
npm run test:ci
if ($LASTEXITCODE -ne 0) { throw 'Jest gate failed' }
npm run build:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'Cloudflare asset build failed' }
npx --no-install wrangler deploy --dry-run
if ($LASTEXITCODE -ne 0) { throw 'Worker dry-run failed' }
\`\`\`

Verify every requested SOC route is explicitly in the static allowlist and/or Worker router. \`html_handling: none\` prevents assuming automatic pretty-path resolution. Run negative tests for asset escape, tenant IDOR and unauthenticated dynamic routes.

## 2. Gate B — Dual-domain staging

Only following operator-approved change control:
1. On existing Cloudflare account, identify the validated Worker and route collision matrix.
2. Bind \`soc.cyberdudebivash.in\` to the same reviewed Worker release using the approved custom-domain configuration; preserve \`blog.\` unchanged.
3. Verify TLS, strict headers, CSP, D1/R2 service bindings, API auth, payment/entitlement callbacks (read-only canaries) and domain-scoped cookies; never copy a customer key into logs.
4. Test path and query parity for each representative static and API endpoint; especially \`/posts/*\`, \`/cve/*\`, \`/intel/\`, \`/rss.xml\`, \`/api/v1/intel/live\`, \`/customer-assurance.html\`.
5. Verify legal identity, SOC 2 non-certification disclosure, status/freshness semantics, no fabricated customer/incident metrics, accessibility/mobile layout, and anti-XSS output encoding.

Example **read-only** checks from an operator workstation:

\`\`\`powershell
$names = @('blog.cyberdudebivash.in','soc.cyberdudebivash.in')
$paths = @('/','/posts/','/rss.xml','/customer-assurance.html','/api/v1/intel/live')
foreach ($name in $names) {
  Resolve-DnsName $name -ErrorAction Stop | Select-Object Name,Type,NameHost,IPAddress
  foreach ($path in $paths) {
    $url = "https://$name$path"
    try {
      $res = Invoke-WebRequest -Uri $url -Method Get -MaximumRedirection 0 -UseBasicParsing -ErrorAction Stop
      '{0} {1} {2}' -f [int]$res.StatusCode,$url,$res.Headers['content-type']
    } catch [System.Net.WebException] {
      $http = $_.Exception.Response
      if ($http) {
        '{0} {1} {2}' -f [int]$http.StatusCode,$url,$http.ContentType
      } else {
        Write-Warning "$url : $($_.Exception.Message)"
      }
    }
  }
}
\`\`\`

This probe is compatible with Windows PowerShell 5.1 and PowerShell 7; a DNS/TLS/read failure is a NO-GO, not permission to force deployment. Use authenticated API negative tests separately; a 401/403 result from an intentionally protected route is not itself a service outage.

## 3. Gate C — Canonical migration, not before

- Update code/build canonical \`soc.\` references in the reviewed release; preserve API origins or separate service names where genuinely needed. Update \`connect-src\`, all fetch clients and allowed callback origins together.
- Preserve content identity. Implement **path-preserving 308 redirects** from historical \`blog.\` URLs to matching \`soc.\` URLs only after two-host route parity is verified. Exclude paths where semantics, security/cookie scopes or webhook callers require deliberate separate handling. Redirects must preserve the full path and query and not loop.
- Update RSS, XML sitemap, robots, canonical tags, hreflang where applicable, JSON-LD, OpenGraph, social links, Search Console properties and inbound platform links.
- Keep historical \`blog.\` hostname working as redirected origin for SEO/link continuity; do not delete existing records as the first step.
- Ensure canonical / redirect rollout cannot emit inconsistent identity between two simultaneously active destinations.

## 4. Gate D — Commercial SOC release

Before permitting customer sign-in or paid SOC checkout on \`soc.\`:
- Authenticated real-tenant integration and adversarial cross-tenant tests pass.
- Independent incident security review, audit logs, MFA, data protection/retention, customer disclosure and backup/restore drills pass.
- One lawful written pilot scope is signed and validated against actual staffing; escalation and service hours are explicit. SLA only where signed.
- Payment provider (existing approved authority) and fulfillment verified end-to-end; no self-reported revenue.
- Customer-owned acceptance has been captured.

## 5. Acceptance and rollback

Save: reviewed commit SHA, Worker deployment ID, exact DNS record changes, old Worker version, test results, release decision, customer sign-offs and ongoing monitoring owner.

Rollback triggers: increased 4xx/5xx, stale or unverified CTI/telemetry, authentication errors, broken old-URL parity, any cross-tenant leak, payment or entitlement failure, unbounded Cloudflare cost. Restore the previously recorded healthy Worker deployment and validated DNS configuration, then revert canonical changes only as coordinated with routing. Recheck both hostnames, original feeds and customer access.

### P0 legal/customer route identity matrix (source-only)

For every approved release, independently verify **both canonical and `og:url`**
within the document `<head>` on:
`/`, `/soc-readiness-assessment.html`, `/about.html`,
`/terms.html`, `/privacy.html`, `/security-disclosure.html` and
`/contact.html`. The read-only `scripts/soc-hostname-truth-gate.cjs`
now checks these seven paths in source mode or with `--live`.
The last three routes previously advertised `blog.cyberdudebivash.in`;
correction of the **source** metadata must not be called a live fix until
independent `soc.` public probes show corresponding URLs after an
authorized deployment. Legacy CTI image and endpoint URLs are separate
compatibility concerns: do not blindly replace them.

Release acceptance must also confirm actual Cloudflare deployment provenance,
all customer-visible legal copy, authorized product scope, and both hostname
behavior. A successful SEO/source gate alone **never** authorizes customer
monitoring or production GO.

**This document does not initiate DNS, routing, secrets, Worker deploy, checkout or customer operations.**