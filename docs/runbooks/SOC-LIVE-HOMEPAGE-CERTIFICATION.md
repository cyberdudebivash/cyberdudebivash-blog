# SENTINEL APEX SOC — Read-only Public Release Gate

**Purpose:** Certify that an actual public HTTP response has the corrected homepage structure and accurate SOC/CTI product identity, rather than assuming that a merged GitHub PR has deployed to Cloudflare.

## Operator commands (read only)

From the `cyberdudebivash-blog` repository after reviewing the exact checkout:

```powershell
node scripts/soc-live-homepage-certify.js
node scripts/soc-live-homepage-certify.js --soc
```

The first checks the existing CTI website at `https://blog.cyberdudebivash.in/`. The second checks the intended future `https://soc.cyberdudebivash.in/` separately, and **does not assume DNS exists**.

The script uses a single GET with `Accept: text/html`, redirect handling disabled, `cache: no-store`, a bounded 3 MiB streaming read and an abort deadline. It validates HTTP 200 + HTML and invokes the existing `scripts/soc-homepage-integrity.js` source contract against the actual received HTML.

## Decision vocabulary

- **PASS (exit 0):** the specific checked public edge response is an HTML page with exactly one main, reports container, CTI live feed, enterprise CTA, statistics/spotlight/featured section and current truthful product title.
- **FAIL (exit 2):** the checked edge provided an HTML page violating source structure/title, an unexpected HTTP code, a redirect or non-HTML content. Do not publish a release note saying live repair is complete.
- **INCONCLUSIVE (exit 3):** a connection/read failure, bounded-body rejection or HTTP 429 prevented trustworthy inspection. Do not downgrade this to PASS or interpret it as a source publication failure; retry from an authorized network/region and examine edge logs.

Output is a bounded JSON record with URL, checked UTC time, HTTP status where available, page title, counts, SHA-256 of received HTML and a reason. **The HTML digest is not a Git commit SHA**; the site currently does not provide sufficient release attestation to associate a public response with the exact deployed Worker version.

## Non-goals

This script does not:
- assert that every Cloudflare region has converged to one deployment;
- prove source/feed timestamp freshness, user counts, IOC accuracy, a functioning authenticated SOC or a paid customer subscription;
- exercise POST, API secrets, Cloudflare dashboard, D1 mutations, pricing, DNS edits, remote rollout, GitHub pushes or payment processing;
- change the current canonical `blog.` hostname to `soc.`.

For customer release, pair a PASS with approved Cloudflare deployment ID/source SHA evidence, production read-only API health probes, live CTI source freshness, branded mobile/browser smoke tests, authorized rollback plan and operator/customer sign-off. The public browser result currently shows the legacy `SOC 2 & CTI` homepage, so treat the incident as open until independently rechecked after an authorized deployment.

**Gate:** source CI and one read-only public edge canary are necessary but not sufficient for SOC GA. Do not remove controls to force a green rollout.
