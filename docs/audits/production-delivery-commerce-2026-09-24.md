# Production delivery and commerce audit — 2026-09-24

## Proof before change and blast radius
|Field|Evidence|
|---|---|
|Objective|Detect public delivery failures and keep interrupted Gumroad sale recording retryable|
|Files|scripts/check_blogger_public_delivery.py; tests/test_blogger_public_delivery.py; .github/workflows/freshness-check.yml; api/v1/billing/gumroad-webhook.js; api/v1/billing/__tests__/gumroad-webhook.test.js; this audit|
|Reuse|Existing Blogger freshness evaluator and Redis/payment utilities|
|Defect|Freshness classifier reads only local ledger. Gumroad sets completion before hash/index writes and treats failed dedup lookup as absence.|
|Risk|Medium: independent read-only monitor can alert on previously undetected outages; payment endpoint keeps same request/response contract.|
|Consumers|Scheduled freshness workflow; Gumroad Ping sale audit endpoint; Jest and Python evidence CI. No product entitlement, routing, HTML, schema, SEO, or bundle change.|
|Rollback|Revert this focused commit. Restore prior monitor workflow and payment handler; reconcile any failed sales from provider records before acknowledging them.|

## Baseline
- Repository owns Blogger automation, separate blog application, Vercel config and a Cloudflare migration configuration. Cloudflare wrangler.jsonc has no production routes and omits the D1 database ID; it does not prove a live Cloudflare deployment.
- Latest inspected credentialed run: 35981517726. Run report logs/run-20260924-093433.json: 2 published, 4 rejected, DEGRADED, zero fetch-back discrepancies. Report generation rejects include analytical depth below 2,200 words, paragraph and list density. These gates remain unchanged.
- Main workflow security, smoke, evidence and Node test runs inspected were successful. Success does not prove public homepage rendering or paid customer fulfillment.
- Blogger live public fetch from this audit environment hit a Google access challenge. No live-theme export available. Public visibility remains unverified until the new probe executes successfully from production CI and browser checks confirm rendering.
- No Cloudflare billing/usage or payment-provider account connector is available. Current plan allowances, usage, captured revenue and live entitlement fulfillment are UNKNOWN. Financial planning assumes zero revenue pending provider evidence. No quota or publication cadence increase in this change.

## Prioritized findings
|Priority|Finding|Disposition|
|---|---|---|
|P0|Recent ledger can mask absent public report/feed|Add independent public feed + desktop/mobile anchor probe; nonzero on stale or unknown results|
|P0|Gumroad partial storage failure poisons dedup|Completion marker written last; storage lookup failure returns 500 before writes|
|P0|Live payment-to-entitlement completion unproven|Needs provider configuration, deployment identity and credentialed test evidence; this sale-audit handler does not grant entitlements|
|P1|Four of six generation candidates rejected|Preserve evidence gates; investigate source depth and provider output separately|
|P1|Current Cloudflare plan and usage unavailable|Keep current workload limits; block capacity increases until usage evidence|
|P1|Payment state transitions, retention and reconciliation need broader review|This fix addresses partial-write retries only; Gumroad refund-after-sale and concurrent audit events require follow-up|

## Probe contract and cost
Three public GETs per run: summary feed limited to 5 entries, desktop homepage, mobile homepage. Each response capped at 4 MiB, each request has a 15-second socket timeout. Existing 30-minute cadence means 144 public GETs/day, about 4,320/30 days. These target Blogger and add no Cloudflare storage or generation work. Latest feed permalink must be linked on both pages; raw script-string occurrences do not count. This proves HTML linkage, not CSS visibility or browser rendering. Challenge/redirect/malformed/oversized responses fail closed. The probe never triggers publication; it cannot cause a publication storm.

## Validation
Local five-case probe checks passed; Node syntax passed. Isolated execution of the real Gumroad handler verified partial write failure, successful retry, duplicate acknowledgment and dedup lookup outage. Full CI is required on the PR. No live payment was performed and no revenue is claimed.
