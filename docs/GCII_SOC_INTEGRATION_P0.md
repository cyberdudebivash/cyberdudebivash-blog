# SOC Global Critical Incident Intelligence — P0 integration

Status: PROPOSED / NOT DEPLOYED.

Consume the versioned GCII incident feed produced by SENTINEL APEX Threat Intel; do not build a separate incident truth store.

## UI
- Critical Incidents desk: title, status, confidence, severity, updated time, source provenance, and stale-data indicator.
- Evidence drawer links each factual claim to its sources; disputed actor attribution is visibly marked.
- Incident lifecycle and material changes are shown independently of CVE counters.
- Empty state must distinguish zero verified incidents from unavailable or stale feed.
- Accessibility: keyboard navigation, focus visibility, text contrast, no color-only status.
- Escape untrusted text; validate URLs against HTTPS allowlist; no innerHTML with feed content.

## Consumer contract
Schema: GCII v1 in companion Threat Intel release contract.
Reject invalid schemas, out-of-range timestamps, unsupported statuses and unsafe URLs.
Cache last-known-good with explicit age and freshness; never silently replace with empty data.

## Release gates
Contract tests; malformed-feed and outage tests; SOC UI accessibility checks; CSP/XSS review; version pinning; rollback; live source and status checks.
No customer-facing claims of continuous coverage until ingestion, scheduler, and production observability are verified.
