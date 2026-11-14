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

## P0 session-expiry guard — prepared, not production-deployed (14 November 2026)

The global-incident renderer already restricts the **initial** feed to a
publication timestamp no older than two hours and incidents updated in the last
24 hours. The original loader fetched only once; cards could remain displayed
after either deadline if a customer kept a browser tab open.

The updated `soc-global-incidents-loader.js` stores only the verified public
snapshot in page memory. A single five-second local timer re-evaluates the same
`CDBGlobalIncidents.selectFreshIncidents` predicate. Repaint occurs only when
the selected incidents actually change; **no periodic network polling** and no
new Cloudflare requests, storage, external vendors or recurring costs are added.
Visibility/focus rechecks are immediate. When a feed expires, the renderer
withholds the cards and reports stale evidence; the snapshot is discarded and
cannot later be promoted without a newly fetched source. Page exit clears cards
and aborts in-flight work so browser back-forward-cache restoration cannot
present old incident cards as live.

The versioned loader URL in `soc.html` is pinned for a future approved release,
and `tests/soc-gcii-session-expiry.test.cjs` is included in `test:ci`,
`check:cloudflare` and `test:soc-frontend`. This protects against old
loader assets surviving after a deployment. The new test suite checks incident
and feed expiry, no redraw when unchanged, zero extra requests, tab resume,
invalid/stale initial data, navigation and in-flight response races.

**Outstanding release evidence:** full Node `--test` execution, old-suite
regression, actual customer browser tests, confirmed source-generated incident
feed/API freshness, verified production asset and Worker SHA, customer acceptance,
and rollback. The feed's `sha256` field is currently validated as a hexadecimal
field by the browser consumer; that alone is **not cryptographic authentication**
of the producer. Avoid promising cryptographically verified incident provenance
without a separate signed feed/producer verification gate.

The owner requires one coordinated all-platform production deployment after
explicit approval. This implementation is source-only and remains **NO-GO** for
worldwide customer release until the above evidence is complete.
