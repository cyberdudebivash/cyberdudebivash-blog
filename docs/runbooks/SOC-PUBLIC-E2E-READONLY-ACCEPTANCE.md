# SENTINEL APEX SOC — P0 public integration acceptance (read only)

The operator-only gate `scripts/soc-public-integration-gate.cjs` makes **exactly five** bounded, sequential **unauthenticated same-origin GET** requests, with a 9-second per-request timeout, a 300 KB per-response cap, no retries, and no network calls on import or during unit tests. It is **not scheduled** and is **not** a deploy, finance, customer, webhook, payment, D1, or R2 activity.

### Covered source-to-public flows

| Flow | Positive acceptance | Fail-closed negative |
|---|---|---|
| `/soc.html` | HTTP 200 HTML; SOC branding; canonical + `og:url` in document head use the SOC origin | Legacy blog SEO, missing/duplicate identity, HTML failure |
| `/workbench.html` | HTTP 200 HTML; `noindex`; explains internal `X-Analyst-Key` | Unexpected indexing or missing internal-auth indicator |
| `/api/v1/workbench/dashboard` **without credentials** | HTTP 401, JSON `UNAUTHORIZED`, `no-store`, no wildcard CORS | Anonymous access, caching, CORS exposure or wrong denial contract |
| `/api/v1/intel?action=stats` | Strict JSON counters, parseable timestamp under four hours | Malformed counters, stale/future timestamp |
| `/live-intel.json` | JSON feed, published-count parity, timestamp under four hours and within 15 minutes of stats | Malformed/stale feed, cross-layer count/timestamp drift |

Run the fully offline regressions first:

```bash
node --test tests-js/soc-public-integration-gate.test.js
```

An authorized operator may run an **optional** public read-only probe:

```bash
node scripts/soc-public-integration-gate.cjs --live
```

Do not add credentials, browser cookies, customer identifiers, tenant IDs or query secrets. The probe prints only status and defect codes, never response bodies. A `SOURCE_PUBLIC_READONLY_PASS` result means *only these five public GET observations* passed; it does **not** prove authenticated tenant A/B isolation, scoped customer data, D1/R2 transaction reliability, payment fulfillment, externally delivered alerts, real managed coverage, publisher/Blogger SLA, exact Worker release SHA, or zero-overage Cloudflare headroom.

### Last observed state (independent read-only inspection, 24 October 2026)

- Public SOC pages were accessible; `/soc.html` still exposed legacy `blog.` canonical identity. **HOLD**.
- Unauthenticated workbench dashboard returned 401. This is expected anonymous denial, not proof of authenticated RBAC.
- Public `/api/v1/intel?action=stats` and `/live-intel.json` reported data generated around **23 October 2026 04:58 UTC**, more than four hours old during the 24 October inspection. **HOLD**.
- Neither the live endpoint's latest publishing timestamp nor a passing offline test authorizes customer release. #360, #404, #400, #418, #432–#434 and source/deployed parity remain independent NO-GO gates.

**No deployment, migration, DNS, billing or paid resource changes occur under this runbook.**
