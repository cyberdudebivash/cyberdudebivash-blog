# IOC Commercial Readiness

**Date:** 2026-10-01 UTC. Basis: executed tests and the live refresh, not intent. The platform is pre-revenue, and this change adds **no** paid infrastructure.

## 1. Capability matrix (what each plan actually receives)

| Capability | Free / Starter | Pro | Team | Enterprise | Evidence |
|---|---|---|---|---|---|
| IOC feed JSON (`/api/v1/intel?action=iocs`) | 403 | ✓ | ✓ | ✓ | `intel-iocs-evidence-feed.test.js` (real handler) |
| Per-indicator provenance, confidence basis, expiry, recommended action | — | ✓ | ✓ | ✓ | same |
| Filters (type, confidence, status, source, malware, CVE, since/until, action) | — | ✓ | ✓ | ✓ | `ioc-engine.test.js` |
| Revocation notices (`revocations[]`) | — | ✓ | ✓ | ✓ | `ioc-engine.test.js` |
| STIX 2.1 bundle (`format=stix`) | — | ✗ (JSON + `stix_note`) | ✓ | ✓ | real handler; OASIS `stix2` parse |
| IOC nodes in graph / unified search / `action=ioc` | excluded | ✓ evidence-backed only | ✓ | ✓ | real handler |
| Public status (`/api/intel/iocs.json`) | ✓ counts and source states, **no values** | ✓ | ✓ | ✓ | build test |

All gates use `tierAtLeast()` from `api/_lib/tier-entitlements.js`. No `tier === …` literals were added.

## 2. Offer-copy corrections made in this change (`api.html`)

| Before | After | Reason |
|---|---|---|
| "Extracted and correlated from 12 authoritative sources. Enterprise: STIX 2.1 export." | Names the 4 abuse.ch sources; per-indicator source link, confidence basis and expiry; "Team and Enterprise: STIX 2.1" | 4 sources, not 12; STIX is sold on Team too |
| "STIX 2.1 bundle … MITRE ATT&CK pattern syntax. Ready for OpenCTI ingestion." | "STIX patterns, stable IDs, TLP marking and source references" | STIX patterns are not ATT&CK; OpenCTI ingestion was not tested |
| "Bulk IOC export (CSV/JSON)" | "Bulk IOC export (JSON, 200 per page)" | CSV is not implemented on `action=iocs` |
| "Custom IOC tagging + reporting" (Enterprise) | removed | not implemented |

Not changed (outside the IOC scope, recorded for follow-up): the API page still lists "Seats: 5 included" on Team. Seat enforcement does not exist (gap register, #310).

## 3. Honest selling position

- **Defensible claims:**
  - curated, deduplicated, lifecycle-managed indicators from named public sources;
  - every indicator links to its source record;
  - deterministic, published confidence and expiry rules;
  - a block/alert/hunt recommendation;
  - STIX 2.1 that validates against the OASIS reference library.
- **Not defensible:**
  - proprietary discovery;
  - real-time delivery;
  - fixed indicator counts;
  - "validated" or zero false positives;
  - actor attribution;
  - CSV export.

## 4. Revenue path

| Step | Status |
|---|---|
| IOC feed unblocks the Pro value proposition (it was empty) | Done on merge and deploy |
| Team STIX becomes real value (the bundle was empty or invalid) | Done on merge and deploy |
| Premium store (detection packs, reports) | **BLOCKED: operator.** D1 migrations not applied (see the certification document) |
| Paid acquisition proof (Razorpay test-mode transaction) | **BLOCKED:** no test credentials in this environment |
| Next value multipliers (no new infrastructure) | CSV/TAXII-style pagination cursor; per-customer watchlist match against the feed (needs D1 migrations); SIEM push of `block`-only indicators |

## 5. Cost impact

| Item | Change |
|---|---|
| New Cloudflare resources | **None** (no D1, KV, R2, Queues or Durable Objects; no new bindings or secrets) |
| Worker bundle | +~930 KB raw / ~97 KB gzip (feed bundled), against the current ~3.3 MB gzip |
| GitHub Actions | One extra step per pipeline run, measured at under 2 s, about 13 MB downloaded |
| Repository growth | Store ≤ 2,000 records (~3 MB) plus feed ~0.9 MB, rewritten per run (git delta-compressed) |
