# Intel Factory — Security Assessment

**Date:** 2026-09-30 UTC · **Scope:** blog.cyberdudebivash.in Worker + static assets, API handlers under `api/`,
payment paths, public intelligence channels. Defensive review only; all live probes were unauthenticated
read-only GET/OPTIONS requests. **Register:** see `INTEL-FACTORY-PRODUCTION-GAP-REGISTER.md`.

## 1. Executive summary

Transport, framing and content-type headers are strong, internal repository files are not exposed, and every
authenticated API route rejects unauthenticated calls. The material findings are integrity and entitlement defects
rather than classic injection flaws: a paid tier denied its entitlements (fixed), payments that could be stranded
(fixed), third-party CORS proxies able to alter intelligence shown to users (open, homepage path removed), and a
placeholder PGP key on the CTI site (blocked on Blogger). No hardcoded secrets were introduced; none were found in
changed files.

## 2. Controls verified live

| Control | Evidence (2026-09-30) | Result |
|---|---|---|
| HSTS | `max-age=63072000; includeSubDomains; preload` on HTML and API | PASS |
| CSP (HTML) | `default-src 'self'`; `frame-ancestors 'none'`; script-src allows `'unsafe-inline'` + 4 CDNs | PASS with caveat (inline scripts required by current pages) |
| CSP (API) | `default-src 'none'; frame-ancestors 'none'` | PASS |
| X-Frame-Options / nosniff / Referrer-Policy / Permissions-Policy | DENY / nosniff / strict-origin-when-cross-origin / camera,mic,geo disabled | PASS |
| API cache | `Cache-Control: no-store, no-cache, must-revalidate` on 401 | PASS |
| Auth enforcement | `/api/v1/intel/*`, `/auth/me`, `/customer/dashboard`, `/ioc/search` → 401; `/admin/payments/pending` → 401 "Valid X-Admin-Key"; `/workbench/cases` → 401 | PASS |
| Internal file exposure | `/CLAUDE.md`, `/OPERATIONS.md`, `/RUNBOOKS.md`, `/docs/PRICING.md`, `/package.json`, `/wrangler.jsonc`, `/.env.example`, `/intel-state.json`, `/data/published_posts.json`, `/logs/`, `/admin-payments.html` → 404 | PASS (allowlist build + route-table block list) |
| CORS | `*` with header-based auth (`Authorization`/`X-API-Key`); no cookies set anywhere in `api/` or `workers/` | PASS (no ambient credentials, so no CSRF surface) |
| Razorpay signatures | HMAC-SHA256 + `crypto.timingSafeEqual` for payment and webhook signatures (`api/_lib/razorpay.js`) | PASS |
| Request IDs | No `X-Request-ID` on API responses | GAP (P2, below) |

## 3. Findings

| ID | Sev | Finding | Status |
|---|---|---|---|
| ICF-P0-001 | P0 | CTI homepage shows a placeholder PGP block (`mQGNBF+1234…`, `4096R/BIVASH_NAYAK`). A researcher encrypting to it cannot reach the operator, or reaches the wrong party. | BLOCKED (Blogger theme) |
| ICF-P0-002 | P0 | Authorization logic error: paid Team tier under-granted on 10 gates. Fixed with a canonical, fail-closed `tierAtLeast()`; recurrence guard test fails on any new literal pair. | FIXED |
| ICF-P0-004 | P0 | Payment state machine wrote replay markers before the grant. Fixed ordering; replay protection preserved. | FIXED |
| ICF-P1-004 | P1 | `connect-src` allows `api.allorigins.win`, `corsproxy.io`, `thingproxy.freeboard.io`, `api.rss2json.com`; `intelligence.html`, `live-feed-widget.js`, `auto-intel-engine.js` fetch intelligence through them. A compromised or malicious proxy can alter displayed intelligence (integrity, provenance), and any rendering via `innerHTML` becomes an XSS vector. Homepage use removed this tranche. | OPEN |
| ICF-P2-001 | P2 | `npm audit`: 6 high, all dev tooling (wrangler → miniflare → undici/sharp; brace-expansion) plus `js-yaml` (direct, merge-key CPU DoS). `js-yaml` parses only first-party Sigma (`detection-intelligence.js#validateSigmaStructural` ← canonical store), not request input, so it is not remotely reachable. Prod-only tree: 1 moderate. | OPEN — upgrade in a dedicated dependency change (wrangler 4.145.0, js-yaml 5.4.2) |
| ICF-P2-007 | P2 | No request ID on API responses or logs, so a customer report cannot be correlated with Worker logs. | OPEN |
| ICF-P3-002 | P3 | `razorpay-webhook.js` uses `req.body` when it is already an object instead of `JSON.parse(rawBody)` (the verified bytes). Safe only while the adapter derives `req.body` from the same bytes. | OPEN |
| — | Info | `billing-legacy.js` → `intel.cyberdudebivash.com/api/payment/razorpay/verify` bridge is HMAC-signed only when `APEX_BRIDGE_SECRET` is set, and the receiver must verify it (separate repository, documented in code). | Cross-service boundary; verify in platform repo |
| — | Info | Payment instructions fall back to `cyberdudebivash@upi` when `UPI_ID` is unset (`payment-utils.js`). | Confirm env set in production (ICF-P1-001 decision) |

## 4. Changes in this tranche with security relevance

- `api/_lib/tier-entitlements.js`: unknown or mis-cased tiers never elevate (`tierAtLeast('PRO','pro') === false`);
  `__proto__` resolves to the free profile.
- Payment grant ordering (ICF-P0-004): no new state; replay markers still block re-application once a grant succeeds.
- `runtime-state.js`: all browser fetches for runtime state are same-origin with an 8 s AbortController deadline.
- Homepage no longer contacts a third-party proxy (ICF-P1-005).
- CVSS corrections are read from a committed ledger; no runtime call to NVD from the Worker (no new egress, no new secret).
- `scripts/verify-cvss-provenance.js` reads optional `NVD_API_KEY` from the environment; never logged or written.

## 5. Secrets review

Changed files were reviewed for credentials: none added. The ledger contains only public NVD data. The
`.env.example` file is not in the public build (verified 404).

## 6. Recommended next security tranche

1. Replace proxy-based RSS/KEV fetching in `intelligence.html` / `live-feed-widget.js` / `auto-intel-engine.js` with
   first-party pipeline JSON, then remove the four proxy origins from `connect-src` (ICF-P1-004).
2. Add `X-Request-ID` (Worker-generated UUID, echoed in error bodies and logs) in `workers/lib/router.js` (ICF-P2-007).
3. Dedicated dependency upgrade PR (ICF-P2-001) with the full release gate.
4. Operator: publish a genuine PGP key or remove the PGP block from the CTI theme (ICF-P0-001).
