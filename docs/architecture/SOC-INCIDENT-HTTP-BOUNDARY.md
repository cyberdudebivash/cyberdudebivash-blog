# SENTINEL APEX SOC — Incident HTTP Boundary (Phase 5 Preview)

**Status:** Source-only; NOT wired to the production Cloudflare Worker; feature gate disabled by default.

## Available design

`api/_lib/soc-incident-http.js` implements a small HTTP Request/Response adapter for an approved future `https://soc.cyberdudebivash.in` route, assuming an independently verified incident service is injected. It does **not** implement login or validate signatures itself: that is the responsibility of Phase 4 identity/session composition and Phase 3 tenant authorization.

The factory requires explicit `approvedOrigin`, a fully implemented incident service, and an `enabled` flag. If the flag is missing or false, **all requests return 404**. This does not add the route to `workers/lib/route-table.js`, `workers/lib/router.js`, or Cloudflare DNS.

Proposed future path (NOT LIVE): `/api/v1/soc/tenants/{tenant_id}/incidents` and `/api/v1/soc/tenants/{tenant_id}/incidents/{incident_id}`.

- GET list or specific incident (bounded limit 1–50; explicit filter only).
- POST incident create with mandatory bearer token, JSON content type, bounded request body and an idempotency key.
- PATCH incident with mandatory UUID-like incident ID, version precondition (If-Match) and idempotency key.
- Explicitly reject cookies, missing bearer authorization, unexpected queries, other hosts/origins, unapproved methods and unknown routes.
- No CORS approval for third-party origins and no cacheable responses; no raw SQL, D1 error details, bearer tokens or secrets in error output.
- Mutable operations are further protected by Phase 3 server-side RBAC, SQLite audit triggers, replay protection and version comparisons.

## Required before activating an actual HTTP route

1. The Phase 4 identity/session PR #366 must pass review and integrate a real operator-approved OIDC provider, verified token issuance, session enrollment and revocation.
2. Complete signed and authorized D1 migrations 0009–0011 after schema inventory, isolated D1 rehearsal, backup/restore, data residency and cost review.
3. Establish an edge-enforced rate limiter that fails closed, WAF controls, request audit trails, response hardening, bearer-token lifecycle, IdP JWKS rotation, MFA and revocation drills.
4. Execute complete Workerd + native D1 live-like tests, IDOR and race-condition negatives, expected versus actual HTTP response tests, accessible customer-facing UI review and rollback.
5. Obtain separate operator-approved production deployment and customer/contract acceptance. Do not infer release from CI, merger, or a green non-production demo.

## Caveat

This adapter is not an externally usable SOC incident API. The default 404 is intentional, not a failure to fix by toggling a development flag. No customer telemetry, billing, subscription, incident actions or hostname cutover is carried out by this PR.

**Verdict:** internal HTTP contract code candidate; **production SOC NO-GO**.
