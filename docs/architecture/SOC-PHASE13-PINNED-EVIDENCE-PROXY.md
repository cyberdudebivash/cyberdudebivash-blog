# SENTINEL APEX SOC — Phase 13 pinned source-evidence proxy client

**Status:** SOURCE ONLY. No real SIEM/EDR vendor, customer proxy, provider credential, public route or customer-operated SOC is enabled.

## Gap addressed

Phase 12 introduced independent SHA-256 verification of bytes returned by an authorized source adapter, but the injected adapter had no implementation. Any HTTP client used for this purpose could accidentally accept a user-provided hostname or unbounded response and expose a bearer token to a caller-controlled URL. The Phase 13 client supplies **a fixed-origin, scoped, stream-limited implementation for a standard customer-authorized evidence proxy contract**. It is not a proprietary vendor-specific EDR integration.

## Internal API

`createSocPinnedEvidenceProxy({bindings,resolveToken,fetcher,maxBytes,timeoutMs})` requires an immutable list of up to 32 exact tenant+connector bindings. Every entry defines `{tenantId,connectorId,endpoint}` with a canonical HTTPS, no-credential, no-query, no-fragment, non-IP, non-local endpoint. Duplicate tenant/connector bindings fail at startup. A tenant or connector not enrolled in the bindings cannot obtain a token or make a network request.

The only accepted read request is `{tenantId,connectorId,sourceEventId,signal}`. It must come from Phase 12 after an authenticated analyst and primary tenant D1 review check. `sourceEventId` is a strictly bounded opaque identifier used **only as the `event_id` query parameter on the pinned endpoint**. It never selects the network origin, path or bearer token.

`resolveToken(tenantId,connectorId)` is an independent trusted, server-side secret manager callback. Its exact implementation, provisioning and credential rotation are not part of this PR; this source does not add customer tokens or new Cloudflare secrets.

The client uses a GET with `Authorization: Bearer …`, `Accept: application/octet-stream`, `redirect: error` and `cache: no-store`. The standardized customer-managed proxy MUST return HTTP 200, `Content-Type: application/octet-stream` and three identity response headers:
- `x-soc-tenant-id`
- `x-soc-connector-id`
- `x-soc-source-event-id`

All must match the trusted requested scope exactly. These headers are a required source identity binding under the proxy's independently authenticated TLS/security domain, **not cryptographic evidence of provider honesty by themselves**.

The response body is read incrementally and limited while streaming (default 256 KiB, maximum configurable 1 MiB). Both actual received bytes and Content-Length are checked. A configured deadline and abort signal protect against stalled network connections. The client returns only the four fields expected by Phase 12's independent SHA-256 verifier, with raw bytes held transiently in memory; no payload is persisted or returned to an API client.

`createSocPinnedEvidenceBoundary` composes this client with the existing signed OIDC/MFA/session-revocation check, primary D1 analyst authorization and audit-atomic review. It only exposes internal `review` and `linkToIncident` methods. No HTTP router, Cloudflare account binding, D1 schema or customer source adapter was altered.

## Security properties and limitations

The fixed endpoint is defined by trusted operator configuration—not an arbitrary user field—and direct IP, localhost, insecure HTTP, embedded credentials, fragments, path traversal and query preconfiguration are rejected. **DNS-level SSRF/rebinding protections, a controlled egress network and certificate pinning are separate deployment controls**; URL validation by itself does not defeat a maliciously changed DNS record. An operator must inspect and authorize customer endpoint DNS, identity, TLS trust, IP policy and egress firewall rules before a pilot.

A generic proxy can only guarantee this contract if the **customer's real EDR/SIEM provider integration** performs independent source record lookup and returns exactly the bytes from which the original ingestion digest was computed. The provider needs stable, immutable/canonical original bytes. Re-serialized JSON or a normalized record can produce a different hash. Proxy implementation, provider token, source ownership and signed customer permission remain unimplemented.

The client rejects status 429 and 5xx; it does not auto-retry events or queue a source-read operation. Retry budgets, edge concurrency limits, token expiry/refresh, circuit breaking, data residency, audit logging of authorized reads (without PII), per-tenant quotas and incident response operations must be designed and tested before customer SLA commitments.

## Negative-test gates

Jest tests enforce allowlisted exact source binding, HTTPS-only origin, zero caller-provided URL, no token on wrong tenant, strict response identity, no redirects, no JSON/gzip, upper-bounded streaming, abort timeout, source mismatches, credential outages, no API credential leakage and real SHA recomputation. A separate integrated Jest suite uses a genuinely signed RS256/MFA access token, a primary-D1 session/membership fixture, a pinned mock HTTP Response with source bytes, and review write verification. **All generated fixtures are unit tests, not customer telemetry.**

This PR does **not** create a live SIEM or EDR provider adapter, connect an enterprise customer, deploy Workers, apply database migrations, configure new paid services, modify DNS, or charge customers.

## Next go/no-go sequence

1. Have a real pilot customer sign scope, source-owner authorization, collection consent and processing/retention terms.
2. Select one vendor and approved tenant-bound network origin; implement and threat-model the actual provider-to-standard-proxy mapping and connector secret handling.
3. Rehearse the full D1 migration chain and Workerd/KV/HTTP latency, timeouts, multi-tenant denial, rule provenance and source byte equivalence in staging; verify usage and cloud spending.
4. Run the read-only homepage/deployment canary and confirm the exact live Cloudflare Worker/asset SHA, then authorize reversible `soc.cyberdudebivash.in` rollout.
5. Perform operational analyst case-handling, audit custody, paid checkout/fulfillment and signed customer acceptance before any managed SOC claims.

**Customer SOC GA decision: NO-GO.**
