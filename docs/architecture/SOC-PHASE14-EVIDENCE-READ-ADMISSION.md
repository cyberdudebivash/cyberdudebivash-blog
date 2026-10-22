# SENTINEL APEX SOC — Phase 14 evidence-read cost and abuse admission

**Status:** Source-only security hardening. No public Worker route, Cloudflare D1 migration, customer evidence retrieval, billing, or DNS change.

## Confirmed gap

Merged Phase 13 created a pinned HTTPS provider-evidence client with trusted endpoint bindings, response-size bounds and timeouts, but it could be repeatedly invoked without any **durable per-tenant request limit**. Internal misuse, malfunctioning connectors or a compromised reviewer might amplify third-party and Cloudflare costs. Local process counters would not hold across Workers and regions.

## Fail-closed design

- New additive, metadata-only offline migration `0016_soc_evidence_read_budget.sql` introduces `soc_evidence_read_windows`, keyed by **tenant_id, connector_id, five-minute window start** with a bounded consumed counter and last-admitted timestamp. No source-event ID, payload, bearer secret, operator identity or customer PII is retained in this ledger. A retention/cleanup policy is still required for long-running production.
- New `soc-evidence-read-budget.js` executes exactly **one** conditional, parameterized D1 `INSERT ... SELECT ... ON CONFLICT ... DO UPDATE ... WHERE consumed < limit RETURNING consumed` in `nativeD1.withSession('first-primary')`. The `SELECT` verifies ACTIVE tenant and APPROVED connector even when the window row already exists. Quota checks and updates occur atomically in the same SQLite statement, avoiding a read-then-write race.
- Default admission quota is **12 provider reads per tenant+connector per five minutes**; trusted operator can set 1–60. The app never uses a fallback local quota on D1 outage, and invalid scope or failed quota returns no authorization.
- `soc-pinned-evidence-proxy.js` now **requires `admitRead`** at construction and calls it after exact pinned tenant/connector scope validation, but *before* the provider token resolver or HTTP fetch. Undefined/falsy, unavailable or denied budget grants fail closed; the error does not expose D1/provider secrets.
- `soc-pinned-evidence-boundary.js` constructs the **real D1 budget** itself; public callers cannot inject a fake allowance through this composition API. Signed MFA OIDC/current tenant analyst checks remain upstream of this gate, and the existing source-byte SHA256/review audit still applies downstream.
- Failed requests (including rejected provider responses, no matching source bytes or network outages) consume one admission slot by design. This limits abuse/cost, not just successful evidence reads. No retries are introduced.

## Verification

- Offline Python SQLite tests use the **actual admission SQL exported by the Node module** against the complete migration chain 0009–0016 and validate two-read exhaustion, atomic gate, separate tenants/connectors, window rollovers, suspended tenants and paused/revoked connectors, malformed windows and zero seeded event data.
- Jest tests cover quota configuration, first-primary D1 access, fail-closed D1 outages, invalid scope, 5-minute reset, zero token-fetch activity after quota denial, absence of local fallback, and entire OIDC→primary D1→quota→provider→analyst-review chain.

## Important limits before any customer-facing release

- This is **not** a global concurrency limit; concurrent provider requests up to the five-minute window's allowance may still execute simultaneously. Introduce a tenant-scoped concurrency gate, Workerd integration load tests and provider circuit breakers before offering an SLA.
- D1 quotas bound admitted reads but do **not** cap D1 itself under abusive inbound traffic. Network/API authentication, edge rate limits, WAF and service-level circuit breaking are separately required; this library is internal and no public endpoint was added.
- Provider request quotas, operator-approved token resolver, host DNS/egress controls, real EDR/SIEM adapter, signed customer consent, paid-source rate charges, legal retention and data residency remain unimplemented.
- The budget ledger will grow across five-minute windows; define and approve safe pruning, backup, and cost/retention limits before production rollout. No automatic deletion is done in this change.
- Validate native Cloudflare D1 `INSERT RETURNING` support and primary-session consistency under Workerd staging; offline SQLite and mocked Jest do not certify the live D1 implementation. No remote migration or customer data changes have been performed.
- Avoid false claims of a live, staffed SOC or revenue. `soc.cyberdudebivash.in` DNS remains under a separate approved migration gate.

**Release decision:** Security-source review only. Customer SOC remains **NO-GO**.
