# P0 SOC customer access and shared subscription release contract

Status: PROPOSED / NOT PRODUCTION CERTIFIED
Date: 2026-10-30
Scope: SENTINEL APEX Threat Intel and SOC shared commercial subscription; AI Security Hub independent.

## Commercial boundary
- Threat Intel + SOC: one Razorpay subscription per customer for PRO USD 49/month, ENTERPRISE USD 499/month, or MSSP USD 999/month. No duplicate SOC charge.
- AI Security Hub: independent Razorpay checkout and subscription. Neither purchase grants access to the other commercial product implicitly.
- Existing Intel gateway and revenue engine remain the billing authority pending code and deployed-state verification. Do not create another billing authority in SOC.
- A paid subscription does not imply access to unfinished SOC features. Expose only features explicitly certified and enabled for that tier.

## Fail-closed SOC access contract
1. Authenticate the caller with an approved customer identity or scoped service credential. Internal ANALYST_KEYS are not customer identity.
2. Resolve a server-trusted subscription identity and its lifecycle status from the canonical authority. Never trust a client-supplied plan, tenant ID, or billing status.
3. Resolve tenant membership, resource and action permission server-side. Every customer query, export, background job and object fetch must apply the authenticated tenant predicate.
4. Deny on unavailable entitlement authority, unknown tier, expired or revoked subscription, mismatched tenant, absent scope, or unverified identity. Public intelligence endpoints remain governed separately.
   - **Separate plan eligibility from SOC incident-feature authorization.** A PRO/ENTERPRISE/MSSP Threat Intel key is not sufficient to read or mutate customer incidents. The isolated SOC HTTP adapter requires a server-verified decision naming `product=SENTINEL_APEX_SOC`, `subscriptionStatus=active`, the authenticated tenant, and an explicit `soc.incidents.read` (GET) or `soc.incidents.write` (POST/PATCH) capability. Unknown, missing or ambiguous grants deny access. The authority must resolve the canonical shared payment record and must not infer SOC activation from a plan label or user-submitted claims.
   - **Billing lifecycle:** the source-only managed SOC incident interface rejects `past_due` until a separately approved service-specific grace policy exists; this does not alter current Threat Intel grace behavior or the existing premium report access.
   - The authority implementation, tenant-to-customer binding, service-specific entitlements and external OIDC verification still require independent implementation/certification. Source-only guards do not constitute access provisioning.
5. Cache only with a bounded revocation strategy backed by a strongly consistent authorization decision; do not make eventually consistent KV the sole revocation authority.
6. Audit access decisions without logging credentials, raw customer telemetry or payment secrets.

## Required staging certification
| Test | Pass criterion |
| --- | --- |
| Signed Razorpay test-mode PRO/Enterprise/MSSP payment | One canonical subscription, exactly one matching tier grant in both platforms |
| Duplicate browser verification and webhook replay | No duplicate charge, grant, key, or side effect |
| Forged or unsigned webhook | Rejected without state change |
| Payment cancellation, expiry, failed renewal and refund | Both products apply the same effective lifecycle state |
| Customer A reading customer B object/search/export | Denied; no metadata leakage |
| Customer-selected tenant/role/tier in headers or body | Ignored or rejected |
| Internal analyst key on customer endpoint | Denied unless explicitly authenticated and scoped as a customer principal |
| Threat Intel + SOC purchase on Hub endpoints | No implicit Hub entitlement |
| Hub purchase on Intel + SOC endpoints | No implicit Intel/SOC entitlement |
| Entitlement authority outage | Fail closed, observable error, no privilege escalation |
| Auth revocation or role downgrade | Enforced within documented revocation objective |
| Rollback and reconciliation | Previous stable release restored without losing payment ledger integrity |

## Deployment HOLD conditions
- SOC customer workbench remains internal-only until tenant-isolated data model, server-side enforcement, negative tests, audit evidence and independent review pass.
- Do not publish SOC 2 certification, 24/7 monitoring, customer incident metrics or Fortune 500 adoption claims without independent evidence.
- Do not modify live Razorpay plans, existing customer subscriptions, DNS, Cloudflare bindings or secrets under this documentation-only change.
- Before release: record deployed SHAs, signed test results, pricing-page parity, operator approval, rollback path and incident owner.

## Related evidence
- SOC architecture: docs/architecture/SENTINEL-APEX-SOC-TRANSFORMATION-2026-10-21.md
- SOC cutover: docs/runbooks/SOC-DOMAIN-CUTOVER.md
- Intel release ledger: cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM docs/CUSTOMER_RELEASE_LEDGER.md
- Intel payment runbook: docs/PAYMENT_RELEASE_OPERATOR_RUNBOOK.md in the Intel repository

This contract is a release gate, not evidence that shared SOC entitlement integration already exists.
