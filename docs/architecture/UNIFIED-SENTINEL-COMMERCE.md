# Unified Sentinel APEX Commerce

**Status:** implemented 2026-10-02 (owner decision: Sentinel APEX is the only payment authority; entitlement bridge: service binding to the gateway, chosen by the owner).

This is an architectural event under CLAUDE.md. It adds a new Worker-to-Worker dependency.

## One payment architecture

```
Intel Factory / blog (discovery, previews, delivery)
  → "Unlock with Sentinel APEX" → intel.cyberdudebivash.com/upgrade.html?plan=pro&utm_…
  → Sentinel APEX Razorpay subscription (sentinel-revenue-engine)
  → Sentinel APEX API key  cdb_<tier>_… in API_KEYS_KV + strong-consistency authority
  → blog premium endpoints: key → SENTINEL_GATEWAY service binding → /api/auth/validate
  → tier PRO | ENTERPRISE | MSSP → certified, SELLABLE report → R2 artifact (SHA-256 verified)
```

The blog no longer takes money for reports. `action=checkout` returns `410 PREMIUM_CHECKOUT_MOVED` and has no side effect.

## Current architecture (before)

| Element | Before |
|---|---|
| Payment for reports | Standalone Razorpay order per report on the blog (₹1,999), blog webhook to fulfil |
| Customer credential | Blog `sentinel_…` key (Upstash Redis `user:key:<sha256>`) |
| Access | Per-report `premium_entitlements` row only |
| Sentinel APEX subscribers | **Not recognised.** Their `cdb_…` keys live in the gateway's `API_KEYS_KV`, and no Sentinel APEX payment ever writes the blog's Redis |

## Why it was insufficient

The owner's decision makes the Sentinel APEX subscription the entitlement. The blog's own key store cannot see that subscription, so without a bridge a paying PRO subscriber could not download.

Two alternatives were rejected:

- **Reading `API_KEYS_KV` directly.** It misses revocations held in the gateway's strong-consistency authority, which overrides the KV `subscription_status`. It would also give the blog read access to every raw intel key.
- **Sharing `CDB_JWT_SECRET`.** A blog compromise could then mint gateway tokens.

## Proposed and implemented architecture

| Element | After |
|---|---|
| Binding | `wrangler.jsonc` `services: [{ binding: "SENTINEL_GATEWAY", service: "sentinel-apex-gateway" }]`. A binding to an existing Worker, not a new resource |
| Authority | The gateway's existing `GET /api/auth/validate` (`resolveAuth`: KV record, strong-consistency key/customer state, expiry, subscription status). Response `{ valid, tier, sub }` |
| Credential families | `cdb_…` or a SENTINEL-APEX JWT goes to the gateway. `sentinel_…` goes to the existing `authenticate()`, unchanged |
| Tier mapping | Gateway `PRO`, `ENTERPRISE`, `MSSP` (exact case) are eligible; `FREE` and anything else are not. Blog tier `pro`/`team`/`enterprise` (`tierAtLeast(tier,'pro')`) is eligible |
| Access rule | `legacy purchase` OR (`status=SELLABLE` AND `certification_state=PREMIUM_CERTIFIED` AND plan eligible) |
| Code | `api/_lib/sentinel-plan-entitlement.js` (URL helper, tier policy, gateway call); `api/_lib/sentinel-gateway-binding.js` (binding holder); `premium-commerce-service.js` `listPremiumLibrary` / `downloadPremiumReport`; route `api/v1/premium-intelligence.js` |
| Upgrade URL | One helper, `premiumUpgradeUrl()`, built on `payment-utils.INTEL_UPGRADE_URL`. UTMs are sanitised to `[a-z0-9._-]`; never an email, key or ID |

## Expected benefits

- One payment authority.
- No second webhook to operate.
- Subscribers get every certified report with no per-report purchase.
- Revocation follows the gateway's own authority.
- The Razorpay frontend script is removed from the store page.

## Cost and latency

| Item | Impact |
|---|---|
| New Workers / D1 / R2 / KV / Queues / DO / cron | **0** |
| Per premium library or download call | ≤ 1 internal service-binding subrequest. Cached per isolate for 60 s, so library then download is one call. Catalog and preview pages make 0 calls |
| Gateway side effects | Brute-force counters (`RATE_LIMIT_KV`) only on invalid keys, bucketed per real client IP (forwarded) |
| Removed | Razorpay `checkout.js` from the store page; standalone order creation |

## Compatibility

| Consumer | Effect |
|---|---|
| `action=catalog` / `detail` | Additive fields `required_plan`, `upgrade_url`. `price_minor`/`currency` kept as historical metadata |
| `action=checkout` | **410** `PREMIUM_CHECKOUT_MOVED` + `upgrade_url` (was 201/4xx). 0 orders ever existed |
| `action=verify`, webhook | Unchanged (legacy orders; none exist) |
| `action=library` / `download` | Accept `cdb_…` keys as well. Response adds `access`, `plan_access`, `upgrade_url`. Legacy buyers unchanged |
| `listLibrary` / `downloadReport` (dashboard, evidence route) | Unchanged |
| `createCheckout` | Deprecated, unrouted, kept for reconciliation |

## Rollback

1. Revert the PR. This removes the binding and restores the checkout route.
2. Or keep the code and remove `services` from `wrangler.jsonc`. Plan downloads then fail closed with `503 ENTITLEMENT_SERVICE_UNAVAILABLE`; legacy and blog-key access keep working.

## Known limits

- The gateway resolves an unknown or missing KV `tier` to `PRO` (`TIERS[record.tier] || TIERS.PRO`). The blog maps only the exact strings it is given, so it cannot detect a malformed record that the gateway has already mapped to PRO. That quirk is in the gateway, outside this repository.
- Revocation lag at the blog is at most 60 s (per-isolate cache).
- **Verify after deploy:** the blog forwards the caller's IP as `CF-Connecting-IP`/`X-Forwarded-For` over the binding. If the runtime does not let the gateway see those values, its brute-force counter would bucket all blog callers together. Five invalid keys would then lock platform-key validation for the lockout window. That fails closed (no access granted) but is an availability risk. The 60 s negative cache limits repeated bad-key calls.
- `getEvidenceContract` (`/api/v1/intel/evidence/<id>`) still uses legacy entitlements only. Plan subscribers download the report but not yet the SOC evidence contract.
