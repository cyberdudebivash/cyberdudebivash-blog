# Premium Intelligence Access Runbook

Premium reports are included with **Sentinel APEX PRO, ENTERPRISE and MSSP**. Architecture: `docs/architecture/UNIFIED-SENTINEL-COMMERCE.md`.

## Customer journey

1. Browse `https://blog.cyberdudebivash.in/intelligence-store.html`. Each card shows title, version, evidence cut-off, sources, scope, SHA-256 and "What's inside".
2. "Unlock with Sentinel APEX" goes to `https://intel.cyberdudebivash.com/upgrade.html?plan=pro&utm_source=intel-factory&utm_medium=premium-intelligence&utm_campaign=sentinel-apex-conversion&utm_content=<report_id>`.
3. After subscribing, the customer opens `/customer-library.html` and enters their Sentinel APEX key (`cdb_…`). Earlier blog keys (`sentinel_…`) also work.
4. Download. The response carries `X-Content-SHA256`; the customer can compare it with the SHA-256 on the card.

## API

| Call | Result |
|---|---|
| `GET /api/v1/premium-intelligence?action=catalog` | Public. Certified SELLABLE reports with `artifact_sha256`, `required_plan`, `upgrade_url`. Never `artifact_key` |
| `GET …?action=library` + `Authorization: Bearer <key>` | Reports available on this key: `access` is `SENTINEL_APEX_PLAN` or `PURCHASE`, plus `plan_access` and `upgrade_url` |
| `GET …?action=download&report_id=<id>` + key | 200 bytes + `X-Content-SHA256` |
| `POST …?action=checkout` | **410** `PREMIUM_CHECKOUT_MOVED` + `upgrade_url`. No side effect |

| Error | Status | Meaning |
|---|---|---|
| `PREMIUM_PLAN_REQUIRED` | 403 | Report available, but the key has no eligible plan. Body has `upgrade_url` |
| `REPORT_NOT_AVAILABLE` | 403 | Report is PAUSED, RETIRED or not certified (plan holders included) |
| `REPORT_NOT_FOUND` | 404 | Unknown report |
| `INVALID_KEY` | 401 | Sentinel APEX credential not recognised or not active (revoked, expired, cancelled) |
| `ENTITLEMENT_SERVICE_UNAVAILABLE` | 503 | Gateway unreachable or binding missing. Fail closed; retry |

## Rules that do not change

- Product status overrides plan: PAUSED or RETIRED reports are never served to plan holders.
- Nothing in the URL grants access: `?plan=`, UTMs, tier parameters and browser storage are all ignored.
- Keys only in headers. `?api_key=` is never used for a platform credential.
- Legacy buyers keep the exact artifact they bought, even if the product is later paused or retired. A full refund still revokes it (`markFullyRefunded`).

## Operator checks

```bash
# Gateway contract (no credential): {"valid":false,"tier":"free"}
curl -s https://intel.cyberdudebivash.com/api/auth/validate
# Checkout retired:
curl -s -X POST 'https://blog.cyberdudebivash.in/api/v1/premium-intelligence?action=checkout' -H 'content-type: application/json' -d '{}'
# Free/unknown key → 401/403; a test PRO key (operator-owned) → 200 with X-Content-SHA256
```

## Troubleshooting

| Symptom | Check |
|---|---|
| Every subscriber gets 503 | `SENTINEL_GATEWAY` binding on the deployed Worker (Cloudflare → Workers → cyberdudebivash-blog → Settings → Bindings); `sentinel-apex-gateway` deployed and healthy |
| A subscriber gets 401 | Gateway says the key is inactive. Check the subscription and key status in Sentinel APEX, not the blog |
| A subscriber gets 403 `PREMIUM_PLAN_REQUIRED` | The gateway returned a tier other than PRO/ENTERPRISE/MSSP |
| A report is missing for subscribers | Catalog row status (`SELLABLE`?) and certification. Use `set-status` with the analyst key |
| Access still works right after a cancellation | Up to 60 s per isolate (validation cache) |
