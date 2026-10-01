# Plan Cutover Payment Reconciliation (2026-10-01)

## Window

| Event | Time (UTC) |
|---|---|
| Razorpay live keys set on the blog Worker | ~11:40 |
| Redis connected; first successful blog plan order | ~11:54 |
| PR cyberdudebivash/cyberdudebivash-blog#317 live (blog plan orders return 410) | 12:46 |

During this window, `POST /api/v1/billing?action=create-razorpay-order` could create real Razorpay orders for blog plans, such as Pro at ₹1,499.

## Evidence

**Source:** Cloudflare Workers observability for `cyberdudebivash-blog`, 11:30 to 13:30 UTC.
- Head sampling is at the default 1.0, so every invocation is logged.
- Triggers covered: `POST /api/v1/billing`, `POST /api/v1/billing/razorpay-webhook` and `POST /api/v1/premium-intelligence`.
- **NOT VERIFIED:** the Razorpay Dashboard/API was not available to this audit. The read-only tool `scripts/reconcile-razorpay-window.js` produces the authoritative Razorpay-side listing (see §4).

| Time | Request | Status | Caller |
|---|---|---|---|
| 11:44:58 | create-razorpay-order | 500 (Redis not yet configured) | audit canary (`curl`, Anthropic network) |
| 11:45:22 | create-razorpay-order | 500 (Redis not yet configured) | audit canary |
| 11:54:20 | create-razorpay-order | **201** | audit canary, `razorpay-canary@cyberdudebivash.com` |
| 11:54:21 | create-razorpay-order with an injected `amount` | 400 | audit canary |
| 11:54:23 | verify-razorpay-payment with a forged signature | 403 | audit canary |
| 11:54:24 | webhook, unsigned and forged | 400 / 400 | audit canary |
| 11:54:26 | premium checkout without a key | 401 | audit canary |
| 12:46:19 | create-razorpay-order | 410 (after #317) | audit canary |

**No other caller** reached any billing, webhook or premium endpoint in the window:
- no browser plan checkout;
- no `verify-razorpay-payment` success;
- no signed webhook delivery.

D1 `premium_orders` holds 0 rows.

## Classification

| Order | Payment State | Test/Real | Amount | Old Plan | Current Entitlement | Action |
|---|---|---|---:|---|---|---|
| Created 11:54:20 (`order_TidP…`) | Unpaid (no verify success, no signed webhook) | TEST_UNPAID (`r***@cyberdudebivash.com`) | ₹1,499.00 | pro | none | None; expires unpaid |
| Possibly created at 11:44:58 (the request returned 500 after the Razorpay call) | Unpaid; the order id was never returned to any client, so nobody could pay it | TEST_UNPAID | ₹1,499.00 | pro | none | None; expires unpaid |
| Possibly created at 11:45:22 (same) | Unpaid | TEST_UNPAID | ₹1,499.00 | pro | none | None; expires unpaid |

## Totals

| Item | Count |
|---|---:|
| Captured overlap orders | **0** |
| Real customers affected | **0** |
| Customers reconciled or migrated | 0 (none needed) |
| Unpaid test canaries | up to 3 (1 confirmed created, 2 possibly created) |

## Confirming on the Razorpay side (operator, read-only)

```powershell
$env:RAZORPAY_KEY_ID = "<key id>"; $env:RAZORPAY_KEY_SECRET = "<key secret>"
node scripts/reconcile-razorpay-window.js 2026-10-01T11:40:00Z 2026-10-01T12:50:00Z
```

The script classifies each order and masks emails:
- states: `TEST_UNPAID`, `REAL_UNPAID`, `REAL_CAPTURED`, `REAL_REFUNDED`, `UNKNOWN`;
- owners: `BLOG_PLAN`, `INTEL_FACTORY_PREMIUM`, `OTHER`.

**Expected result:** "BLOG_PLAN captured needing migration: 0".

## Migration procedure (only if a REAL_CAPTURED blog plan order ever appears)

1. Confirm the payment is captured in Razorpay and not refunded.
2. Map the plan to the nearest Sentinel APEX plan: starter and pro become PRO Defense; team and enterprise become Enterprise SOC.
3. Grant that plan on the Sentinel APEX platform for at least the purchased period, with an audit note citing the Razorpay payment ID. Never charge the customer again.
4. Record the action in this table.

Unpaid, failed, abandoned and canary orders are never migrated.
