# Blog Razorpay Webhook Runbook

## What the blog sells

Since 2026-10-01 the commercial boundary is:

- **Sentinel APEX platform** (`intel.cyberdudebivash.com/upgrade.html`) sells every plan and subscription.
- **The blog** sells only premium intelligence reports.

The two may share one Razorpay account, so this webhook receives platform events too. It must fulfil only orders the blog created.

## Configuration

| Item | Value |
|---|---|
| Endpoint | `https://blog.cyberdudebivash.in/api/v1/billing/razorpay-webhook` |
| Events | `payment.captured`, `order.paid`, `refund.processed` |
| Secret | Worker secret `RAZORPAY_WEBHOOK_SECRET` (`npx wrangler secret put RAZORPAY_WEBHOOK_SECRET --name cyberdudebivash-blog`). The value is entered in the Razorpay webhook form and never committed or logged. |
| Other Razorpay secrets | `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` (premium checkout and verification) |

Why these three events are sufficient:

- `payment.captured` and `order.paid` both carry the payment entity used for fulfilment. Either one completes a purchase if the buyer closes the browser before the checkout callback.
- `refund.processed` drives refund revocation.

No other event type is read, so subscribing to more only adds load. `payment.authorized` is not needed because orders use `payment_capture: 1`.

**Add this as a separate webhook.** Do not edit or delete the Sentinel APEX platform's own webhook; Razorpay allows several per account.

## Order ownership

New premium orders carry server-set notes, derived from the D1 catalog row:

```json
{ "platform": "CYBERDUDEBIVASH_INTEL_FACTORY", "product_type": "PREMIUM_REPORT",
  "sku": "<report_id>", "artifact_sha256": "<sha256>",
  "commerce": "premium_intelligence", "report_id": "<report_id>" }
```

The notes are for dashboard attribution and reconciliation. Fulfilment does not rely on notes. The authoritative ownership record is the `premium_orders` row that checkout writes in D1 before any payment can happen; it is unique on `razorpay_order_id`.

## Processing

```text
HMAC-SHA256(raw body, RAZORPAY_WEBHOOK_SECRET)
  missing or invalid ............ 400, no side effect
parse the same raw bytes (never an adapter-parsed body)
payment.captured / order.paid:
  premium_orders row for payment.order_id?   (one indexed D1 read)
    yes -> payment id/order/amount/currency/captured must match the order snapshot
           -> claim payment (ORDER_CREATED -> PAYMENT_VERIFIED)
           -> grant entitlement
           -> mark ENTITLED (the replay marker)
           -> 200
    no  -> legacy blog plan record in Redis (DEPRECATED; pre-cutover, 24 h TTL)?
             yes -> legacy plan confirmation
             no  -> foreign_platform_webhook_ignored -> 200, no writes
refund.processed:
  premium order for refund.payment_id?
    full refund    -> order REFUNDED, entitlement REFUNDED -> 200
    partial refund -> no change -> 200
  otherwise -> foreign_platform_webhook_ignored -> 200, no writes
```

The handler makes no external calls (no Razorpay order lookup, no feed or pipeline work). Classifying an event costs one indexed D1 read, plus one Redis read if the event is not premium.

## Order state machine (`premium_orders.state`)

| State | Meaning | Allowed next state |
|---|---|---|
| `ORDER_CREATED` | Razorpay order created; nothing paid | `PAYMENT_VERIFIED` (only with `razorpay_payment_id IS NULL`) |
| `PAYMENT_VERIFIED` | Captured payment claimed for this order | `ENTITLED`, `REFUNDED` |
| `ENTITLED` | Entitlement granted (the fulfilment marker) | `REFUNDED` |
| `REFUNDED` | Processed full refund; access revoked | none (terminal) |
| `CANCELLED` | Reserved | none |

A payment event for a `REFUNDED` order is acknowledged and re-grants nothing. Unpaid orders stay `ORDER_CREATED`; Razorpay expires them.

## Replay, mismatch and retry behaviour

| Situation | HTTP | Effect |
|---|---|---|
| The same `payment.captured` or `order.paid` again, or both | 200 | One entitlement in total. A delivery on an `ENTITLED` order with the same payment returns immediately. |
| Wrong amount, wrong currency, payment not captured | 200 | Logged as `premium_payment_rejected`; nothing granted |
| A second, different payment for an entitled order | 200 | `PAYMENT_CONFLICT` logged; refund the duplicate manually |
| D1 or Redis unavailable, or the entitlement write fails | 500 | Razorpay retries. The order is not marked `ENTITLED` until the entitlement row exists. |
| Platform (Sentinel APEX) or unknown order | 200 | `foreign_platform_webhook_ignored`; zero writes |
| Duplicate full refund | 200 | Idempotent (the state is already `REFUNDED`) |

## Refund policy

- **Full refund** (`refund.status=processed`, and the payment is `refunded` or `amount_refunded >= amount`):
  - the entitlement becomes `REFUNDED`;
  - future downloads are refused;
  - the order and the download audit are kept.
- A copy downloaded before the refund cannot be recalled.
- **Partial refund:** access stays.
- **Plan refunds** for historical blog plan payments are logged only. Tier changes are an operator decision.

## Download access model

Access is account-based and persistent: the buyer's API key owns the entitlement. A download:

1. authenticates the API key;
2. looks up the caller's own `ACTIVE` entitlement;
3. checks the artifact's size and hash;
4. reads the object from R2 (private bucket, no public URL);
5. returns it with `Cache-Control: private, no-store`.

Every download is written to `premium_download_audit`.

## Observability (Workers logs, PII-free)

| Event | Fields |
|---|---|
| `premium_order_created` | `order`, `report`, `amount_minor`, `currency` |
| `premium_payment_verified` | `event` or `via`, `order`, `report` |
| `premium_entitlement_granted` | `order`, `report` |
| `premium_payment_rejected` | `event`, `order`, `payment`, `code` |
| `premium_report_downloaded` | `order`, `report` |
| `premium_refund_processed` | `refund`, `order`, `full_refund` |
| `foreign_platform_webhook_ignored` | `event`, `order` or `refund`, `platform` |

No email, card data, API key, signature or payload is logged.

## Test procedure

1. **Unsigned request:** `curl -X POST <endpoint> -H 'Content-Type: application/json' -d '{}'` should return `400 Missing X-Razorpay-Signature`.
2. **Ping:** in the Razorpay Dashboard, use Webhooks → this webhook → "Test webhook" (if offered). A signed ping returns 200.
3. **Real purchase:** make one premium purchase with the operator's own identity and a free API key.
   - Expected Workers logs: `premium_order_created`, then `premium_payment_verified`, then `premium_entitlement_granted`.
   - The report appears in My Intelligence and downloads.
   - The Razorpay delivery log shows 200 for both `payment.captured` and `order.paid`.
4. **Refund:** refund that payment in full. Expect `premium_refund_processed` with `full_refund:true`; the download is then refused.

Automated coverage: `api/v1/__tests__/premium-webhook-integrity.test.js`. It runs the real webhook, service and D1 SQL (migration 0008 on SQLite) with real HMAC signatures, and 8 of 8 negative controls are detected.

## Disable / rollback

| Situation | Action |
|---|---|
| Stop premium fulfilment by webhook | Disable the blog webhook in the Razorpay Dashboard. The checkout callback still verifies purchases. |
| Stop premium sales | Pause a report: `POST /api/v1/premium-intelligence?action=set-status` with `{report_id, status:"PAUSED"}` (analyst key). To stop all sales: `npx wrangler secret delete RAZORPAY_KEY_SECRET --name cyberdudebivash-blog`; checkout then returns "Online purchase temporarily unavailable". |
| Bad deploy | Roll back the Worker version in Cloudflare, then `git revert` the release commit. |
