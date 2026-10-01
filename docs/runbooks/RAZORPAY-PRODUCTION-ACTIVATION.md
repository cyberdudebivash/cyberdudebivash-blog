# Razorpay Production Activation Runbook

**Status (2026-10-01):** secrets configured on the Worker (live keys), verified live.

**Scope change (owner decision 2026-10-01):** API **plans** are sold only on the
CYBERDUDEBIVASH SENTINEL APEX platform checkout
(`https://intel.cyberdudebivash.com/upgrade.html`), which has its own Razorpay
integration and webhook. On the blog, Razorpay now serves **premium
intelligence reports** only:

- `billing?action=create-razorpay-order` and `action=create-subscription`
  return `410 PLAN_CHECKOUT_MOVED` with `checkout_url`.
- `action=verify-razorpay-payment` and the webhook still complete plan
  orders created before the switch.
- The blog webhook below is still required, for premium-report payments and
  refunds (a full refund revokes the report entitlement). Razorpay accounts
  can hold several webhooks, so it coexists with the platform's own webhook.

No secret values appear in this document or anywhere in the repository.

## 1. Worker identity (verified)

| Field | Value | Evidence |
|---|---|---|
| Worker script | `cyberdudebivash-blog` | `wrangler.jsonc` `name`; Cloudflare API script list |
| Route | `blog.cyberdudebivash.in` (custom domain) | `wrangler.jsonc` `routes` |
| Runtime | `compatibility_date` 2026-08-17, `nodejs_compat` | Secrets are exposed to `process.env`, which `api/_lib/razorpay.js` reads |
| Bindings | `DB` (D1 `sentinel-apex-core`), `PREMIUM_REPORTS` (R2 `sentinel-apex-premium-reports`), `ASSETS` | `wrangler deploy --dry-run` |

## 2. Secrets (exact names)

| Secret | Used by | Purpose |
|---|---|---|
| `RAZORPAY_KEY_ID` | `api/_lib/razorpay.js` | Public key id; returned to checkout.js |
| `RAZORPAY_KEY_SECRET` | `api/_lib/razorpay.js` | REST auth; checkout signature HMAC |
| `RAZORPAY_WEBHOOK_SECRET` | `api/_lib/razorpay.js` | Webhook signature HMAC |

Optional, already supported:
- `PREMIUM_COMMERCE_CURRENCIES` (default `INR`).
- `ANALYST_KEYS`, required to publish premium reports (see §9).

## 3. Configure the secrets

Run from the repository root, authenticated as the account owner. Each command prompts for the value, so nothing lands in shell history.

```powershell
npx wrangler whoami                      # confirm the expected account before any change
npx wrangler secret list --name cyberdudebivash-blog
npx wrangler secret put RAZORPAY_KEY_ID --name cyberdudebivash-blog
npx wrangler secret put RAZORPAY_KEY_SECRET --name cyberdudebivash-blog
npx wrangler secret put RAZORPAY_WEBHOOK_SECRET --name cyberdudebivash-blog
```

`wrangler secret put` deploys a new Worker version immediately; no source change or redeploy is needed. Activate **test-mode keys first** (`rzp_test_…`) and complete §5–§8 before switching to live keys.

## 4. Razorpay Dashboard: webhook

| Setting | Value |
|---|---|
| URL | `https://blog.cyberdudebivash.in/api/v1/billing/razorpay-webhook` |
| Secret | the same value stored as `RAZORPAY_WEBHOOK_SECRET` |
| Events | `payment.captured`, `order.paid`, `refund.processed` |

Pre-activation check, verified 2026-10-01:
- A request without a signature returns `400 Missing X-Razorpay-Signature`.
- A request with a forged signature returns `400 Invalid signature`.

## 5. Activation checks (test mode, operator test identity only)

Never use a real customer as the first canary.

| # | Check | Expected |
|---|---|---|
| 1 | `POST /api/v1/billing?action=create-razorpay-order` with `{email, plan_type:"pro"}` | `201`. `order.amount` = 149900 (paise), `currency` INR, and `key_id` starts with `rzp_test_` |
| 2 | The same request with an extra `amount` field | `400 INVALID_FIELDS` (the client cannot set the price) |
| 3 | Complete checkout in `/pricing.html` with a Razorpay test card | Success screen shows "Pro Tier Activated!" (or "Payment confirmed — register…" if no key exists yet) |
| 4 | Re-POST the same `verify-razorpay-payment` body | `already_processed: true`; tier unchanged; no second grant |
| 5 | Razorpay Dashboard → webhook delivery log | `payment.captured` delivered with `200`; redelivery returns `200` and grants nothing new |
| 6 | Tamper the signature in a verify call | `403 INVALID_SIGNATURE`; no grant |
| 7 | Close the browser before the callback, then let the webhook arrive | Tier is still granted (webhook path) |

## 6. Entitlement verification

- `GET /api/v1/intel?action=iocs` with the test account's API key should return `200` with indicators.
- For a Team purchase, `format=stix` returns a bundle.

## 7. Refund verification

1. Refund the test payment in the Razorpay Dashboard.
2. Expect `refund.processed`, delivered `200`.
3. Expect an audit event `RAZORPAY_REFUND_RECORDED`, recorded once even if Razorpay redelivers.

**API plans:** the tier is **not** revoked automatically. Revocation after a refund is an operator decision; apply it with the existing admin tooling. Payment history is never deleted.

**Premium reports:** a processed **full** refund revokes the report entitlement automatically. A partial refund does not.

## 8. Go live

1. Repeat §3 with live keys.
2. Update the Razorpay webhook to live mode with the same URL and events.
3. Make one low-value live purchase with the operator identity, then refund it.
4. Repeat checks 1, 3, 5 and §7.

## 9. Premium reports (after §5 passes)

```powershell
node scripts/publish-premium-reports.js                      # dry run: certifies all 4 locally
$env:PREMIUM_ANALYST_KEY = "<analyst key>"; node scripts/publish-premium-reports.js --publish
```

The script calls the production `publish-certified` endpoint, which:
1. stores the reviewed artifact and evidence in R2 and verifies them;
2. writes the D1 catalog row;
3. is confirmed by the script through the public `detail` endpoint.

Afterwards, `GET /api/v1/premium-intelligence?action=catalog` should return `count: 4`.

## 10. Disable / rollback

| Situation | Action |
|---|---|
| Stop online checkout immediately | `npx wrangler secret delete RAZORPAY_KEY_SECRET --name cyberdudebivash-blog`. Checkout returns `503` with the email fallback. Verification also returns `503`, so nothing is granted. |
| Bad deploy | Roll back to the previous Worker version via Cloudflare deployment controls, and `git revert` the release commit. |
| Pause a premium product | `POST action=set-status` with `{report_id, status:"PAUSED"}` (analyst key). The catalog hides it; existing entitlements keep working. |
