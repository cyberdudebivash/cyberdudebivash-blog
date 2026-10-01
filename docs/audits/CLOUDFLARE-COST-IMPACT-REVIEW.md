# Cloudflare Cost Impact Review — Revenue Activation Tranche (2026-10-01)

**Scope:**
- Razorpay hardening.
- Premium catalog manifest and publisher.
- Seat-claim removal.
- IOC hard limit.
- Widget polling reduction.

Guardrails and limits are in `docs/operations/CLOUDFLARE-COST-GUARDRAILS.md`.

## Current resource inventory (verified via Cloudflare API)

| Resource | State |
|---|---|
| Account | 24 Workers, 9 D1, 4 R2, 10 KV, 2 Queues, all pre-existing |
| This Worker | `cyberdudebivash-blog`: D1 `sentinel-apex-core`, R2 `sentinel-apex-premium-reports`, static `ASSETS`, cron `*/30` (pre-existing) |
| D1 `sentinel-apex-core` | 512 KB; 37 application tables |
| R2 `sentinel-apex-premium-reports` | empty |

**New resources created by this tranche: NONE.** No Worker, D1, R2, KV, Queue, Durable Object, cron or binding.

## Current verified plan

**NOT VERIFIED.** The `/subscriptions` endpoint is not readable with the available token. The 3.4 MB gzip bundle exceeds the Workers Free script limit, so Workers Paid is likely; this is an inference.

## Current verified usage

**NOT VERIFIED.** The analytics GraphQL query returned no data for this token.

## Incremental impact

| Dimension | Change | Assessment |
|---|---|---|
| Worker requests | No new endpoints, routes or crons | **0** |
| Worker subrequests | `verify-razorpay-payment` now calls `GET /payments/{id}` once per verification | +1 per purchase (only after Razorpay is activated) |
| Worker CPU | Constant-time checks only | negligible |
| D1 reads/writes | No new queries. Publishing 4 products = 4 catalog upserts, once. Checkout/verify use the existing indexed paths. | one-time, ~4 writes |
| R2 storage | 4 products × (report ~20–35 KB + evidence ~70–90 KB) | ≈ 0.45 MB |
| R2 Class A | Publication: 4 × 2 puts | 8 operations, one-time |
| R2 Class B | Publication: 4 × 2 heads (8). Per paid download: 1 head + 1 get | proportional to paid downloads only |
| Cron | None added. The existing `*/30` cron now finds migrated (empty) tables. | negligible reads |
| Static assets | Live widget: 60 s → 15 min, paused when hidden. Served by `ASSETS` without Worker invocation. | **reduction** (bandwidth only) |
| Worker bundle | `config/premium-catalog.json` and the publisher are not imported by the Worker | +0.95 KiB gzip of code (dry-run: 3,410.13 KiB on `main` → 3,411.08 KiB with this change) |
| GitHub Actions | One manual `sentinel-apex.yml` dispatch to verify the rebalance | not Cloudflare |

## Worst-case scenario

The worst case is Razorpay activated and heavy purchase traffic:
- each purchase adds one Worker request (order), one verification with one subrequest, and one webhook request;
- each download costs 2 R2 Class B operations.

Even 10,000 purchases a month would add ≈ 30,000 Worker requests and ≈ 20,000 Class B operations, orders of magnitude below any Workers Paid included allowance. That framing is conditional on the unverified plan.

Abuse paths are bounded:
- order creation is IP rate-limited (5/day);
- verification is limited to 3/day per IP;
- list endpoints are capped at 100–500 rows;
- the IOC feed is hard-capped at 600.

## Overage risk

None identified. Every recurring change is zero or a reduction. The only new per-event costs scale with paid transactions.

## Mitigation

- Hard limits are enforced in code and pinned by tests (`cost-guardrails.test.js`, 5/5 mutations detected).
- With plan and usage NOT VERIFIED, the policy BLOCKs any future recurring increase until the operator fills the budget table.

## Classification

**ZERO MATERIAL INCREMENT.** Recurring workload is unchanged or reduced. One-time publication costs are a handful of D1/R2 operations, and per-purchase costs scale only with revenue.
