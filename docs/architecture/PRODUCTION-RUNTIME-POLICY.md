# Production runtime policy

Effective 2026-09-24 under explicit operator direction: retire Vercel completely.
This supersedes historical dual-host migration and cutover instructions.

- Cloudflare Workers is the supported HTTP runtime for the separate blog.
- Blogger remains the CTI publication destination.
- Existing GitHub Actions ingestion, generation and publication schedules remain;
  hosting retirement must not stop them or increase their cadence.
- The existing Node-compatible API handlers and Worker request/response adapter
  remain supported. They are not a retired hosting dependency.
- Preserve existing D1/R2 and legacy Redis state until separately audited,
  reconciled and migrated. Do not destroy state as part of hosting cleanup.
- Only Razorpay and Gumroad may supply payment confirmation. Preserve signature
  verification, idempotency, customer isolation and secure delivery.
- No new paid resources, plan upgrades or unbounded work. Confirm account limits
  and measured usage before increasing throughput.

Source configuration is not evidence of live deployment, entitlement fulfillment
or cloud account usage. Historical audit documents retain their original dates
and findings; their hosting instructions must not be used for current releases.
Use OPERATIONS.md and RUNBOOKS.md for release and recovery procedures.
