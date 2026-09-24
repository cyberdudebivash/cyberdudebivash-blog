# Vercel retirement — 2026-09-24

| Proof before change | Evidence / decision |
|---|---|
| Objective | Remove the retired hosting integration at the operator's explicit request. |
| Affected files | `vercel.json`, `.vercelignore`, `vercel-ignore-build.sh`, `.github/workflows/security-audit.yml`, `.github/workflows/smoke-test.yml`, `.github/workflows/alert-delivery.yml`, `.github/workflows/ai-security-intel.yml`, `package.json`, `RUNBOOKS.md`, `OPERATIONS.md`, `.env.example`, `.assetsignore`, `privacy.html`, `docs/architecture/PRODUCTION-RUNTIME-POLICY.md`; new scripts/check-cloudflare-runtime.js, scripts/check-cloudflare-runtime.test.js and this audit. |
| Reuse | Existing Worker response headers, static asset builder and security-header tests; existing API adapter and route table. |
| Evidence | Operator confirms Vercel is dead; security-audit still requires vercel.json; operations instruct deployment to retired provider. |
| Risk | Medium: CI/build configuration; no API, database or publishing contract change. |
| Regression risk | Deleting the old header source could silently disable security validation. Replace it with native response and static-header assertions. |
| Rollback | Revert this focused commit through a reviewed PR; rebuild and redeploy the last verified Cloudflare release if an application release was performed. Never change DNS as a rollback shortcut. |

| Blast radius | Assessment |
|---|---|
| Imports / consumers | New CI validator imports existing security-headers and asset builder; runtime modules unchanged. |
| Pages / API / SEO | privacy.html provider disclosure only; route definitions, metadata and all payment handlers unchanged. |
| CI | security-audit native validation; smoke-test and scheduler comments/messages updated. Existing cadence retained. |
| Build / performance | Existing allowlisted dist-public build; no added runtime dependency or workload. Lighthouse not measured by this source-only change. |
| Monetization | Removes retired hosting instructions; Razorpay and Gumroad remain the only authorized payment providers. No checkout activation or entitlement change. |

The architecture retains Cloudflare Workers HTTP handling, GitHub Actions report generation and Blogger publication. The Node request/response adapter is active Cloudflare compatibility code and must remain. Historical audit documents and intelligence reporting about third-party incidents are evidence, not deployment configuration. This directive supersedes their retired-host deployment instructions.

Cloudflare account bindings, current billing/usage and live deployment identity are not verified through repository cleanup. No DNS, cloud resources, secrets or plan upgrades are changed. A merged change is not proof of deployment.


## Validation and reuse

Native header validation passes; 9 existing response-header tests and 4 release-gate tests pass locally. Negative cases prove that reintroduced deployment configuration, missing dynamic security headers and missing static HTML CSP fail the gate. Existing response header implementation and asset builder are reused unchanged. Zero duplicate routes or runtime components; no runtime dependency changes. Full repository CI and credentialed deployment are separate checks.
