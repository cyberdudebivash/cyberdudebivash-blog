# SENTINEL APEX SOC — customer delivery manifest and acceptance control

**Purpose:** make the first sellable human-led SOC Readiness & Detection Engineering Assessment reproducible, traceable and fail-closed. This package contains **no real customer or threat telemetry**.

## Mandatory source boundaries
- Use the public page `/soc-readiness-assessment.html` only as an enquiry/statement-of-scope interface.
- Never put completed customer manifests or report attachments in this public GitHub repository, Cloudflare static assets, CTI feeds, analytics, issue comments or test fixtures.
- Store any completed manifest with authorized access in the customer's approved private delivery system. Its `privateReference` is opaque and MUST NOT be a public link, credential, token or raw evidence.
- Template values are deliberate `__REQUIRED__` placeholders and intentionally FAIL validation.
- Seller is CYBERDUDEBIVASH ECOSYSTEM (sole proprietorship); legal and tax acceptance are independent.
- The gate is an **offline source/delivery completeness check**, not a certification of evidence authenticity or customer consent. Human review and signed receipts are separately mandatory.

## Report manifest instructions
Copy `docs/commercial/templates/SOC-READINESS-DELIVERY.template.json` to **private customer-approved storage** and populate with actual proof. The working copy must not be committed.

| Field | Evidence semantics |
|---|---|
| `engagementId`, `customerReference` | Internal opaque references, no customer names/emails |
| `scope` | Tenant ID, authorized assets/methods, explicit exclusions |
| `authorization` | APPROVED, signed reference, actor role and expiry (before access) |
| `evidence` | E-* identifiers, source, private locator, integrity SHA-256, collection time, tenant |
| `findings` | F-* id, severity/confidence, CONFIRMED vs NOT_VERIFIED, impact, limitations, recommendation, validation plan |
| `detectionStatus` | DRAFT unless validated against appropriate telemetry and analyst-approved |
| `deliverables` | Approved scope, coverage inventory, report, remediation backlog, handoff receipt |
| `qa` | Human reviewer approval with private receipt |
| `customerAcceptance` | PENDING until a genuinely authorized customer approves or rejects the deliverable |

## Offline quality gates
From a trusted private operator workstation with Node.js:
```powershell
node scripts/soc-readiness-delivery-gate.cjs --stage=preflight C:\Private\engagement.json
node scripts/soc-readiness-delivery-gate.cjs --stage=delivery C:\Private\engagement.json
node scripts/soc-readiness-delivery-gate.cjs --stage=accepted C:\Private\engagement.json
```

- **preflight:** signed, unexpired authorization, scope boundaries and correctly scoped metadata.
- **delivery:** preflight plus nonempty evidence references, full deliverable manifest and human QA.
- **accepted:** delivery plus genuine customer acceptance receipt that follows QA. The acceptance stage cannot be inferred from payment or email sent.
- Reject unknown referenced evidence, duplicate IDs, missing hashes, expired authorization, cross-tenant evidence, false confidence, unapproved validated detections and placeholder fields.
- The CLI reports **only error codes and aggregate counts**. Never include raw customer data in output.
- A PASS proves schema/metadata completeness only, not a SOC 2 certification, that the evidence is genuine, that the service was delivered, or that the customer accepted the specific engagement; receipts must still be independently checked.

## Negative controls and safety cases
Unit tests use **synthetic**, detached data. Deliberately block cross-tenant evidence, expired authorization, duplicate/unknown evidence, unsupported confirmed findings, validated detections without proof, missing QA, absent acceptance and bogus placeholders. Retain all failures as release blockers; do not weaken checks to satisfy customer conversion goals.
