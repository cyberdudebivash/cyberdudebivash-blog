# SENTINEL APEX SOC — First Sellable Service (engineering pilot contract)
**Date:** 2026-10-22  
**Status:** DELIVERY PLAYBOOK DRAFT / NOT CUSTOMER-ACCEPTED  
**Business model:** CYBERDUDEBIVASH ECOSYSTEM, sole proprietorship  
**Offer:** SOC Readiness & Detection Engineering Assessment (request-for-proposal; NOT a managed-SOC subscription)  
**Customer page (after reviewed deployment):** `/soc-readiness-assessment.html`

## Scope and value
The first service is **bounded engineering/advisory delivery** for an explicitly authorized customer. Assess an agreed environment's telemetry visibility, detection engineering readiness, investigation/evidence handling and response governance. The operator can manually deliver an evidence-linked report without asserting fully staffed 24/7 SOC operations or provisioning risky customer ingest before security validation.

**Customer problem:** the organization cannot substantiate what it can reliably detect/investigate or which evidence/response controls are missing.  
**Outcome:** a prioritized, source-backed gap register and controlled improvement plan.

## Required preflight / signed engagement
1. Identify real customer contracting party and authorized technical sponsor; validate signed proposal, price, tax treatment, confidentiality and payment terms before any work. The landing page never charges.
2. Agree a written scope: systems, supported log sources, business hours, review depth, exclusions and explicitly approved methods. No unauthorized scanning.
3. Define data classification, residency, access, minimal evidence, safe transfer, deletion/retention, and named sign-off contacts. Do not request secrets or raw sensitive data by ordinary email.
4. Assign a human delivery owner and capacity; identify independent review/QA expectations. Don't promise unavailable staffing or turnaround.
5. Agree sample quantity and format before analysis. Use synthetic demonstration fixtures only with explicit labeling; real evidence requires lawful authorization.

## Deliverable manifest
| Artifact | Acceptance criterion | Gate |
|---|---|---|
| D1 Signed scope and rules of engagement | Customer/proprietor approved, exclusions and timeline recorded | Required before intake |
| D2 Coverage and evidence inventory | Each claimed source/asset has evidence locator or explicit NOT VERIFIED | Evidence quality |
| D3 Triage and detection quality matrix | Rules labeled DRAFT vs validated; no fabricated alerts/exploits | Analyst QA |
| D4 Prioritized security improvement backlog | Finding, impact, owner, effort estimate if supported, remediation and validation | Technical QA |
| D5 Executive-ready report | Scope/method, dates, source provenance, confidence, findings, limitations and recommendations | Editorial QA |
| D6 Handoff and acceptance receipt | Named authorized customer review, revisions, acceptance/rejection recorded | Closure gate |

## Execution lifecycle
ENQUIRY → FEASIBILITY/PROPOSAL → CONTRACT/ROE → AUTHORIZED EVIDENCE INTAKE → ANALYSIS → QA → DELIVERY → CUSTOMER ACCEPTANCE → INVOICE/RECEIPT RECONCILIATION (as contract requires).

**Operational fail-closed gates**
- Reject unscoped targets, expired authorization and unverifiable source artifacts.
- Do not copy customer evidence into public CTI feeds, training data or analytics.
- No remote containment, credential extraction, active exploitation, 24/7 monitoring, ticketing SLA or fully managed response as part of this first offer.
- For evidence gaps, write **NOT VERIFIED**, never manufacture observations.
- If a detection is not runtime-tested against suitable telemetry, state **DRAFT / REQUIRES CUSTOMER VALIDATION**.
- Record a correction path and customer dispute/appeal window in the signed agreement, not as a universal promise.

## Sales conversion and fulfillment matrix
| Stage | Present evidence | State at writing | Owner action |
|---|---|---|---|
| Marketing asset | Static page and SOC landing link authored | SOURCE ONLY | Review + CI + authorized manual deploy |
| Working enquiry | `mailto:contact@cyberdudebivash.in` link, not a fake form | LINK AUTHORED / MAILBOX DELIVERY NOT VERIFIED | Human reply/triage |
| Price | No published fixed fee or invented subscription | QUOTE REQUIRED | Price after scope/capacity review |
| Contract/ROE | Not customer-signed | BLOCKED | Explicit customer authorization |
| Customer data handling | Policy path exists; no customer consent recorded | NOT VERIFIED | Agree transfer/security terms |
| Technician capacity | No staffed coverage evidence | NOT VERIFIED | Confirm operator availability |
| First assessed evidence | No client-specific artifact | NOT VERIFIED | Execute authorized engagement |
| Delivery acceptance | No customer signature/receipt | BLOCKED | Confirm delivery and corrective actions |
| Payment/revenue | No verified customer charge or settlement | NOT VERIFIED | Separate payment reconciliation |

## Separate product interfaces
- **SENTINEL APEX Threat Intel:** intelligence sources, APIs, and linked reports; evidence must be sourced.
- **SENTINEL APEX AI Security Hub:** independently gated AI security offerings; no shared unverified entitlements.
- **SENTINEL APEX SOC:** scoped engineering/advisory offer now; managed tenant-isolated SOC only after full technical and customer-operation certification.

## Go/No-go
- **GO for internal engineering preparation** after source review and CI.
- **CONDITIONAL GO for marketing/enquiry** only after approved public deployment, live navigation/parity and legal/service copy acceptance. No checkout is present.
- **NO-GO for charging or starting a specific engagement** until authorized and signed scope, capacity and finance workflow are accepted.
- **NO-GO for managed SOC subscriptions, continuous monitoring, pilot telemetry, production domain cutover and SOC 2 certification claims** absent their separate gates.

## Verification evidence to collect before first sale
1. Screenshot/mobile/keyboard accessibility evidence at 360/390/768/1024/1440px.
2. Static build test, all link destinations, live canonical and cache/hash comparison.
3. Operator mailbox end-to-end reply receipt (do not submit fabricated enquiries).
4. Signed engagement scope, access approval and report sample based on synthetic data marked DEMO.
5. Actual invoice/settlement and customer deliverable acceptance, separately recorded.

Source branch/PR implementation is not runtime certification. Preserve CTI publishing URLs and current `blog.` hostname until an approved migration.
