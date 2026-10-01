# Premium Report Commercial Certification (2026-10-01)

**Sources:**
- Production D1 `premium_report_catalog` and R2 `sentinel-apex-premium-reports`, read through the Cloudflare API;
- `config/premium-catalog.json`;
- the rendered artifacts, re-certified locally with `evaluatePremiumCertification`.

## Catalog integrity (production)

| SKU / report_id | Price | Status | Artifact (R2 key suffix) | SHA-256 (prefix) | Size (D1 = R2) | Content type | Evidence object | Reviewer |
|---|---:|---|---|---|---:|---|---|---|
| `qilin-spoonful-of-comfort-premium-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/213eec33….md` | `213eec33d30d` | 22,602 = 22,602 | text/markdown; charset=utf-8 | `.reportx.json` 68,746 B | BIVASH NAYAK |
| `dragonforce-vermont-xcenter-premium-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/4bac2b5c….md` | `4bac2b5c7058` | 25,295 = 25,295 | text/markdown; charset=utf-8 | 75,140 B | BIVASH NAYAK |
| `medusalocker-bija-industrie-premium-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/4b986cde….md` | `4b986cdee8b3` | 21,238 = 21,238 | text/markdown; charset=utf-8 | 68,147 B | BIVASH NAYAK |
| `cve-2025-62593-ray-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/dde2c5ce….md` | `dde2c5ce3efe` | 20,084 = 20,084 | text/markdown; charset=utf-8 | 59,326 B | BIVASH NAYAK |

All four rendered artifacts and their canonical evidence objects exist in the private R2 bucket at the keys and sizes recorded in D1.
- **Price:** 199900 paise (₹1,999), INR.
- **Orders and entitlements:** D1 holds 0 orders and 0 entitlements; no sales yet.

## Value audit (each report against the free public article)

| Report | Words | Sections | ATT&CK refs | Detection | Sources | Free public article on the blog |
|---|---:|---:|---:|---|---:|---|
| Qilin / Spoonful of Comfort | 3,005 | 23 | 27 | Sigma rule (shadow-copy deletion, `TVInstallRestore` task masquerade) + hunting hypotheses | 5 retrieved, hash-pinned | none |
| DragonForce / Vermont XCenter | 3,193 | 23 | 104 | Sigma + hunting | 5 | none |
| MedusaLocker / Bija Industrie | 2,650 | 22 | 10 | Detection + hunting (includes the FBI/CISA AA22-181A advisory) | 5 | none |
| CVE-2025-62593 (Ray) | 2,556 | 24 | 6 | Detection + hunting; severity disagreement between two authoritative scores analysed | 7 | 1 post (CVE summary) |

**Common structure:**
- executive summary;
- scope and methodology;
- claim or vulnerability record;
- actor/vulnerability analysis;
- ATT&CK mapping;
- detection;
- hunting;
- forecast;
- alternative hypotheses;
- regulatory considerations (ransomware);
- intelligence gaps;
- technical recommendations;
- a sources and evidence ledger with retrieval hashes.

**Strengths:** the claims are hedged where the evidence is single-source, and rule maturity is stated honestly ("SYNTAX_VALIDATED only").

**Assessment:** the content is analyst-grade and sourced, and it goes well beyond the free material (three of the four topics have no public article at all).

## Known defect: release labelling (owner accepted, sale continues)

Each delivered artifact is titled "… — **Premium Intelligence Canary**". The text also carries pipeline wording:
- "this session";
- "this canary set";
- Sigma ids `reportx-canary-…`.

The report IDs also end in `-canary`. This wording is part of the human-reviewed, hash-bound artifact and cannot be edited without a new review.

The owner decided on 2026-10-01 to **keep all four on sale as is**. The fix is a reissue:

1. re-render without the canary/internal wording;
2. a new human review bound to the new hash;
3. republish with `scripts/publish-premium-reports.js`.

**Market-fit note:** three reports concern single-source leak-site claims against small organisations. Their buyer value rests mainly on the actor analysis and the detection/hunting content rather than the victim claim.

## Purchase path

| Step | Endpoint / control | Status |
|---|---|---|
| Catalog | `GET premium-intelligence?action=catalog` (D1 only; no R2 call per visitor) | live, 4 SELLABLE |
| Buy | `POST action=checkout` (API key; 5/day/IP; artifact HEAD before order; amount from catalog; ownership notes) | ready |
| Pay | Razorpay Checkout (live keys on the Worker) | ready |
| Confirm | `POST action=verify` (signature + server-fetched captured payment) or the webhook | ready; **webhook needs configuring in the Razorpay Dashboard** |
| Access | `GET action=library` / `action=download` (own `ACTIVE` entitlement, hash- and size-checked R2 read, `private, no-store`) | ready |
| Unavailable | "Online purchase temporarily unavailable. Contact bivash@cyberdudebivash.com" (no manual UPI/bank fallback) | tested |

**Prerequisite:** buyers need a free API key from `/api-dashboard.html` before buying. Account-based access depends on it.
