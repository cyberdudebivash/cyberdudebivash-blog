# Premium Report Commercial Certification (2026-10-01)

**Result: 0 of 4 v2 reports are CUSTOMER READY. Ray v3.0 passes every automated gate and awaits human review. 4 v1 reports remain on sale and fail the same review.**

A paid report must give a SOC analyst, CTI analyst, detection engineer or CISO materially more than the free sources it is built from. If it is mostly reformatted free content, it is `NOT_FOR_SALE`. The gate is not lowered to keep the catalog at four products.

## Commercial value test (INR 1,999 each)

| Report | Free alternative a buyer already has | What the paid report adds | Materially more value? |
|---|---|---|---|
| CVE-2025-62593 (Ray) | Blog post `posts/cve-2025-62593-ray-project-ray.html`: one source (KEV), "CVSS 0", generic attack path. NVD and KEV pages. | Reconciles the CNA (9.4) and NVD (8.8) scores; root cause and exploit prerequisites; analysis of the RondoDox pre-disclosure attempt and its payload flaw; hypotheses and gaps | **YES.** v2 was blocked by an outdated core judgement and a rule that missed the documented path. **v3.0 resolves both and adds what the free sources lack:** an exposure-path analysis showing patching alone leaves reachable dashboards open, three rules built from the vendor fix, 57 dated indicators, and six prioritised actions. Awaiting human review. |
| DragonForce / Vermont XCenter | Blackpoint Cyber's public 30-page profile; Group-IB blog; ransomware.live victim and group pages (including the infostealer counts) | A condensed synthesis of those sources; the victim claim is one leak-site line | **NO**: condensed public sources. Detection half non-functional. |
| Qilin / Spoonful of Comfort | MITRE ATT&CK S1242/G1050/G1036; Wikipedia; the aggregator post | A restatement of those pages; a vssadmin rule that public Sigma rule sets already cover | **NO** |
| MedusaLocker / Bija Industrie | CISA/FBI advisory AA22-181A (free, with full indicator tables) | A summary of a 2022 advisory, **withholding** the indicators the advisory itself publishes | **NO**: less than the free source |

The three ransomware reports share a structural weakness: a single unconfirmed leak-site claim gives nothing incident-specific (no sample, no IOCs, no TTPs). The only content left is actor background that is already public. This format should not be sold at INR 1,999. Formats that can clear the bar are listed under "Next" below.

## Commercial release matrix

| SKU | Human Review | v2 Published | Payment | Webhook | Download | Refund | Customer Ready |
|---|---|---|---|---|---|---|---|
| PIR-VULN-CVE-2025-62593-RAY (v3.0) | PENDING (automated gates PASS) | NO | BLOCKED (no controlled purchase) | BLOCKED (Razorpay Dashboard) | PASS in tests; live 401 unauthenticated | BLOCKED | **NO** |
| PIR-RANSOMWARE-DRAGONFORCE-VERMONT-XCENTER | FAIL (v1 **PAUSED** 2026-10-02) | NO | BLOCKED | BLOCKED | PASS in tests; live 401 | BLOCKED | **NO** (NOT_FOR_SALE) |
| PIR-RANSOMWARE-QILIN-SPOONFUL-OF-COMFORT | FAIL (v1 **PAUSED** 2026-10-02) | NO | BLOCKED | BLOCKED | PASS in tests; live 401 | BLOCKED | **NO** (NOT_FOR_SALE) |
| PIR-RANSOMWARE-MEDUSALOCKER-BIJA-INDUSTRIE | FAIL (v1 **PAUSED** 2026-10-02) | NO | BLOCKED | BLOCKED | PASS in tests; live 401 | BLOCKED | **NO** (NOT_FOR_SALE) |

"PASS in tests" means the end-to-end suite on a real SQLite D1 with real HMAC: `api/v1/__tests__/premium-webhook-integrity.test.js`, 28 tests. It covers:
- browser close;
- callback before or after the webhook;
- duplicate events;
- the race guard;
- cross-account denial;
- full and partial refunds;
- no R2 read after revocation.

That is not provider evidence. Live provider evidence needs the operator steps in `docs/runbooks/BLOG-RAZORPAY-WEBHOOK.md`.

## Update 2026-10-02: unreviewed products paused

As instructed, the Qilin, DragonForce and MedusaLocker v1 products were set to **PAUSED** in production. They are no longer listed or purchasable; artifacts, hashes and history are kept, and there were 0 buyers. Ray v1 stays on sale until Ray v3 is approved and published; the publisher then retires it. It is the only product currently taking payment. It carries the outdated EPSS judgement described above, so pausing it before v3 ships remains an available owner choice.

## Owner decision required: the v1 products on sale

All four v1 products are human-approved (2026-08-18), and existing entitlements remain valid. Today's review finds:

- **Ray v1** states a materially outdated judgement ("EPSS notably low", now p99.17). Its rule filters out the DNS-rebinding requests it claims to detect. **Recommendation: pause now.** A buyer would act on a wrong risk signal.
- **All v1:** "Premium Intelligence Canary" headings and a customer-visible `…-canary` `report_id`. **Recommendation: pause until replaced.**

Pausing is reversible, hides the product from the catalog, and keeps existing buyers' access. It requires the analyst key, which is held by the operator, never committed, and never printed:

```bash
# PAUSED hides the product; SELLABLE restores it. Existing entitlements are unaffected.
for id in cve-2025-62593-ray-canary dragonforce-vermont-xcenter-premium-canary \
          qilin-spoonful-of-comfort-premium-canary medusalocker-bija-industrie-premium-canary; do
  curl -sS -X POST "https://blog.cyberdudebivash.in/api/v1/premium-intelligence?action=set-status" \
    -H "Content-Type: application/json" -H "X-Analyst-Key: $PREMIUM_ANALYST_KEY" \
    -d "{\"report_id\":\"$id\",\"status\":\"PAUSED\"}"; echo
done
```

After pausing, `intelligence-store.html` shows its empty-catalog state. Commercial impact: the store is pre-revenue. The live system shows no captured blog premium order: 0 captured overlap orders at cutover, and the controlled purchase has not been run. Pausing therefore forgoes no realised revenue and removes a trust risk.

## Next: a sellable product line

| Candidate | Why it clears the bar | Cost |
|---|---|---|
| **Ray v3: refreshed edition** | Live EPSS/KEV (forensic triage); corrected detection with separate remote-exposure and DNS-rebinding (Host header ≠ loopback) logic, each with explicit maturity; version-check and `--dashboard-host` hardening steps; RondoDox indicators pulled from source with dates. | Existing pipeline: generate → human review → publish |
| Exploited-CVE assessments (KEV additions) | Vulnerability reports carry first-party analysis (score reconciliation, prerequisites, detection) that free pages lack. Ray is the template. | Same |
| Actor dossiers built on several confirmed incidents, not one leak claim | Can carry sourced, dated IOCs and validated hunts | Same |

All three reuse the existing Worker, D1, R2 and publisher. No new infrastructure, and no scheduled regeneration: paid reports stay generate → human review → publish.

---

## History: Tranche 4 certification (earlier on 2026-10-01), superseded

Kept as the production evidence record. Its value assessment ("goes well beyond the free material") is **superseded** by the full-text review above. Its catalog, R2 and purchase-path facts were current at the time.


**Sources:**
- Production D1 `premium_report_catalog` and R2 `sentinel-apex-premium-reports`, read through the Cloudflare API;
- `config/premium-catalog.json`;
- the rendered artifacts, re-certified locally with `evaluatePremiumCertification`.

### Catalog integrity (production)

| SKU / report_id | Price | Status | Artifact (R2 key suffix) | SHA-256 (prefix) | Size (D1 = R2) | Content type | Evidence object | Reviewer |
|---|---:|---|---|---|---:|---|---|---|
| `qilin-spoonful-of-comfort-premium-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/213eec33….md` | `213eec33d30d` | 22,602 = 22,602 | text/markdown; charset=utf-8 | `.reportx.json` 68,746 B | BIVASH NAYAK |
| `dragonforce-vermont-xcenter-premium-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/4bac2b5c….md` | `4bac2b5c7058` | 25,295 = 25,295 | text/markdown; charset=utf-8 | 75,140 B | BIVASH NAYAK |
| `medusalocker-bija-industrie-premium-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/4b986cde….md` | `4b986cdee8b3` | 21,238 = 21,238 | text/markdown; charset=utf-8 | 68,147 B | BIVASH NAYAK |
| `cve-2025-62593-ray-canary` | 199900 INR | SELLABLE, PREMIUM_CERTIFIED | `…/dde2c5ce….md` | `dde2c5ce3efe` | 20,084 = 20,084 | text/markdown; charset=utf-8 | 59,326 B | BIVASH NAYAK |

All four rendered artifacts and their canonical evidence objects exist in the private R2 bucket at the keys and sizes recorded in D1.
- **Price:** 199900 paise (₹1,999), INR.
- **Orders and entitlements:** D1 holds 0 orders and 0 entitlements; no sales yet.

### Value audit (each report against the free public article)

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

### Known defect: release labelling (owner accepted, sale continues)

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

### Purchase path

| Step | Endpoint / control | Status |
|---|---|---|
| Catalog | `GET premium-intelligence?action=catalog` (D1 only; no R2 call per visitor) | live, 4 SELLABLE |
| Buy | `POST action=checkout` (API key; 5/day/IP; artifact HEAD before order; amount from catalog; ownership notes) | ready |
| Pay | Razorpay Checkout (live keys on the Worker) | ready |
| Confirm | `POST action=verify` (signature + server-fetched captured payment) or the webhook | ready; **webhook needs configuring in the Razorpay Dashboard** |
| Access | `GET action=library` / `action=download` (own `ACTIVE` entitlement, hash- and size-checked R2 read, `private, no-store`) | ready |
| Unavailable | "Online purchase temporarily unavailable. Contact bivash@cyberdudebivash.com" (no manual UPI/bank fallback) | tested |

**Prerequisite:** buyers need a free API key from `/api-dashboard.html` before buying. Account-based access depends on it.
