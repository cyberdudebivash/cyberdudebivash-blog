# Premium Report Human Review (v2 reissue, 2026-10-01)

A premium report is sellable only after a **named human** approves the exact artifact. The approval is a ReviewRecord bound to the artifact's SHA-256. Automated gates prepare the report; they never approve it. No v2 report has been approved yet.

> **Status 2026-10-01 (second review): all four v2 artifacts FAIL editorial review. Do not sign an approval for these bytes.** See "Review record 2026-10-01" below. The publisher now also enforces an editorial gate (`scripts/premium-editorial-gate.js`), so it refuses these artifacts even with an approval.

## What changed from v1 (identical evidence, customer-facing presentation)

`reportx-canary/premium_reissue_v2.py` rebuilds each report from its original module. The evidence graph, claims, sources, metrics, detection logic and hypotheses are all unchanged; nothing was re-researched or invented. It then applies one explicit rewrite table:

| v1 (internal) | v2 (customer-facing) |
|---|---|
| `# <subject> — Premium Intelligence Canary` | `# Sentinel APEX Ransomware Intelligence Report -- <subject>` (or `Vulnerability Intelligence Assessment`), followed by a header: brand, version 2.0, evidence cut-off (from the sources' own retrieval dates), and the detection-maturity statement |
| "all fetched as raw bytes … content_sha256 computed programmatically from the checked-in raw files, never hand-typed" | "each archived at retrieval and identified in Appendix A by the SHA-256 of its retrieved content" |
| "this session" | "for this assessment" / "during this assessment" |
| "this canary set" | "this report series" |
| `## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)` | `## Generic Defensive Readiness` |
| `- content_sha256: \`…\`` (ledger) | `- SHA-256 of retrieved content: \`…\`` |
| Sigma `id: reportx-canary-…` | `id: sentinel-apex-…` (updated in the DetectionRule object as well) |
| report id `…-canary` | `sentinel-apex-ransomware-…` / `sentinel-apex-vuln-…` |

Each report changes on 26–28 lines; every other line is byte-identical to the v1 text that was approved on 2026-08-18.
- **Fail-closed rewrites:** a missing source phrase stops the reissue.
- **23-control gate:** re-run on every v2 bundle; 23/23 PASS on all four.
- **Copy gate:** finds 0 internal terms (`premium intelligence canary`, `canary`, `this session`, `checked-in raw files`, `hand-typed`, `reportx`, `GENERIC_DEFENSIVE_READINESS`, `content_sha256`, `internal pipeline`, `test artifact`, `test-only`, `fixture`, `staging`, `demo-only`). Legitimate intelligence vocabulary is allowed: "proof sample", "Mimikatz module", "browser session".

## Review gates (PASS/FAIL, no scores)

The automated column is evidence the reviewer can rely on. The human column is the reviewer's own judgement after reading the full artifact (`reportx-canary/exports/v2/<id>-export.json` → `bundle.rendered_text`) and its reviewer pack (`<id>-REVIEWER-PACK.md`).

| Gate | What to check | Automated pre-check (all four v2) | Human |
|---|---|---|---|
| Evidence | Every material claim is backed by registered evidence | 23-control gate: controls 4, 5, 17 PASS | ☐ |
| Provenance | Sources are authoritative, dated, hash-identified; the ledger matches the text | Controls 1, 2, 14, 20 PASS | ☐ |
| Technical depth | Analysis beyond the free article; actor/vulnerability specifics | Control 22 PASS (2,607–3,248 words, 16–17 sections) | ☐ |
| Actionability | Hunting steps and recommendations usable by a SOC | Control 12 PASS (recommendations carry an evidence basis) | ☐ |
| Detection quality | The rule is correct and honestly qualified (`SYNTAX_VALIDATED`, not lab-tested) | Control 13 PASS (no state promotion) | ☐ |
| Executive relevance | The summary states what happened, why it matters, urgency and uncertainty | — | ☐ |
| Editorial quality | No internal language, no unsupported marketing claims, clean formatting | Copy gate PASS; control 15 PASS | ☐ |
| Commercial presentation | Title, header and price are appropriate for INR 1,999 | Manifest titles/slugs pass the copy gate | ☐ |
| Unsupported claims / factual correctness | Spot-check each "confirmed" statement against its source | Controls 7, 8, 9, 10, 11 PASS | ☐ |
| Remediation accuracy | Patches, versions and mitigations are correct | — | ☐ |
| Duplicate content | No padding or template repetition | Depth assessment: 0 template-repetition findings | ☐ |

## Known editorial considerations for the reviewer

- Three reports cover **single-source leak-site claims** against small organisations. They state this explicitly (H1/H2 hypotheses). The buyer value is mostly the actor analysis, detection and hunting content.
- All detection rules are `SYNTAX_VALIDATED` only. The v2 header says so, as the reports themselves do.
- **Evidence cut-off is 2026-08-17.** Facts may have moved since (for example DragonForce's "current tracked scale"). Approve as dated intelligence, or request a refresh.

## Approve (or reject) — human step

After reading each artifact in full, run this from `Sentinel-APEX/engine` (one command per report):

```bash
python3 cli.py reportx-review approve ../../reportx-canary/exports/v2/<report_id>-export.json \
  --reviewer "<Full Name>" --role "LEAD ANALYST" \
  --out ../../reportx-canary/exports/v2/<report_id>-REVIEW-RECORD.json
# or: reportx-review reject|request-changes … --comments "<why>"
```

| report_id | artifact SHA-256 to approve |
|---|---|
| `sentinel-apex-ransomware-qilin-spoonful-of-comfort` | `577d01ee728b1c50de537ff0b2ac18e2647ef436d5f512135e00d475cbcdf8b3` |
| `sentinel-apex-ransomware-dragonforce-vermont-xcenter` | `ddd603a0b9f1767fab3e6375cea1acbfef57bb4aa431f7afb03c3f78072d5c7b` |
| `sentinel-apex-ransomware-medusalocker-bija-industrie` | `2f888eec7008f0bc7f816c320ee1708477754979fcce964dab0b58b088c4357c` |
| `sentinel-apex-vuln-cve-2025-62593-ray` | `28f6f430c2e7a1c1d0d72d2753700455c0633032db454cc8dd569594eaa385df` |

Then publish, from the repository root:

```bash
node scripts/publish-premium-reports.js                       # dry run: must print CERTIFIED x4
PREMIUM_ANALYST_KEY=<analyst key> node scripts/publish-premium-reports.js --publish
```

For each product, the publisher:
1. writes the v2 artifact to R2 and verifies it, then writes the catalog row;
2. confirms that the live product serves the approved SHA-256;
3. only then retires the superseded v1 product.

Unchanged artifacts are not re-uploaded. Commit the four REVIEW-RECORD files as the audit record.

## Review record 2026-10-01 (full read of all four v2 artifacts)

This is the editorial pre-approval review: every line of each `bundle.rendered_text` was read, and key facts were re-checked against live primary sources on 2026-10-01. It is **not** a ReviewRecord. A ReviewRecord still has to be signed by a named human, and for these bytes it must not be.

### Defects common to all four v2 artifacts (copy gate missed them)

| Defect | Example in the customer text | Gate code |
|---|---|---|
| Evidence-graph internals | "via an explicit evidence_refs/source_refs chain" | `CUSTOMER_COPY_INTERNAL_TERMS` |
| Internal claim IDs | "(evidence: c-ttp-impact)" in every recommendation | `CUSTOMER_COPY_INTERNAL_TERMS` |
| References to material the buyer never receives | "in this bundle's `forecasts` field"; Ray: "Claim Ledger appendix" (no such appendix) | `CUSTOMER_COPY_INTERNAL_TERMS` |
| Engineering file name | Ray: "per evidence_integrity.py's documented policy" | `CUSTOMER_COPY_INTERNAL_TERMS` |
| Defensive filler | "Real, directly-sourced …", "a real, quantified data point" | reviewer (not gated) |
| Evidence cut-off 2026-08-17, 45 days old | All four | `EVIDENCE_STALE` (30-day window) |

### Per-report findings

| Report | Material finding (FAIL) | Verified against |
|---|---|---|
| CVE-2025-62593 (Ray) | **Outdated central judgement.** The report argues "EPSS notably low (0.369%, 29.94th percentile) despite the KEV listing", and its forecast is "tempered by the currently low EPSS". The FIRST EPSS API on 2026-10-01 returns **0.62459 (99.17th percentile)**. CISA KEV now also lists `forensicTriage: Yes` (BOD 26-04 forensics triage requirements), which the report omits. | `api.first.org/data/v1/epss?cve=CVE-2025-62593`; CISA KEV JSON feed |
| CVE-2025-62593 (Ray) | **Detection rule excludes the attack it describes.** The documented chain is DNS rebinding from the developer's own browser, so the malicious POST reaches Ray **from 127.0.0.1**. The rule's `filter_internal_client: src_ip 127.0.0.1/32` removes exactly those requests. It only catches remote job submission, yet the text claims it flags "the exact network-observable step common to every variant". | NVD description (developer tool; Firefox/Safari; DNS rebinding) |
| CVE-2025-62593 (Ray) | Unsupported generalisation: "Ray … typically run on a developer's own workstation rather than as an internet-facing service", followed by an unsourced inference that RondoDox "broadened … into developer-tooling supply chains". RondoDox is an internet scanner; its attempt implies internet-exposed Ray. | Report's own sources |
| CVE-2025-62593 (Ray) | Hunting section ties RondoDox scanner IPs to the DNS-rebinding chain (different delivery paths). It also tells buyers to fetch the IOCs from Bitsight, so the free source has more indicators than the paid report. | — |
| DragonForce / Vermont XCenter | **Detection rule half non-functional.** `TargetFilename` is a file-event field, but the rule declares `logsource: process_creation`, so `selection_encrypted_extension` can never match. The title says "Ransom Note Pattern", but the rule matches an encrypted-file extension. | Sigma logsource taxonomy; `DETECTION_FIELD_LOGSOURCE_MISMATCH` |
| Qilin / Spoonful of Comfort | "hospitality/specialty-gifting business": "specialty-gifting" appears in no source (the aggregator says "Hospitality"). | Appendix A |
| MedusaLocker / Bija Industrie | "Seven gaps are explicitly unresolved", but eight are listed. | Report text |
| All three ransomware reports | The victim content is one leak-site line (no sample, no confirmation). The actor content restates free public sources (MITRE ATT&CK pages, Wikipedia, CISA AA22-181A, the Blackpoint profile). MedusaLocker withholds the indicators that the free CISA advisory publishes. See the commercial test in `docs/audits/PREMIUM-REPORT-COMMERCIAL-CERTIFICATION.md`. | — |

What held up: every quoted figure checked against Appendix A matches its excerpt. CVSS 9.4/8.8, KEV dates, CWE-94/352, the fixed version 2.52.0, and the Firefox/Safari prerequisite match NVD and KEV today. T1685 is a valid ATT&CK v18 technique (the MITRE S1242 page lists T1685 and T1685.005). Every hypothesis, unknown and maturity label (`SYNTAX_VALIDATED`) is stated honestly.

### Verdicts

| Report | Evidence | Editorial | Detection | Commercial | Decision |
|---|---|---|---|---|---|
| Ray | FAIL (outdated EPSS/KEV) | FAIL | FAIL | PASS once refreshed | **REQUEST CHANGES**: refresh to a v3 edition |
| DragonForce | PASS (as of 08-17) | FAIL | FAIL | FAIL | **NOT_FOR_SALE** in this format |
| Qilin | PASS (as of 08-17) | FAIL | PASS (commodity) | FAIL | **NOT_FOR_SALE** in this format |
| MedusaLocker | PASS (as of 08-17) | FAIL | PASS (low confidence) | FAIL | **NOT_FOR_SALE** in this format |

Recording a rejection keeps the decision auditable (run from `Sentinel-APEX/engine`):

```bash
python3 cli.py reportx-review request-changes ../../reportx-canary/exports/v2/sentinel-apex-vuln-cve-2025-62593-ray-export.json \
  --reviewer "<Full Name>" --role "LEAD ANALYST" --comments "EPSS/KEV outdated; Sigma loopback filter excludes the DNS-rebinding path" \
  --out ../../reportx-canary/exports/v2/sentinel-apex-vuln-cve-2025-62593-ray-REVIEW-RECORD.json
```

A `REQUEST_CHANGES` or `REJECT` record is refused by the certifier (`REVIEW_NOT_APPROVED`), so writing one can never publish anything.
