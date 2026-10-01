# Premium Report Human Review (v2 reissue, 2026-10-01)

A premium report is sellable only after a **named human** approves the exact artifact. The approval is a ReviewRecord bound to the artifact's SHA-256. Automated gates prepare the report; they never approve it. No v2 report has been approved yet.

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
