# Intelligence Quality Audit

**Date:** 2026-09-30 UTC · **Corpus:** `api/intel/live.json` (100 items, generated 2026-09-30T16:47Z),
`api/intel/cve/*.json` (2,676 records), `live-intel.json` (150), `api/intel/iocs.json`, `api/intel/threat-graph.json`,
`posts/` (6,784), sampled CTI Blogger posts. Authoritative checks against the NVD CVE API 2.0 and the upstream
`intel.cyberdudebivash.com/api/v1/intel/latest.json`.

## 1. Executive summary

The **current generator** is materially more honest than the corpus it produced historically. It keeps KEV CVSS
unknown, labels detections "reference draft", and frames attack paths as representative rather than observed.
The **served corpus**, however, still carried legacy defects that reached paying customers through the rolling
window and per-CVE files:

- CVSS 9.5 on 123 CVEs; 119 disagree with NVD/CNA, 10 are below 7.0.
- Pseudo-IOCs from vulnerability text.
- KEV flags lost on KEV-sourced records.
- A permanently empty IOC feed.

This tranche corrects the first three at the serving and publishing boundary and fixes the pseudo-IOC root cause in
the generator. Confidence remains the weakest explainability area.

## 2. Field completeness (API live feed, 100 items)

| Field | Present | Note |
|---|---|---|
| cvss | 99 | Provenance field absent before this tranche; now `cvss_source`/`cvss_status` for ledger CVEs |
| cvss_vector | 0 | Now carried for ledger CVEs from NVD evidence |
| epss | 0 | Not ingested |
| cwe | 0 | Not ingested |
| cves | 77 | |
| refs | 86 | Some legacy refs joined ("a ; b"); now split at serve time |
| cisa_kev | 100 (flag) | **0 true** despite 21 KEV-sourced items; reconciled at serve time |
| exploited | 100 (flag) | 53 true; includes 3 Reddit (Tier D) items (see §4) |
| iocs / ioc_count | 0 | Feed-level IOC store empty (ICF-P0-010) |
| mitre / ATT&CK | 0 | Not in API items (present in HTML reports only) |
| confidence | 0 native | API adds fixed `_trust.confidence_score` (ICF-P1-002) |
| tlp, remediation | 0 | Not modelled in the API item |

Unknown fields are left absent rather than filled, which is correct. The gaps (EPSS, CWE, ATT&CK in the API) are
product gaps, not integrity defects.

## 3. CVSS provenance (ICF-P0-006)

| CVE | Served | Authoritative (NVD CVE API 2.0, 2026-09-30) |
|---|---|---|
| CVE-2023-27351 | 9.5 | 7.5 — v3.1, nvd@nist.gov (Primary) |
| CVE-2024-27199 | 9.5 | 7.3 — v3.1, nvd@nist.gov (Primary) |
| CVE-2026-32202 | 9.5 (threat_level LOW) | 4.3 — v3.1, secure@microsoft.com |

Cohort: 123 CVEs served at 9.5 across API items, CVE records, and top/raw feeds. 123/123 resolved: 4 genuinely
9.5, 119 different, 10 below 7.0. Upstream currently emits `null` for unknown scores and no 9.5, so the cohort is
legacy data persisted by the rolling window. The distribution also shows 9.8 on 623/2,676 CVE records (23%). 9.8 is
the most common critical NVD score, so this is **not** evidence of fabrication, but it merits a sampled verification
with the same tool (`scripts/verify-cvss-provenance.js`, ideally with `NVD_API_KEY`).

Selection rule (deterministic, recorded per entry): NVD Primary v3.1 > v4.0 > v3.0 > v2; else CNA Secondary; else
`null`/NOT_ASSESSED.

## 4. Source tiering

S2N trust weights (`api/_lib/s2n-engine.js`): NVD / CISA KEV / CISA alerts / MSRC 1.00; GitHub advisories, CERT-EU
0.95; vendor research 0.85; exploit archives 0.78–0.82; journalism 0.65–0.75; abuse.ch feeds 0.80. This maps
reasonably onto the mission's Tier A–C.

Gaps:
- **Tier D (Reddit) is not tiered as unverified.** 3 Reddit items in the paid API feed carry `exploited: true` and a
  CVSS parsed from the post title (e.g. "Cisco ISE scores a perfect CVSS 10.0"), with `sources_confirmed: 1`.
  A Tier D assertion is presented as fact without corroboration (§13). Remediation: Tier D items keep
  `exploited`/`cvss` as `SOURCE-REPORTED` claims (separate fields) until corroborated by Tier A/B.
- **Circular provenance** (ICF-P1-006): 68/100 API items are attributed to `sentinel_apex` (our sibling platform),
  not the original publisher.

## 5. Evidence semantics

| Semantic | Current generator (`fetch-live-intel.js`) | Legacy corpus |
|---|---|---|
| Attack path | "Representative attack path … not a claim of observed activity" | Earlier posts show generic chains (e.g. "full server takeover" in 739 posts) |
| Exploitation | `hasConfirmedExploitation()` requires explicit observed-exploitation language (tested) | Reddit/Tier D exploited flags persist |
| Detection | "Reference Detection Draft — Not production-validated" / "Not false-positive validated" | "tuned, FP-validated YARA rule packs" (2,041 posts), now neutralized in the build |
| Business impact | Avoids "complete system compromise" (tested) | "Remote code execution — full server takeover without authentication possible" in 739 posts |

The explicit VERIFIED / SOURCE-REPORTED / ASSESSMENT / HYPOTHESIS labelling of §16 is implemented in the Python CTI
path (`automation/cti_integrity_revenue_v19_1_claim_semantics.py`, `report_contract.py`) but not in the Node blog
template. Recommended next: a claim-semantics field in API items and a template badge per assertion.

## 6. Confidence model

`attestItem()` returns `confidence_score` 0.95 / 0.98 / 0.82 based only on source count or KEV, a fixed methodology
string for every item, and `verified_at: now`. It is deterministic but neither explainable nor evidence-dimensioned
(§17). The Python path has a richer model (`automation/key_judgements.py`, analytical depth gate). Remediation
(additive, contract-safe): add `confidence_basis` (dimensions: authority, corroboration, specificity, freshness)
and set `verified_at` to the evidence timestamp. **OPEN** (ICF-P1-002).

## 7. IOC engine

- Structured feeds (urlhaus, threatfox, malwarebazaar, otx) are the only legitimate IOC sources in code.
- Advisory-text extraction produced 1,069 pseudo-IOCs in 458 records. Root cause fixed; legacy withheld at record level.
- 911 unprovenanced graph IOC nodes (e.g. CVE ids typed `indicator`, confidence 23.5) remain; withholding is OPEN
  because existing tests assert `ioc:domain:example.com` exists.
- `api/intel/iocs.json` is empty in every available version (ICF-P0-010).
- Defanging for presentation: current post template renders indicators inside tables without defanging. Recommend
  defanged display + normalized machine value.

## 8. Detection artefacts

Current template labels Sigma/YARA as reference drafts and instructs environment validation. The detection engine
(`Sentinel-APEX/engine-node/detection-engine.js`) runs structural validation (`detection-intelligence.js#validateSigmaStructural`
parses YAML); status states exist (`governance.status`, REVOKED). YARA compilation and KQL/SPL execution are not
tested (no compiler/SIEM in CI), and product copy now says so (ICF-P0-003/005). Recommended states for the API:
`REFERENCE_DRAFT` / `SYNTAX_VALIDATED` / `ENVIRONMENT_VALIDATION_REQUIRED`, mapped from existing governance fields.

## 9. Legacy corpus policy (applied)

| Defect class | Action | Provenance |
|---|---|---|
| Unsupported marketing copy | Build-time replacement with current-generator wording | Source posts unchanged in git |
| Unsupported CVSS | Dated correction notice + corrected score widgets; narrative retained | Ledger with NVD evidence |
| Pseudo-IOCs | Withheld with `ioc_status` + count | Source records unchanged |
| KEV flag / joined refs | Reconciled from the record's own provenance | Source records unchanged |
| Generic impact claims ("full server takeover", 739 posts) | Not changed; recommend historical-template disclaimer or noindex review | — |

## 10. Next quality tranche

1. ICF-P0-010: persistent structured-feed IOC store.
2. ICF-P0-009 remainder: graph/search withholding (+ test contract update).
3. Tier D claim semantics (§4) and ICF-P1-006 original-publisher provenance.
4. Sampled CVSS verification of the 9.8 cluster with `NVD_API_KEY`.
5. ICF-P1-002 explainable confidence.
