# Ray v3.0 Approval Packet

**CDB INTERNAL APPROVAL: APPROVED**

This artifact is approved under CYBERDUDEBIVASH internal release governance.

Canonical review identity:

```yaml
reviewer_type: cdb_internal
reviewer: cyberdudebivash
```

The approval remains bound to the exact artifact SHA-256; any artifact change invalidates it.

## Product

| Field | Value |
|---|---|
| SKU | `PIR-VULN-CVE-2025-62593-RAY` |
| Title | Sentinel APEX Vulnerability Intelligence Assessment — CVE-2025-62593 (Ray) |
| Version | 3.0 (supersedes v1 `cve-2025-62593-ray-canary`, on sale; the failed v2 is withdrawn) |
| report_id | `sentinel-apex-vuln-cve-2025-62593-ray-v3` |
| Artifact | `reportx-canary/exports/v3/sentinel-apex-vuln-cve-2025-62593-ray-v3-export.json` → `bundle.rendered_text` |
| **Artifact SHA-256** | `8b79dc179a4e6f339ae276c47552b00193e911351f6b387fa776fd73d5974b21` |
| Size | 43,933 bytes (about 6,000 words, 21 sections) |
| Price | 199,900 paise (INR 1,999) |
| Evidence cut-off | 2026-10-01; the publisher refuses it after **2026-10-31** (30-day window) |
| R2 key on publish | `premium-reports/sentinel-apex-vuln-cve-2025-62593-ray-v3/8b79dc17….md` (existing bucket) |

**Revision on 2026-10-02.** One sentence in Business Impact went beyond its source ("model weights, training data and pipeline credentials sit on the same hosts"). It now quotes Oligo's finding directly. This changed the hash from `036b02d8…` to the value above, and every pin and document was updated. Nothing else changed.

## Review results

| Area | Result | Basis |
|---|---|---|
| Factual integrity | **PASS** | Re-checked live on 2026-10-02: EPSS 0.62459 (p99.165, dated 2026-10-01), unchanged. KEV catalog 2026.10.01: due 2026-08-20, forensicTriage Yes, ransomware Unknown. Affected versions < 2.52.0, fixed in 2.52.0 (advisory, NVD). CVSS 9.4 (CNA, v4) and 8.8 (NVD, v3.1). CWE-94/352. SSVC active, automatable yes, total. |
| Source provenance | **PASS** | 20 sources: 18 carry the SHA-256 of archived content; 2 (the GitHub advisory and the CISA guidance return 403) carry fingerprints of the quoted excerpts. Primary sources lead every fact: vendor advisory, fix commit and source, NVD, CISA, FIRST, MITRE, WHATWG. Secondary sources (Bitsight, Oligo, The Hacker News) are labelled SOURCE-REPORTED. |
| IOC quality | **PASS** | 57 indicators, all published by Bitsight or Oligo. Defanged; typed; dated by observation window; LOW blocking confidence for addresses (7–16 months old). No pseudo-IOCs, and nothing is attributed to this CVE that its sources do not attribute. |
| ATT&CK | **PASS** | T1189 for the browser path (ANALYST ASSESSMENT, medium, with its reasoning). T1190 and post-exploitation techniques taken from MITRE campaign C0045 and labelled as ShadowRay activity, not CVE-2025-62593. |
| Detection | **PASS** | Two rules SYNTAX_VALIDATED (rule and condition parse in pySigma 1.5.1) and one DRAFT. Each is stated as not lab-tested, with its telemetry needs listed. No production-readiness wording (engine promotion-language check passes). |
| Executive content | **PASS** | Business impact comes from documented ShadowRay outcomes (credential theft, model and code visibility). No loss figures or customer impact are invented. |
| Limitations | **PASS** | Five intelligence gaps and a Limitations section: untested rules, header-logging dependency, indicator age, unmeasured exposure count. |
| Editorial | **PASS** | No canary/test/fixture/staging/demo/placeholder wording. Every "test"/"internal"/"pipeline" occurrence is technical ("not lab-tested", "authorised testing", "internal DNS names", "log pipeline"). Editorial gate: 0 findings. |
| Commercial value | **PASS** | It goes beyond the free blog post (one source, "CVSS 0") and the vendor pages. It adds the exposure-path analysis (patching does not protect reachable dashboards), detection built from the fix, dated indicators, a hunting procedure and prioritised remediation. |
| Automated gates | **PASS** | 23/23 commercial-readiness controls; editorial gate; deterministic rebuild from archived sources; publisher end-to-end test (publish, confirm hash, retire v1 Ray). |

## Unresolved limitations the reviewer accepts by approving

1. **Key judgement 5** ("patching alone does not secure a network-reachable dashboard") is an ANALYST ASSESSMENT drawn from the fix diff and `RAY_AUTH_MODE` being opt-in. No vendor statement says it in those words.
2. **Rules 1–2** need header logging in front of port 8265, which Ray does not provide. The report says so.
3. **No public confirmation** of a successful intrusion via this CVE exists. The report labels this UNKNOWN.
4. **EPSS and KEV are dated 2026-10-01.** Approval after 2026-10-31 requires a refresh.

## Sources

| ID | Publisher | Source date | Retrieved | Integrity |
|---|---|---|---|---|
| `s-ghsa` | Ray project (GitHub Security Advisory, CNA) | 2025-11-26 | 2026-10-01 | excerpt fingerprint `6405339a64b8…` |
| `s-ray-fix` | Ray project (fix commit 70e7c72, 'Add denial of fetch headers') | 2025-11-14 | 2026-10-01 | content `8f1088cf1773…` |
| `s-ray-source` | Ray project (source, release tag ray-2.52.0) | 2025-11-26 | 2026-10-01 | content `ddbc4ff2f695…` |
| `s-ray-auth` | Ray project (source, release tag ray-2.52.0) | 2025-11-26 | 2026-10-01 | content `1dfc9eb36b5c…` |
| `s-nvd` | NVD (NIST) | 2026-08-18 | 2026-10-01 | content `0b23d9741dc4…` |
| `s-cisa-kev` | CISA (KEV catalog version 2026.09.30) | 2026-09-30 | 2026-10-01 | content `2b4053dded58…` |
| `s-cisa-bod` | CISA (BOD 26-04 implementation guidance, updated 2026-08-25) | 2026-08-25 | 2026-10-01 | excerpt fingerprint `8c1b3702d438…` |
| `s-epss-now` | FIRST.org EPSS API (current score) | 2026-10-01 | 2026-10-01 | content `ab34e8f3998f…` |
| `s-epss-series` | FIRST.org EPSS API (30-day time series) | 2026-09-30 | 2026-10-01 | content `a2d1a6266ab2…` |
| `s-epss-0818` | FIRST.org EPSS API (score as of 2026-08-18) | 2026-08-18 | 2026-10-01 | content `7f7780be06a2…` |
| `s-epss-0824` | FIRST.org EPSS API (score as of 2026-08-24) | 2026-08-24 | 2026-10-01 | content `81ce0e225f4a…` |
| `s-epss-0925` | FIRST.org EPSS API (score as of 2026-09-25) | 2026-09-25 | 2026-10-01 | content `4e2e682d9c00…` |
| `s-bitsight` | Bitsight (J. Godinho, 2026-03-11) | 2026-03-11 | 2026-10-01 | content `6c2ab56a3b77…` |
| `s-oligo` | Oligo Security (A. Lumelsky, G. Elbaz, 2025-11-18) | 2025-11-18 | 2026-10-01 | content `04667deea0dc…` |
| `s-mitre-c0045` | MITRE ATT&CK (campaign C0045, ShadowRay) | undated | 2026-10-01 | content `3fced7c9f326…` |
| `s-mitre-t1189` | MITRE ATT&CK (T1189) | undated | 2026-10-01 | content `d03736c06b9b…` |
| `s-mitre-t1190` | MITRE ATT&CK (T1190) | undated | 2026-08-17 | content `8f496d7a86d2…` |
| `s-thn` | The Hacker News (R. Lakshmanan, 2026-08-18) | 2026-08-18 | 2026-10-01 | content `157237b94037…` |
| `s-whatwg-fetch` | WHATWG Fetch Living Standard (last updated 2026-09-21) | 2026-09-21 | 2026-10-01 | content `244c88182131…` |
| `s-pytorch` | PyTorch Foundation (2025-10-22) | 2025-10-22 | 2026-08-17 | content `662ef46bba39…` |

## CDB internal approval record

| Field | Value |
|---|---|
| reviewer_type | `cdb_internal` |
| reviewer | `cyberdudebivash` |
| Decision | **APPROVE** |
| Approval timestamp (UTC) | `2026-10-02T02:40:03Z` |
| Review record file | `reportx-canary/exports/v3/sentinel-apex-vuln-cve-2025-62593-ray-v3-REVIEW-RECORD.json` |

### 1. Approval record

The artifact-bound review record is committed at:

`reportx-canary/exports/v3/sentinel-apex-vuln-cve-2025-62593-ray-v3-REVIEW-RECORD.json`

It records:

```yaml
reviewer_type: cdb_internal
reviewer: cyberdudebivash
decision: APPROVE
artifact_sha256: 8b79dc179a4e6f339ae276c47552b00193e911351f6b387fa776fd73d5974b21
```

The record binds to SHA-256 `8b79dc17…`. Any other bytes are refused (`ARTIFACT_HASH_MISMATCH`).

### 2. Publish (from the repository root)

```bash
node scripts/publish-premium-reports.js --only PIR-VULN-CVE-2025-62593-RAY          # dry run: must print CERTIFIED
PREMIUM_ANALYST_KEY=<analyst key> node scripts/publish-premium-reports.js --only PIR-VULN-CVE-2025-62593-RAY --publish
```

Sequence:
1. live detail check;
2. `publish-certified` (R2 put, R2 verify, then the D1 catalog row);
3. confirm the live SHA-256;
4. retire v1 Ray (`cve-2025-62593-ray-canary` → RETIRED).

Existing v1 buyers keep access (there are none today: 0 orders, 0 entitlements on 2026-10-02).

### 3. Audit record

The review record is committed as the audit record. CYBERDUDEBIVASH internal approval is recorded above with the canonical CDB identity and timestamp.

### 4. Verify live

- the catalog lists `sentinel-apex-vuln-cve-2025-62593-ray-v3` with `artifact_sha256` `8b79dc17…`;
- v1 Ray is gone from the catalog;
- a download without a key returns 401.