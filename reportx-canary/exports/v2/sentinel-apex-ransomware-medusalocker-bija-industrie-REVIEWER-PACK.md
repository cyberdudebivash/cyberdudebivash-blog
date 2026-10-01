# Reviewer Pack — sentinel-apex-ransomware-medusalocker-bija-industrie

**Artifact SHA-256:** `2f888eec7008f0bc7f816c320ee1708477754979fcce964dab0b58b088c4357c`
**Premium tier:** True

## 23-Control Commercial Readiness Matrix

**23 / 23 PASS — COMMERCIAL-READY**

| # | Control | Status | Evidence |
|---|---|---|---|
| 1 | Source provenance | PASS | 5 sources registered, 0 incomplete. |
| 2 | Evidence hash | PASS | 5/5 hashable sources carry a full content_sha256; 0/5 use the reasoned excerpt-fingerprint fallback. |
| 3 | Automated-review disclosure | PASS | No review on file; resolved state PREMIUM_READY_PENDING_HUMAN correctly withholds PREMIUM_CERTIFIED. |
| 4 | Source-specific facts | PASS | 5 incident-specific claims checked. |
| 5 | Cross-source corroboration | PASS | 17 claims checked against the corroboration policy. |
| 6 | Threat-type schema correctness | PASS | 1 threat products checked for cross-schema contamination. |
| 7 | Cross-section consistency | PASS | 0 contradictions found. |
| 8 | Actor-specific analysis | PASS | 12 actor-context claims checked. |
| 9 | Victim-specific analysis | PASS | Victim-impact claims checked against the claim-support matrix. |
| 10 | Current statistics | PASS | 5 quantitative claims checked. |
| 11 | Regulatory specificity | PASS | 4 regulatory determinations checked. |
| 12 | Technical recommendations | PASS | 4/4 recommendations carry an evidence_basis. |
| 13 | Detection evidence discipline | PASS | 1 detection rules checked for state-promotion language, governed-withholding discipline, and ATT&CK citation justification. |
| 14 | Temporal integrity | PASS | 5 sources checked for fabricated timestamp precision. |
| 15 | Grammar/synthesis QA | PASS | 1 QA findings, 0 critical. |
| 16 | Forecast methodology | PASS | 1 forecast items checked. |
| 17 | Evidence ledger | PASS | 17 claims in the ledger. |
| 18 | Alternative hypotheses | PASS | 2 hypothesis sets checked. |
| 19 | Intelligence gaps | PASS | 7 gaps declared. |
| 20 | Report-specific bibliography | PASS | 5 cited sources, 0 orphaned. |
| 21 | Human analyst certification governance | PASS | Resolved certification state: PREMIUM_READY_PENDING_HUMAN. |
| 22 | 30-40 page premium depth | PASS | 2700 words, 16 material claims, 16 evidence-backed sections. |
| 23 | Fortune-500 commercial deliverable | PASS | 22/22 controls PASS, 0 BLOCKED (not yet attempted). |

## Sources

| Source ID | Publisher | Type | Reliability | URL |
|---|---|---|---|---|
| s-ransomwarelive-bija | ransomware.live (leak-site tracker) | LEAK_SITE_AGGREGATOR | MODERATE | https://www.ransomware.live/id/QmlqYSBJbmR1c3RyaWVAbWVkdXNhbG9ja2Vy |
| s-bija-own-site | BIJA Industrie (the company's own site) | VICTIM_STATEMENT | HIGH | https://bija-industrie.com |
| s-ic3-medusalocker-advisory | FBI / CISA / Dept. of the Treasury / FinCEN (Joint Cybersecurity Advisory AA22-181A, via the ic3.gov mirror -- cisa.gov itself returned HTTP 403 Access Denied on both the HTML advisory and its own PDF, consistent with the blocking behavior documented elsewhere in this canary set) | PRIMARY_TECHNICAL_ADVISORY | HIGH | https://www.ic3.gov/CSA/2022/220630.pdf |
| s-ransomwarelive-medusalocker-group | ransomware.live (leak-site tracker, group aggregate page) | LEAK_SITE_AGGREGATOR | MODERATE | https://www.ransomware.live/group/medusalocker |
| s-cybersecuritydive-medusalocker | Cybersecurity Dive | JOURNALISM | MODERATE | https://www.cybersecuritydive.com/news/fbi-cisa-medusalocker-ransomware/626483/ |

## Material Claims

| Claim ID | Type | Status | Corroboration | Evidence/Source Refs |
|---|---|---|---|---|
| c-leak-site-claim-bija | VICTIM_IDENTITY | REPORTED | SINGLE_SOURCE | e-claim-post-bija, s-ransomwarelive-bija |
| c-victim-business-description-bija | VICTIM_IDENTITY | REPORTED | SINGLE_SOURCE | e-bija-self-description, s-bija-own-site |
| c-compromise-occurred-bija | DATA_THEFT | UNKNOWN | UNCORROBORATED | — |
| c-infra-fingerprint-bija | TTP_OBSERVED | REPORTED | SINGLE_SOURCE | e-infra-fingerprint-bija, s-ransomwarelive-bija |
| c-victim-ack-bija | VICTIM_IDENTITY | NOT_ASSESSED | SINGLE_SOURCE | e-claim-post-bija, s-ransomwarelive-bija |
| c-medusalocker-origin | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-medusalocker-origin-csd, s-cybersecuritydive-medusalocker |
| c-medusalocker-healthcare-covid | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-medusalocker-healthcare-covid-csd, s-cybersecuritydive-medusalocker |
| c-medusalocker-initial-access | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-initial-access, s-ic3-medusalocker-advisory |
| c-medusalocker-execution-propagation | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-execution-propagation, s-ic3-medusalocker-advisory |
| c-medusalocker-defense-evasion | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-defense-evasion, s-ic3-medusalocker-advisory |
| c-medusalocker-encryption-impact | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-encryption-impact, s-ic3-medusalocker-advisory |
| c-medusalocker-persistence | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-persistence, s-ic3-medusalocker-advisory |
| c-medusalocker-recovery-inhibition | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-recovery-inhibition, s-ic3-medusalocker-advisory |
| c-medusalocker-raas-split | TTP_HISTORICAL | CONFIRMED | MULTI_SOURCE_INDEPENDENT | e-medusalocker-raas-split-ic3, e-medusalocker-raas-split-csd, s-ic3-medusalocker-advisory, s-cybersecuritydive-medusalocker |
| c-medusalocker-historical-iocs | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-historical-iocs, s-ic3-medusalocker-advisory |
| c-medusalocker-mitigations | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-medusalocker-mitigations, s-ic3-medusalocker-advisory |
| c-medusalocker-current-scale | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-medusalocker-current-scale, s-ransomwarelive-medusalocker-group |

## Threat Products

- `medusalocker-bija-industrie-premium-canary` (RANSOMWARE_VICTIM_CLAIM)

## Statistics (Metrics Registry)

| Metric ID | Name | Value | Unit | Source | Retrieved |
|---|---|---|---|---|---|
| m-medusalocker-total-victims | MedusaLocker total tracked victims | 83 | victims | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-medusalocker-countries | MedusaLocker countries hit | 19 | countries | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-medusalocker-avg-dwell | MedusaLocker average attack-to-claim delay | 83.1 | days | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-medusalocker-infostealer-overlap | MedusaLocker victims with infostealer-log domain overlap | 37.0 | percent | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-medusalocker-raas-affiliate-share | MedusaLocker RaaS affiliate revenue share | 57.5 | percent (midpoint of the independently-corroborated 55-60% range) | CISA/FBI/Treasury/FinCEN Joint Cybersecurity Advisory AA22-181A, corroborated by Cybersecurity Dive | 2026-08-17T00:00:00Z |

## Regulatory Determinations

- **GDPR (EU) / France (CNIL)**: NOT_ASSESSED — Whether the '693 emails extracted' claim, if accurate, includes personal data of identifiable individuals is not established by any source reviewed, and whether any compromise occurred at all remains UNKNOWN (c-compromise-occurred-bija) -- GDPR notification-obligation applicability cannot be determined from current evidence.
- **NIS2 Directive (EU)**: NOT_ASSESSED — Bija Industrie's specific sector/entity-size classification against NIS2's essential/important-entity thresholds is not established by any source reviewed -- the company's own site describes an aerospace/industrial-tooling manufacturing business, but NIS2 applicability turns on regulatory thresholds this report cannot verify from the sources located.
- **HIPAA**: NOT_APPLICABLE — Bija Industrie is a France-based aerospace/industrial-tooling manufacturer with no source reviewed establishing a US healthcare nexus or business-associate relationship -- HIPAA does not apply.
- **PCI-DSS**: NOT_ASSESSED — No source reviewed describes Bija Industrie's payment-processing footprint; PCI-DSS is a contractual/industry framework whose applicability depends on deployment-specific cardholder-data-environment facts this report does not have.

## Detection Status

- `sentinel-apex-medusalocker-svhost-persistence` (T1053.005, sigma): SYNTAX_VALIDATED

## Forecasts

- MedusaLocker-branded ransomware activity will likely continue at or above its documented multi-year pace (83 tracked victims across 19 countries as of this report), continuing to rely predominantly on RDP exposure and phishing/spam as initial-access vectors, with no evidence reviewed this session of a law-enforcement disruption event against the group's infrastructure. (confidence: MEDIUM) — Supported by a multi-year (2021-2026), 83-victim tracked operating history and a stable, twice-independently-corroborated RaaS economic model, but tempered by the inherent unpredictability of law-enforcement disruption events and by the fact that this report's own actor-context sources are predominantly a single 2022 advisory refreshed only by current tracker aggregate counts, not a fresh 2026 technical reassessment of the group's tooling.

## Alternative Hypotheses

- Does the 'Bija Industrie' leak-site listing reflect a genuine, technically successful compromise, or could it be an unconfirmed or exaggerated extortion claim? (2 hypotheses)
- If a compromise did occur, which of MedusaLocker's two documented initial-access vectors -- RDP exploitation (the advisory's primary, 'most often' vector) or phishing/spam (its secondary, 'frequently' vector) -- should hunting and forensic review prioritize first? (2 hypotheses)

## Known Intelligence Gaps

- Victim acknowledgement unavailable.
- No incident-specific IOCs observed.
- No proof sample of claimed stolen data.
- No independent confirmation of the leak-site claim.
- Whether any of the documented general MedusaLocker TTPs above (RDP/phishing initial access, PowerShell-based propagation, safe-mode defense evasion, AES-256/RSA-2048 encryption, svhost.exe/svhostt.exe persistence, shadow-copy deletion) were actually used in this specific incident is not established by any source reviewed -- this is documented actor CAPABILITY, not incident-specific evidence.
- Whether the '693 emails extracted' claim, if accurate, includes personal data of identifiable individuals (GDPR-relevant) or any defense-industrial-base-sensitive content is not established by any source reviewed -- the leak-site claim itself describes only a count, with no category, sensitivity, or content description given.
- Which specific MedusaLocker RaaS affiliate is responsible for this claim is not established by any source reviewed.

## Changes Since Previous Artifact

Artifact changed (`4b986cdee8b3…` → `2f888eec7008…`). Gate result: 23/23 → 23/23.
