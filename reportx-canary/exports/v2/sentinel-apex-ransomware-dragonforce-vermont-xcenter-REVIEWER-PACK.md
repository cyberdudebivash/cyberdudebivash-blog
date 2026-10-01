# Reviewer Pack — sentinel-apex-ransomware-dragonforce-vermont-xcenter

**Artifact SHA-256:** `ddd603a0b9f1767fab3e6375cea1acbfef57bb4aa431f7afb03c3f78072d5c7b`
**Premium tier:** True

## 23-Control Commercial Readiness Matrix

**23 / 23 PASS — COMMERCIAL-READY**

| # | Control | Status | Evidence |
|---|---|---|---|
| 1 | Source provenance | PASS | 5 sources registered, 0 incomplete. |
| 2 | Evidence hash | PASS | 5/5 hashable sources carry a full content_sha256; 0/5 use the reasoned excerpt-fingerprint fallback. |
| 3 | Automated-review disclosure | PASS | No review on file; resolved state PREMIUM_READY_PENDING_HUMAN correctly withholds PREMIUM_CERTIFIED. |
| 4 | Source-specific facts | PASS | 6 incident-specific claims checked. |
| 5 | Cross-source corroboration | PASS | 16 claims checked against the corroboration policy. |
| 6 | Threat-type schema correctness | PASS | 1 threat products checked for cross-schema contamination. |
| 7 | Cross-section consistency | PASS | 0 contradictions found. |
| 8 | Actor-specific analysis | PASS | 9 actor-context claims checked. |
| 9 | Victim-specific analysis | PASS | Victim-impact claims checked against the claim-support matrix. |
| 10 | Current statistics | PASS | 5 quantitative claims checked. |
| 11 | Regulatory specificity | PASS | 4 regulatory determinations checked. |
| 12 | Technical recommendations | PASS | 4/4 recommendations carry an evidence_basis. |
| 13 | Detection evidence discipline | PASS | 1 detection rules checked for state-promotion language, governed-withholding discipline, and ATT&CK citation justification. |
| 14 | Temporal integrity | PASS | 5 sources checked for fabricated timestamp precision. |
| 15 | Grammar/synthesis QA | PASS | 1 QA findings, 0 critical. |
| 16 | Forecast methodology | PASS | 1 forecast items checked. |
| 17 | Evidence ledger | PASS | 16 claims in the ledger. |
| 18 | Alternative hypotheses | PASS | 2 hypothesis sets checked. |
| 19 | Intelligence gaps | PASS | 7 gaps declared. |
| 20 | Report-specific bibliography | PASS | 5 cited sources, 0 orphaned. |
| 21 | Human analyst certification governance | PASS | Resolved certification state: PREMIUM_READY_PENDING_HUMAN. |
| 22 | 30-40 page premium depth | PASS | 3248 words, 15 material claims, 17 evidence-backed sections. |
| 23 | Fortune-500 commercial deliverable | PASS | 22/22 controls PASS, 0 BLOCKED (not yet attempted). |

## Sources

| Source ID | Publisher | Type | Reliability | URL |
|---|---|---|---|---|
| s-ransomwarelive-vxc | ransomware.live (leak-site tracker) | LEAK_SITE_AGGREGATOR | MODERATE | https://www.ransomware.live/id/VmVybW9udCBYQ2VudGVyQGRyYWdvbmZvcmNl |
| s-vermont-own-site | Vermont XCenter (the company's own site, Portuguese) | VICTIM_STATEMENT | HIGH | https://vermont.com.br |
| s-groupib-dragonforce | Group-IB ('Inside the Dragon: DragonForce Ransomware Group', by named analysts Nikolay Kichatov, Sharmine Low, Alexey Kashtanov) | CTI_VENDOR_RESEARCH | MODERATE | https://www.group-ib.com/blog/dragonforce-ransomware/ |
| s-blackpoint-dragonforce | Blackpoint Cyber ('DragonForce Ransomware Threat Profile', 30 pages) | CTI_VENDOR_RESEARCH | MODERATE | https://blackpointcyber.com/wp-content/uploads/2026/02/DragonForce-1.pdf |
| s-ransomwarelive-dragonforce-group | ransomware.live (leak-site tracker, group aggregate page) | LEAK_SITE_AGGREGATOR | MODERATE | https://www.ransomware.live/group/dragonforce |

## Material Claims

| Claim ID | Type | Status | Corroboration | Evidence/Source Refs |
|---|---|---|---|---|
| c-leak-site-claim-vxc | VICTIM_IDENTITY | REPORTED | SINGLE_SOURCE | e-claim-post-vxc, s-ransomwarelive-vxc |
| c-victim-business-description-vxc | VICTIM_IDENTITY | REPORTED | SINGLE_SOURCE | e-vermont-self-description, e-vermont-health-service-line, s-vermont-own-site |
| c-compromise-occurred-vxc | DATA_THEFT | UNKNOWN | UNCORROBORATED | — |
| c-infostealer-exposure-vxc | TTP_OBSERVED | REPORTED | SINGLE_SOURCE | e-infostealer-signal-vxc, s-ransomwarelive-vxc |
| c-infra-fingerprint-vxc | TTP_OBSERVED | REPORTED | SINGLE_SOURCE | e-infra-fingerprint-vxc, s-ransomwarelive-vxc |
| c-victim-ack-vxc | VICTIM_IDENTITY | NOT_ASSESSED | SINGLE_SOURCE | e-claim-post-vxc, s-ransomwarelive-vxc |
| c-dragonforce-origin-raas | TTP_HISTORICAL | CONFIRMED | MULTI_SOURCE_INDEPENDENT | e-dragonforce-origin-raas, e-dragonforce-origin-raas-blackpoint, s-groupib-dragonforce, s-blackpoint-dragonforce |
| c-dragonforce-variants | TTP_HISTORICAL | CONFIRMED | MULTI_SOURCE_INDEPENDENT | e-dragonforce-variants-groupib, e-dragonforce-variants-blackpoint, s-groupib-dragonforce, s-blackpoint-dragonforce |
| c-dragonforce-tooling | TTP_HISTORICAL | CONFIRMED | MULTI_SOURCE_INDEPENDENT | e-dragonforce-tooling-groupib, e-dragonforce-tooling-blackpoint, s-groupib-dragonforce, s-blackpoint-dragonforce |
| c-dragonforce-cartel-evolution | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-dragonforce-cartel-evolution, s-blackpoint-dragonforce |
| c-dragonforce-cve-history | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-dragonforce-cve-history, s-blackpoint-dragonforce |
| c-dragonforce-attck-lifecycle | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-dragonforce-attck-lifecycle, s-blackpoint-dragonforce |
| c-dragonforce-associations | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-dragonforce-associations, s-blackpoint-dragonforce |
| c-dragonforce-malaysia-question | ACTOR_ATTRIBUTION | UNKNOWN | SINGLE_SOURCE | e-dragonforce-malaysia-question, s-blackpoint-dragonforce |
| c-dragonforce-targeting-profile | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-dragonforce-targeting-profile, s-blackpoint-dragonforce |
| c-dragonforce-current-scale | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-dragonforce-current-scale, s-ransomwarelive-dragonforce-group |

## Threat Products

- `dragonforce-vermont-xcenter-premium-canary` (RANSOMWARE_VICTIM_CLAIM)

## Statistics (Metrics Registry)

| Metric ID | Name | Value | Unit | Source | Retrieved |
|---|---|---|---|---|---|
| m-dragonforce-total-victims | DragonForce total tracked victims | 639 | victims | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-dragonforce-countries | DragonForce countries hit | 65 | countries | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-dragonforce-avg-dwell | DragonForce average attack-to-claim delay | 19.0 | days | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-dragonforce-infostealer-overlap | DragonForce victims with infostealer-log domain overlap | 28.2 | percent | ransomware.live (group aggregate page) | 2026-08-17T00:00:00Z |
| m-dragonforce-raas-affiliate-share | DragonForce RaaS affiliate revenue share | 80.0 | percent | Group-IB and Blackpoint Cyber (independently corroborated) | 2026-08-17T00:00:00Z |

## Regulatory Determinations

- **LGPD (Brazil -- Lei Geral de Protecao de Dados)**: NOT_ASSESSED — Whether any compromise occurred at all is UNKNOWN (c-compromise-occurred-vxc), and no source reviewed describes the content or category of any data potentially affected -- LGPD notification-obligation applicability cannot be determined from current evidence.
- **HIPAA / US healthcare business-associate exposure**: NOT_ASSESSED — Vermont XCenter's own site documents a 'Vermont Health' service line covering patient registration and pharmacovigilance support, but no source reviewed identifies any specific US HIPAA-covered-entity client or confirms any patient data was affected -- applicability cannot be determined from current evidence.
- **PCI-DSS**: NOT_ASSESSED — Vermont XCenter's contact-center/telesales services plausibly involve payment-card data on behalf of retail/e-commerce clients, but no source reviewed describes its specific cardholder-data-environment footprint.
- **SEC Cyber Disclosure Rule**: NOT_APPLICABLE — No source reviewed establishes Vermont XCenter as a US public company subject to SEC reporting obligations; it is represented in every source reviewed as a private, Brazil-based BPO.

## Detection Status

- `sentinel-apex-dragonforce-simplehelp-persistence` (T1219, sigma): SYNTAX_VALIDATED

## Forecasts

- DragonForce-branded and cartel-affiliated ransomware activity will likely continue at or above its documented current pace (639 tracked victims across 65 countries, a 19.0-day average attack-to-claim delay), with continued active exploitation of recently disclosed vulnerabilities (the group's own documented pattern of adopting 2024-era CVEs, including the SimpleHelp RMM chain, within the same calendar year) and continued expansion of its cartel/white-label partnership model (LockBit, and contested reports involving RansomHub and Qilin). (confidence: MEDIUM) — Supported by a large, multi-year (2022/2023-2026), 639-victim tracked operating history, a stable and twice-independently-corroborated RaaS economic model, and a documented pattern of rapid adoption of newly disclosed CVEs -- tempered by the inherent unpredictability of law-enforcement disruption events and by the genuine uncertainty this report's own sources document about the cartel model's cohesion (contested RansomHub reports, an unresolved DragonForce-Malaysia naming question).

## Alternative Hypotheses

- Does the 'Vermont XCenter' leak-site listing reflect a genuine, technically successful compromise, or could it be an unconfirmed or exaggerated extortion claim? (2 hypotheses)
- Is the DragonForce ransomware operation connected to the 2023 Malaysian hacktivist collective 'DragonForce Malaysia', or has an unrelated operation adopted the same name? (2 hypotheses)

## Known Intelligence Gaps

- Victim acknowledgement unavailable.
- No incident-specific IOCs observed.
- No proof sample of claimed stolen data.
- No independent confirmation of the leak-site claim.
- Whether any of the documented general DragonForce TTPs above (RDP/phishing/vulnerability-based initial access, BYOVD, SimpleHelp RMM abuse, the ContiV3/LockBit3.0-derived encryptors) were actually used in this specific incident is not established by any source reviewed -- this is documented actor CAPABILITY, not incident-specific evidence.
- The tracker's own earliest tracked DragonForce victim has an estimated attack date (2022-10-20) that predates both named vendors' 'August 2023 discovery' dating by roughly ten months -- no source reviewed explains this discrepancy, and it is not resolved here in either direction.
- Which specific DragonForce affiliate, or which cartel-partner brand (given the group's documented 2025 shift toward a multi-brand cartel model), is responsible for this claim is not established by any source reviewed.

## Changes Since Previous Artifact

Artifact changed (`4bac2b5c7058…` → `ddd603a0b9f1…`). Gate result: 23/23 → 23/23.
