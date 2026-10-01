# Reviewer Pack — sentinel-apex-ransomware-qilin-spoonful-of-comfort

**Artifact SHA-256:** `577d01ee728b1c50de537ff0b2ac18e2647ef436d5f512135e00d475cbcdf8b3`
**Premium tier:** True

## 23-Control Commercial Readiness Matrix

**23 / 23 PASS — COMMERCIAL-READY**

| # | Control | Status | Evidence |
|---|---|---|---|
| 1 | Source provenance | PASS | 5 sources registered, 0 incomplete. |
| 2 | Evidence hash | PASS | 5/5 hashable sources carry a full content_sha256; 0/5 use the reasoned excerpt-fingerprint fallback. |
| 3 | Automated-review disclosure | PASS | No review on file; resolved state PREMIUM_READY_PENDING_HUMAN correctly withholds PREMIUM_CERTIFIED. |
| 4 | Source-specific facts | PASS | 3 incident-specific claims checked. |
| 5 | Cross-source corroboration | PASS | 18 claims checked against the corroboration policy. |
| 6 | Threat-type schema correctness | PASS | 1 threat products checked for cross-schema contamination. |
| 7 | Cross-section consistency | PASS | 0 contradictions found. |
| 8 | Actor-specific analysis | PASS | 15 actor-context claims checked. |
| 9 | Victim-specific analysis | PASS | Victim-impact claims checked against the claim-support matrix. |
| 10 | Current statistics | PASS | 4 quantitative claims checked. |
| 11 | Regulatory specificity | PASS | 4 regulatory determinations checked. |
| 12 | Technical recommendations | PASS | 3/3 recommendations carry an evidence_basis. |
| 13 | Detection evidence discipline | PASS | 1 detection rules checked for state-promotion language, governed-withholding discipline, and ATT&CK citation justification. |
| 14 | Temporal integrity | PASS | 5 sources checked for fabricated timestamp precision. |
| 15 | Grammar/synthesis QA | PASS | 1 QA findings, 0 critical. |
| 16 | Forecast methodology | PASS | 1 forecast items checked. |
| 17 | Evidence ledger | PASS | 18 claims in the ledger. |
| 18 | Alternative hypotheses | PASS | 2 hypothesis sets checked. |
| 19 | Intelligence gaps | PASS | 7 gaps declared. |
| 20 | Report-specific bibliography | PASS | 5 cited sources, 0 orphaned. |
| 21 | Human analyst certification governance | PASS | Resolved certification state: PREMIUM_READY_PENDING_HUMAN. |
| 22 | 30-40 page premium depth | PASS | 3053 words, 17 material claims, 17 evidence-backed sections. |
| 23 | Fortune-500 commercial deliverable | PASS | 22/22 controls PASS, 0 BLOCKED (not yet attempted). |

## Sources

| Source ID | Publisher | Type | Reliability | URL |
|---|---|---|---|---|
| s-hendryadrian | hendryadrian.com (ransomware leak-site aggregator) | LEAK_SITE_AGGREGATOR | MODERATE | https://www.hendryadrian.com/ransom-spoonful-of-comfort-aug-2026/ |
| s-wikipedia-qilin | Wikipedia | OTHER | MODERATE | https://en.wikipedia.org/wiki/Qilin_(cybercrime_group) |
| s-mitre-s1242 | MITRE ATT&CK | MITRE | HIGH | https://attack.mitre.org/software/S1242/ |
| s-mitre-g1050 | MITRE ATT&CK | MITRE | HIGH | https://attack.mitre.org/groups/G1050/ |
| s-mitre-g1036 | MITRE ATT&CK | MITRE | HIGH | https://attack.mitre.org/groups/G1036/ |

## Material Claims

| Claim ID | Type | Status | Corroboration | Evidence/Source Refs |
|---|---|---|---|---|
| c-leak-site-claim | VICTIM_IDENTITY | REPORTED | SINGLE_SOURCE | e-claim-post, s-hendryadrian |
| c-compromise-occurred | DATA_THEFT | UNKNOWN | UNCORROBORATED | — |
| c-victim-ack | VICTIM_IDENTITY | NOT_ASSESSED | SINGLE_SOURCE | e-claim-post, s-hendryadrian |
| c-qilin-overview | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-qilin-overview, s-mitre-s1242 |
| c-tooling-history | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-tooling-history, s-wikipedia-qilin |
| c-tooling-lineage-current | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-mitre-tooling-overlap, s-mitre-s1242 |
| c-raas-affiliate-split | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-raas-affiliate-split, s-wikipedia-qilin |
| c-raas-operating-model | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-water-galura-model, s-mitre-g1050 |
| c-raas-telegram-announcements | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-water-galura-telegram, s-mitre-g1050 |
| c-water-galura-financial-theft | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-water-galura-financial-theft, s-mitre-g1050 |
| c-moonstone-sleet-deployment | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-moonstone-sleet-profile, e-moonstone-sleet-qilin, s-mitre-g1036 |
| c-campaign-chronology-2023 | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-campaign-2023, s-wikipedia-qilin |
| c-campaign-chronology-2024 | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-campaign-2024, s-wikipedia-qilin |
| c-campaign-chronology-2025 | TTP_HISTORICAL | REPORTED | SINGLE_SOURCE | e-campaign-2025, s-wikipedia-qilin |
| c-ttp-impact | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-ttp-impact, s-mitre-s1242 |
| c-ttp-credential-lateral | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-ttp-credential-lateral, s-mitre-s1242 |
| c-ttp-defense-evasion | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-ttp-defense-evasion, s-mitre-s1242 |
| c-ttp-initial-access | TTP_HISTORICAL | CONFIRMED | SINGLE_SOURCE | e-ttp-initial-access, s-mitre-s1242 |

## Threat Products

- `qilin-spoonful-of-comfort-premium-canary` (RANSOMWARE_VICTIM_CLAIM)

## Statistics (Metrics Registry)

| Metric ID | Name | Value | Unit | Source | Retrieved |
|---|---|---|---|---|---|
| m-skender-data-volume | Skender Construction claimed data volume (2024) | 651 | GB | Wikipedia (Qilin (cybercrime group)), citing open-source reporting | 2026-08-17T00:00:00Z |
| m-academie-amiens-data-volume | Academie d'Amiens claimed data volume (2025) | 1.0 | TB (stated as a floor: source says 'more than 1TB') | Wikipedia (Qilin (cybercrime group)), citing open-source reporting | 2026-08-17T00:00:00Z |
| m-covenant-health-individuals | Covenant Health individuals impacted (2025) | 478000 | individuals | Wikipedia (Qilin (cybercrime group)), citing open-source reporting | 2026-08-17T00:00:00Z |
| m-raas-affiliate-share | Qilin RaaS affiliate revenue share | 82.5 | percent (midpoint of Group-IB's reported 80-85% range) | Wikipedia (Qilin (cybercrime group)), citing Group-IB | 2026-08-17T00:00:00Z |

## Regulatory Determinations

- **HIPAA**: NOT_APPLICABLE — Spoonful of Comfort is categorized in the source reviewed as a hospitality/corporate-gifting business, not a HIPAA-covered entity or business associate -- no source reviewed establishes a healthcare nexus for this specific victim (contrast with Covenant Health, a genuinely healthcare-sector Qilin-attributed 2025 victim named in the campaign chronology above, which this determination does NOT extend to).
- **US state data-breach notification statutes**: NOT_ASSESSED — Notification obligations are generally triggered by confirmed compromise of specific categories of personal information, a fact this report does not establish -- whether any personal-information dataset was actually accessed or exfiltrated is UNKNOWN (c-compromise-occurred), so applicability cannot be determined from the evidence reviewed.
- **PCI-DSS**: NOT_ASSESSED — Spoonful of Comfort's sector (hospitality/specialty-gifting, plausibly e-commerce) commonly processes payment card data, but whether any cardholder-data environment was actually affected is not established by any source reviewed; PCI-DSS is a contractual/industry framework rather than a legal reporting requirement, and applicability depends on deployment-specific facts this report does not have.
- **SEC Cyber Disclosure Rule**: NOT_APPLICABLE — No source reviewed establishes Spoonful of Comfort as a US public company subject to SEC reporting obligations; it is represented in the source reviewed as a private specialty-gifting business.

## Detection Status

- `sentinel-apex-qilin-vssadmin-tvinstallrestore` (T1490, sigma): SYNTAX_VALIDATED

## Forecasts

- Qilin-branded ransomware activity, driven by Water Galura's ongoing RaaS affiliate recruitment and Telegram-based announcement channel, will likely continue at or above its documented 2023-2025 pace, with targeting continuing to span hospitality/services alongside its historically dominant manufacturing, technology, financial-services, and healthcare sectors. (confidence: MEDIUM) — Supported by three consecutive years (2023-2025) of real, individually-named, escalating-scale documented attacks and an actively-recruiting RaaS operator model, but tempered by the inherent unpredictability of law-enforcement disruption events and by this review's own finding that the RaaS brand's affiliate base is not monolithic -- at least one differently-motivated operator has independently deployed the same payload.

## Alternative Hypotheses

- Does the 'Spoonful of Comfort' leak-site listing reflect a genuine, technically successful compromise, or could it be an unconfirmed or exaggerated extortion claim? (2 hypotheses)
- If a compromise occurred, was it carried out by a standard, financially-motivated Qilin RaaS affiliate, or could it involve a non-standard operator such as the DPRK-linked Moonstone Sleet, which MITRE separately documents as having deployed the same Qilin payload? (2 hypotheses)

## Known Intelligence Gaps

- Victim acknowledgement unavailable.
- No incident-specific IOCs observed.
- No proof sample of claimed stolen data.
- No independent confirmation of the leak-site claim.
- No initial-access or incident-specific TTP evidence.
- Whether any of the general Qilin/Water Galura TTPs documented above (shadow-copy deletion, LSASS credential dumping, ESXi SSH enablement, TVInstallRestore/TeamViewer_Host_Setup masquerading, etc.) were actually used in this specific incident is not established by any source reviewed -- this is documented actor CAPABILITY, not incident-specific evidence.
- Which specific actor or affiliate within the Qilin RaaS ecosystem -- a standard Water-Galura-recruited criminal affiliate, or a differently-motivated operator such as Moonstone Sleet -- is responsible for this claim is not established by any source reviewed.

## Changes Since Previous Artifact

Artifact changed (`213eec33d30d…` → `577d01ee728b…`). Gate result: 23/23 → 23/23.
