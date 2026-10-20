# SENTINEL APEX™ — Commercial CTI Reader v14

**Purpose:** Presentation quality, navigation, readability, accessibility and print-export consistency for source-attributed intelligence reports. This feature is an **additive shared renderer layer**. Its presence does not certify a report, qualify a withheld IOC, grant premium access, or attest SOC 2.

## Shared reader architecture

- Static intelligence posts: `fetch-live-intel.js → generatePostHTML → posts/*.html`.
- Standalone CVE intelligence: `generate-cve-pages.js → renderPage → cve/*.html`.
- Existing SOC/CTI cover: `scripts/cti-soc-cover.js` (preserved).
- Existing v13 evidence legibility rules: `scripts/cti-reading-style-v13.js` (preserved).
- New v14: `scripts/cti-enterprise-reader-v14.js`, **one identical stylesheet ID per page** plus a keyboard-native `details` reading guide. No external assets, fonts, runtime fetches, scripts, or state mutations.

## Customer-facing design system

| Reading mode | Design contract |
|---|---|
| CISO / board | Balanced 27–43px title, concise scan path, visually separated evidence/decision blocks; do not imply customer impact without customer telemetry |
| SOC analyst | 44px minimum navigation touch target, 78ch measure for report prose, 1.82 line-height, highlighted sourced facts and clearly identified recommended actions |
| Detection engineer | Horizontal scrolling for wide indicator, technique and code tables; tabular numerals; no forced ellipsis of IOC strings |
| Mobile (380–760px) | Two-column metric cards where space allows, two-column shortcut links, one-column shortcuts at very narrow widths, responsive cover and source table |
| Accessibility | Visible keyboard focus, native `details/summary`, text contrast-preserving slate/azure palette, reduced-motion safeguard, no Javascript requirement for reading/navigation |
| Browser print / PDF | A4, 15mm side/top/bottom baseline, light background/ink, readable inline tables and wrapped code, no advertising/navigation/sidebar chrome, report sources and caveats preserved |

The guide says that source facts are from cited records; suggested analyst checks are not claims of completed SOC activity; customer exposure remains unverified pending asset inventory and telemetry. **Do not add a TLP:CLEAR badge unless an actual separately certified TLP record supports it.** No report confidence score or source count is invented by this upgrade.

## Acceptance and failure boundaries

Run:

```bash
node --test tests-js/cti-enterprise-reader-v14.test.js
node --test tests-js/cti-reading-experience-v13.test.js
npm run build:cloudflare
node scripts/preflight-customer-route-markers.cjs dist-public
```

The first command is an explicit required step in the main Test Suite Build Verification job; the existing tests and production-route preflight remain in place.

**Visual QA required before customer release:** render representative (1) CVE with a verified source and CVSS, (2) source-reported exploitation, (3) non-CVE article, (4) no IOC/unknown exposure, (5) long IOC/code block. Review desktop 1440px, tablet 768px, phone 390px and 320px, 200% zoom, keyboard-only navigation, dark-mode contrast and A4 PDF output. Ensure references and unknown-state caveats remain readable and tables do not clip. Record screenshots/print diffs and approvals under the actual review SHA.

**Out of scope:** live CTI feed freshness, P20–P26 publication eligibility, report storage or production deployment, premium entitlements, checkout, new data sources or content generation. Full customer release requires independent source certification, allowed TLP marking and object/download fetchback. Never promote withheld reports through presentation changes.
