# SENTINEL APEX SOC — cross-platform UI, branding and commercial experience

**Release type:** SOC presentation and customer experience overhaul, not a claim that the entire managed SOC service is technically live.

## Architecture and platform differentiation

- **SENTINEL APEX SOC**, target `https://soc.cyberdudebivash.in/`, is the unified *operational* platform for analyst workflows, CTI-informed hunting, detection guidance, incident readiness, assurance and enterprise engagement.
- **SENTINEL APEX Threat Intel**, `https://intel.cyberdudebivash.com/`, remains the separate threat intelligence/API product.
- **SENTINEL APEX AI Security Hub**, `https://www.cyberdudebivash.in/`, remains the separate AI security and governance product.
- **CYBERDUDEBIVASH ECOSYSTEM**, the existing proprietor's commercial umbrella, remains legal seller attribution. No incorporation, Fortune 500 customers, or audited SOC 2 certification is claimed by UI changes.

## What the change actually ships

1. **Universal identity and navigation**: all HTML copied by the Cloudflare allowlisted asset builder receives one SOC-branded cross-platform header, mobile-scrollable navigation, consistent links to SOC overview, intelligence, hunting, detections, incident readiness, assurance, service-status evidence, and a scoped enterprise assessment CTA. Desktop/mobile responsive tokens and keyboard focus/reduced-motion controls are in `soc-platform-ui.css`.
2. **Flagship SOC overview**: `/soc.html` is a premium security operations landing interface with accurate capability directory, human analyst evidence workflow, trust posture and signed-scope enterprise CTA. The page intentionally displays no fabricated incident counts, customer logos or false uptime statistics.
3. **Homepage transformation**: `index.html` now foregrounds `SENTINEL APEX SOC — Hybrid SOC + CTI`, adds a premium functional command overview and routes users to the correct modules. Original source-linked CTI reports and the immutable feed are preserved.
4. **All-pages rebrand**: `scripts/soc-platform-presentation.cjs` is invoked by the public builder on every HTML page, including root commercial pages, CTI categories, CVE records and archived reports. It transforms header/nav/footer/SEO presentation labels, not original research, author names, evidence, URLs, payment identifiers or code. It preserves existing customer assurance disclosures and truthful `SOC 2-aligned, not certified` wording.
5. **Commercial handoff**: CTAs link to `/enterprise-onboarding.html`, `/pricing.html` and scoped modules—no fake checkout, new subscription tier or unauthorized payment action.
6. **Brand and SEO**: changes to homepage title/OG, structured WebPage classification, PWA name/description, accessible alt/ARIA labels and new page's SEO are covered in tests. Actual hostnames, technical GitHub repo names and source links are intentionally left alone.

## Coverage matrix

| Area | Customer surface | Release state |
|---|---|---|
| SOC overview and services | `/soc.html`, `/`, `/products.html`, `/enterprise.html` | Presentation upgrade; service claims scoped |
| Threat intelligence | `/intel/`, `/intelligence.html`, `/threat-intelligence.html`, CVE and report archives | Shared SOC shell, preserved CTI data |
| Detection engineering | `/detections/`, `/detection-quality.html`, `/review-queue.html` | Shared navigation; real customer detections remain gated |
| Hunting and investigations | `/hunts.html`, `/workbench.html`, `/dossier.html` | Shared UI; internal keys/tenancy remain security gated |
| Incident readiness | `/customer-incident-response.html`, `/enterprise-onboarding.html` | Clear escalation and sales workflow |
| Assurance, legal, service evidence | `/customer-assurance.html`, `/service-status.html`, `/privacy.html`, `/terms.html` | Consistent navigation, original truth preserved |
| Commercial and customer support | `/pricing.html`, `/buy.html`, `/customer-library.html`, `/contact.html` | No changes to payment implementation or claims |
| Archive and feeds | `/posts/`, `/research/`, `/cve/`, RSS, JSON | Preserved historical evidence and source citation |
| Other modules | All remaining allowlisted HTML | Shared SOC shell + accessible navigation |

## Domain migration — separate, reversible production operation

The historical `blog.cyberdudebivash.in` is a **technical deployed hostname**, not the product name. **Do not globally replace URL strings**: they appear in canonical tags, provider callbacks, CSP, payment return URLs, RSS, sitemap, signed source links, Cloudflare custom domain routes and original evidence. Such a replace before cutover would break clients and SEO and could leak payments.

**Cutover gates**:
1. Verify `soc.cyberdudebivash.in` DNS, Cloudflare route/Worker/Pages target, certificate and origin/asset behavior in a controlled production change.
2. Audit all hostname-bound CSP, CORS, cookies, OAuth redirects, checkout return URLs, provider webhooks, open graph, sitemap, feeds and security headers; test with staging fixtures.
3. Deploy new SOC hostname in parallel with the old hostname. Run actual HTTP/HTML, desktop/mobile, RUM, account/payments and incident API smoke tests, source freshness and rollback canaries before moving primary/canonical URLs.
4. Set `soc.` canonical and XML sitemap origin only after public DNS/HTTPS and real routing prove successful; preserve old report URLs through verified same-path redirects or existing aliases. Record an exact deployed SHA and change ticket.
5. Publish product identity/release communications only after operator acceptance. Keep CTI publisher and existing `intel.`/AI Security Hub products independently functional.

**Do not apply D1 migrations 0009–0016, provision customer telemetry, enable managed monitoring, route security incidents, charge cards or claim external SOC 2 audit because of this UI PR.**

## Quality and compliance gates

- Responsive performance: width 320/375/768/1280/1920 px, no horizontal body overflow, WCAG-aware contrast and 44px interactive targets; keyboard, focus, reduced motion, screen-reader navigation.
- SEO: exactly one accurate page title/canonical, no broken links, accessible logo descriptions, correct PWA name, no duplicate SOC bar or duplicate main landmark.
- Security: exact build allowlist, no new external JS/CDN, no moving customer secrets or source evidence, preserved HTTP/HTTPS technical endpoints until cutover.
- SOC 2-aligned control design: access controls, audit trail, change-management evidence, incident procedures, data classification and availability monitoring need testable operator evidence plus an independent auditor before saying `SOC 2 Type II certified`.
- Commercial: request a scoped assessment with confirmed coverage, scope and staff availability; measure legitimate leads, qualified pipeline and fulfilled purchases, not fabricated revenue.

**Decision:** source-level SOC platform presentation can be reviewed and tested separately. Full operated SOC, Fortune 500 commercialization, certified SOC 2 and `soc.` DNS cutover remain gated.
