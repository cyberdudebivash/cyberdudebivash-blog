# SOC + CTI Public-Facing P0 Audit — 2026-11-12 (read-only)

**Scope:** `soc.cyberdudebivash.in`, `cti.cyberdudebivash.in`, source GitHub repository `cyberdudebivash/cyberdudebivash-blog`, and AI Hub coupling. **No deploy or customer-data mutation.**  
**Evidence as of:** 2026-11-12 UTC. The public web index is not a fresh authenticated browser certification.  
**Owner:** CYBERDUDEBIVASH ECOSYSTEM, explicit production release approval required.

## Deployment ownership and barriers

| Surface | Origin | Source evidence | Release blocker |
| --- | --- | --- | --- |
| SOC `soc.cyberdudebivash.in` | Cloudflare Worker + static assets from this repository | `OPERATIONS.md`; `workers/entry.js` | #433; account-wide zero-overage attestation and manual exact-SHA approval |
| Legacy `blog.cyberdudebivash.in` | Same Worker/legacy hostname | `OPERATIONS.md` | Must verify both public hostnames and both root/API feed paths |
| CTI `cti.cyberdudebivash.in` | Blogger theme + Python/Blogger syndication in this repository | `blogger-theme/README-production-theme.md`; `automation/*` | #222 and #434; live theme not in repository |
| Intel API `intel.cyberdudebivash.com` | Separate threat-intel repository | `OPERATIONS.md` | Separate gateway release and feed freshness policy |
| AI Hub `cyberdudebivash.in` | Separate private ai-security-hub repository | GitHub repository metadata | Separate security/customer release gate |

## P0-1 — Unsupported CTI homepage assurance and attribution (confirmed in public indexed content)

Publicly visible CTI homepage content includes claims such as `142 Tenants`, `99.99% ONLINE`, `$2.4M` exposure, `SOC 2 Type II`, `91.2%` SOAR automation, `1,420` IOC matches, `96/100` cloud posture, `WCAG 2.2 AA Verified`, and `Zero Active Leaks`, without timestamps and corresponding telemetry or assurance exhibits. The sample IOC table pairs the empty-input SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` with Lazarus Group. This is not a usable malicious-file IOC. Other homepage declarations include placeholder PGP key material and potentially obsolete company-legal wording.

**Impact:** Material risk to enterprise procurement trust, intelligence reliability, research attribution, and compliance messaging. **Do not infer these are true customer counts, actual insurance coverage, or a confirmed SOC 2 attestation.**

**Remediation:** Keep the existing fail-closed proof-first audit. This PR adds seven precise patterns and regression tests. The live theme must be exported using the Blogger dashboard before editing. Remove demo fixtures or replace them with source-backed, timestamped telemetry and evidence links; correct attribution or remove the sample IOC. Reserve verified badges for formal evidence. Re-run the live audit and confirm real post links on the public site. Track **#222** until verified.

## P0-2 — SOC source-to-production freshness and deployment divergence

The current main-source `live-intel.json` observed during audit has `generatedAt=2026-11-12T10:46:31.830Z` and `totalPublished=7412`. This proves only repository-source currency; it does not certify the Cloudflare edge. Earlier independently documented read-only production evidence in PR #558 and issue #433 observed the SOC root feed at `2026-10-23T04:58:15Z` and 6466 publications. PR #558 (freshness-driven live badge) is **merged**, but merge does not establish live rollout. Do not convert those previous edge checks into a fresh November 12 deployment claim without retesting.

**Remediation acceptance:** Owner-approved account-wide cost/usage guard, drift classification and zero-unclassified paths, release SHA and rollback baseline, manual deploy, then four-way independent feed checks: both SOC and blog domains, `/live-intel.json` and `/api/intel/live.json`. Validate `generatedAt`, publication counts, age, and relevant content against independently certified release evidence. Stale/unavailable stays visibly non-LIVE. Track **#433**.

## P0-3 — CTI syndication and public distribution

Blogger syndication is an hourly scheduled pipeline with quality gates; a workflow success, source file update, or a fetched single post does not prove current homepage and feed freshness. Check publication ledger, idempotent post IDs, fetch-back, public landing and two consecutive scheduled freshness checks. Do not forcibly publish thin or duplicate reports merely to reach volume. Track **#434**.

## P1 — Enterprise experience / lead conversion after P0

- CISO-first, mobile-readable latest-report table with publication/disclosure/observed timestamps, confidence, source provenance, exploitation status, and supported actions.
- Separate `current 24h` from `archive`, never invent activity for an empty window.
- Evidence-linked SOC 2 Trust Services Criteria mappings **without** implying a Type II attestation.
- Single commercial journey for advisory service inquiries, transparent scope and pricing, measurable lead capture and fulfilled customer deliverables; no claims of existing customers or revenue without records.
- Accessibility and performance certification based on actual audits, not cosmetic badge labels.

## Validation/rollback ledger

| Gate | Current state | Required evidence |
| --- | --- | --- |
| Public CTI indexed-page findings | Observed; live browser not independently verified in this session | Live-theme export + exact page read + source/telemetry citation |
| Trust-gate patch | Proposed as draft PR #560 | Python audit unit tests + CI + human review |
| SOC edge age as of this audit | **UNVERIFIED** | Fresh independent dual-host/raw-feed check |
| Customer tenant isolation, watchlist receipt and restore | **NOT CERTIFIED** | Authenticated negative tests, real opted-in delivery receipt, isolated backup restore |
| Cloudflare usage/cost ceiling | **NOT CERTIFIED** | Owner-reviewed <=2h snapshot, zero extra metered spend + reserves |
| Production rollout | **HOLD** | Exact-SHA authorization, rollback, post-deploy acceptance |

**NO-GO:** Do not describe production as repaired, customer SOC monitoring as GA, or SOC 2 attestation as complete until their respective evidence gates pass.

Sources: [CTI homepage](https://cti.cyberdudebivash.in/), [SOC issue #433](https://github.com/cyberdudebivash/cyberdudebivash-blog/issues/433), [CTI trust issue #222](https://github.com/cyberdudebivash/cyberdudebivash-blog/issues/222), [Blogger freshness issue #434](https://github.com/cyberdudebivash/cyberdudebivash-blog/issues/434), [merged badge PR #558](https://github.com/cyberdudebivash/cyberdudebivash-blog/pull/558), `OPERATIONS.md`, `blogger-theme/README-production-theme.md`, `scripts/audit_live_cti_home.py`.
