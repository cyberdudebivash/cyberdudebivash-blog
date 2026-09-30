# CTI SEO Recovery Assessment (issue #219)

**Property:** `https://cti.cyberdudebivash.in/` (Blogger, custom domain over `cyberbivash.blogspot.com`)
**Assessed:** 2026-09-30 UTC · **Register item:** ICF-P0-008 (and ICF-P0-001 for theme identity)

## 1. Executive summary

The Search Console cliff that began 2026-08-16 (−96.7% impressions over 28 days, per #219) is **not explained by a
technical indexability regression**: sampled posts return 200 with self-referential canonicals, `index, follow`
robots meta and `x-robots-tag: all`, and robots.txt only disallows `/search`. The strongest repository-verifiable
signal is **content similarity at scale**: sampled CVE-template reports share a median 69% (max 96%) of their word
6-grams with each other, with up to 69% boilerplate per page, across a sitemap of ~13,600 URLs. That profile matches
Google's scaled-content and helpful-content risk patterns. It is a *consistent* explanation, **not a proven root
cause**; proof requires Search Console page-level data, which this environment does not have.

The existing mitigation (PR #221: public Blogger lane capped at 16 posts/day) is in effect: CVE-template publications
fell from 5–10/day (2026-09-11…13) to 0–2/day (2026-09-22…30). The remaining exposure is the legacy corpus and the
theme-level identity leak, both of which need Blogger access.

## 2. Evidence

### 2.1 Crawl/index controls (live, 2026-09-30)

| Check | Result |
|---|---|
| `robots.txt` | `User-agent: * / Disallow: /search / Allow: /` + sitemap — no accidental block |
| Homepage canonical / og:url | `https://cti.cyberdudebivash.in/` |
| 6 random posts from sitemap page 1 | HTTP 200; canonical = own URL on custom domain; `<meta name=robots content="index, follow, max-image-preview:large, …">`; header `x-robots-tag: all` |
| Sitemap | Index of 17 pages × 800 URLs (≈13,600); page 1 lastmod 2026-09-30 |
| Identity | Theme still emits a WebSite JSON-LD node with `@id` `https://cyberbivash.blogspot.com/#website` (`audit_live_cti_home.py`: `blogspot_public_identity`) |

No noindex, canonical-to-elsewhere, or robots regression was found on sampled URLs.

### 2.2 Content similarity (reproducible)

Tool: `scripts/measure_cti_template_similarity.py` (stdlib, read-only; tests in
`tests/test_measure_cti_template_similarity.py`).

`python3 scripts/measure_cti_template_similarity.py --page 1 --sample 8 --seed 11` on 2026-09-30:

| Post (sitemap page 1) | Words | Boilerplate share |
|---|---|---|
| cve-2026-82281-cvss-74-high-severity | 2,406 | 0.42 |
| cve-2026-79657-cvss-98-critical | 2,483 | 0.41 |
| cve-2026-17141-cvss-98-critical | 1,569 | 0.69 |
| cve-2026-82277-cvss-98-critical | 1,615 | 0.68 |
| cve-2026-82280-cvss-71-high-severity | 1,645 | 0.65 |
| cve-2026-71941-cvss-72-high-severity | 2,703 | 0.37 |
| cve-2026-78181-cvss-73-high-severity | 1,628 | 0.67 |
| researchers-say-openai-agents-were (news analysis) | 4,542 | 0.12 |

Pairwise 6-gram containment: **min 0.21 · median 0.69 · max 0.96**. The one analysis-led post scores 0.12; the
CVE-template posts cluster at 0.37–0.69.

### 2.3 Publication cadence (sitemap lastmod, page 1)

| Window | Posts/day | CVE-template posts/day |
|---|---|---|
| 2026-09-11 … 09-13 | 11–14 | 6–10 |
| 2026-09-22 … 09-30 | 6–16 | 0–2 |

## 3. What this change set does for SEO

- Keeps publication capped (no change to the #221 cap).
- Removes unsupported trust claims from blog.cyberdudebivash.in pages, which cross-link to CTI (ICF-P0-003/005).
- Corrects fabricated CVSS on published pages via a visible, dated correction notice (ICF-P0-006). Accuracy is an E-E-A-T input.
- Adds a repeatable similarity KPI instead of anecdotal inspection.

It does **not** change the Blogger theme or legacy Blogger posts: both require credentials unavailable here.

## 4. Recovery plan (operator-executed, measured)

| Step | Action | Tooling in repo | Acceptance |
|---|---|---|---|
| 1 | Export the live theme, prepare candidate, restore | `prepare_blogger_production_theme.py`, `certify_blogger_theme_baseline.py` | `audit_live_cti_home.py` exit 0; no Blogspot `@id` |
| 2 | Legacy quality audit (dry run) | `workflow_dispatch` → `blogger-legacy-quality.yml` (`python -m automation.legacy_quality_auditor`) | Report lists posts with `eligible_for_quarantine` + reasons |
| 3 | Quarantine the thinnest templated CVE posts (noindex or draft), highest similarity first | same workflow (apply mode) | Quarantine count and URL list recorded with the original content SHA-256 (auditor preserves it) |
| 4 | Re-measure similarity weekly | `measure_cti_template_similarity.py --sample 30 --json` over several sitemap pages | Median containment of *indexed* posts < 0.40 |
| 5 | Keep the 16/day cap until recovery | `blogger-syndication.yml` | Unchanged until step 6 |
| 6 | Search Console | Compare 28-day impressions/clicks vs 2026-08-23…09-19 baseline (835 / 6) | Sustained increase over ≥ 4 weeks; representative URLs "Indexed" in URL Inspection |

Raise the publication cap only after step 6 passes, and only for reports that clear the analytical-depth gate
(`automation/analytical_depth_gate.py`) at TACTICAL or above.

## 5. Risks and limits

- Correlation is not causation: a Google core/spam update in the same window cannot be excluded without Search Console
  query/page breakdowns.
- Quarantining legacy URLs reduces indexed count; that is intended. Measure clicks, not URL count.
- Do not "recover" by publishing more pages; that repeats the suspected cause.

## 6. Blockers

| Operation | Reason | Operator action | Validation |
|---|---|---|---|
| Theme identity fix | Blogger API v3 has no theme resource | Dashboard backup/restore (step 1) | `python3 scripts/audit_live_cti_home.py` exit 0 |
| Legacy quarantine | `BLOGGER_CLIENT_ID/SECRET/REFRESH_TOKEN` are GitHub secrets | Run `blogger-legacy-quality.yml` | Auditor report committed as artifact |
| Root-cause proof | Search Console data not accessible here | Export page-level performance for 2026-08-01…09-30 | Lost URLs vs retained URLs compared by similarity score |
