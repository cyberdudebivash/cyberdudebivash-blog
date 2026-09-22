# Production Blogger Theme — Provenance Status

## Finding: the live theme has drifted from every file in this directory

Verified 2026-08-24 by fetching live pages from `cti.cyberdudebivash.in`
(the custom domain mapped to the `cyberbivash.blogspot.com` Blogger blog)
with crawler and browser user agents and diffing their rendered `<head>`
against all five theme exports currently stored here
(`cyberbivash-v22-part1.xml`, `cyberbivash-v22-part2.xml`,
`cyberbivash-v22-FINAL.xml`, `cyberbivash-v23-FINAL.xml`,
`cyberbivash-v24-TRUST.xml`).

**None of the five match what is actually live.** Concrete, verified
differences:

| Signal | Live production | v22/v23 files | v24-TRUST file |
|---|---|---|---|
| `og:site_name` | `CYBERDUDEBIVASH SENTINEL APEX` | `CYBERDUDEBIVASH — AI Cybersecurity Intelligence` | `CyberBivash AI` |
| `<title>` brand suffix | `\| CYBERDUDEBIVASH SENTINEL APEX` | (v23 uses `data:blog.pageTitle`, no fixed suffix shown) | `\| CyberBivash AI SOC` |
| `twitter:site` / `twitter:creator` | `@CDBSENTINELAPEX` | `@cyberdudebivash` | *(absent entirely)* |
| `og:image` source | `data:blog.postImageUrl`-equivalent, correctly populated from the post's real first image | `data:blog.postImageUrl` with a branded static fallback | hardcoded to the literal broken string `https://googleusercontent.com` |
| Extra `WebSite` JSON-LD node (`@id`/`url` = `cyberbivash.blogspot.com`) | **present** | not present | not present |

That last row is the one unresolved defect this PR could not fix: a
`WebSite` schema.org node in the live `<head>` still declares the
Blogspot hosting URL as this site's canonical identity
(`"@id": "https://cyberbivash.blogspot.com/#website"`). It is
independently confirmed by `automation/social_preview_certifier.py`'s
`certify_live_html()` against a real fetched page — see the P0
certification doc for the exact run. **It is not emitted by anything in
this repository's Python pipeline** (that pipeline's own
`cyberbivash.blogspot.com` leak, in `seo_optimizer.py`'s Organization
`sameAs`, *is* fixed by this PR) — it is theme-level markup, live only in
Blogger's own theme editor.

## Why this repository cannot fix that node

1. **No automated theme-deployment pipeline exists.** Every workflow under
   `.github/workflows/` that touches Blogger (`blogger-syndication.yml`,
   `blogger-integrity-ci.yml`, `blogger-legacy-quality.yml`) publishes
   *posts* via the Blogger Posts API. None of them call Blogger's Themes
   API (`blogs.themes.getByBlogId` / `.update`). The five XML files in
   this directory are historical exports/backups, not a source the live
   site is ever rebuilt from.
2. **This sandbox has no live Blogger credentials.** `BLOGGER_CLIENT_ID`,
   `BLOGGER_CLIENT_SECRET`, and `BLOGGER_REFRESH_TOKEN` are GitHub Actions
   secrets, unavailable here — so neither exporting the real live theme
   nor pushing a fix to it was possible from this session, and doing
   either without live verification would mean claiming an untested,
   unverified change to a live, publicly-served theme. That is exactly
   the kind of unverified production claim this task's own execution
   standard prohibits.

## What a credentialed operator should do

1. **Export the real live theme now**, before touching anything else, so
   a true baseline exists. Use Blogger's dashboard theme backup/download
   capability (Theme → Backup / Restore or Edit HTML, depending on the current
   Blogger UI) and save the complete live theme XML. **Do not use a guessed
   Blogger v3 theme API endpoint:** the public Blogger API v3 documents
   blogs/posts/pages/comments and does not expose a supported theme
   read/update resource. The downloaded dashboard export is therefore the
   authoritative replacement for the five stale files here.
2. **Checksum and commit it** as `blogger-theme/production-current.xml`
   with a `production-current.sha256` alongside it, so future drift is
   detectable (`sha256sum -c` against the live export) instead of
   discovered by manual diffing the way this finding was.
3. **Locate and fix the `WebSite` JSON-LD node** in that real file —
   change its `@id`/`url` from `https://cyberbivash.blogspot.com/` (and
   `/#website`) to `https://cti.cyberdudebivash.in/` (and `/#website`),
   matching `Config.public_cti_url` on the Python side. Re-upload through
   Blogger's supported dashboard theme editor/restore flow, then re-verify with
   `automation.social_preview_certifier.certify_live_html()` and
   `python scripts/audit_live_cti_home.py` against the real public page.
4. **Retire `cyberbivash-v22-*.xml` and `cyberbivash-v23-FINAL.xml`** once
   the real export lands — they predate the live theme and add no value
   as history once a real, checksummed snapshot exists.
   `cyberbivash-v24-TRUST.xml` is closer in structure to production but is
   still not a match; keep it only if there's a specific reason to
   preserve that intermediate revision, otherwise it should retire too.

## What this PR did NOT touch here

No file in this directory was modified by the P0 social-preview-trust-v2
work. Editing a theme file that has already been proven not to match
production would not fix anything live and risks leaving a *third*,
equally-stale artifact behind — worse than the honest gap this README
documents.
