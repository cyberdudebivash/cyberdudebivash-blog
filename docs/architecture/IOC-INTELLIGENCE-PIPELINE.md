# IOC Intelligence Pipeline — Evidence-Only, Persistent

**Status:** implemented on branch `claude/amazing-thompson-h8ukxi` (closes gap ICF-P0-010 and the graph/search remainder of ICF-P0-009).
**Owner module:** `api/_lib/ioc-engine/`. **Refresh:** `scripts/refresh-ioc-intelligence.js`. **Policy:** `docs/intelligence/IOC-SOURCE-POLICY.md`.

## 1. Dependency graph before this change (as found)

| Producer | Artifact | Consumers | Defect |
|---|---|---|---|
| `fetch-live-intel.js` (~L2899) | `api/intel/iocs.json` (public static + bundled) | `api/_lib/intel.js` `PATHS.iocs` → `api/v1/intel.js` `action=iocs` | Rebuilt every run from the current run's top-40 items only, so nothing persisted. Its only structured inputs (`fetchURLhaus`/`fetchThreatFox` API calls) return **401** and are swallowed as 0 items. Result: `count: 0` in production. |
| `fetch-live-intel.js` → `threat-graph.js#buildGraphFromIntel` | `api/intel/threat-graph.json` (public static + bundled) | `getGraph`, `search-index.js` IOC docs, `getIocDetail`, dossiers, legacy `/api/v1/ioc/*` | **911 IOC nodes with no source attribute**: regex output from advisory prose (`github.com`, `microsoft.com`, `169.254.169.254`, `www.cve.org`, `docs.cilium.io`, 316 fix-commit-style SHA-1s, 146 `indicator`-typed strings). |
| (none since 2026-07-31) | `data/ioc-canonical.json` (2 records, incl. `192.168.1.1` labelled CRITICAL C2) | `api/_lib/ioc-canonical.js` — no runtime importer | Disconnected legacy store, already marked "MUST NOT read" in `api/v1/ioc/search.js`. Left untouched (deprecated, unserved). |
| `api/v1/intel.js#buildSTIXBundle` | STIX response | Team/Enterprise | Random ids on every request, `[file:value = …]` (not a STIX object path), `artifact:value` fallback, unescaped values, and a bundle carrying 2.0-only `spec_version`/`created`. |
| `getIntel('iocs')` | API page | `action=iocs` | Default `limit=25` applied *before* the handler's own pagination, plus CVE-shaped tier filters applied to IOC rows. |

## 2. Architecture after this change

```
config/ioc-sources.json  (allowlist: 4 abuse.ch CC0 exports, caps, thresholds, revocations)
        │
scripts/refresh-ioc-intelligence.js   ← sentinel-apex.yml step "Refresh evidence-only IOC feed"
  ├─ per source: SSRF guard (https, *.abuse.ch only, no redirects) → bounded fetch
  │   (timeout, max_bytes stream cap, ETag/If-Modified-Since) → adapters.parseSource
  │   (structured fields only, validate.js on every value, per-source cap)
  ├─ store.mergeCandidates   dedupe by type|value, multi-source observations kept
  ├─ store.refreshDerived    re-validate, revoke, age, score, provenance_hash, retention
  ├─ store.buildFeed         ACTIVE/STALE ≥ MEDIUM, cap 600 balanced by type_shares, honest feed_status
  ├─ store.validateFeed      publication gate (refuses to write on any problem)
  └─ atomic writes (tmp+rename):
        data/ioc-store.json   persistent store (API-only, never a public asset)
        data/ioc-feed.json    customer feed (bundled into the Worker, API-only)
        api/intel/iocs.json   public value-free status summary
                │
Worker (bundled on deploy via drift reconciler / deploy workflow)
  ├─ api/_lib/ioc-engine/feed.js  getFeed · queryFeed · runtimeFeedStatus · projectGraph
  ├─ /api/v1/intel?action=iocs    Pro+ JSON; Team+ STIX 2.1 (api/_lib/ioc-engine/stix.js)
  └─ api/_lib/intel.js#loadGraph  serving projection: unproven IOC nodes removed,
                                   feed indicators added → graph, unified search,
                                   action=ioc, dossiers, legacy /api/v1/ioc/*
Build: scripts/build-cloudflare-assets.js#stripUnprovenGraphIocs strips unproven IOC
       nodes from the public static threat-graph.json copy (same projection, empty feed).
```

**Single source of truth:** `data/ioc-feed.json` is the only customer IOC dataset. `fetch-live-intel.js` no longer writes `iocs.json`.

## 3. Storage decision (cost mandate)

| Option | Verdict |
|---|---|
| D1 `sentinel-apex-core` | Rejected for now. Production D1 has **no application tables** (migrations 0001–0008 were never applied; verified via the Cloudflare API in Phase A), and GitHub Actions has no D1 write path. |
| New KV/R2/D1 resource | Rejected: the cost mandate forbids new or duplicate resources. |
| **Repository artifact + Worker bundle** | **Chosen.** Zero added cost; persistence comes from git history (auditable, revertible). The bundle adds about 97 KB gzip. Store bounded at 2,000 records, feed at 600. |

Trade-off: the feed refreshes on deploy (drift reconciler, at most every 30 min after a pipeline commit), not per request. `feed_status.freshness` reports `stale` when the published file is older than 6 h.

## 4. Canonical record

`id` (`ioc:<type>:<sha256(type|value)[0:24]>`), `stix_id` (UUIDv5), `value`, `display_value` (defanged), `type` (ipv4/ipv6/domain/url/sha256/sha1/md5), `source`, `source_name`, `source_url` (record URL), `source_tier`, `source_published_at`, `sources[]`, `first_seen`, `last_seen`, `ingested_at`, `updated_at`, `confidence` (LOW/MEDIUM/HIGH/VERY_HIGH), `confidence_score`, `confidence_basis[]`, `status` (ACTIVE/STALE/EXPIRED/REVOKED), `tlp`, `context`, `tags`, `related_cves` / `related_malware` / `related_actors` (source-asserted only), `expires_at`, `provenance_hash`, `validation{syntax, public_routability, reserved_value}`, `flags{shared_hosting}`, `detection{recommended_action}`, `observations[]` (one per source record).

## 5. Deterministic models

**Confidence.**
- Per observation: ThreatFox `confidence_level ≥ 90` → HIGH, 75–89 → MEDIUM (<75 is never ingested).
- URLhaus online → HIGH; Feodo online → HIGH, offline → MEDIUM; MalwareBazaar signed sample → HIGH.
- Aggregate = maximum, **+1** with ≥2 distinct sources, **−1** when STALE. The basis is published with each record.

**Aging** (from the source's own `last_seen`; absence from a later export never deletes):

| Type | STALE after | EXPIRED after |
|---|---|---|
| ipv4 / ipv6 | 7 d | 30 d |
| url | 14 d | 60 d |
| domain | 30 d | 90 d |
| sha256 / sha1 / md5 | 90 d | 365 d |

- EXPIRED is never published and is purged 30 d later.
- REVOKED (operator list, or the value fails a current safety rule) is never published, is listed in `revocations[]` and purged after 90 d.

**Feed composition (`type_shares` in `config/ioc-sources.json`).** The 600-slot cap is allocated by type: url 30 %, domain 20 %, sha256 20 %, ipv4 15 %, ipv6 / sha1 / md5 5 % each.
- Pass 1 gives each type its best records up to its quota.
- Pass 2 gives unused slots to the best remaining records of any type, so the cap is always filled.

Without this, the freshest type fills the whole cap. On 2026-10-01 that was online URLs: 426 URLs vs 7 hashes, while 157 hashes were eligible. The publication gate refuses unknown types, negative shares, or a sum above 1.

**Detection exposure.** `block` only for ACTIVE, ≥HIGH, non-shared-hosting values. `alert` for MEDIUM or shared hosting. `hunt` for STALE. Nothing low-confidence is auto-block.

## 6. Failure model

| Failure | Behaviour |
|---|---|
| One source times out / 4xx / 5xx / oversize / malformed | That source is `failed`; others ingest; feed `degraded`; stored indicators retained. |
| All sources fail | Last-known-good indicators republished with ages updated; `degraded` (or `unavailable` if nothing is stored). |
| Feed fails `validateFeed` | Nothing is written; previous files remain; exit 1; the workflow step warns and continues. |
| Crash mid-write | tmp+rename leaves the previous file intact. |
| Healthy run with zero qualifying indicators | `status: healthy`, `indicator_count: 0`; nothing is fabricated. |

## 7. Rollback

1. `git revert` the merge. `fetch-live-intel.js` then writes `iocs.json` again (empty, as before). The API returns to the previous behaviour.
2. Alternatively, set `"enabled": false` on the sources: the next run drops their observations and publishes an honest empty feed.
3. Restore the Worker version via Cloudflare deployment controls.

There are no D1/KV/R2 schema changes and no new bindings or secrets.
