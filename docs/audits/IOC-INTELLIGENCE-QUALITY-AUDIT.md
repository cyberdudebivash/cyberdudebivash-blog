# IOC Intelligence Quality Audit

**Date:** 2026-10-01 UTC · **Scope:** the evidence-only IOC engine (`api/_lib/ioc-engine/`) and every surface that serves IOCs.
Numbers are from the live refresh executed on 2026-10-01 at 05:33 UTC (`node scripts/refresh-ioc-intelligence.js`). The committed `data/ioc-feed.json` is that run's output.

## 1. Before → after

| Surface | Before (production, 2026-10-01) | After (this branch) |
|---|---|---|
| `action=iocs` | 0 indicators (`api/intel/iocs.json` `count: 0`); API paths returned 401 upstream and were swallowed | 600 indicators, each with ≥1 source record URL; honest `feed_status` |
| Threat graph / unified search / `action=ioc` | 911 IOC nodes with **no provenance**, incl. `github.com`, `microsoft.com`, `learn.microsoft.com`, `169.254.169.254`, `169.254.0.0`, `www.cve.org`, `docs.cilium.io`, 316 SHA-1 strings, 146 `indicator`-typed text fragments | 0 unproven IOC nodes served; 600 evidence-backed nodes. Legacy ids return 404. The persisted graph file is unchanged (projection only). |
| Public `/api/intel/threat-graph.json` | Same 911 unproven nodes, public | Stripped at build (`stripUnprovenGraphIocs`) |
| STIX 2.1 | Random ids; `[file:value=…]`; `artifact:value`; unescaped; 2.0 bundle fields | Parses with OASIS `stix2` (`allow_custom=False`): 601 objects; `stix2-patterns`: 0 pattern errors |
| Persistence | None: rebuilt from the current run | `data/ioc-store.json`; absence never deletes; type-specific aging |

## 2. Live ingestion results (one run)

| Source | Records | Ingest-filtered | Safety-rejected | Accepted (cap) |
|---|---|---|---|---|
| ThreatFox | 6,792 | 437 below confidence 75; 1,093 duplicate value (ip with several ports) | 3 `protected_domain`, 2 `ipv4_cgnat`, 1 `domain_syntax` | 300 |
| URLhaus | 15,316 | 13,441 not online | 0 | 200 |
| Feodo Tracker | 5 | — | 0 | 5, then all **EXPIRED** (source last saw them 2026-03; the source file was last modified 2026-06-30); none published |
| MalwareBazaar | 1,265 | 308 without signature | 0 | 150 |

**Published feed:**

| Dimension | Breakdown |
|---|---|
| Size | 600 (cap) of 650 stored |
| By type | url 237, domain 148, sha256 150, ipv4 65 |
| By confidence | HIGH 496, MEDIUM 104 |
| By recommended action | `block` 491, `alert` 109 (incl. 5 shared-hosting URLs) |

Multi-source corroboration in this run: 0. The per-source caps select each source's newest records, so overlap is currently rare, and VERY_HIGH is therefore not present yet. This is reported as is; it is not inflated.

## 3. Negative controls

| Control | Validator | In source export (adapter) | Stored value (store) | Hand-edited feed (gate) | API | Public build |
|---|---|---|---|---|---|---|
| `github.com` | `protected_domain` | rejected | — | — | absent; legacy node 404 | stripped |
| `microsoft.com` | `protected_domain` | rejected | — | — | absent | stripped |
| `169.254.169.254` | `ipv4_link_local` | rejected (ip:port and URL) | auto-REVOKED | refused | absent; legacy node 404 | stripped |
| `127.0.0.1` | `ipv4_loopback` | rejected | — | — | absent | — |
| `localhost` | `domain_syntax` | rejected | — | — | absent | — |
| `CVE-2026-12345` | `cve_identifier` | rejected | — | — | absent | — |
| `abcdef1234567890abcdef1234567890abcdef12` | `hash_placeholder` | rejected | — | — | absent | — |

Mutation evidence: each safeguard was disabled in turn and the suite re-run. **17 of 17 mutations were detected.** They covered:
- the link-local range, protected domains, placeholder hashes, CVE-as-domain;
- the graph provenance check and the feed-gate provenance check;
- the STIX hash pattern, STIX escaping and the STIX tier gate;
- last-known-good, corroboration and aging;
- online-only and context-less hashes;
- the SSRF allowlist, the byte cap and public-summary leakage.

The build-level gate was also proven by removing the strip step: the deploy test fails.

## 4. Residual quality limits (stated, not hidden)

1. **Tier-B only.** All sources are abuse.ch community feeds. Confidence reflects the source's assertion plus our lifecycle; we do not independently verify maliciousness.
2. **No actor attribution.** `related_actors` stays empty because no ingested source asserts actors in a structured field. Actor filtering therefore returns no results.
3. **CVE links are sparse.** `related_cves` comes only from source tags (0 in this run).
4. **Feed freshness depends on pipeline cadence.** The pipeline actually runs every 1.5–5 h; `feed_status.freshness` flips to `stale` after 6 h. Moving to a guaranteed cadence would need a Worker-cron `workflow_dispatch` token (an operator secret; not created).
5. **Public-suffix handling** uses a short list of two-label suffixes, not the full PSL. Protection is conservative (it may protect less on exotic suffixes); it never wrongly protects attacker domains.
6. `data/ioc-canonical.json` (2 legacy seed records, incl. `192.168.1.1`) remains on disk. It is deprecated and has no serving consumer. Deletion is deferred per the deprecation policy.
