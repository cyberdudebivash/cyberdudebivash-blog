# IOC Source Policy

**Rule zero: no source = no customer IOC.** Every published indicator links to at least one allowlisted source record (`observations[].source_url`). The publication gate (`store.validateFeed`) refuses to write a feed in which any item lacks one.

## 1. Allowlist (`config/ioc-sources.json`, the only registry)

| Id | Export | Tier | Licence | Ingest filter | Cap/run |
|---|---|---|---|---|---|
| `threatfox` | `https://threatfox.abuse.ch/export/json/recent/` | B | CC0, per abuse.ch terms | `confidence_level ≥ 75`; hashes only with malware family | 300 |
| `urlhaus` | `https://urlhaus.abuse.ch/downloads/json_recent/` | B | CC0 | `url_status == online` | 200 |
| `feodotracker` | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` | B | CC0 | — (aging decides) | 200 |
| `malwarebazaar` | `https://bazaar.abuse.ch/export/csv/recent/` | B | CC0 | sample must carry a `signature` | 150 |

- **Why these sources:** each publishes structured indicator records with an explicit indicator field and type, a stable record URL, timestamps, and a licence that permits commercial redistribution. They need no API key; the keyed abuse.ch APIs previously used return 401.
- **Tier B:** a reputable community or curated feed. Tier A (vendor or government advisories with first-party IOCs) is not ingested yet. Advisory prose is never an IOC source (ICF-P0-009).
- **Adding a source** requires all of the following:
  - a structured export;
  - a licence review;
  - an adapter with fixture tests and negative controls;
  - an https host added to the SSRF allowlist (`ALLOWED_HOST` in the refresh script);
  - a policy update here.

## 2. What is never an IOC

The validator (`api/_lib/ioc-engine/validate.js`) returns a stable reason code for each rejection:

- Non-public addresses: RFC 1918, loopback, link-local (incl. `169.254.169.254`), CGNAT, documentation, benchmarking, multicast, reserved; the IPv6 equivalents and IPv4-mapped addresses.
- Protected registrable domains and their subdomains:
  - our own properties;
  - code hosting;
  - package registries;
  - major vendors;
  - CDNs;
  - documentation and social hosts;
  - abuse.ch, NIST, CISA, MITRE.
- A URL on shared hosting (e.g. `raw.githubusercontent.com`) may be published, but it is flagged `shared_hosting` and never `block`.
- Reserved TLDs, `example.*`, CVE identifiers, version strings, and IP literals typed as domains.
- Degenerate or placeholder digests (e.g. `abcdef1234567890…`), and any hash without a malware-family context.
- Values regex-extracted from text. Adapters read only the source's indicator field.

Required negative controls (tested at validator, adapter, store, API and build level):

`github.com`, `microsoft.com`, `169.254.169.254`, `127.0.0.1`, `localhost`, `CVE-2026-12345`, `abcdef1234567890abcdef1234567890abcdef12`.

## 3. Rate and fetch discipline

- **Frequency:** one conditional GET per source per pipeline run (`If-None-Match` / `If-Modified-Since`). The exports update every few minutes, while the pipeline runs every 1–5 h.
- **Bounds:** a timeout per source, a streamed byte cap, `redirect: 'error'`, and a ceiling of 50,000 records per export.

## 4. Revocation

To revoke a value, add `{ "type", "value", "reason" }` to a `revocations` array in `config/ioc-sources.json`. The next run marks it `REVOKED`, removes it from the feed and lists it in `revocations[]` so customers can retract it. A value that fails a newer safety rule is revoked automatically (`safety_filter:<reason>`).

## 5. Customer statements we may make

- **We may say:** source names, licence, record links, counts *as returned by the API at that moment*, and the confidence and aging model.
- **We may not say:**
  - fixed indicator counts in marketing;
  - "real-time";
  - "validated", "zero false positives", or exclusivity;
  - that we discover these indicators. They are curated from abuse.ch community feeds with our own validation, deduplication, scoring and lifecycle.
