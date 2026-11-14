# SENTINEL APEX SOC — Read-only Public Release Gate

**Purpose:** Certify that an actual public HTTP response has the corrected homepage structure and accurate SOC/CTI product identity, rather than assuming that a merged GitHub PR has deployed to Cloudflare.

## Operator commands (read only)

From the `cyberdudebivash-blog` repository after reviewing the exact checkout:

```powershell
node scripts/soc-live-homepage-certify.js
node scripts/soc-live-homepage-certify.js --soc

# Exact approved release HTML (requires an already built dist-public/index.html).
# These commands READ the edge and the local artifact; they do not build/deploy.
node scripts/soc-live-homepage-certify.js --release-asset
node scripts/soc-live-homepage-certify.js --soc --release-asset
```

The first checks the existing CTI website at `https://blog.cyberdudebivash.in/`. The second checks the intended future `https://soc.cyberdudebivash.in/` separately, and **does not assume DNS exists**.

The script uses a single GET with `Accept: text/html`, redirect handling disabled, `cache: no-store`, a bounded 3 MiB streaming read and an abort deadline. It validates HTTP 200 + HTML and invokes the existing `scripts/soc-homepage-integrity.js` source contract against the actual received HTML.

## P0 strict homepage asset-parity gate

The basic commands above certify only **structure and branding**; their PASS is
**not proof of the latest homepage being deployed**. The `--release-asset`
mode compares the exact SHA-256 of the approved
`dist-public/index.html` to the publicly served HTML bytes at each host.
Both hostnames must pass separately after a coordinated, owner-approved
deployment. An obsolete but otherwise structurally valid homepage now fails
with `PUBLIC_HOMEPAGE_ASSET_SHA256_MISMATCH`, rather than being accepted as
customer-ready. Missing approved artifact fails closed. The certifier never
builds or changes the artifact, website or production state.

The build itself checks `assertHomepageIntegrity` on **both** source
`index.html` and the final transformed `dist-public/index.html` before it
is written. This rejects hard-coded old featured-report cards even if they lack
an `AUTO-GENERATED` marker. Historical research remains available from
`/archive.html`, but it must not be presented as current SOC operational
intelligence.

**Coordinated deployment freeze:** This is a release blocker and preflight;
it is not authority to deploy. During the freeze, only capture source/build
checks and read-only edge evidence. At the eventual agreed global release,
record the approved repository SHA, generated asset hash, Cloudflare Worker
version, both public-host hash checks, genuine report/source freshness, and
operator rollback approval. Matching HTML hashes do not prove CTI freshness,
the deployed Worker SHA, global propagation, or customer API health.

## Decision vocabulary

- **PASS (exit 0):** the specific checked public edge response has valid homepage structure and title. In `--release-asset` mode, it also exactly matches the approved built HTML SHA-256. Neither mode alone is production GA proof.
- **FAIL (exit 2):** the checked edge provided an HTML page violating source structure/title, an unexpected HTTP code, a redirect or non-HTML content. Do not publish a release note saying live repair is complete.
- **INCONCLUSIVE (exit 3):** a connection/read failure, bounded-body rejection or HTTP 429 prevented trustworthy inspection. Do not downgrade this to PASS or interpret it as a source publication failure; retry from an authorized network/region and examine edge logs.

Output is a bounded JSON record with URL, checked UTC time, HTTP status where available, page title, counts, SHA-256 of received HTML and a reason. **The HTML digest is not a Git commit SHA**; the site currently does not provide sufficient release attestation to associate a public response with the exact deployed Worker version.

## Non-goals

This script does not:
- assert that every Cloudflare region has converged to one deployment;
- prove source/feed timestamp freshness, user counts, IOC accuracy, a functioning authenticated SOC or a paid customer subscription;
- exercise POST, API secrets, Cloudflare dashboard, D1 mutations, pricing, DNS edits, remote rollout, GitHub pushes or payment processing;
- change the current canonical `blog.` hostname to `soc.`.

For customer release, pair a PASS with approved Cloudflare deployment ID/source SHA evidence, production read-only API health probes, live CTI source freshness, branded mobile/browser smoke tests, authorized rollback plan and operator/customer sign-off. The public browser result currently shows the legacy `SOC 2 & CTI` homepage, so treat the incident as open until independently rechecked after an authorized deployment.

**Gate:** source CI and one read-only public edge canary are necessary but not sufficient for SOC GA. Do not remove controls to force a green rollout.
