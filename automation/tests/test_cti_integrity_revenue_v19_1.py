from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from bs4 import BeautifulSoup

from automation import cti_integrity_revenue_v19_1 as v19_1
from automation.cti_integrity_revenue_v19_1_claim_semantics import install_claim_semantics_v19_1
from automation.report_integrity import PublicationIntegrityError

install_claim_semantics_v19_1()


def _source_only_fixture() -> str:
    return """
    <article>
      <h1>CVE-2026-83959 - Substance3D Sampler</h1>
      <div class="cdbd-kpi"><span>SEVERITY</span><strong>UNSPECIFIED</strong></div>
      <div class="cdbd-kpi"><span>TLP</span><strong>NOT ASSIGNED</strong></div>
      <img src="https://blog.cyberdudebivash.in/api/og?title=Test&amp;severity=HIGH&amp;cve=CVE-2026-83959">

      <div><span>CORROBORATION</span><strong>SOURCE ASSESSED</strong></div>
      <div><span>DETECTION</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>HUNTING</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>SOC PLAYBOOK</span><strong>PRESENT</strong></div>
      <div><span>EVIDENCE TIER</span><strong>FLASH_READY</strong></div>

      <section class="cdbv8-brief"><div class="cdbv8-brief-grid">
        <article><p>CVE-2026-83959. Full analysis, Sigma/YARA rules, IOCs, Attack Chain.</p></article>
      </div></section>

      <h3>Executive Summary</h3>
      <p>CVE-2026-83959. Full analysis, Sigma/YARA rules, IOCs, Attack Chain.</p>
      <h3>Verified Facts</h3>
      <ul><li>Source publisher: CYBERDUDEBIVASH</li><li>Source published: 2026-09-06T22:45:10+00:00</li></ul>
      <h3>Technical Analysis</h3>
      <p>Heap grooming may target function pointers and attempt arbitrary code execution.</p>
      <h3>MITRE ATT&amp;CK Assessment</h3>
      <p>Not established in cited evidence.</p>
      <h3>Indicators &amp; Observables</h3>
      <p>Not established in cited evidence.</p>
      <h3>Detection Engineering Guidance</h3>
      <p>Identify telemetry and validate evidence before deployment.</p>
      <h3>Threat Hunting Queries</h3>
      <p>Begin with exposure validation; no source-backed pivot is established.</p>
      <h3>SOC Analyst Playbook</h3>
      <ul><li>Validate whether the technology exists internally.</li></ul>

      <section class="cdbv18-commercial" data-astra-revenue-v18="true" data-report-family="cve_advisory">
        <div class="cdbv18-boundary">Paid tiers change delivery, not certainty.</div>
        <a data-cdb-tier="free" data-cdb-v18-cta="api_docs" href="https://blog.cyberdudebivash.in/api.html">API DOCUMENTATION</a>
        <a data-cdb-tier="starter" data-cdb-v18-cta="api_starter" href="https://blog.cyberdudebivash.in/api-dashboard.html">GET API ACCESS</a>
        <a data-cdb-tier="pro" data-cdb-v18-cta="soc_pro" href="https://blog.cyberdudebivash.in/pricing.html">UNLOCK SOC PRO</a>
        <a data-cdb-tier="enterprise" data-cdb-v18-cta="enterprise" href="https://blog.cyberdudebivash.in/pricing.html">ENTERPRISE ACCESS</a>
      </section>

      <a href="mailto:bivash@cyberdudebivash.com">Request Vulnerability Scan →</a>
      <a href="mailto:bivash@cyberdudebivash.com">Request This Assessment →</a>

      <h4>Related Intelligence Reports</h4>
      <ul><li><a href="/related.html">Google Releases Chrome Update to Patch not established as actively exploited in cited evidence V8 Zero-Day</a></li></ul>
    </article>
    """


def _context():
    return SimpleNamespace(
        report_id="CDB-CTI-2026-E235859C8BD7",
        family="cve_advisory",
        family_label="CVE Vulnerability Advisory",
    )


def test_source_only_live_dossier_regressions_are_repaired_without_inventing_facts():
    rendered = v19_1.enforce_cti_integrity_revenue_v19_1(
        _source_only_fixture(),
        article=SimpleNamespace(title="CVE-2026-83959 - Substance3D Sampler"),
        context=_context(),
    )
    soup = BeautifulSoup(rendered, "html.parser")
    text = soup.get_text(" ", strip=True)

    assert v19_1.MARKER in rendered
    assert "Full analysis, Sigma/YARA rules, IOCs, Attack Chain" not in text
    assert "SOURCE_ONLY_PRELIMINARY" in text
    assert "FLASH_READY" not in text
    assert "EVIDENCE CLASS // GENERAL VULNERABILITY-CLASS CONTEXT" in text
    assert "SINGLE SOURCE" in text
    assert "GUIDANCE_ONLY" in text
    assert "GENERIC_VALIDATION_PLAYBOOK" in text

    severity = next(card for card in soup.select(".cdbd-kpi") if card.find("span").get_text(strip=True) == "SEVERITY")
    assert severity.find("strong").get_text(strip=True) == "UNSPECIFIED"
    tlp = next(card for card in soup.select(".cdbd-kpi") if card.find("span").get_text(strip=True) == "TLP")
    assert tlp.find("strong").get_text(strip=True) == "TLP:CLEAR"
    assert tlp["data-cdb-distribution-assigned-by"] == "CYBERDUDEBIVASH"

    image = soup.find("img")
    assert image["src"] == v19_1.NEUTRAL_OG_URL
    assert "severity=HIGH" not in rendered

    free = soup.select_one('a[data-cdb-tier="free"]')
    assert free["href"] == "https://blog.cyberdudebivash.in/api.html"
    for anchor in soup.select('a[data-cdb-tier="starter"],a[data-cdb-tier="pro"],a[data-cdb-tier="enterprise"]'):
        parsed = urlparse(anchor["href"])
        query = parse_qs(parsed.query)
        assert parsed.path == "/buy.html"
        assert query["checkout"] == ["1"]
        assert query["plan"] == [anchor["data-cdb-tier"]]
        assert query["utm_campaign"] == ["astra_cash_conversion_v19"]

    service_links = soup.select('a[data-cdb-v19-1-service-intake="true"]')
    assert len(service_links) == 2
    for anchor in service_links:
        parsed = urlparse(anchor["href"])
        query = parse_qs(parsed.query)
        assert parsed.path == "/contact.html"
        assert parsed.fragment == "inquiry-form-card"
        assert query["service"] == ["vulnerability_assessment"]
        assert query["report_id"] == ["CDB-CTI-2026-E235859C8BD7"]
        assert query["utm_campaign"] == ["astra_cash_conversion_v19_1"]

    related = soup.find("a", href="/related.html").get_text(" ", strip=True)
    assert "not established as actively exploited in cited evidence" not in related.lower()
    assert "V8 Zero-Day" not in related
    assert related == "Google Releases Chrome Update to Patch Zero-Day"


def test_v19_1_is_idempotent():
    once = v19_1.enforce_cti_integrity_revenue_v19_1(_source_only_fixture(), context=_context())
    twice = v19_1.enforce_cti_integrity_revenue_v19_1(once, context=_context())
    assert once == twice


def test_rich_evidence_preserves_flash_ready_and_real_operational_artifacts():
    html = """
    <article>
      <div class="cdbd-kpi"><span>SEVERITY</span><strong>HIGH</strong></div>
      <div class="cdbd-kpi"><span>TLP</span><strong>NOT ASSIGNED</strong></div>
      <div><span>DETECTION</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>HUNTING</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>SOC PLAYBOOK</span><strong>PRESENT</strong></div>
      <div><span>EVIDENCE TIER</span><strong>FLASH_READY</strong></div>
      <img src="https://blog.cyberdudebivash.in/api/og?title=Test&amp;severity=MEDIUM">
      <h3>Executive Summary</h3><p>Validated IOC 203.0.113[.]7 with Sigma rule and MITRE ATT&amp;CK mapping T1059.</p>
      <h3>Verified Facts</h3><ul>
        <li>Source publisher: Vendor</li><li>Source published: 2026-09-07</li>
        <li>Observed indicator: 203.0.113[.]7</li><li>Behavior mapped to T1059</li>
      </ul>
      <h3>MITRE ATT&amp;CK Assessment</h3><p>T1059 is source-backed.</p>
      <h3>Indicators &amp; Observables</h3><p>203.0.113[.]7</p>
      <h3>Detection Engineering Guidance</h3><pre>title: Test Rule\nlogsource:\n  category: process_creation\ndetection:\n  condition: selection</pre>
      <h3>Threat Hunting Queries</h3><pre>DeviceProcessEvents | where FileName == "test.exe"</pre>
      <h3>SOC Analyst Playbook</h3><p>Validate and escalate.</p>
    </article>
    """
    rendered = v19_1.enforce_cti_integrity_revenue_v19_1(html, context=_context())
    soup = BeautifulSoup(rendered, "html.parser")
    text = soup.get_text(" ", strip=True)
    assert "FLASH_READY" in text
    assert "SOURCE_ONLY_PRELIMINARY" not in text
    assert "Validated IOC" in text
    assert "EXECUTABLE" in text
    assert "EXECUTABLE_QUERY" in text
    image = soup.find("img")
    query = parse_qs(urlparse(image["src"]).query)
    assert query["severity"] == ["HIGH"]


def test_final_validator_blocks_unrepaired_positive_artifact_claim():
    soup = BeautifulSoup("""
      <div class="cdbd-kpi"><span>TLP</span><strong>TLP:CLEAR</strong></div>
      <h3>Executive Summary</h3><p>Full Sigma rules and IOCs are included.</p>
      <h3>Indicators &amp; Observables</h3><p>Not established in cited evidence.</p>
      <h3>MITRE ATT&amp;CK Assessment</h3><p>Not established in cited evidence.</p>
      <h3>Detection Engineering Guidance</h3><p>Guidance only.</p>
      <h3>Threat Hunting Queries</h3><p>Guidance only.</p>
    """, "html.parser")
    caps = v19_1._capabilities(soup)
    with pytest.raises(PublicationIntegrityError):
        v19_1._validate_final(soup, "UNSPECIFIED", False, caps)


def test_explicit_negative_artifact_disclosure_is_not_treated_as_capability_claim():
    soup = BeautifulSoup("""
      <div class="cdbd-kpi"><span>TLP</span><strong>TLP:CLEAR</strong></div>
      <h3>Executive Summary</h3><p>Source-backed IOCs and MITRE ATT&amp;CK mappings are not established in this record.</p>
      <h3>Indicators &amp; Observables</h3><p>Not established in cited evidence.</p>
      <h3>MITRE ATT&amp;CK Assessment</h3><p>Not established in cited evidence.</p>
      <h3>Detection Engineering Guidance</h3><p>Guidance only.</p>
      <h3>Threat Hunting Queries</h3><p>Guidance only.</p>
    """, "html.parser")
    caps = v19_1._capabilities(soup)
    v19_1._validate_final(soup, "UNSPECIFIED", False, caps)


def test_og_builder_never_converts_unknown_severity_to_high(monkeypatch):
    calls = []

    def inner(*args, **kwargs):
        calls.append((args, kwargs))
        return "https://example.test/api/og?severity=HIGH"

    monkeypatch.setattr(v19_1, "_INNER_OG_BUILDER", inner)
    assert v19_1._patched_og_builder(None, "Title", None, "", None, "Intel") == v19_1.NEUTRAL_OG_URL
    assert calls == []
    assert v19_1._patched_og_builder(None, "Title", "HIGH", "", None, "Intel").startswith("https://example.test/")
    assert len(calls) == 1


def test_telemetry_is_non_secret_and_does_not_change_commercial_truth_sources():
    telemetry = v19_1.telemetry_snapshot()
    assert telemetry["prices_changed"] is False
    assert telemetry["payment_system_changed"] is False
    assert telemetry["reportx_tier_engine_changed"] is False
    assert telemetry["provider_policy_changed"] is False
    assert telemetry["telemetry_contains_pii"] is False
    assert telemetry["telemetry_contains_credentials"] is False
    serialized = str(telemetry).lower()
    assert "email" not in serialized
    assert "api_key" not in serialized
    assert "password" not in serialized
