from types import SimpleNamespace

from automation.cti_dossier_presentation import (
    MARKER,
    ROOT_CLASS,
    VISUAL_SYSTEM,
    decorate_cti_dossier,
)


BASE_HTML = """
<img src="https://example.test/card.png" alt="card"/>
<h3>Executive Summary</h3>
<p>A source-linked campaign report.</p>
<h3>Threat Severity Assessment</h3>
<p>Severity is assessed as High. Confidence in severity rating is Medium.</p>
<h3>Verified Facts</h3>
<ul><li>Source publisher: GBHackers Security</li></ul>
<h3>Executive Decision Matrix</h3>
<table><tr><th>Decision</th><th>Recommendation</th></tr><tr><td>Teams External Access</td><td>Restrict to specific domains</td></tr></table>
<h3>Provenance and Certification</h3>
<p>Generated UTC 2026-09-05T08:43:47.030185Z</p>
"""


def _article(**overrides):
    values = dict(
        title="Spring Ring Campaign Uses Teams Vishing, PowerShell RAT and NTLM Relay Attacks",
        labels=["Malware Research", "Threat Intelligence"],
        source="global_rss",
        source_publisher="GBHackers Security",
        cvss_score=None,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def _context(**overrides):
    values = dict(
        report_id="CDB-CTI-2026-C51BE2974378",
        certification_status="FLASH_READY",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_dossier_renders_enterprise_command_deck_and_preserves_content():
    rendered = decorate_cti_dossier(BASE_HTML, _article(), _context())
    assert MARKER in rendered
    assert ROOT_CLASS in rendered
    assert "ADVANCED CTI DOSSIER" in rendered
    assert "CDB-CTI-2026-C51BE2974378" in rendered
    assert "GBHackers Security" in rendered
    assert "global_rss" not in rendered.split("cdbd-kpis", 1)[1].split("</div>", 7)[0]
    assert "Restrict to specific domains" in rendered
    assert "FLASH_READY" in rendered


def test_metadata_uses_publisher_and_existing_severity_evidence():
    rendered = decorate_cti_dossier(BASE_HTML, _article(), _context())
    assert ">HIGH<" in rendered
    assert ">MEDIUM<" in rendered
    assert ">GBHackers Security<" in rendered


def test_cvss_is_canonical_severity_when_structured():
    rendered = decorate_cti_dossier(BASE_HTML, _article(cvss_score=9.8), _context())
    assert ">CRITICAL<" in rendered


def test_unknown_states_remain_explicit_and_no_compliance_claims():
    no_claim_html = "<h3>Executive Summary</h3><p>No risk classification is asserted.</p>"
    unknown = decorate_cti_dossier(
        no_claim_html,
        _article(source=None, source_publisher=None),
        _context(report_id=None, certification_status=None),
    )
    assert ">UNSPECIFIED<" in unknown
    assert ">NOT ASSIGNED<" in unknown
    assert "NOT EXPOSED" in unknown
    assert ">CRITICAL<" not in unknown
    assert "SOC 2 CERTIFIED" not in unknown.upper()
    assert "SOC 2 COMPLIANT" not in unknown.upper()


def test_duplicate_canonical_sections_converge_to_later_reportx_version():
    html = """
    <h3>Executive Summary</h3><p>first summary</p>
    <h3>MITRE ATT&amp;CK Assessment</h3><p>speculative mapping</p>
    <h3>Technical Analysis</h3><p>middle</p>
    <h3>MITRE ATT&amp;CK Assessment</h3><p>Not established in cited evidence.</p>
    <h3>Executive Summary</h3><p>canonical summary</p>
    """
    rendered = decorate_cti_dossier(html, _article(), _context())
    assert "speculative mapping" not in rendered
    assert "first summary" not in rendered
    assert "Not established in cited evidence." in rendered
    assert "canonical summary" in rendered
    assert rendered.count('<h3 class="cdbd-section-title" id="mitre-att-ck-assessment">MITRE ATT&amp;CK Assessment</h3>') == 1
    assert rendered.count('<h3 class="cdbd-section-title" id="executive-summary">Executive Summary</h3>') == 1


def test_dossier_is_idempotent():
    once = decorate_cti_dossier(BASE_HTML, _article(), _context())
    twice = decorate_cti_dossier(once, _article(), _context())
    assert once == twice
    assert twice.count(f"<!-- {MARKER} -->") == 1


def test_navigation_and_section_anchors_are_generated():
    rendered = decorate_cti_dossier(BASE_HTML, _article(), _context())
    assert 'href="#executive-summary"' in rendered
    assert 'href="#verified-facts"' in rendered
    assert 'href="#executive-decision-matrix"' in rendered
    assert 'href="#provenance-and-certification"' in rendered
    assert 'class="cdbd-section-title"' in rendered


def test_blogger_safe_css_mobile_print_and_no_script_dependency():
    rendered = decorate_cti_dossier(BASE_HTML, _article(), _context())
    assert "@media(max-width:640px)" in rendered
    assert "@media print" in rendered
    assert ".cdb-cti-dossier table" in rendered
    assert "<script" not in rendered.lower()
    assert "position:sticky" in rendered


def test_existing_article_links_and_images_survive_reserialization():
    original = '<img src="https://example.test/x.png"/><p><a href="https://gbhackers.com/x">Source</a></p>'
    rendered = decorate_cti_dossier(original, _article(), _context())
    assert "https://example.test/x.png" in rendered
    assert "https://gbhackers.com/x" in rendered
    assert ">Source<" in rendered


def test_enterprise_visual_system_exposes_requested_semantic_components():
    html = """
    <h3>Executive Summary</h3><p>Leadership should validate exposure before escalation.</p>
    <h3>SOC Analyst Playbook</h3><p>Review endpoint, identity, and network telemetry tied to the cited behavior.</p>
    <h3>Enterprise Exposure Assessment</h3><p>Confirm the cited technology exists in authoritative inventory.</p>
    <h3>Intelligence Gaps &amp; Collection Requirements</h3><p>Independent corroboration is not yet established.</p>
    <h3>Remediation &amp; Validation Plan</h3><p>Apply only source-supported controls and verify the post-change state.</p>
    """
    rendered = decorate_cti_dossier(html, _article(), _context(family="general_intelligence"))

    assert VISUAL_SYSTEM in rendered
    assert 'data-cdb-component="report-hero"' in rendered
    assert 'data-cdb-component="metadata-grid"' in rendered
    assert 'data-cdb-component="status-led-group"' in rendered
    assert 'data-cdb-component="quick-snapshot-card"' in rendered
    assert 'data-cdb-component="section-card"' in rendered
    assert 'data-cdb-component="callout-box"' in rendered
    assert "SITUATION SNAPSHOT" in rendered
    assert "Leadership should validate exposure before escalation." in rendered
    assert "Review endpoint, identity, and network telemetry" in rendered


def test_family_visual_theme_uses_existing_structured_family_or_labels_only():
    ransomware = decorate_cti_dossier(
        BASE_HTML,
        _article(labels=["Threat Intelligence", "Ransomware"], source="ransomware_intel"),
        _context(family="ransomware_claim"),
    )
    malware = decorate_cti_dossier(
        BASE_HTML,
        _article(labels=["Malware Research", "Threat Intelligence"]),
        _context(family="general_intelligence"),
    )

    assert "RANSOMWARE / EXTORTION CLAIM" in ransomware
    assert "cdbd-family-ransomware-claim" in ransomware
    assert 'data-report-family="ransomware_claim"' in ransomware
    assert "MALWARE INTELLIGENCE" in malware
    assert "cdbd-family-malware" in malware


def test_status_leds_are_non_probabilistic_and_do_not_invent_corroboration():
    rendered = decorate_cti_dossier(
        "<h3>Executive Summary</h3><p>One source reports the development.</p>",
        _article(),
        _context(family="general_intelligence"),
    )

    assert "FAIL-CLOSED GATES ACTIVE" in rendered
    assert "EVIDENCE-BOUND" in rendered
    assert "NOT EXPLICITLY ASSERTED" in rendered
    assert "NO SYNTHETIC VISUAL METRICS" in rendered
    assert "INDEPENDENT CORROBORATION" not in rendered


def test_existing_corroboration_language_can_be_surfaced_without_new_claim():
    rendered = decorate_cti_dossier(
        "<h3>Evidence &amp; Source Assessment</h3>"
        "<p>Independent corroboration is present in the cited evidence.</p>",
        _article(),
        _context(family="general_intelligence"),
    )
    assert "INDEPENDENT CORROBORATION" in rendered


def test_ioc_and_detection_blocks_receive_presentation_only_component_markers():
    html = """
    <h3>Indicators &amp; Observables</h3>
    <table><tr><th>Type</th><th>Value</th></tr><tr><td>SHA-256</td><td>abc123</td></tr></table>
    <h3>Detection Engineering Guidance</h3>
    <pre>DeviceProcessEvents | where FileName == "example.exe"</pre>
    """
    rendered = decorate_cti_dossier(html, _article(), _context())

    assert 'data-cdb-component="ioc-table"' in rendered
    assert "ioc-table" in rendered
    assert 'data-cdb-component="detection-code-block"' in rendered
    assert "detection-code-block" in rendered
    assert "abc123" in rendered
    assert 'FileName == "example.exe"' in rendered


def test_visual_upgrade_improves_accessibility_without_client_side_script():
    rendered = decorate_cti_dossier(BASE_HTML, _article(), _context())

    assert "a:focus-visible" in rendered
    assert "@media(forced-colors:active)" in rendered
    assert "@media(prefers-reduced-motion:reduce)" in rendered
    assert 'aria-label="Evidence and delivery status indicators"' in rendered
    assert 'aria-label="Executive and SOC situation snapshot"' in rendered
    assert "<script" not in rendered.lower()


def test_snapshot_omits_missing_sections_instead_of_fabricating_placeholders():
    rendered = decorate_cti_dossier(
        "<h3>Executive Summary</h3><p>Only the sourced executive statement exists.</p>",
        _article(),
        _context(),
    )

    assert "Only the sourced executive statement exists." in rendered
    assert "SOC ACTION" not in rendered
    assert "EXPOSURE DECISION" not in rendered
    assert "INTELLIGENCE GAPS" not in rendered
    assert "REMEDIATION &amp; VALIDATION" not in rendered
