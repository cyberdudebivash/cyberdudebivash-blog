from datetime import datetime, timezone

from scripts.audit_live_cti_home import audit_html


NOW = datetime(2026, 9, 22, tzinfo=timezone.utc)


def test_clean_custom_domain_home_passes():
    html = """
    <html><head>
      <link rel="canonical" href="https://cti.cyberdudebivash.in/">
      <script type="application/ld+json">
        {"@type":"WebSite","url":"https://cti.cyberdudebivash.in/"}
      </script>
    </head><body>
      <article><time>21 September 2026</time>Fresh verified CTI</article>
    </body></html>
    """
    assert audit_html(html, now=NOW) == []


def test_placeholder_and_unverified_claims_are_blocked():
    html = """
    <html><head><link rel="canonical" href="https://cti.cyberdudebivash.in/"></head>
    <body>
      <p>Active Managed Tenants 142 Tenants</p>
      <p>Financial Risk Exposure $2.4M</p>
      <p>Platform Status: 99.99% ONLINE</p>
      <p>Compliance Frameworks: ISO 27001, SOC 2 Type II</p>
      <pre>mQGNBF+1234BCDEF... Key ID: 4096R/BIVASH_NAYAK</pre>
      <time>21 September 2026</time>
    </body></html>
    """
    codes = {f.code for f in audit_html(html, now=NOW)}
    assert "managed_tenant_claim" in codes
    assert "financial_risk_claim" in codes
    assert "platform_uptime_claim" in codes
    assert "soc2_type2_claim" in codes
    assert "placeholder_pgp" in codes
    assert "placeholder_pgp_id" in codes


def test_blogspot_identity_and_stale_home_are_blocked():
    html = """
    <html><head>
      <link rel="canonical" href="https://cti.cyberdudebivash.in/">
      <script type="application/ld+json">
        {"@type":"WebSite","@id":"https://cyberbivash.blogspot.com/#website"}
      </script>
    </head><body><time>8 August 2026</time></body></html>
    """
    findings = audit_html(html, now=NOW, max_freshness_days=14)
    codes = {f.code for f in findings}
    assert "blogspot_public_identity" in codes
    assert "homepage_freshness" in codes


def test_wrong_canonical_is_blocked():
    html = """
    <html><head>
      <link rel="canonical" href="https://cyberbivash.blogspot.com/">
    </head><body><time>21 September 2026</time></body></html>
    """
    codes = {f.code for f in audit_html(html, now=NOW)}
    assert "canonical_wrong_host" in codes


def test_global_threat_and_insurance_score_are_blocked_live():
    html = """
    <html><head><link rel="canonical" href="https://cti.cyberdudebivash.in/"></head>
    <body><p>Global Threat Level 88.4</p><p>Cyber Insurance Score 94/100</p>
    <time>21 September 2026</time></body></html>
    """
    codes = {f.code for f in audit_html(html, now=NOW)}
    assert "global_threat_level_claim" in codes
    assert "cyber_insurance_score_claim" in codes


def test_live_public_incorporation_claim_is_blocked():
    html = """<html><head><link rel="canonical" href="https://cti.cyberdudebivash.in/"></head>
    <body><footer>CYBERDUDEBIVASH PRIVATE LIMITED</footer><time>21 September 2026</time></body></html>"""
    codes = {f.code for f in audit_html(html, now=NOW)}
    assert "unsupported_incorporation" in codes
    safe_html = html.replace("CYBERDUDEBIVASH PRIVATE LIMITED", "CYBERDUDEBIVASH ECOSYSTEM")
    assert "unsupported_incorporation" not in {f.code for f in audit_html(safe_html, now=NOW)}



def test_additional_unverified_cti_telemetry_and_accessibility_claims_are_blocked():
    html = """
    <html><head><link rel="canonical" href="https://cti.cyberdudebivash.in/"></head>
    <body>
      <p>SOAR Automation Rate 91.2% Auto-Remediated</p>
      <p>Active IOC Matches 1,420 Blocked at Edge</p>
      <p>Cloud Security Posture 96/100 AWS / GCP / Azure</p>
      <p>Triage Queue 12 Pending</p>
      <p>Accessibility Engine: WCAG 2.2 AA Verified</p>
      <p>Ransomware Risk Level LOW Zero Active Leaks</p>
      <time>21 September 2026</time>
    </body></html>
    """
    codes = {f.code for f in audit_html(html, now=NOW)}
    assert {
        "soar_automation_claim",
        "ioc_matches_claim",
        "cloud_posture_claim",
        "triage_queue_claim",
        "accessibility_certification_claim",
        "ransomware_zero_leaks_claim",
    } <= codes


def test_empty_file_hash_is_not_lazarus_ioc_and_is_blocked_when_attributed():
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    start = '<html><head><link rel="canonical" href="https://cti.cyberdudebivash.in/"></head><body>'
    end = "<time>21 September 2026</time></body></html>"
    attributed = start + digest + " SHA256 Hash Lazarus Group 96/100 " + end
    assert "empty_sha_lazarus_attribution" in {
        f.code for f in audit_html(attributed, now=NOW)
    }

    # A factual mention of the well-known empty-file digest must not be blocked.
    educational = start + "SHA-256 of an empty file: " + digest + " " + end
    assert "empty_sha_lazarus_attribution" not in {
        f.code for f in audit_html(educational, now=NOW)
    }


def test_generic_soc2_alignment_language_does_not_claim_attestation():
    html = """
    <html><head><link rel="canonical" href="https://cti.cyberdudebivash.in/"></head>
    <body><p>SOC 2 Trust Services Criteria-informed control mapping. No attestation.</p>
    <time>21 September 2026</time></body></html>
    """
    assert audit_html(html, now=NOW) == []
