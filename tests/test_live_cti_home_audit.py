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
