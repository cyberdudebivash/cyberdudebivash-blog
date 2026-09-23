import hashlib
from pathlib import Path

from scripts.certify_blogger_theme_baseline import certify_theme, main


GOOD_THEME = """
<html>
<head>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "WebSite",
  "@id": "https://cti.cyberdudebivash.in/#website",
  "url": "https://cti.cyberdudebivash.in/"
}
</script>
</head>
<body>CYBERDUDEBIVASH SENTINEL APEX</body>
</html>
"""


def _write_baseline(tmp_path: Path, content: str, *, wrong_hash: bool = False):
    theme = tmp_path / "production-current.xml"
    checksum = tmp_path / "production-current.sha256"
    theme.write_text(content, encoding="utf-8")
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    checksum.write_text(("0" * 64 if wrong_hash else digest) + "  production-current.xml\n", encoding="utf-8")
    return theme, checksum


def test_clean_checksummed_custom_domain_theme_passes(tmp_path):
    theme, checksum = _write_baseline(tmp_path, GOOD_THEME)
    assert main(["--theme", str(theme), "--checksum", str(checksum)]) == 0


def test_checksum_mismatch_fails_closed(tmp_path):
    theme, checksum = _write_baseline(tmp_path, GOOD_THEME, wrong_hash=True)
    assert main(["--theme", str(theme), "--checksum", str(checksum)]) == 1


def test_missing_authoritative_export_is_baseline_error(tmp_path):
    assert main([
        "--theme", str(tmp_path / "missing.xml"),
        "--checksum", str(tmp_path / "missing.sha256"),
    ]) == 2


def test_blogspot_website_identity_is_blocked():
    theme = """
    <script type="application/ld+json">
      {"@type":"WebSite","@id":"https://cyberbivash.blogspot.com/#website",
       "url":"https://cyberbivash.blogspot.com/"}
    </script>
    """
    codes = {f["code"] for f in certify_theme(theme)["findings"]}
    assert "website_jsonld_blogspot_identity" in codes
    assert "website_jsonld_custom_domain_missing" in codes


def test_known_placeholder_and_unverified_claims_are_blocked():
    theme = GOOD_THEME + """
    <div>Real-time Indicators: 142,890+</div>
    <div>Board SLA Compliance 99.4%</div>
    <div>Active Managed Tenants 142 Tenants</div>
    <div>Financial Risk Exposure $2.4M</div>
    <div>Cyber Insurance Score 94/100</div>
    <div>Compliance Frameworks: ISO 27001, SOC 2 Type II</div>
    <pre>mQGNBF+1234BCDEF... 4096R/BIVASH_NAYAK</pre>
    """
    codes = {f["code"] for f in certify_theme(theme)["findings"]}
    assert {
        "indicator_count_claim",
        "board_sla_claim",
        "managed_tenant_claim",
        "financial_risk_claim",
        "cyber_insurance_score_claim",
        "soc2_type2_claim",
        "placeholder_pgp",
        "placeholder_pgp_id",
    }.issubset(codes)


def test_theme_without_explicit_website_jsonld_fails():
    result = certify_theme("<html><body>clean</body></html>")
    assert result["status"] == "FAIL"
    assert {f["code"] for f in result["findings"]} == {"website_jsonld_missing"}
