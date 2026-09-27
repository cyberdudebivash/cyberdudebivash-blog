from pathlib import Path

def test_customer_release_requires_post_cutover_theme_evidence():
    workflow=Path(".github/workflows/customer-release-certification.yml").read_text(encoding="utf-8")
    assert "Require authoritative post-cutover Blogger theme evidence" in workflow
    assert "test -s blogger-theme/production-current.xml" in workflow
    assert "test -s blogger-theme/production-current.sha256" in workflow
    assert "python scripts/certify_blogger_theme_baseline.py --json" in workflow
    assert "python scripts/audit_live_cti_home.py" in workflow
    assert "const blockers = [222];" in workflow
