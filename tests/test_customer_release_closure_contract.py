import re
from pathlib import Path

REQUIRED_CUSTOMER_P0_ISSUES = {222, 360, 418, 432, 433, 434, 494}


def test_customer_release_requires_post_cutover_theme_evidence():
    workflow = Path('.github/workflows/customer-release-certification.yml').read_text(encoding='utf-8')
    assert 'Require authoritative post-cutover Blogger theme evidence' in workflow
    assert 'test -s blogger-theme/production-current.xml' in workflow
    assert 'test -s blogger-theme/production-current.sha256' in workflow
    assert 'python scripts/certify_blogger_theme_baseline.py --json' in workflow
    assert 'python scripts/audit_live_cti_home.py' in workflow


def test_customer_global_go_requires_all_known_p0s_and_both_feed_types():
    workflow = Path('.github/workflows/customer-release-certification.yml').read_text(encoding='utf-8')
    match = re.search(r'const\s+blockers\s*=\s*\[([\d,\s]+)\]\s*;', workflow)
    assert match is not None, 'global release blocker list is missing'
    blocked_issues = {int(x) for x in re.findall(r'\d+', match.group(1))}
    assert REQUIRED_CUSTOMER_P0_ISSUES <= blocked_issues

    final_verdict = workflow.index('CUSTOMER_RELEASE_STATUS=GO')
    root_check = workflow.index('node scripts/certify-soc-public-feed-parity.cjs')
    api_check = workflow.index('node scripts/certify-soc-s2n-api-release.cjs --monitor-public')
    assert root_check < final_verdict
    assert api_check < final_verdict
