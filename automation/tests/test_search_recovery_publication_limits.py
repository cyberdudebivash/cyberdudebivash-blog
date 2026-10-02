from pathlib import Path

from automation import premium_factory_throughput as factory


def test_public_blogger_hourly_delivery_contract_is_bounded():
    assert factory.FACTORY_HOURLY_TARGET == 4
    assert factory.FACTORY_DAILY_FLOOR == 96
    assert factory.FACTORY_DAILY_GOAL == 96
    assert factory.FACTORY_RUNS_PER_DAY == 24
    assert factory.FACTORY_WRITE_BURST == 4
    assert factory.FACTORY_RUNS_PER_DAY * factory.FACTORY_WRITE_BURST == 96


def test_blogger_workflow_uses_hourly_cadence_and_four_report_burst():
    workflow = Path(".github/workflows/blogger-syndication.yml").read_text(encoding="utf-8")
    assert 'cron: "17 * * * *"' in workflow
    assert 'default: "4"' in workflow
    assert "github.event.inputs.max_posts || '4'" in workflow
    assert "target 4 verified reports/hour" in workflow


def test_freshness_monitor_covers_customer_facing_blogger_and_preserves_write_cap():
    workflow = Path(".github/workflows/freshness-check.yml").read_text(encoding="utf-8")
    assert "check_blogger_publication_freshness.py" in workflow
    assert "--max-age-minutes 75" in workflow
    assert "--min-posts-in-window 4" in workflow
    assert "blogger-syndication.yml" in workflow
    assert "max_posts: '4'" in workflow
    assert "45 * 60 * 1000" in workflow
    assert "steps.freshness.outputs.recovery_required != 'true'" in workflow

def test_push_public_delivery_canary_treats_provider_429_as_observable_not_delivery_failure():
    workflow = Path(".github/workflows/freshness-check.yml").read_text(encoding="utf-8")
    assert "BLOGGER_PUBLIC_RATE_LIMITED" in workflow
    assert "Provider returned HTTP 429" in workflow
    assert 'exit "$EXIT_CODE"' in workflow
    assert "python3 scripts/check_blogger_public_delivery.py --attempts 1" in workflow
