from pathlib import Path

from automation import premium_factory_throughput as factory


def test_public_blogger_search_recovery_limits_are_bounded():
    assert factory.FACTORY_DAILY_FLOOR == 6
    assert factory.FACTORY_DAILY_GOAL == 24
    assert factory.FACTORY_RUNS_PER_DAY == 8
    assert factory.FACTORY_WRITE_BURST == 4
    assert factory.FACTORY_RUNS_PER_DAY * factory.FACTORY_WRITE_BURST == 32


def test_blogger_workflow_uses_recovery_cadence_and_burst():
    workflow = Path(".github/workflows/blogger-syndication.yml").read_text(encoding="utf-8")
    assert 'cron: "17 */3 * * *"' in workflow
    assert 'default: "4"' in workflow
    assert "github.event.inputs.max_posts || '4'" in workflow
    assert "hard ceiling 16 Blogger pages/day" in workflow


def test_freshness_monitor_covers_customer_facing_blogger_and_preserves_write_cap():
    workflow = Path(".github/workflows/freshness-check.yml").read_text(encoding="utf-8")
    assert "check_blogger_publication_freshness.py" in workflow
    assert "--max-age-minutes 240" in workflow
    assert "blogger-syndication.yml" in workflow
    assert "max_posts: '2'" in workflow
    assert "45 * 60 * 1000" in workflow
    assert "steps.freshness.outputs.recovery_required != 'true'" in workflow
