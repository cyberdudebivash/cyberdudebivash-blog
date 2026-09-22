from pathlib import Path

from automation import premium_factory_throughput as factory


def test_public_blogger_search_recovery_limits_are_bounded():
    assert factory.FACTORY_DAILY_FLOOR == 6
    assert factory.FACTORY_DAILY_GOAL == 12
    assert factory.FACTORY_RUNS_PER_DAY == 8
    assert factory.FACTORY_WRITE_BURST == 2
    assert factory.FACTORY_RUNS_PER_DAY * factory.FACTORY_WRITE_BURST == 16


def test_blogger_workflow_uses_recovery_cadence_and_burst():
    workflow = Path(".github/workflows/blogger-syndication.yml").read_text(encoding="utf-8")
    assert 'cron: "17 */3 * * *"' in workflow
    assert 'default: "2"' in workflow
    assert "github.event.inputs.max_posts || '2'" in workflow
    assert "hard ceiling 16 Blogger pages/day" in workflow
