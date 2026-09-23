from datetime import datetime, timedelta, timezone

from scripts.check_blogger_publication_freshness import evaluate_blogger_freshness


NOW = datetime(2026, 9, 23, 16, 0, tzinfo=timezone.utc)


def _state(*minutes_ago: int):
    return {
        "posts": {
            f"p{idx}": {
                "published_at": (NOW - timedelta(minutes=minutes)).isoformat(),
                "title": f"Report {idx}",
            }
            for idx, minutes in enumerate(minutes_ago)
        }
    }


def test_customer_publication_freshness_is_healthy_inside_threshold():
    result = evaluate_blogger_freshness(
        _state(30, 180),
        now=NOW,
        max_age_minutes=240,
    )
    assert result["status"] == "BLOGGER_HEALTHY"
    assert result["exit_code"] == 0
    assert result["recovery_required"] is False
    assert result["age_minutes"] == 30.0


def test_customer_publication_freshness_requires_recovery_after_four_hours():
    result = evaluate_blogger_freshness(
        _state(241, 500),
        now=NOW,
        max_age_minutes=240,
    )
    assert result["status"] == "BLOGGER_STALE"
    assert result["exit_code"] == 2
    assert result["recovery_required"] is True
    assert result["age_minutes"] == 241.0


def test_latest_success_wins_over_older_publications():
    result = evaluate_blogger_freshness(
        _state(500, 20, 300),
        now=NOW,
        max_age_minutes=240,
    )
    assert result["status"] == "BLOGGER_HEALTHY"
    assert result["age_minutes"] == 20.0


def test_missing_publication_evidence_is_monitor_error_not_blind_recovery():
    result = evaluate_blogger_freshness(
        {"posts": {}},
        now=NOW,
        max_age_minutes=240,
    )
    assert result["status"] == "BLOGGER_STATE_ERROR"
    assert result["exit_code"] == 1
    assert result["recovery_required"] is False
    assert "no_parseable_published_at" in result["defects"]


def test_future_timestamp_is_monitor_error():
    state = {
        "posts": {
            "future": {
                "published_at": (NOW + timedelta(minutes=10)).isoformat(),
            }
        }
    }
    result = evaluate_blogger_freshness(
        state,
        now=NOW,
        max_age_minutes=240,
    )
    assert result["status"] == "BLOGGER_STATE_ERROR"
    assert result["exit_code"] == 1
    assert result["recovery_required"] is False
    assert "latest_publication_timestamp_in_future" in result["defects"]


def test_list_shaped_legacy_post_state_is_supported():
    state = {
        "posts": [
            {"published_at": (NOW - timedelta(minutes=15)).isoformat()},
            {"published_at": "not-a-timestamp"},
        ]
    }
    result = evaluate_blogger_freshness(
        state,
        now=NOW,
        max_age_minutes=240,
    )
    assert result["status"] == "BLOGGER_HEALTHY"
    assert result["age_minutes"] == 15.0
