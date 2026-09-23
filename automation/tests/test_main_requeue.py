"""Tests for main.py's early-break requeue safeguard.

Analysis of logs/run-*.json (4019 historical run reports) showed the
publish loop's `break` on BloggerRateLimitError/BloggerAuthError only ever
queued the one article that triggered the error for retry — every other
discovered-but-not-yet-attempted article in that run's batch was silently
dropped from the report, relying on being rediscovered from its original
source on a later run (not guaranteed for sources with a small rolling
window, e.g. RSS feeds). 21.5% of all runs hit this path historically;
effectively 100% of the most recent 100 runs did, since Blogger's rate
limit is now hit before every discovered batch is exhausted.
"""
from types import SimpleNamespace
from unittest.mock import Mock

import automation.main as main_module
from automation.content_discovery import DiscoveredArticle
from automation.main import (
    _article_selection_key,
    _merge_retry_and_fresh,
    _next_backfill_candidate,
    _pipeline_exit_code,
    _publication_attempt_limit,
    _pipeline_run_status,
    _requeue_unattempted,
)


def _article(n):
    return DiscoveredArticle(
        url=f"https://example.com/{n}",
        title=f"Article {n}",
        summary="summary",
        published_at="2026-07-28T00:00:00Z",
        content_hash=f"hash{n}",
        labels=["Threat Intelligence"],
        source="global_rss",
    )


def test_requeues_every_remaining_article_with_the_triggering_error():
    state = Mock()
    remaining = [_article(1), _article(2), _article(3)]

    count = _requeue_unattempted(remaining, state, "HTTP 429 rate limited")

    assert count == 3
    assert state.add_to_retry_queue.call_count == 3
    for call, article in zip(state.add_to_retry_queue.call_args_list, remaining):
        called_article, called_reason = call.args
        assert called_article is article
        assert called_reason == "not attempted — pipeline stopped early: HTTP 429 rate limited"


def test_empty_remaining_list_is_a_no_op():
    state = Mock()
    count = _requeue_unattempted([], state, "some error")
    assert count == 0
    state.add_to_retry_queue.assert_not_called()


def test_clean_run_returns_success_exit_code():
    assert _pipeline_exit_code({"published": 2, "failed": 0}) == 0


# ── run_status classification (SUCCESS / DEGRADED / FAILED) ────────────────
#
# Supersedes the prior binary policy documented in
# docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md
# ("Decision (owner, 2026-08-20): Option A — leave as-is", i.e. any failed
# article, including a correctly-blocked one, reddened the whole run). The
# P0 Intel Factory Publication Reliability mandate explicitly re-raised this
# exact question and specified a 3-state model instead — see
# docs/audits/SENTINEL-APEX-INTEL-FACTORY-PUBLICATION-RELIABILITY-V1-CERTIFICATION.md
# for the full reasoning. These tests pin down the new, intentional policy:
# an integrity block, a self-healing rate limit, or a queued-for-retry
# publish error are all DEGRADED (still exit 0) — the pipeline did its job.
# Only a broken credential or an exception outside the pipeline's own error
# taxonomy is FAILED (exit 1).

def test_run_missing_entirely_is_success():
    assert _pipeline_run_status({"published": 3, "failed": 0, "posts": []}) == "SUCCESS"


def test_integrity_blocked_alone_is_degraded_not_failed():
    report = {
        "published": 2,
        "failed": 1,
        "integrity_blocked": 1,
        "posts": [
            {"status": "published"},
            {"status": "published"},
            {"status": "integrity_blocked"},
        ],
    }
    assert _pipeline_run_status(report) == "DEGRADED"
    report["run_status"] = _pipeline_run_status(report)
    assert _pipeline_exit_code(report) == 0


def test_rate_limited_alone_is_degraded_not_failed():
    report = {
        "published": 2,
        "failed": 1,
        "posts": [
            {"status": "published"},
            {"status": "published"},
            {"status": "rate_limited"},
        ],
    }
    assert _pipeline_run_status(report) == "DEGRADED"
    report["run_status"] = _pipeline_run_status(report)
    assert _pipeline_exit_code(report) == 0


def test_publish_error_alone_is_degraded_not_failed():
    report = {
        "published": 2,
        "failed": 1,
        "posts": [
            {"status": "published"},
            {"status": "published"},
            {"status": "publish_error"},
        ],
    }
    assert _pipeline_run_status(report) == "DEGRADED"
    report["run_status"] = _pipeline_run_status(report)
    assert _pipeline_exit_code(report) == 0


def test_auth_error_is_failed_even_with_other_successful_publications():
    report = {
        "published": 2,
        "failed": 1,
        "posts": [
            {"status": "published"},
            {"status": "published"},
            {"status": "auth_error"},
        ],
    }
    assert _pipeline_run_status(report) == "FAILED"
    report["run_status"] = _pipeline_run_status(report)
    assert _pipeline_exit_code(report) == 1


def test_unexpected_exception_is_failed():
    report = {
        "published": 2,
        "failed": 1,
        "posts": [
            {"status": "published"},
            {"status": "published"},
            {"status": "error"},
        ],
    }
    assert _pipeline_run_status(report) == "FAILED"
    report["run_status"] = _pipeline_run_status(report)
    assert _pipeline_exit_code(report) == 1


def test_clean_run_is_success_status():
    report = {
        "published": 2,
        "failed": 0,
        "posts": [{"status": "published"}, {"status": "published"}],
    }
    assert _pipeline_run_status(report) == "SUCCESS"


def test_terminal_status_wins_even_if_it_is_not_the_only_failure():
    """A run with both a healthy integrity block and a genuine auth error
    must still be FAILED — the terminal condition can never be masked by
    also containing a benign one."""
    report = {
        "published": 1,
        "failed": 2,
        "posts": [
            {"status": "published"},
            {"status": "integrity_blocked"},
            {"status": "auth_error"},
        ],
    }
    assert _pipeline_run_status(report) == "FAILED"


def test_exit_code_never_infers_failed_from_a_missing_run_status():
    """A report that was never run through run_pipeline()'s own
    classification (no run_status key at all) must not be silently treated
    as FAILED just because it has a nonzero failed count — only an explicit
    run_status of "FAILED" may produce exit code 1."""
    assert _pipeline_exit_code({"published": 2, "failed": 1}) == 0


def test_fresh_article_replaces_stale_retry_with_same_source_url():
    stale = _article(1)
    stale.content_hash = "old-template-hash"
    fresh = _article(1)
    fresh.title = "Article 1 without placeholder taxonomy"
    fresh.content_hash = "new-template-hash"
    state = Mock()
    state.is_published.return_value = False
    state.is_source_url_published.return_value = False

    merged = _merge_retry_and_fresh([stale], [fresh], state)

    assert merged == [fresh]


def test_published_source_url_suppresses_legacy_retry_hash():
    stale = _article(2)
    stale.content_hash = "legacy-hash"
    state = Mock()
    state.is_published.return_value = False
    state.is_source_url_published.return_value = True

    assert _merge_retry_and_fresh([stale], [], state) == []


def test_publication_attempt_budget_is_bounded_and_separate_from_write_target():
    assert _publication_attempt_limit(0) == 0
    assert _publication_attempt_limit(1) == 3
    assert _publication_attempt_limit(2) == 6
    # Global safety ceiling: a larger future write target must not create an
    # unbounded transform/API retry loop.
    assert _publication_attempt_limit(5) == 6


def test_quality_backfill_selects_an_unattempted_candidate(monkeypatch):
    first = _article(11)
    replacement = _article(12)
    attempted = {_article_selection_key(first)}

    def fake_select(retry_articles, fresh_articles, max_posts):
        assert max_posts == 1
        assert first not in fresh_articles
        assert replacement in fresh_articles
        return SimpleNamespace(articles=[replacement])

    monkeypatch.setattr(main_module, "select_publication_batch", fake_select)

    candidate, source_kind = _next_backfill_candidate(
        [],
        [first, replacement],
        attempted,
    )

    assert candidate is replacement
    assert source_kind == "fresh"


def test_quality_backfill_never_reselects_an_attempted_retry(monkeypatch):
    attempted_retry = _article(21)
    attempted_retry.source = "retry-source"
    fresh = _article(22)
    attempted = {_article_selection_key(attempted_retry)}

    def fake_select(retry_articles, fresh_articles, max_posts):
        assert retry_articles == []
        assert fresh_articles == [fresh]
        return SimpleNamespace(articles=[fresh])

    monkeypatch.setattr(main_module, "select_publication_batch", fake_select)

    candidate, source_kind = _next_backfill_candidate(
        [attempted_retry],
        [fresh],
        attempted,
    )

    assert candidate is fresh
    assert source_kind == "fresh"
