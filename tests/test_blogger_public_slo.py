"""Strict public Blogger publication SLO: all evidence read from the public feed."""
from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_blogger_public_delivery as probe

NOW = datetime(2026, 10, 25, 10, 0, tzinfo=timezone.utc)
BASE_PATH = "/2026/10/report-"


def public_feed(minutes):
    entries = []
    for number, age in enumerate(minutes):
        entries.append({
            "id": {"$t": f"post-{number}"},
            "published": {"$t": (NOW - timedelta(minutes=age)).isoformat()},
            "link": [{"rel": "alternate", "href": probe.BASE + f"{BASE_PATH}{number}.html"}],
        })
    return {"feed": {"entry": entries}}


def homepages():
    return '<a href="' + probe.BASE + BASE_PATH + '0.html">newest</a>'


def evaluate(minutes, **kwargs):
    return probe.evaluate(public_feed(minutes), homepages(), homepages(),
                          NOW, max_age_minutes=75, min_posts_in_window=4, **kwargs)


def test_four_distinct_public_reports_satisfy_delivery_slo():
    result = evaluate([5, 20, 40, 70, 150])
    assert result["exit_code"] == 0
    assert result["publication_count_window"] == 4
    assert result["minimum_posts_required"] == 4
    assert result["desktop_linked"] and result["mobile_linked"]


def test_public_link_is_not_enough_when_four_report_slo_is_missed():
    result = evaluate([5, 20, 40, 150])
    assert result["status"] == "BLOGGER_STALE"
    assert result["exit_code"] == 2
    assert result["recovery_required"] is False  # Public probe never dispatches.
    assert "publication_count_below_slo:3<4" in result["defects"]


def test_repeated_post_id_does_not_fabricate_public_publications():
    feed = public_feed([5])
    feed["feed"]["entry"] *= 4
    result = probe.evaluate(feed, homepages(), homepages(), NOW,
                            max_age_minutes=75, min_posts_in_window=4)
    assert result["status"] == "BLOGGER_STALE"
    assert result["publication_count_window"] == 1


def test_public_probe_rejects_noncanonical_older_post_link():
    feed = public_feed([5, 20, 40, 70])
    feed["feed"]["entry"][2]["link"][0]["href"] = "https://example.net/post.html"
    import pytest
    with pytest.raises(ValueError, match="invalid_public_permalink"):
        probe.evaluate(feed, homepages(), homepages(), NOW,
                       max_age_minutes=75, min_posts_in_window=4)


def test_public_probe_rejects_future_timestamp():
    result = evaluate([-10, 5, 20, 30])
    assert result["exit_code"] == 1
    assert "latest_publication_timestamp_in_future" in result["defects"]
