"""Public surface failures must not be hidden by a recent local ledger."""
import importlib.util
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_blogger_public_delivery as probe

NOW = datetime(2026, 9, 24, 10, tzinfo=timezone.utc)
URL = probe.BASE + "/2026/09/report.html"


def feed(stamp="2026-09-24T09:30:00Z"):
    return {"feed": {"entry": [{"id": {"$t": "post-1"}, "published": {"$t": stamp}, "link": [{"rel": "alternate", "href": URL}]}]}}


def test_public_post_on_both_homepages():
    result = probe.evaluate(feed(), '<a href="' + URL + '">report</a>', '<a href="/2026/09/report.html?m=1">report</a>', NOW)
    assert result["exit_code"] == 0
    assert result["desktop_linked"] and result["mobile_linked"]


def test_script_reference_is_not_a_visible_link():
    result = probe.evaluate(feed(), '<script>"' + URL + '"</script>', '<a href="' + URL + '">report</a>', NOW)
    assert result["exit_code"] == 1
    assert result["defects"] == ["desktop_missing_latest_permalink"]
    assert result["recovery_required"] is False


def test_stale_public_feed_fails_even_with_links():
    html = '<a href="' + URL + '">report</a>'
    result = probe.evaluate(feed("2026-09-23T09:30:00Z"), html, html, NOW)
    assert result["exit_code"] == 2
    assert result["recovery_required"] is False


def test_foreign_host_does_not_count_as_homepage_link():
    html = '<a href="https://example.org/2026/09/report.html">report</a>'
    assert probe.evaluate(feed(), html, html, NOW)["exit_code"] == 1


def test_empty_feed_fails_closed():
    import pytest
    with pytest.raises(ValueError, match="empty_or_invalid"):
        probe.evaluate({"feed": {}}, "", "", NOW)
