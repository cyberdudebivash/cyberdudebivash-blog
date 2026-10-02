"""Public surface failures must not be hidden by a recent local ledger."""
import importlib.util
import json
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


def test_retry_delay_honors_provider_seconds_without_shortening():
    assert probe.retry_delay("37", 1, NOW) == 37


def test_retry_delay_uses_bounded_exponential_fallback():
    assert probe.retry_delay(None, 1, NOW) == 5
    assert probe.retry_delay(None, 2, NOW) == 10


def test_fetch_uses_single_request_when_attempt_budget_is_one(monkeypatch):
    calls = []

    class Response:
        url = probe.BASE + "/"
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, _limit): return b"ok"

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return Response()

    monkeypatch.setattr(probe, "urlopen", fake_urlopen)
    assert probe.fetch(probe.BASE + "/", "desktop", attempts=1) == "ok"
    assert len(calls) == 1


def test_actions_push_canary_uses_single_attempt_budget():
    workflow = Path(".github/workflows/freshness-check.yml").read_text(encoding="utf-8")
    marker = "name: Verify public delivery with the released probe"
    assert marker in workflow
    block = workflow.split(marker, 1)[1].split("\n\n  freshness-check:", 1)[0]
    assert "python3 scripts/check_blogger_public_delivery.py --attempts 1" in block

def test_public_probe_cli_accepts_attempt_budget_and_applies_it_to_all_reads(monkeypatch, capsys):
    calls = []

    current_stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = json.dumps(feed(current_stamp))

    def fake_fetch(url, endpoint="public", attempts=3, max_retry_after=60):
        calls.append((endpoint, attempts))
        if endpoint == "feed":
            return payload
        return '<a href="' + URL + '">report</a>'

    monkeypatch.setattr(probe, "fetch", fake_fetch)
    monkeypatch.setattr(sys, "argv", ["check_blogger_public_delivery.py", "--attempts", "1"])

    assert probe.main() == 0
    assert calls == [("feed", 1), ("desktop", 1), ("mobile", 1)]
    assert '"exit_code": 0' in capsys.readouterr().out


def test_stale_freshness_defect_is_not_reclassified_as_public_linkage_failure():
    html = '<a href="' + URL + '">report</a>'
    result = probe.evaluate(feed("2026-09-23T09:30:00Z"), html, html, NOW)
    assert result["status"] == "BLOGGER_STALE"
    assert result["exit_code"] == 2
    assert "publication_count_below_slo:0<1" in result["defects"]