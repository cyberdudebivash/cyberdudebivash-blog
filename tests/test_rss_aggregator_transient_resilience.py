from unittest.mock import Mock

import requests

from automation.rss_aggregator import GlobalRSSAggregator, _Feed


_VALID_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><item>
<title>Verified threat intelligence update</title>
<link>https://example.test/intel/1</link>
<description>Source-backed security report.</description>
<pubDate>Mon, 21 Sep 2026 21:00:00 GMT</pubDate>
</item></channel></rss>"""


def _response(status: int, text: str = "") -> Mock:
    response = Mock()
    response.status_code = status
    response.text = text
    if status >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(f"HTTP {status}")
    else:
        response.raise_for_status.return_value = None
    return response


def test_fetch_feed_retries_transient_server_response_once(monkeypatch):
    calls = [_response(503), _response(200, _VALID_RSS)]

    def fake_get(*args, **kwargs):
        return calls.pop(0)

    monkeypatch.setattr("automation.rss_aggregator.requests.get", fake_get)

    items = GlobalRSSAggregator.__new__(GlobalRSSAggregator)._fetch_feed(
        _Feed("Test Feed", "https://example.test/rss")
    )

    assert len(items) == 1
    assert items[0]["title"] == "Verified threat intelligence update"
    assert calls == []


def test_fetch_feed_retries_network_exception_once(monkeypatch):
    attempts = 0

    def fake_get(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise requests.ConnectionError("temporary reset")
        return _response(200, _VALID_RSS)

    monkeypatch.setattr("automation.rss_aggregator.requests.get", fake_get)

    items = GlobalRSSAggregator.__new__(GlobalRSSAggregator)._fetch_feed(
        _Feed("Test Feed", "https://example.test/rss")
    )

    assert len(items) == 1
    assert attempts == 2


def test_fetch_feed_does_not_retry_permanent_client_error(monkeypatch):
    attempts = 0

    def fake_get(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        return _response(404)

    monkeypatch.setattr("automation.rss_aggregator.requests.get", fake_get)

    items = GlobalRSSAggregator.__new__(GlobalRSSAggregator)._fetch_feed(
        _Feed("Test Feed", "https://example.test/rss")
    )

    assert items == []
    assert attempts == 1
