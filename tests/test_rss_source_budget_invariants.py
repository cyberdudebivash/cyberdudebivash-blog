"""Regression gates for the global RSS source request budget.

These tests keep source expansion deliberate: duplicate endpoints waste outbound
requests, and non-HTTPS endpoints weaken transport integrity.  They do not make
network calls.
"""

from automation.rss_aggregator import _GLOBAL_FEEDS


def test_global_feed_urls_are_unique():
    urls = [feed.url for feed in _GLOBAL_FEEDS]

    assert len(urls) == len(set(urls)), "duplicate RSS endpoints waste request budget"


def test_global_feed_names_are_unique():
    names = [feed.name for feed in _GLOBAL_FEEDS]

    assert len(names) == len(set(names)), "duplicate feed identities make source attribution ambiguous"


def test_global_feeds_use_https_transport():
    insecure = [feed.url for feed in _GLOBAL_FEEDS if not feed.url.startswith("https://")]

    assert insecure == [], f"RSS sources must use HTTPS: {insecure}"
