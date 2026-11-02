"""
Tests for GlobalRSSAggregator — parallel feed fetching, parsing, filtering.
"""

import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.content_discovery import DiscoveredArticle, PublicationState, _compute_hash
from automation.rss_aggregator import GlobalRSSAggregator, _Feed, _GLOBAL_FEEDS


MOCK_FEED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Mock Security Feed</title>
    <item>
      <title>Critical Zero-Day Exploited in Popular VPN Appliance</title>
      <link>https://example-outlet.com/posts/vpn-zero-day</link>
      <description>Attackers are actively exploiting a zero-day in a widely deployed VPN appliance.</description>
      <pubDate>{pub_date}</pubDate>
    </item>
  </channel>
</rss>"""


def _recent_pub_date() -> str:
    import email.utils
    return email.utils.format_datetime(datetime.now(timezone.utc))


def _make_config(tmpdir: str) -> Config:
    cfg = Config()
    cfg.state_file = os.path.join(tmpdir, "state.json")
    cfg.max_article_age_hours = 48
    return cfg


def _make_mock_response(text: str) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.text = text
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


class TestGlobalFeedRegistry(unittest.TestCase):
    def test_feed_list_has_25_plus_sources(self):
        self.assertGreaterEqual(len(_GLOBAL_FEEDS), 25)

    def test_feed_list_entries_are_well_formed(self):
        for feed in _GLOBAL_FEEDS:
            self.assertTrue(feed.name)
            self.assertTrue(feed.url.startswith("https://"))

    def test_feed_names_are_unique(self):
        names = [f.name for f in _GLOBAL_FEEDS]
        self.assertEqual(len(names), len(set(names)))

    def test_cert_eu_uses_published_category_specific_feed(self):
        cert_feeds = [f.url for f in _GLOBAL_FEEDS if f.name == "CERT-EU Publications"]
        self.assertEqual(cert_feeds, ["https://cert.europa.eu/publications/threat-intelligence-rss"])

    def test_default_groq_fallbacks_exclude_deprecated_model(self):
        self.assertNotIn("qwen/qwen3.6-27b", Config().llm_model_groq_fallbacks)
        with patch.dict(os.environ, {"GROQ_FALLBACK_MODELS": ""}):
            self.assertNotIn("qwen/qwen3.6-27b", Config.from_env().llm_model_groq_fallbacks)


class TestGlobalRSSAggregator(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.state = PublicationState(self.config.state_file)
        self.source = GlobalRSSAggregator(self.config)

    def test_returns_empty_when_all_feeds_fail(self):
        with patch("requests.get", side_effect=Exception("Connection refused")):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_parses_valid_feed_response(self):
        xml = MOCK_FEED_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_mock_response(xml)):
            result = self.source.discover(self.state)
        self.assertGreater(len(result), 0)
        article = result[0]
        self.assertEqual(article.source, "global_rss")
        self.assertIn("VPN", article.title)

    def test_required_labels_present(self):
        xml = MOCK_FEED_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_mock_response(xml)):
            result = self.source.discover(self.state)
        self.assertGreater(len(result), 0)
        labels = result[0].labels
        self.assertIn("CYBERDUDEBIVASH", labels)
        self.assertIn("Threat Intelligence", labels)
        self.assertIn("Global Intel", labels)

    def test_already_published_filtered(self):
        url = "https://example-outlet.com/posts/vpn-zero-day"
        title = "Critical Zero-Day Exploited in Popular VPN Appliance"
        content_hash = _compute_hash(url, title)
        dummy = DiscoveredArticle(
            url=url,
            title=title,
            summary="",
            published_at=datetime.now(timezone.utc).isoformat(),
            content_hash=content_hash,
            labels=["Global Intel"],
            source="global_rss",
        )
        self.state.mark_published(dummy, "post-1", "https://blogger.com/post-1")

        xml = MOCK_FEED_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_mock_response(xml)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_old_entries_filtered_by_age(self):
        xml = MOCK_FEED_XML.format(pub_date="Mon, 01 Jan 2024 00:00:00 +0000")
        with patch("requests.get", return_value=_make_mock_response(xml)):
            result = self.source.discover(self.state)
        self.assertEqual(result, [])

    def test_full_content_includes_source_publisher(self):
        xml = MOCK_FEED_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_mock_response(xml)):
            result = self.source.discover(self.state)
        self.assertGreater(len(result), 0)
        self.assertIn("Source Publisher:", result[0].full_content)

    def test_source_publisher_is_a_real_structured_field_not_just_free_text(self):
        # COMMERCIAL-QUALITY-2026-08-18: previously the real feed name only
        # existed buried inside full_content's free text, so nothing
        # downstream (source_reliability(), the rendered publisher label)
        # could reliably use it -- every article collapsed to the generic
        # "global_rss" connector name regardless of which of the ~40
        # distinct, individually-known outlets it actually came from.
        xml = MOCK_FEED_XML.format(pub_date=_recent_pub_date())
        with patch("requests.get", return_value=_make_mock_response(xml)):
            result = self.source.discover(self.state)
        self.assertGreater(len(result), 0)
        known_names = {f.name for f in _GLOBAL_FEEDS}
        self.assertIn(result[0].source_publisher, known_names)


class TestFetchFeed(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = _make_config(self.tmpdir)
        self.source = GlobalRSSAggregator(self.config)
        self.feed = _Feed("Test Feed", "https://example.com/feed")

    def test_returns_empty_on_network_failure(self):
        with patch("requests.get", side_effect=Exception("timeout")):
            items = self.source._fetch_feed(self.feed)
        self.assertEqual(items, [])

    def test_returns_empty_on_malformed_xml(self):
        with patch("requests.get", return_value=_make_mock_response("NOT VALID XML <<<")):
            items = self.source._fetch_feed(self.feed)
        self.assertEqual(items, [])

    def test_caps_items_per_feed(self):
        many_items = "".join(
            f"""
    <item>
      <title>Article {i}</title>
      <link>https://example.com/article-{i}</link>
      <description>Description {i}</description>
      <pubDate>{_recent_pub_date()}</pubDate>
    </item>"""
            for i in range(9)
        )
        xml = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>{many_items}</channel></rss>"""
        with patch("requests.get", return_value=_make_mock_response(xml)):
            items = self.source._fetch_feed(self.feed)
        self.assertLessEqual(len(items), 6)


if __name__ == "__main__":
    unittest.main()
