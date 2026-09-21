"""CYBERDUDEBIVASH® SENTINEL APEX — Global Threat Intelligence RSS Aggregator

Polls 25+ of the world's leading cybersecurity publishers and vendor research
blogs in parallel, surfacing breaking CVEs, malware/ransomware campaigns,
APT activity, and security news for analyst-grade syndication.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests

from .config import Config
from .content_discovery import (
    DiscoveredArticle,
    PublicationState,
    _compute_hash,
    _infer_labels,
    _is_recent,
    _parse_feed_items,
    _parse_rfc_date,
)
from .logger import setup_logger

logger = setup_logger("rss_aggregator")

_FEED_TIMEOUT_SECONDS = 10
_MAX_ITEMS_PER_FEED = 6
_MAX_WORKERS = 24
_MAX_FETCH_ATTEMPTS = 2
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class _Feed:
    name: str
    url: str


_GLOBAL_FEEDS: tuple[_Feed, ...] = (
    _Feed("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    _Feed("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    _Feed("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    _Feed("Dark Reading", "https://www.darkreading.com/rss.xml"),
    _Feed("SecurityWeek", "https://www.securityweek.com/feed/"),
    _Feed("Security Affairs", "https://securityaffairs.com/feed"),
    _Feed("The Record by Recorded Future", "https://therecord.media/feed"),
    _Feed("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/"),
    _Feed("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    _Feed("GBHackers Security", "https://gbhackers.com/feed/"),
    _Feed("HackRead", "https://www.hackread.com/feed/"),
    _Feed("CyberScoop", "https://cyberscoop.com/feed/"),
    _Feed("SC Media", "https://www.scmagazine.com/feed/"),
    _Feed("CSO Online", "https://www.csoonline.com/index.rss"),
    _Feed("Schneier on Security", "https://www.schneier.com/feed/atom/"),
    _Feed("Wired Security", "https://www.wired.com/feed/category/security/latest/rss"),
    _Feed("Ars Technica Security", "https://feeds.arstechnica.com/arstechnica/security"),
    _Feed("ZDNet Security", "https://www.zdnet.com/topic/security/rss.xml"),
    _Feed("TechCrunch Security", "https://techcrunch.com/category/security/feed/"),
    _Feed("Cyber Defense Magazine", "https://www.cyberdefensemagazine.com/feed/"),
    _Feed("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed_full.xml"),
    _Feed("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    _Feed("Google Security Blog", "https://security.googleblog.com/feeds/posts/default"),
    _Feed("Cisco Talos Intelligence", "https://blog.talosintelligence.com/rss/"),
    _Feed("Palo Alto Unit42", "https://unit42.paloaltonetworks.com/feed/"),
    _Feed("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/"),
    _Feed("Kaspersky Securelist", "https://securelist.com/feed/"),
    _Feed("ESET WeLiveSecurity", "https://www.welivesecurity.com/feed/"),
    _Feed("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml"),
    _Feed("Sophos News", "https://news.sophos.com/en-us/feed/"),
    _Feed("Fortinet FortiGuard Labs", "https://www.fortinet.com/blog/threat-research.rss"),
    _Feed("Check Point Research", "https://research.checkpoint.com/feed/"),
    _Feed("Trend Micro Research", "https://feeds.trendmicro.com/TrendMicroResearch"),
    _Feed("Rapid7 Blog", "https://www.rapid7.com/blog/rss.xml"),
    _Feed("Qualys Security Blog", "https://blog.qualys.com/feed"),
    _Feed("Tenable Blog", "https://www.tenable.com/blog/feed"),
    _Feed("Mandiant Blog", "https://www.mandiant.com/resources/blog/rss.xml"),
    _Feed("SentinelOne Labs", "https://www.sentinelone.com/blog/feed/"),
    _Feed("Recorded Future Blog", "https://www.recordedfuture.com/blog/feed/"),
    _Feed("GreyNoise Blog", "https://www.greynoise.io/blog/rss.xml"),
    _Feed("AttackIQ Blog", "https://www.attackiq.com/blog/feed/"),
    _Feed("Huntress Labs Blog", "https://www.huntress.com/blog/rss.xml"),
    _Feed("Binary Defense Blog", "https://www.binarydefense.com/blog/feed/"),
    _Feed("Secureworks Blog", "https://www.secureworks.com/blog/rss"),
    _Feed("Cybereason Blog", "https://www.cybereason.com/blog/rss.xml"),
    _Feed("Red Canary Blog", "https://redcanary.com/blog/feed/"),
    _Feed("Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml"),
    _Feed("Lumen Black Lotus Labs", "https://blog.lumen.com/category/black-lotus-labs/feed/"),
    _Feed("Team Cymru Blog", "https://team-cymru.com/blog/feed/"),
    _Feed("PortSwigger Research", "https://portswigger.net/research/rss"),
    _Feed("Tripwire State of Security", "https://www.tripwire.com/state-of-security/feed"),
    _Feed("US-CERT Alerts", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    _Feed("NCSC UK Alerts", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
    _Feed("ENISA News", "https://www.enisa.europa.eu/media/news-items/news-wires/RSS"),
    _Feed("CERT-EU Publications", "https://www.cert.europa.eu/publications/rss"),
    _Feed("Australian ASD ACSC", "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/rss"),
    _Feed("NIST NVD Recent CVEs", "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"),
    _Feed("AWS Security Blog", "https://aws.amazon.com/blogs/security/feed/"),
    _Feed("Azure Security Blog", "https://techcommunity.microsoft.com/gxcuf89792/rss/board?board.id=AzureSecurityBlog"),
    _Feed("Google Cloud Security Blog", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    _Feed("Snyk Security Blog", "https://snyk.io/blog/category/security/feed/"),
    _Feed("Aqua Security Blog", "https://www.aquasec.com/blog/feed/"),
    _Feed("Lacework Blog", "https://www.lacework.com/blog/feed/"),
    _Feed("Sysdig Blog", "https://sysdig.com/blog/feed/"),
    _Feed("MITRE ATT&CK Blog", "https://medium.com/feed/mitre-attack"),
    _Feed("OWASP Blog", "https://owasp.org/feed.xml"),
    _Feed("Protect AI Blog", "https://protectai.com/blog/rss.xml"),
    _Feed("HiddenLayer Blog", "https://hiddenlayer.com/research/feed/"),
    _Feed("LLM Security News", "https://llmsecurity.net/index.xml"),
    _Feed("Reddit r/netsec", "https://www.reddit.com/r/netsec/.rss"),
    _Feed("Reddit r/cybersecurity", "https://www.reddit.com/r/cybersecurity/.rss"),
    _Feed("Full Disclosure", "https://seclists.org/rss/fulldisclosure.rss"),
    _Feed("Packet Storm Security", "https://packetstormsecurity.com/headlines.xml"),
    _Feed("Exploit-DB RSS", "https://www.exploit-db.com/rss.xml"),
    _Feed("VulnHub Blog", "https://www.vulnhub.com/rss/blog/"),
    _Feed("NCC Group Research", "https://research.nccgroup.com/feed/"),
    _Feed("WithSecure Labs", "https://labs.withsecure.com/feed/"),
    _Feed("Bugcrowd Blog", "https://www.bugcrowd.com/blog/feed/"),
    _Feed("HackerOne Blog", "https://www.hackerone.com/resources/hackerone/feed"),
)


class GlobalRSSAggregator:
    """Fetches breaking cybersecurity news from 25+ global publishers in parallel."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def discover(self, state: PublicationState) -> list[DiscoveredArticle]:
        """Return new DiscoveredArticle entries gathered from all global feeds."""
        articles: list[DiscoveredArticle] = []
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            futures = {executor.submit(self._fetch_feed, feed): feed for feed in _GLOBAL_FEEDS}
            for future in as_completed(futures):
                feed = futures[future]
                try:
                    items = future.result()
                except Exception as e:
                    logger.warning("Global feed failed", extra={"feed": feed.name, "error": str(e)})
                    continue
                for item in items:
                    article = self._to_article(feed, item, state)
                    if article is not None:
                        articles.append(article)
        logger.info("Global RSS aggregation complete", extra={"feeds_polled": len(_GLOBAL_FEEDS), "new_articles": len(articles)})
        return articles

    def _fetch_feed(self, feed: _Feed) -> list[dict]:
        """Fetch and parse a feed, retrying one transient network/server failure."""
        resp = None
        for attempt in range(1, _MAX_FETCH_ATTEMPTS + 1):
            try:
                resp = requests.get(feed.url, timeout=_FEED_TIMEOUT_SECONDS, headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0"})
            except Exception as e:
                if attempt < _MAX_FETCH_ATTEMPTS:
                    logger.info("Retrying transient feed failure", extra={"feed": feed.name, "attempt": attempt, "error": str(e)})
                    continue
                logger.warning("Feed fetch failed", extra={"feed": feed.name, "error": str(e)})
                return []

            if resp.status_code in _RETRYABLE_STATUS_CODES:
                if attempt < _MAX_FETCH_ATTEMPTS:
                    logger.info("Retrying transient feed response", extra={"feed": feed.name, "status": resp.status_code, "attempt": attempt})
                    continue
                logger.warning("Feed fetch failed after transient retry", extra={"feed": feed.name, "status": resp.status_code})
                return []

            try:
                resp.raise_for_status()
            except Exception as e:
                logger.warning("Feed fetch failed", extra={"feed": feed.name, "error": str(e)})
                return []
            break

        if resp is None:
            return []
        try:
            items = _parse_feed_items(resp.text)
        except Exception as e:
            logger.warning("Feed parse failed", extra={"feed": feed.name, "error": str(e)})
            return []
        return items[:_MAX_ITEMS_PER_FEED]

    def _to_article(self, feed: _Feed, item: dict, state: PublicationState) -> Optional[DiscoveredArticle]:
        url = item.get("url", "")
        title = item.get("title", "")
        if not url or not title:
            return None
        pub_date = _parse_rfc_date(item.get("pub_date", ""))
        if not _is_recent(pub_date, self.config.max_article_age_hours):
            return None
        content_hash = _compute_hash(url, title)
        if state.is_published(content_hash):
            return None
        summary = item.get("summary", "")
        labels = _infer_labels(title, summary)
        for required_label in ["CYBERDUDEBIVASH", "Threat Intelligence", "Global Intel"]:
            if required_label not in labels:
                labels.append(required_label)
        pub_iso = pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()
        full_content = f"Source Publisher: {feed.name}\nOriginal Article: {url}\n\n{summary}"
        return DiscoveredArticle(url=url, title=title, summary=summary, published_at=pub_iso, content_hash=content_hash, labels=labels, source="global_rss", full_content=full_content, source_publisher=feed.name)
