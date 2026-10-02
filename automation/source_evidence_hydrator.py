"""P0 selected-source evidence hydration for the Blogger premium factory.

The external RSS layer already preserves publisher-supplied full feed bodies
when available (premium_source_rss_v15). Some curated feeds expose only a short
preview, however. Those candidates reach the premium generator with too little
raw evidence for the unchanged 2,200/18/18 long-form gate.

This module performs a *bounded, selected-candidate-only* fetch of the exact
publisher article URL already supplied by the curated RSS feed. It is not a
crawler and never expands discovery. At most the finite publication-attempt
set can be hydrated. The fetch is fail-open for availability and fail-closed
for destination safety:

- http/https only;
- localhost, literal private/special IPs, and DNS resolutions to private/special
  addresses are rejected;
- redirects are followed manually and revalidated, max 3;
- response size and wall-clock timeout are bounded;
- only HTML/XHTML is accepted;
- active/script/navigation chrome is removed;
- evidence is adopted only when it is materially richer than the feed body.

No publication/evidence gate is lowered and no generated prose becomes source
material.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from .content_discovery import DiscoveredArticle
from .logger import setup_logger

logger = setup_logger("source_evidence_hydrator")

MARKER = "CDB-SELECTED-SOURCE-EVIDENCE-HYDRATION-P0"
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 512_000
MAX_SOURCE_CHARS = 24_000
CONNECT_TIMEOUT_SECONDS = 3.05
READ_TIMEOUT_SECONDS = 7
MIN_RICHER_WORD_GAIN = 120
HYDRATE_BELOW_SOURCE_WORDS = 1800

_RUNTIME = {
    "eligible": 0,
    "attempted": 0,
    "adopted": 0,
    "rejected_destination": 0,
    "transport_failed": 0,
    "non_html": 0,
    "not_richer": 0,
    "bytes_read": 0,
}


@dataclass(frozen=True)
class HydrationResult:
    attempted: bool
    adopted: bool
    reason: str
    before_words: int
    after_words: int


def _plain_words(value: str) -> list[str]:
    soup = BeautifulSoup(value or "", "lxml")
    return [part for part in soup.get_text(" ", strip=True).split() if part]


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_global)


def _validate_public_destination(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host or host == "localhost" or host.endswith(".local"):
        return False

    # Literal IP: require globally routable.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return _public_ip(host)

    # Curated RSS is trusted as a source list, but article links are still
    # untrusted input. Resolve every hostname and reject if any address is not
    # globally routable, preventing private/link-local/loopback SSRF.
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError:
        return False
    addresses = {item[4][0] for item in infos if item and item[4]}
    return bool(addresses) and all(_public_ip(address) for address in addresses)


def _bounded_get_html(url: str) -> Optional[str]:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        if not _validate_public_destination(current):
            _RUNTIME["rejected_destination"] += 1
            return None
        try:
            response = requests.get(
                current,
                timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
                headers={
                    "User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0",
                    "Accept": "text/html,application/xhtml+xml;q=0.9",
                },
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException:
            _RUNTIME["transport_failed"] += 1
            return None

        if response.status_code in {301, 302, 303, 307, 308}:
            location = str(response.headers.get("Location") or "").strip()
            response.close()
            if not location:
                _RUNTIME["transport_failed"] += 1
                return None
            current = urljoin(current, location)
            continue

        if response.status_code != 200:
            response.close()
            _RUNTIME["transport_failed"] += 1
            return None

        content_type = str(response.headers.get("Content-Type") or "").lower()
        if content_type and "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            response.close()
            _RUNTIME["non_html"] += 1
            return None

        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=16_384):
                if not chunk:
                    continue
                remaining = MAX_RESPONSE_BYTES - total
                if remaining <= 0:
                    break
                piece = chunk[:remaining]
                chunks.append(piece)
                total += len(piece)
                if total >= MAX_RESPONSE_BYTES:
                    break
        finally:
            response.close()
        _RUNTIME["bytes_read"] += total
        encoding = response.encoding or "utf-8"
        return b"".join(chunks).decode(encoding, errors="replace")
    _RUNTIME["transport_failed"] += 1
    return None


def _extract_article_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "lxml")
    for node in soup(["script", "style", "noscript", "iframe", "object", "embed", "form", "nav", "footer", "header"]):
        node.decompose()

    selectors = (
        "article",
        "main",
        "[role='main']",
        ".article-body",
        ".article-content",
        ".post-content",
        ".entry-content",
    )
    candidates: list[str] = []
    for selector in selectors:
        for node in soup.select(selector):
            text = "\n".join(line.strip() for line in node.get_text("\n", strip=True).splitlines() if line.strip())
            if text:
                candidates.append(text)

    if not candidates and soup.body is not None:
        candidates.append("\n".join(
            line.strip() for line in soup.body.get_text("\n", strip=True).splitlines() if line.strip()
        ))
    if not candidates:
        return ""

    text = max(candidates, key=lambda value: len(_plain_words(value)))
    if len(text) <= MAX_SOURCE_CHARS:
        return text
    clipped = text[:MAX_SOURCE_CHARS].rstrip()
    boundary = clipped.rfind(" ")
    if boundary >= int(MAX_SOURCE_CHARS * 0.90):
        clipped = clipped[:boundary].rstrip()
    return clipped + "..."


def hydrate_selected_article(article: DiscoveredArticle) -> HydrationResult:
    """Hydrate one selected global-RSS candidate with its own publisher page."""
    before = len(_plain_words(str(article.full_content or article.summary or "")))
    if str(article.source or "") != "global_rss" or before >= HYDRATE_BELOW_SOURCE_WORDS:
        return HydrationResult(False, False, "not_eligible", before, before)

    _RUNTIME["eligible"] += 1
    _RUNTIME["attempted"] += 1
    html = _bounded_get_html(str(article.url or ""))
    if not html:
        return HydrationResult(True, False, "fetch_unavailable", before, before)

    body = _extract_article_text(html)
    after = len(_plain_words(body))
    if after < before + MIN_RICHER_WORD_GAIN:
        _RUNTIME["not_richer"] += 1
        return HydrationResult(True, False, "not_materially_richer", before, after)

    article.full_content = (
        f"Source Publisher: {article.source_publisher or 'curated RSS publisher'}\n"
        f"Original Article: {article.url}\n"
        "Evidence Capture: publisher article page (selected-candidate hydration)\n\n"
        f"{body}"
    )
    _RUNTIME["adopted"] += 1
    logger.info(
        "Selected RSS source evidence hydrated",
        extra={
            "publisher": article.source_publisher,
            "before_words": before,
            "after_words": after,
        },
    )
    return HydrationResult(True, True, "adopted", before, after)


def telemetry_snapshot() -> dict:
    return {
        "marker": MARKER,
        "new_network_requests_are_selected_only": True,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "max_source_chars": MAX_SOURCE_CHARS,
        **{key: int(value) for key, value in _RUNTIME.items()},
    }
