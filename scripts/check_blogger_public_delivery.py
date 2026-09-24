#!/usr/bin/env python3
"""Read-only public Blogger delivery probe; never dispatches publication."""
import argparse
import json
import time
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from check_blogger_publication_freshness import evaluate_blogger_freshness

BASE = "https://cti.cyberdudebivash.in"
MAX_BYTES = 4 * 1024 * 1024


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.paths = set()

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href", "")
        parsed = urlsplit(href)
        if not parsed.netloc or parsed.hostname == urlsplit(BASE).hostname:
            self.paths.add(parsed.path)


class ProbeTransportError(RuntimeError):
    def __init__(self, endpoint, reason, attempts, http_status=None):
        super().__init__(reason)
        self.endpoint = endpoint
        self.reason = reason
        self.attempts = attempts
        self.http_status = http_status


def retry_delay(value, attempt, now=None):
    """Honor Retry-After; never shorten a provider delay to fit our budget."""
    fallback = 5 * (2 ** (attempt - 1))
    if value is None:
        return fallback
    try:
        delay = int(value)
    except (ValueError, TypeError):
        try:
            target = parsedate_to_datetime(value)
            if target.tzinfo is None:
                return fallback
            delay = (target - (now or datetime.now(timezone.utc))).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return fallback
    return max(1, delay)


def fetch(url, endpoint="public"):
    for attempt in range(1, 4):
        request = Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "CDB-Public-Delivery-Monitor/1.0"})
        try:
            with urlopen(request, timeout=15) as response:
                if urlsplit(response.url).hostname != urlsplit(BASE).hostname:
                    raise ProbeTransportError(endpoint, "unexpected_redirect_host", attempt)
                body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise ProbeTransportError(endpoint, "response_size_limit", attempt)
                return body.decode("utf-8-sig")
        except HTTPError as exc:
            status = exc.code
            delay = retry_delay(exc.headers.get("Retry-After") if exc.headers else None, attempt)
            exc.close()
            if status not in (429, 502, 503, 504):
                raise ProbeTransportError(endpoint, "http_error", attempt, status) from None
            if attempt == 3 or delay > 60:
                reason = "retry_after_exceeds_budget" if delay > 60 else "retries_exhausted"
                raise ProbeTransportError(endpoint, reason, attempt, status) from None
            time.sleep(delay)
        except (URLError, TimeoutError) as exc:
            if attempt == 3:
                raise ProbeTransportError(endpoint, "network_retries_exhausted", attempt) from None
            time.sleep(5 * (2 ** (attempt - 1)))


def evaluate(feed, desktop, mobile, now=None):
    entries = feed.get("feed", {}).get("entry", [])
    if not isinstance(entries, list) or not entries:
        raise ValueError("empty_or_invalid_public_feed")
    parsed = []
    for entry in entries:
        stamp = entry["published"]["$t"]
        date = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if date.tzinfo is None:
            raise ValueError("publication_timezone_missing")
        parsed.append((date, entry))
    newest = max(parsed, key=lambda pair: pair[0])[1]
    post_url = next((link["href"] for link in newest.get("link", []) if link.get("rel") == "alternate"), "")
    url = urlsplit(post_url)
    if url.scheme != "https" or url.hostname != urlsplit(BASE).hostname or not url.path.endswith(".html"):
        raise ValueError("invalid_public_permalink")
    result = evaluate_blogger_freshness({"posts": [{"published_at": newest["published"]["$t"]}]}, now=now)
    result.update({"post_id": newest.get("id", {}).get("$t"), "permalink": post_url, "checked_at": (now or datetime.now(timezone.utc)).isoformat()})
    for label, document in (("desktop", desktop), ("mobile", mobile)):
        links = Links()
        links.feed(document)
        visible = url.path in links.paths
        result[label + "_linked"] = visible
        if not visible:
            result["defects"].append(label + "_missing_latest_permalink")
    # A delivery defect cannot be repaired safely by repeatedly publishing.
    result["recovery_required"] = False
    if result["defects"]:
        result["status"] = "BLOGGER_PUBLIC_DELIVERY_ERROR"
        result["exit_code"] = 1
    return result


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        feed = json.loads(fetch(BASE + "/feeds/posts/summary?alt=json&max-results=5&orderby=published", "feed"))
        result = evaluate(feed, fetch(BASE + "/", "desktop"), fetch(BASE + "/?m=1", "mobile"))
    except ProbeTransportError as exc:
        result = {"status": "BLOGGER_PUBLIC_RATE_LIMITED" if exc.http_status == 429 else "BLOGGER_PUBLIC_PROBE_ERROR",
                  "exit_code": 1, "recovery_required": False, "endpoint": exc.endpoint,
                  "http_status": exc.http_status, "attempts": exc.attempts, "defects": [exc.reason]}
    except Exception as exc:
        result = {"status": "BLOGGER_PUBLIC_PROBE_ERROR", "exit_code": 1, "recovery_required": False, "defects": [type(exc).__name__ + ":" + str(exc)[:200]]}
    print(json.dumps(result, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())

