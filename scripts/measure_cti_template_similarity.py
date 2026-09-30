#!/usr/bin/env python3
"""Measure template/boilerplate overlap across live CTI (Blogger) posts.

Supports the CTI search-visibility incident (issue #219): quantifies how much
of each sampled post body is shared with other posts, so recovery work is
measured rather than assumed. Stdlib only; read-only HTTP GETs.

Metrics (word 6-gram shingles over the post body, scripts/styles removed):
  containment(a, b) = |S(a) & S(b)| / min(|S(a)|, |S(b)|)   pairwise
  boilerplate_share = share of a post's shingles present in >= 75% of sample

Usage:
  python3 scripts/measure_cti_template_similarity.py --page 1 --sample 8 --seed 11 [--json]
Exit code 0 always (measurement tool, not a gate).
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import re
import statistics
from collections import Counter
from urllib.request import Request, urlopen

SITEMAP = "https://cti.cyberdudebivash.in/sitemap.xml?page={page}"
UA = "Mozilla/5.0 (compatible; SentinelApexSEOAudit/1.0)"


def fetch(url: str, timeout: int = 25) -> str:
    with urlopen(Request(url, headers={"User-Agent": UA}), timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def post_words(html: str) -> list[str]:
    m = re.search(r"(?s)<div[^>]*class=['\"][^'\"]*post-body[^'\"]*['\"][^>]*>(.*?)<div[^>]*class=['\"][^'\"]*post-footer", html)
    body = m.group(1) if m else html
    body = re.sub(r"(?s)<(script|style)[^>]*>.*?</\1>", " ", body)
    text = re.sub(r"&[a-z#0-9]+;", " ", re.sub(r"<[^>]+>", " ", body))
    return [w.lower() for w in re.findall(r"[A-Za-z]{2,}", text)]


def shingles(words: list[str], k: int = 6) -> set[tuple[str, ...]]:
    return {tuple(words[i:i + k]) for i in range(max(0, len(words) - k + 1))}


def measure(urls: list[str], fetcher=fetch) -> dict:
    sets = {u: shingles(post_words(fetcher(u))) for u in urls}
    pairs = [len(sets[a] & sets[b]) / min(len(sets[a]), len(sets[b]))
             for a, b in itertools.combinations(urls, 2) if sets[a] and sets[b]]
    counts = Counter(s for u in urls for s in sets[u])
    floor = max(2, int(0.75 * len(urls)))
    common = {s for s, n in counts.items() if n >= floor}
    return {
        "sample_size": len(urls),
        "pairwise_containment": {
            "min": round(min(pairs), 2) if pairs else None,
            "median": round(statistics.median(pairs), 2) if pairs else None,
            "max": round(max(pairs), 2) if pairs else None,
        },
        "posts": [{"url": u, "shingles": len(sets[u]),
                   "boilerplate_share": round(len(sets[u] & common) / max(1, len(sets[u])), 2)} for u in urls],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--page", type=int, default=1)
    ap.add_argument("--sample", type=int, default=8)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    locs = re.findall(r"<loc>([^<]+)</loc>", fetch(SITEMAP.format(page=a.page)))
    random.seed(a.seed)
    result = measure(random.sample(locs, min(a.sample, len(locs))))
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        pc = result["pairwise_containment"]
        print(f"pairwise 6-gram containment min {pc['min']} median {pc['median']} max {pc['max']}")
        for p in result["posts"]:
            print(f"  boilerplate {p['boilerplate_share']:.2f}  {p['url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
