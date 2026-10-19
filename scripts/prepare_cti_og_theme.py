#!/usr/bin/env python3
"""Prepare the ACTUAL exported Blogger theme for SENTINEL APEX OG image cutover.

Source: operator-exported current theme, never stale repository v22/v23/v24.
Output: separate XML candidate, before/after SHA256, and short diff.
Does NOT publish/overwrite Blogger or modify unrelated post content.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

DEFAULT_URL = "https://blog.cyberdudebivash.in/og-sentinel-apex-threat-intel-v1.jpg"
META = re.compile(r"<meta\b[^>]*>", flags=re.IGNORECASE)
PROP = re.compile(r"""(?:property|name)\s*=\s*(['"])(.*?)\1""", flags=re.IGNORECASE)
CONTENT_ATTR = re.compile(r"""\s+(?:expr:content|content)\s*=\s*(['"]).*?\1""", flags=re.IGNORECASE | re.DOTALL)
SCHEMES = {"http", "https"}
SOCIAL = {
    "og:image": "image",
    "og:image:secure_url": "image",
    "twitter:image": "image",
    "og:image:type": "image/jpeg",
    "og:image:width": "1200",
    "og:image:height": "630",
    "og:image:alt": "SENTINEL APEX Threat Intel Platform — global cyber threat intelligence",
    "twitter:image:alt": "SENTINEL APEX Threat Intel Platform — global cyber threat intelligence",
}

def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def prepare_current_theme(xml: str, url: str = DEFAULT_URL) -> tuple[str, dict]:
    """Replace only OG image meta tags inside Blogger theme's HTML <head>."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "blog.cyberdudebivash.in" or not parsed.path.endswith(".jpg"):
        raise ValueError("Image must use the exact HTTPS blog-domain JPG asset")
    if len(xml) < 1500 or "<html" not in xml or "</html>" not in xml:
        raise ValueError("Input is not a complete exported Blogger theme")
    head = re.search(r"<head(?:\s[^>]*)?>", xml, flags=re.IGNORECASE)
    end = re.search(r"</head\s*>", xml, flags=re.IGNORECASE)
    if not head or not end or head.end() >= end.start():
        raise ValueError("Cannot unambiguously locate complete theme head")
    before = xml[head.end():end.start()]
    counters: dict[str, int] = {}
    def replace_meta(m: re.Match[str]) -> str:
        tag = m.group(0)
        attrs = list(PROP.finditer(tag))
        key = next((a.group(2).strip().lower() for a in attrs if a.group(2).strip().lower() in SOCIAL), None)
        if key is None:
            return tag
        counters[key] = counters.get(key, 0) + 1
        newval = url if SOCIAL[key] == "image" else SOCIAL[key]
        if CONTENT_ATTR.search(tag):
            tag = CONTENT_ATTR.sub("", tag)
        # Keep property/name selector, move literal content to a safe XML attr.
        terminator = "/>" if tag.endswith("/>") else ">"
        return tag[:-len(terminator)] + " content='" + newval + "'" + terminator
    after = META.sub(replace_meta, before)
    if counters.get("og:image", 0) < 1 or counters.get("twitter:image", 0) < 1:
        raise ValueError("Active theme OG/Twitter image tags absent or unfamiliar; do not guess")
    if counters["og:image"] > 5 or counters["twitter:image"] > 5:
        raise ValueError("Unusually many OG/Twitter image tags; manually review before changing")
    # Every branch containing the previous post image now points to one hosted
    # brand image; Blogger's first-image post metadata is no longer authoritative.
    if re.search(r"""<meta\b[^>]*(?:property|name)\s*=\s*['"](?:og:image|twitter:image)['"][^>]*expr:content""", after, re.I):
        raise ValueError("Unreplaced dynamic OG image in theme")
    additions = []
    for key in ("og:image:secure_url", "og:image:type", "og:image:width", "og:image:height", "og:image:alt", "twitter:image:alt"):
        if not counters.get(key):
            val = url if SOCIAL[key] == "image" else SOCIAL[key]
            attr = "name" if key.startswith("twitter:") else "property"
            additions.append(f"<meta {attr}='{key}' content='{val}'/>")
    if additions:
        after += "\n<!-- CTI social card metadata: dimensions and accessible text -->\n" + "\n".join(additions) + "\n"
    result = xml[:head.end()] + after + xml[end.start():]
    return result, {"replaced": counters, "appended": [m.split("'")[1] for m in additions], "og_url": url}

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--current", type=Path, required=True, help="Export of live Blogger theme via Theme > Backup")
    ap.add_argument("--candidate", type=Path, required=True, help="Separate output XML (will not overwrite)")
    ap.add_argument("--url", default=DEFAULT_URL)
    args = ap.parse_args(argv)
    if not args.current.is_file() or args.current.resolve() == args.candidate.resolve():
        ap.error("A current theme export and a separate candidate file are required")
    if args.candidate.exists():
        ap.error("Candidate file already exists; refusing overwrite")
    raw = args.current.read_bytes()
    data = raw.decode("utf-8-sig")
    changed, details = prepare_current_theme(data, args.url)
    if data == changed:
        ap.error("No change occurred; do not publish a no-op")
    args.candidate.parent.mkdir(parents=True, exist_ok=True)
    args.candidate.write_text(changed, encoding="utf-8")
    srcsha, dstsha = checksum(raw), checksum(args.candidate.read_bytes())
    sha_path = args.candidate.with_suffix(".sha256")
    if sha_path.exists():
        ap.error("Refusing to overwrite existing checksum")
    sha_path.write_text(dstsha + "  " + args.candidate.name + "\n", encoding="utf-8")
    print("SOURCE_SHA256=" + srcsha)
    print("CANDIDATE_SHA256=" + dstsha)
    print("CANDIDATE=" + str(args.candidate))
    print("REPLACED=" + repr(details["replaced"]))
    diff = list(difflib.unified_diff(data.splitlines(), changed.splitlines(), fromfile="exported-live", tofile="candidate", lineterm=""))
    print("\n".join(diff[:160]))
    print("IMPORTANT: Upload via Blogger Theme editor only after verifying hosted asset and reviewing this diff.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
