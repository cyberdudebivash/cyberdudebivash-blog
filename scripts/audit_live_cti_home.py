#!/usr/bin/env python3
"""Fail-closed audit for the public CTI Blogger homepage.

This tool intentionally audits the *live rendered homepage*, not historical XML
exports in blogger-theme/.  The production theme is controlled in Blogger and
has previously drifted from all stored exports.

Exit codes:
  0 = no blocking trust/freshness/identity findings
  1 = one or more blocking findings
  2 = fetch/audit execution failure

The evidence rules are deliberately narrow.  They target known placeholder or
unsupported public claims observed during the 2026-09-22 Search Console
recovery incident.  A claim can be reintroduced only after the public surface
has a real data source/provenance contract and this guard is updated in the
same reviewed change.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from typing import Iterable
from urllib.request import Request, urlopen

DEFAULT_URL = "https://cti.cyberdudebivash.in/"
DEFAULT_MAX_FRESHNESS_DAYS = 14


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data and data.strip():
            self.parts.append(data.strip())

    def text(self) -> str:
        return " ".join(self.parts)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    evidence: str = ""


# These are production trust blockers unless/until each is backed by a real
# telemetry/evidence contract.  Do not silently weaken this list to make a
# failing homepage pass.
BLOCKED_PUBLIC_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("placeholder_pgp", r"mQGNBF\+1234BCDEF", "Placeholder PGP key material is public."),
    ("placeholder_pgp_id", r"4096R/BIVASH_NAYAK", "Placeholder-looking PGP key id is public."),
    ("managed_tenant_claim", r"\b142\s+Tenants\b", "Unproven managed-tenant count is public."),
    ("financial_risk_claim", r"\$2\.4M\b", "Unproven financial-risk exposure metric is public."),
    ("insured_coverage_claim", r"Insured\s+Coverage\s*:\s*100%", "Unproven insurance coverage claim is public."),
    ("platform_uptime_claim", r"Platform\s+Status\s*:\s*99\.99%\s+ONLINE", "Unproven uptime/SLA claim is public."),
    ("tenant_health_claim", r"Global\s+Tenant\s+Health\s+99\.98%", "Unproven tenant-health claim is public."),
    ("soc2_type2_claim", r"SOC\s*2\s*Type\s*II", "SOC 2 Type II wording requires audit evidence."),
    ("indicator_count_claim", r"Real-time\s+Indicators\s*:\s*142,890\+", "Unproven real-time indicator count is public."),
    ("board_sla_claim", r"Board\s+SLA\s+Compliance\s+99\.4%", "Unproven board SLA metric is public."),
)

_CUSTOM_DOMAIN = "https://cti.cyberdudebivash.in/"
_BLOGSPOT_IDENTITY_RE = re.compile(
    r"https://cyberbivash\.blogspot\.com/?(?:#website)?",
    re.IGNORECASE,
)

_DATE_PATTERNS = (
    # Saturday, 8 August 2026 / 8 August 2026
    re.compile(
        r"(?:(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),\s*)?"
        r"(\d{1,2})\s+"
        r"(January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+(20\d{2})",
        re.IGNORECASE,
    ),
    # August 8, 2026
    re.compile(
        r"(January|February|March|April|May|June|July|August|September|October|November|December)"
        r"\s+(\d{1,2}),\s+(20\d{2})",
        re.IGNORECASE,
    ),
)


def _fetch(url: str, timeout: int) -> str:
    req = Request(
        url,
        headers={
            "User-Agent": "CYBERDUDEBIVASH-Production-Trust-Audit/1.0",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    with urlopen(req, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        if status != 200:
            raise RuntimeError(f"{url} returned HTTP {status}")
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def _visible_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    return unescape(parser.text())


def _parse_dates(text: str) -> list[datetime]:
    dates: set[datetime] = set()
    for index, pattern in enumerate(_DATE_PATTERNS):
        for match in pattern.finditer(text):
            if index == 0:
                day, month_name, year = match.groups()
            else:
                month_name, day, year = match.groups()
            try:
                parsed = datetime.strptime(
                    f"{day} {month_name.title()} {year}",
                    "%d %B %Y",
                ).replace(tzinfo=timezone.utc)
                dates.add(parsed)
            except ValueError:
                continue
    return sorted(dates)


def audit_html(
    html: str,
    *,
    now: datetime | None = None,
    max_freshness_days: int = DEFAULT_MAX_FRESHNESS_DAYS,
) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    text = _visible_text(html)
    findings: list[Finding] = []

    for code, pattern, message in BLOCKED_PUBLIC_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            findings.append(
                Finding(
                    code=code,
                    severity="BLOCK",
                    message=message,
                    evidence=match.group(0),
                )
            )

    # Canonical custom-domain identity is mandatory.
    canonical_match = re.search(
        r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    if not canonical_match:
        # Attribute order can be reversed.
        canonical_match = re.search(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']canonical["\']',
            html,
            re.IGNORECASE,
        )
    if not canonical_match:
        findings.append(
            Finding(
                code="canonical_missing",
                severity="BLOCK",
                message="Live homepage has no canonical link.",
            )
        )
    elif not canonical_match.group(1).startswith(_CUSTOM_DOMAIN):
        findings.append(
            Finding(
                code="canonical_wrong_host",
                severity="BLOCK",
                message="Canonical does not use the CTI custom domain.",
                evidence=canonical_match.group(1),
            )
        )

    # The theme-level WebSite JSON-LD must not identify Blogspot as the public
    # canonical site.  Other Blogger platform metadata may legitimately mention
    # blogspot.com, so target the exact historical public-identity leak.
    leak = _BLOGSPOT_IDENTITY_RE.search(html)
    if leak:
        findings.append(
            Finding(
                code="blogspot_public_identity",
                severity="BLOCK",
                message="Live theme still exposes the underlying Blogspot host as site identity.",
                evidence=leak.group(0),
            )
        )

    dates = _parse_dates(text)
    if dates:
        newest = dates[-1]
        age_days = (now - newest).total_seconds() / 86400
        if age_days > max_freshness_days:
            findings.append(
                Finding(
                    code="homepage_freshness",
                    severity="BLOCK",
                    message=(
                        f"Newest parseable homepage publication date is {age_days:.1f} "
                        f"days old; limit is {max_freshness_days} days."
                    ),
                    evidence=newest.date().isoformat(),
                )
            )
    else:
        findings.append(
            Finding(
                code="homepage_freshness_unknown",
                severity="WARN",
                message="No parseable publication date was found on the homepage.",
            )
        )

    return findings


def _print_human(findings: Iterable[Finding], url: str) -> None:
    findings = list(findings)
    print(f"CTI live audit: {url}")
    if not findings:
        print("PASS: no proof-first/freshness/identity findings.")
        return
    for item in findings:
        suffix = f" | evidence={item.evidence!r}" if item.evidence else ""
        print(f"{item.severity}: {item.code}: {item.message}{suffix}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-freshness-days", type=int, default=DEFAULT_MAX_FRESHNESS_DAYS)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    try:
        html = _fetch(args.url, args.timeout)
        findings = audit_html(
            html,
            max_freshness_days=max(1, args.max_freshness_days),
        )
    except Exception as exc:
        if args.as_json:
            print(json.dumps({"url": args.url, "error": str(exc)}, indent=2))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    blockers = [item for item in findings if item.severity == "BLOCK"]
    if args.as_json:
        print(
            json.dumps(
                {
                    "url": args.url,
                    "status": "FAIL" if blockers else "PASS",
                    "blockers": len(blockers),
                    "findings": [asdict(item) for item in findings],
                },
                indent=2,
            )
        )
    else:
        _print_human(findings, args.url)

    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
