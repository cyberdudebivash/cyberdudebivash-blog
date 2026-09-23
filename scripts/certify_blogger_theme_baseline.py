#!/usr/bin/env python3
"""Fail-closed certifier for the authoritative live Blogger theme export.

This script does not deploy or mutate Blogger. It certifies the exact dashboard
export that an operator has committed as blogger-theme/production-current.xml.

Release invariants:
- an immutable SHA-256 accompanies the export;
- known placeholder/unverifiable trust claims are absent;
- placeholder PGP material is absent;
- the customer-facing WebSite JSON-LD identifies cti.cyberdudebivash.in;
- the underlying Blogspot host is not used as the WebSite public identity.

Exit codes:
  0 = baseline certified
  1 = baseline exists but violates a release invariant
  2 = baseline/checksum cannot be read or parsed
"""

from __future__ import annotations

import argparse
import hashlib
import html as html_module
import json
import re
import sys
from pathlib import Path
from typing import Any

DEFAULT_THEME = Path("blogger-theme/production-current.xml")
DEFAULT_CHECKSUM = Path("blogger-theme/production-current.sha256")
PUBLIC_CTI = "https://cti.cyberdudebivash.in/"
BLOGSPOT = "https://cyberbivash.blogspot.com"

BLOCKED_PATTERNS: tuple[tuple[str, str], ...] = (
    ("placeholder_pgp", r"mQGNBF\+1234BCDEF"),
    ("placeholder_pgp_id", r"4096R/BIVASH_NAYAK"),
    ("managed_tenant_claim", r"\b142\s+Tenants\b"),
    ("financial_risk_claim", r"\$2\.4M\b"),
    ("insured_coverage_claim", r"Insured\s+Coverage\s*:\s*100%"),
    ("platform_uptime_claim", r"Platform\s+Status\s*:\s*99\.99%\s+ONLINE"),
    ("tenant_health_claim", r"Global\s+Tenant\s+Health\s+99\.98%"),
    ("indicator_count_claim", r"Real-time\s+Indicators\s*:\s*142,890\+"),
    ("board_sla_claim", r"Board\s+SLA\s+Compliance\s+99\.4%"),
    ("cyber_insurance_score_claim", r"Cyber\s+Insurance\s+Score\s+94/100"),
    ("soc2_type2_claim", r"SOC\s*2\s*Type\s*II"),
)

SCRIPT_RE = re.compile(
    r"<script\b[^>]*type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
WEBSITE_TYPE_RE = re.compile(
    r"[\"']?@type[\"']?\s*:\s*[\"']WebSite[\"']",
    re.IGNORECASE,
)


def _expected_sha256(path: Path) -> str:
    raw = path.read_text(encoding="utf-8").strip()
    match = re.search(r"\b([0-9a-fA-F]{64})\b", raw)
    if not match:
        raise ValueError("checksum file does not contain a SHA-256 digest")
    return match.group(1).lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _website_jsonld_blocks(theme_text: str) -> list[str]:
    normalized = html_module.unescape(theme_text)
    blocks: list[str] = []
    for match in SCRIPT_RE.finditer(normalized):
        block = match.group(1)
        if WEBSITE_TYPE_RE.search(block):
            blocks.append(block)
    return blocks


def certify_theme(theme_text: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    for code, pattern in BLOCKED_PATTERNS:
        match = re.search(pattern, theme_text, re.IGNORECASE)
        if match:
            findings.append(
                {
                    "code": code,
                    "message": "Known unsupported/placeholder public trust claim remains in the live theme baseline.",
                    "evidence": match.group(0),
                }
            )

    website_blocks = _website_jsonld_blocks(theme_text)
    if not website_blocks:
        findings.append(
            {
                "code": "website_jsonld_missing",
                "message": "No explicit WebSite JSON-LD block was found in the authoritative theme export.",
                "evidence": "",
            }
        )
    else:
        if not any(PUBLIC_CTI.rstrip("/") in block for block in website_blocks):
            findings.append(
                {
                    "code": "website_jsonld_custom_domain_missing",
                    "message": "WebSite JSON-LD does not explicitly identify the CTI custom domain.",
                    "evidence": "",
                }
            )
        if any(BLOGSPOT in block for block in website_blocks):
            findings.append(
                {
                    "code": "website_jsonld_blogspot_identity",
                    "message": "Underlying Blogspot host is still exposed as WebSite public identity.",
                    "evidence": BLOGSPOT,
                }
            )

    return {
        "status": "PASS" if not findings else "FAIL",
        "findings": findings,
        "website_jsonld_blocks": len(website_blocks),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--theme", type=Path, default=DEFAULT_THEME)
    parser.add_argument("--checksum", type=Path, default=DEFAULT_CHECKSUM)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        if not args.theme.is_file():
            raise FileNotFoundError(f"authoritative live theme baseline missing: {args.theme}")
        if not args.checksum.is_file():
            raise FileNotFoundError(f"theme checksum missing: {args.checksum}")
        expected = _expected_sha256(args.checksum)
        actual = _sha256(args.theme)
        text = args.theme.read_text(encoding="utf-8")
    except Exception as exc:
        result = {
            "status": "BASELINE_ERROR",
            "theme": str(args.theme),
            "checksum": str(args.checksum),
            "error": str(exc),
        }
        print(json.dumps(result, indent=2) if args.as_json else f"ERROR: {exc}", file=sys.stderr)
        return 2

    result = certify_theme(text)
    result.update(
        {
            "theme": str(args.theme),
            "checksum": str(args.checksum),
            "expected_sha256": expected,
            "actual_sha256": actual,
            "checksum_match": expected == actual,
        }
    )
    if expected != actual:
        result["status"] = "FAIL"
        result["findings"].insert(
            0,
            {
                "code": "checksum_mismatch",
                "message": "Committed theme bytes do not match the immutable baseline checksum.",
                "evidence": f"expected={expected} actual={actual}",
            },
        )

    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"THEME_STATUS={result['status']}")
        print(f"CHECKSUM_MATCH={'true' if result['checksum_match'] else 'false'}")
        print(f"WEBSITE_JSONLD_BLOCKS={result['website_jsonld_blocks']}")
        for finding in result["findings"]:
            suffix = f" | {finding['evidence']}" if finding.get("evidence") else ""
            print(f"BLOCK: {finding['code']}: {finding['message']}{suffix}")

    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
