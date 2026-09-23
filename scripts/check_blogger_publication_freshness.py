#!/usr/bin/env python3
"""Fail-closed freshness classifier for customer-facing Blogger CTI delivery.

This monitor is intentionally separate from the internal Intel Factory/feed
freshness monitor. A healthy ingestion pipeline does not prove that paying
customers are receiving new Blogger reports.

Exit codes:
  0 = customer-facing publication freshness healthy
  1 = state file malformed / monitor cannot prove freshness
  2 = Blogger publication is stale and controlled recovery is required
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DEFAULT_MAX_AGE_MINUTES = 240
FUTURE_TOLERANCE_MINUTES = 5


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _publication_entries(state: dict[str, Any]) -> Iterable[dict[str, Any]]:
    posts = state.get("posts", {})
    if isinstance(posts, dict):
        for value in posts.values():
            if isinstance(value, dict):
                yield value
    elif isinstance(posts, list):
        for value in posts:
            if isinstance(value, dict):
                yield value


def evaluate_blogger_freshness(
    state: dict[str, Any],
    *,
    now: datetime | None = None,
    max_age_minutes: int = DEFAULT_MAX_AGE_MINUTES,
) -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    max_age_minutes = max(1, int(max_age_minutes))

    published_times = [
        parsed
        for entry in _publication_entries(state)
        if (parsed := _parse_timestamp(entry.get("published_at"))) is not None
    ]

    if not published_times:
        return {
            "status": "BLOGGER_STATE_ERROR",
            "exit_code": 1,
            "recovery_required": False,
            "latest_published_at": None,
            "age_minutes": None,
            "defects": ["no_parseable_published_at"],
        }

    latest = max(published_times)
    delta_minutes = (now - latest).total_seconds() / 60.0

    if delta_minutes < -FUTURE_TOLERANCE_MINUTES:
        return {
            "status": "BLOGGER_STATE_ERROR",
            "exit_code": 1,
            "recovery_required": False,
            "latest_published_at": latest.isoformat(),
            "age_minutes": round(delta_minutes, 1),
            "defects": ["latest_publication_timestamp_in_future"],
        }

    age_minutes = max(0.0, delta_minutes)
    if age_minutes > max_age_minutes:
        return {
            "status": "BLOGGER_STALE",
            "exit_code": 2,
            "recovery_required": True,
            "latest_published_at": latest.isoformat(),
            "age_minutes": round(age_minutes, 1),
            "defects": [],
        }

    return {
        "status": "BLOGGER_HEALTHY",
        "exit_code": 0,
        "recovery_required": False,
        "latest_published_at": latest.isoformat(),
        "age_minutes": round(age_minutes, 1),
        "defects": [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("state_file", nargs="?", default="data/published_posts.json")
    parser.add_argument("--max-age-minutes", type=int, default=DEFAULT_MAX_AGE_MINUTES)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    path = Path(args.state_file)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        result = {
            "status": "BLOGGER_STATE_ERROR",
            "exit_code": 1,
            "recovery_required": False,
            "latest_published_at": None,
            "age_minutes": None,
            "defects": [f"state_read_or_parse_failed:{exc}"],
        }
    else:
        result = evaluate_blogger_freshness(
            state,
            max_age_minutes=args.max_age_minutes,
        )

    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"STATUS={result['status']}")
        print(f"RECOVERY_REQUIRED={'true' if result['recovery_required'] else 'false'}")
        print(f"LATEST_PUBLISHED_AT={result['latest_published_at'] or 'unavailable'}")
        print(f"AGE_MINUTES={result['age_minutes'] if result['age_minutes'] is not None else 'unknown'}")
        if result["defects"]:
            print(f"DEFECTS={','.join(result['defects'])}")

    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
