"""P0 capacity-aware publication allocation for the premium CTI factory.

Production acceptance after Dossier v10 exposed an availability/selection
mismatch: the factory can have a large candidate pool while premium Groq models
are already in, or have only just exited, durable TPD cooldown. The family-fair
scheduler can otherwise select thin candidates that require model expansion to
satisfy the unchanged premium semantic floor, spending scarce provider attempts
only to fail closed with zero publications.

This layer changes scheduling only. It never lowers the public quality floor,
changes evidence admission, trusts previously generated report prose, or turns
provider failure into publish permission.

Capacity is considered constrained when at least two distinct provider/model
TPD saturation signals exist. A signal can be an active durable cooldown or a
recently-expired TPD cooldown still inside a bounded recovery-grace window.
The grace window is necessary because provider retry timestamps are permission
to retry, not proof that enough rolling daily capacity has recovered for a
multi-thousand-token premium report. Production acceptance demonstrated models
relapsing into TPD exhaustion minutes after their stored retry timestamp.

Under constrained capacity, only candidates with enough *normalized source
evidence* to plausibly clear the existing provider-independent compiler path
are admitted to the finite five-post batch. The existing factory scheduler
remains authoritative for family/fresh/retry fairness inside that qualified
pool. If no candidate is source-rich enough, the run is explicitly deferred
rather than burning model calls on artifacts known to depend on unavailable
capacity.

Generated first-party HTML is deliberately NOT counted as source richness just
because it is canonical. Only ``DiscoveredArticle.full_content``/``summary``
and normalized structured fields are measured, preserving the current ReportX
source boundary.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from bs4 import BeautifulSoup

from . import premium_publication as _premium
from . import provider_quota_ledger as _quota
from . import publication_scheduler as _scheduler
from . import rapid_intel_lane_v19_3 as _rapid
from .logger import setup_logger

logger = setup_logger("premium_capacity_allocator_v13")

MARKER = "CDB-PREMIUM-CAPACITY-ALLOCATOR-V13"
MIN_TPD_CAPACITY_SIGNALS = 2
TPD_RECOVERY_GRACE_SECONDS = 30 * 60

# Backward-compatible alias used by existing tests/telemetry consumers.
MIN_ACTIVE_TPD_COOLDOWNS = MIN_TPD_CAPACITY_SIGNALS

# These are derived from the unchanged public semantic floor rather than being
# independent quality thresholds. A candidate must bring substantial real
# source material before deterministic structure is allowed to substitute for
# temporarily unavailable model capacity.
MIN_RICH_EVIDENCE_WORDS = max(1, int(_premium.MIN_VISIBLE_WORDS * 0.80))
MIN_STRUCTURED_EVIDENCE_WORDS = max(1, int(_premium.MIN_VISIBLE_WORDS * 0.55))
MIN_DENSE_STRUCTURED_EVIDENCE_WORDS = max(1, int(_premium.MIN_VISIBLE_WORDS * 0.40))
MIN_STRUCTURED_FIELDS = 6
MIN_DENSE_STRUCTURED_FIELDS = 10

_ORIGINAL_SELECT: Optional[Callable] = None
_ORIGINAL_WRITE_RUN_REPORT: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "capacity_aware_runs": 0,
    "qualified_candidates": 0,
    "deferred_candidates": 0,
    "selected_candidates": 0,
    "recovery_grace_runs": 0,
}

_STRUCTURED_FIELDS = (
    "cve_id",
    "cvss_score",
    "cvss_vector",
    "cwe_ids",
    "affected_vendor",
    "affected_product",
    "epss_score",
    "epss_percentile",
    "kev_listed",
    "kev_date_added",
    "kev_due_date",
    "kev_required_action",
    "ransomware_group",
    "ransomware_sector",
    "ransomware_country",
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: object) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _visible_source_text(article) -> str:
    raw = str(getattr(article, "full_content", None) or getattr(article, "summary", "") or "")
    soup = BeautifulSoup(raw, "html.parser")
    for node in soup(["script", "style", "noscript", "iframe", "object", "embed"]):
        node.decompose()
    return " ".join(soup.stripped_strings)


def _source_word_count(article) -> int:
    return len(re.findall(r"\b[\w][\w'./:+-]*\b", _visible_source_text(article), flags=re.UNICODE))


def _structured_evidence_count(article) -> int:
    count = 0
    for field in _STRUCTURED_FIELDS:
        value = getattr(article, field, None)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set, dict)) and not value:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        count += 1
    return count


def _provider_independent_candidate(article) -> bool:
    """Conservative admission for a report that may have no external LLM.

    This is intentionally stricter than ordinary scheduling. It is not a
    publication gate: downstream ReportX, evidence admission, compiler-input
    floors, Dossier v8, Blogger fetch-back, and all other gates still run and
    remain authoritative.

    P0-DAILY-THREAT-COVERAGE-2026-09-21: Rapid Intelligence is itself a
    provider-independent publication path. A candidate that the rapid lane can
    truthfully handle must therefore survive this *upstream* capacity filter;
    otherwise ransomware/breach/curated-malware candidates are discarded
    before v19.3 can ever route them around provider TPD exhaustion.
    """
    rapid_eligible, _reason = _rapid.rapid_lane_eligibility(article)
    if rapid_eligible:
        return True

    words = _source_word_count(article)
    structured = _structured_evidence_count(article)
    return (
        words >= MIN_RICH_EVIDENCE_WORDS
        or (words >= MIN_STRUCTURED_EVIDENCE_WORDS and structured >= MIN_STRUCTURED_FIELDS)
        or (
            words >= MIN_DENSE_STRUCTURED_EVIDENCE_WORDS
            and structured >= MIN_DENSE_STRUCTURED_FIELDS
        )
    )


def _signal_key(item: dict) -> str:
    return f"{str(item.get('provider') or '').lower()}::{str(item.get('model') or '')}"


def _recent_expired_tpd_signals(*, now: Optional[datetime] = None) -> list[dict]:
    """Read recent expired TPD entries before telemetry cleanup removes them.

    The quota ledger intentionally deletes expired cooldown entries when its
    normal telemetry snapshot is requested. For allocation, however, a just-
    expired TPD retry timestamp is still operationally relevant: it does not
    prove enough rolling daily capacity exists for a full premium generation.
    We therefore inspect the same code-owned, non-secret ledger immediately
    before cleanup and retain only a short, bounded recovery-grace signal.
    """
    current = (now or _utcnow()).astimezone(timezone.utc)
    try:
        path = _quota._state_path()
        _quota._assert_safe_state_target(path)
        if not path.exists():
            return []
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, RuntimeError, json.JSONDecodeError) as exc:
        logger.warning(
            "Capacity allocator could not inspect pre-cleanup quota ledger; active telemetry remains authoritative",
            extra={"error": str(exc)},
        )
        return []

    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, dict):
        return []

    recent: list[dict] = []
    grace = timedelta(seconds=TPD_RECOVERY_GRACE_SECONDS)
    for raw in models.values():
        if not isinstance(raw, dict):
            continue
        if str(raw.get("limit_type") or "").upper() != "TPD":
            continue
        until = _parse_utc(raw.get("unavailable_until"))
        if until is None or until > current:
            # Active entries are supplied by the quota ledger snapshot below.
            continue
        age = current - until
        if age < timedelta(0) or age > grace:
            continue
        recent.append({
            "provider": str(raw.get("provider") or ""),
            "model": str(raw.get("model") or ""),
            "limit_type": "TPD",
            "unavailable_until": until.isoformat(),
            "recovery_grace": True,
            "seconds_since_retry_window": round(age.total_seconds(), 2),
        })
    return recent


def _active_tpd_cooldowns() -> list[dict]:
    snapshot = _quota.telemetry_snapshot()
    return [
        item
        for item in (snapshot.get("active_cooldowns") or [])
        if isinstance(item, dict) and str(item.get("limit_type") or "").upper() == "TPD"
    ]


def _capacity_constrained() -> tuple[bool, list[dict]]:
    # Capture recently-expired entries *before* telemetry_snapshot performs its
    # normal cleanup. This order is a production invariant.
    recent = _recent_expired_tpd_signals()
    active = _active_tpd_cooldowns()

    signals: dict[str, dict] = {}
    for item in recent:
        key = _signal_key(item)
        if key != "::":
            signals[key] = dict(item)
    for item in active:
        key = _signal_key(item)
        if key != "::":
            normalized = dict(item)
            normalized["recovery_grace"] = False
            # Active evidence supersedes a recent-expired entry for same model.
            signals[key] = normalized

    combined = list(signals.values())
    return len(combined) >= MIN_TPD_CAPACITY_SIGNALS, combined


def _zero_selected_metrics(metrics: dict) -> dict:
    result = dict(metrics)
    result.update({
        "fresh_selected": 0,
        "retry_selected": 0,
        "strategic_selected": 0,
        "vulnerability_selected": 0,
        "canonical_selected": 0,
        "selected_families": {},
        "selected_sources": {},
    })
    return result


def capacity_aware_select_publication_batch(
    retry_articles,
    fresh_articles,
    max_posts: int,
):
    """Preserve normal scheduling unless durable telemetry proves saturation."""
    if _ORIGINAL_SELECT is None:
        raise RuntimeError("capacity-aware allocator is not installed")

    # The baseline call is selection-only (no transformation/network/provider
    # work). It preserves existing candidate accounting and gives us the exact
    # production scheduler's view of the pool.
    baseline = _ORIGINAL_SELECT(retry_articles, fresh_articles, max_posts)
    constrained, signals = _capacity_constrained()
    if not constrained:
        return baseline

    active_count = sum(1 for item in signals if not bool(item.get("recovery_grace")))
    recent_count = sum(1 for item in signals if bool(item.get("recovery_grace")))

    _RUNTIME["capacity_aware_runs"] += 1
    if recent_count:
        _RUNTIME["recovery_grace_runs"] += 1

    qualified_fresh = [article for article in fresh_articles if _provider_independent_candidate(article)]
    qualified_retry = [article for article in retry_articles if _provider_independent_candidate(article)]

    # Let the already-proven factory scheduler own fairness within the safe
    # source-rich subset. It still deduplicates and enforces the live burst cap.
    qualified = _ORIGINAL_SELECT(qualified_retry, qualified_fresh, max_posts)
    qualified_count = int(qualified.metrics.get("candidate_count", 0) or 0)
    total_count = int(baseline.metrics.get("candidate_count", 0) or 0)
    deferred_count = max(0, total_count - qualified_count)

    _RUNTIME["qualified_candidates"] += qualified_count
    _RUNTIME["deferred_candidates"] += deferred_count
    _RUNTIME["selected_candidates"] += len(qualified.articles)

    if qualified.articles:
        metrics = dict(qualified.metrics)
        # Candidate pool metrics describe discovery supply, not only the
        # constrained subset. Keep baseline accounting for observability.
        for key in ("candidate_count", "fresh_candidates", "retry_candidates"):
            if key in baseline.metrics:
                metrics[key] = baseline.metrics[key]
    else:
        metrics = _zero_selected_metrics(baseline.metrics)

    metrics.update({
        "capacity_aware_selection": True,
        "provider_capacity_constrained": True,
        "active_tpd_cooldown_count": active_count,
        "recent_tpd_recovery_count": recent_count,
        "tpd_capacity_signal_count": len(signals),
        "tpd_recovery_grace_seconds": TPD_RECOVERY_GRACE_SECONDS,
        "provider_independent_candidates": qualified_count,
        "provider_capacity_deferred_candidates": deferred_count,
        "capacity_allocator_marker": MARKER,
    })

    logger.warning(
        "Provider capacity constrained; publication allocator admitted only source-rich candidates",
        extra={
            "active_tpd_cooldowns": active_count,
            "recent_tpd_recovery_signals": recent_count,
            "tpd_capacity_signals": len(signals),
            "candidate_count": total_count,
            "provider_independent_candidates": qualified_count,
            "selected": len(qualified.articles),
            "deferred": deferred_count,
        },
    )
    return _scheduler.PublicationSelection(list(qualified.articles), metrics)


def _capacity_write_run_report(report: dict, logs_dir: str) -> None:
    if _ORIGINAL_WRITE_RUN_REPORT is None:
        raise RuntimeError("capacity-aware allocator run-report wrapper is not installed")

    constrained = bool(report.get("provider_capacity_constrained"))
    candidates = int(report.get("candidate_count", 0) or 0)
    attempted = int(report.get("discovered", 0) or 0)
    published = int(report.get("published", 0) or 0)
    qualified = int(report.get("provider_independent_candidates", 0) or 0)

    # A capacity-driven zero-selection is not "no intel" and not a healthy
    # publication run. Make the deferred state explicit without manufacturing
    # failed posts or weakening downstream integrity semantics.
    if constrained and candidates > 0 and attempted == 0 and published == 0:
        report["run_status"] = "DEGRADED"
        report["provider_capacity_deferred"] = True
        report["provider_capacity"] = {
            "reason": "active/recent TPD saturation signals left no source-rich candidate eligible for provider-independent premium generation",
            "active_tpd_cooldown_count": int(report.get("active_tpd_cooldown_count", 0) or 0),
            "recent_tpd_recovery_count": int(report.get("recent_tpd_recovery_count", 0) or 0),
            "tpd_capacity_signal_count": int(report.get("tpd_capacity_signal_count", 0) or 0),
            "recovery_grace_seconds": TPD_RECOVERY_GRACE_SECONDS,
            "provider_independent_candidates": qualified,
            "deferred_candidates": int(report.get("provider_capacity_deferred_candidates", candidates) or 0),
            "allocator": MARKER,
        }

    report["capacity_allocator_v13"] = {
        "marker": MARKER,
        "capacity_aware_runs": int(_RUNTIME["capacity_aware_runs"]),
        "recovery_grace_runs": int(_RUNTIME["recovery_grace_runs"]),
        "qualified_candidates": int(_RUNTIME["qualified_candidates"]),
        "deferred_candidates": int(_RUNTIME["deferred_candidates"]),
        "selected_candidates": int(_RUNTIME["selected_candidates"]),
        "min_tpd_capacity_signals": MIN_TPD_CAPACITY_SIGNALS,
        "tpd_recovery_grace_seconds": TPD_RECOVERY_GRACE_SECONDS,
        "min_rich_evidence_words": MIN_RICH_EVIDENCE_WORDS,
        "min_structured_evidence_words": MIN_STRUCTURED_EVIDENCE_WORDS,
        "min_dense_structured_evidence_words": MIN_DENSE_STRUCTURED_EVIDENCE_WORDS,
    }
    _ORIGINAL_WRITE_RUN_REPORT(report, logs_dir)


def install_capacity_aware_allocator_v13(main_module) -> None:
    """Install after factory scheduling and durable quota telemetry exist."""
    global _ORIGINAL_SELECT, _ORIGINAL_WRITE_RUN_REPORT, _INSTALLED
    if _INSTALLED:
        return

    live_select = main_module.select_publication_batch
    if live_select is capacity_aware_select_publication_batch:
        _INSTALLED = True
        return

    _ORIGINAL_SELECT = live_select
    _ORIGINAL_WRITE_RUN_REPORT = main_module._write_run_report
    main_module.select_publication_batch = capacity_aware_select_publication_batch
    main_module._write_run_report = _capacity_write_run_report
    _INSTALLED = True

    logger.info(
        "P0 capacity-aware publication allocator installed",
        extra={
            "marker": MARKER,
            "min_tpd_capacity_signals": MIN_TPD_CAPACITY_SIGNALS,
            "tpd_recovery_grace_seconds": TPD_RECOVERY_GRACE_SECONDS,
            "min_rich_evidence_words": MIN_RICH_EVIDENCE_WORDS,
            "public_quality_floor_unchanged": _premium.MIN_VISIBLE_WORDS,
        },
    )
