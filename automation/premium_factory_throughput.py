"""P0 global CTI publication controls.

The public Blogger lane runs in search-recovery mode: prioritize evidence,
original analysis, freshness and family diversity over raw page volume.
Ingestion, API generation and internal intelligence processing can continue at
high throughput, but public Blogger writes are intentionally bounded to avoid
turning source-backed automation into a scaled-content footprint.

This is a risk-control mitigation while Search Console incident #219 is open;
it is not a claim that publication volume alone caused the visibility cliff.

Safety invariants:
- no public quality threshold is changed;
- ReportX/evidence graph/certification remains authoritative;
- no deterministic fallback is promoted to premium;
- model pacing remains enforced, but per Groq model because the provider
  budgets observed in production are model-scoped;
- every Blogger write still uses the existing certified-artifact hash and
  post-publication fetch-back verification transaction;
- retry expansion changes retention only, never publication eligibility.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from bs4 import BeautifulSoup

from . import key_judgements as _key_judgements
from . import llm_client as _llm
from . import nvd_source as _nvd
from . import premium_provider_budget as _budget
from . import premium_publication as _premium
from . import premium_yield_contract_guard as _contract
from . import premium_yield_hardening as _hardening
from . import publication_scheduler as _scheduler
from .content_discovery import DiscoveredArticle, PublicationState
from .logger import setup_logger

logger = setup_logger("premium_factory_throughput")

# P0-SEARCH-RECOVERY-2026-09-22:
# Search Console shows a sustained CTI visibility collapse after 2026-08-16.
# Keep public publishing selective while root-cause recovery is measured.
# Eight runs/day * two writes/run gives a hard theoretical ceiling of 16 new
# Blogger pages/day, while the normal operating goal is 12 and floor is 6.
# Internal feeds/APIs are not constrained by these public-page limits.
FACTORY_DAILY_FLOOR = 6
FACTORY_DAILY_GOAL = 12
FACTORY_RUNS_PER_DAY = 8
FACTORY_WRITE_BURST = 2
FACTORY_RETRY_QUEUE_LIMIT = 500
FACTORY_RETRY_ATTEMPTS = 5
FACTORY_KEY_JUDGEMENT_MAX = 4
FACTORY_KEY_JUDGEMENT_TOKENS = 900

# P0-DAILY-THREAT-COVERAGE-2026-09-21:
# These are customer delivery classes, not threat-severity classes. The
# scheduler prioritizes any class not yet successfully published in the
# current UTC day when a real source-backed candidate exists. Missing source
# supply remains an observable SLA miss; the factory never fabricates an event.
FACTORY_DAILY_DELIVERY_CLASSES = (
    "ransomware",
    "malware",
    "malware_campaign",
    "malware_attack",
    "breach",
    "threat_analysis",
)

_FACTORY_FAMILY_ORDER = (
    "zero_day",
    "vulnerability",
    "malware",
    "ransomware",
    "breach",
    "incident",
    "campaign",
    "phishing",
    "supply_chain",
    "ai_security",
    "threat_analysis",
)
_STRATEGIC_FACTORY_FAMILIES = frozenset(set(_FACTORY_FAMILY_ORDER) - {"vulnerability"})

_ORIGINAL_TRY_PROVIDER: Optional[Callable] = None
_ORIGINAL_PREMIUM_CALL: Optional[Callable] = None
_ORIGINAL_NVD_DISCOVER: Optional[Callable] = None
_ORIGINAL_ADD_RETRY: Optional[Callable] = None
_ORIGINAL_GET_RETRY: Optional[Callable] = None
_ORIGINAL_WRITE_RUN_REPORT: Optional[Callable] = None
_ORIGINAL_RUN_PIPELINE: Optional[Callable] = None

_MODEL_LAST_STARTED: dict[tuple[str, str], float] = {}
_ACTIVE_STATE_FILE = "data/published_posts.json"
_ACTIVE_MAX_POSTS = FACTORY_WRITE_BURST
_DAILY_DELIVERY_SLA_ACTIVE = False
_ACTIVE_DAILY_DELIVERED: frozenset[str] = frozenset()
_INSTALLED = False


def _configured_groq_models(config) -> list[str]:
    result: list[str] = []
    for model in [config.llm_model_groq, *config.llm_model_groq_fallbacks]:
        value = str(model or "").strip()
        if value and value not in result:
            result.append(value)
    return result


def _stable_index(text: str, modulo: int) -> int:
    if modulo <= 1:
        return 0
    source_match = re.search(r"^SOURCE URL:\s*(.+?)\s*$", text or "", re.MULTILINE)
    identity = source_match.group(1).strip() if source_match else (text or "")[:2048]
    digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).digest()
    return int.from_bytes(digest[:8], "big") % modulo


def _rotate_models(config, prompt: str, *, secondary_only: bool = False):
    models = _configured_groq_models(config)
    if not models:
        return config

    if secondary_only:
        primary = str(config.llm_model_groq or "").strip()
        preferred = [m for m in models if m != primary]
        if not preferred:
            preferred = models[:]
        index = _stable_index(prompt, len(preferred))
        ordered = preferred[index:] + preferred[:index]
        if primary and primary not in ordered:
            ordered.append(primary)
    else:
        index = _stable_index(prompt, len(models))
        ordered = models[index:] + models[:index]

    return replace(
        config,
        llm_model_groq=ordered[0],
        llm_model_groq_fallbacks=tuple(ordered[1:]),
    )


def _pace_groq_model(url: str, model: str, sleep_fn) -> None:
    """Enforce the existing TPM wait independently for each Groq model.

    The previous global clock serialized unrelated model quotas for 65 seconds
    even when a different configured Groq model had a fresh independent TPM
    window.  Production evidence and the existing configuration contract both
    identify the quota as model-scoped.  Same-model calls remain separated by
    the exact existing safety interval; this only removes cross-model idle time.
    """
    if str(url) != str(_llm._GROQ_URL):
        return
    key = (str(url), str(model))
    last = _MODEL_LAST_STARTED.get(key)
    if last is not None:
        elapsed = time.monotonic() - last
        wait = _budget.PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS - elapsed
        if wait > 0:
            sleep_fn(wait)
    _MODEL_LAST_STARTED[key] = time.monotonic()


def model_aware_try_provider(
    name: str,
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
    sleep_fn,
    attempts: Optional[list],
):
    if _ORIGINAL_TRY_PROVIDER is None:
        raise RuntimeError("factory throughput runtime is not installed")

    # A provider-declared long cooldown is stronger evidence than our local
    # TPM clock.  Let the existing cooldown wrapper skip immediately rather
    # than sleeping for a model that is known unavailable for much longer.
    if str(url) == str(_llm._GROQ_URL) and _hardening._cooldown_remaining(url, model) <= 0:
        _pace_groq_model(url, model, sleep_fn)

    return _ORIGINAL_TRY_PROVIDER(
        name=name,
        url=url,
        api_key=api_key,
        model=model,
        prompt=prompt,
        max_tokens=max_tokens,
        extra_headers=extra_headers,
        sleep_fn=sleep_fn,
        attempts=attempts,
    )


def _no_global_pace(_sleep_fn) -> None:
    """Global pacing is replaced by model_aware_try_provider()."""
    return None


def balanced_premium_llm(
    config,
    prompt: str,
    max_tokens: int = 3000,
    attempts=None,
    sleep_fn=time.sleep,
):
    """Distribute long-form generation deterministically across free Groq models."""
    if _ORIGINAL_PREMIUM_CALL is None:
        raise RuntimeError("factory throughput runtime is not installed")
    routed = _rotate_models(config, prompt, secondary_only=False)
    return _ORIGINAL_PREMIUM_CALL(
        routed,
        prompt,
        max_tokens=max_tokens,
        attempts=attempts,
        sleep_fn=sleep_fn,
    )


def balanced_key_judgements_llm(
    config,
    prompt: str,
    max_tokens: int = 2000,
    attempts=None,
    sleep_fn=time.sleep,
):
    """Use independent smaller-model quota for bounded structured judgements.

    The validator remains unchanged and still rejects every judgement that
    cannot bind to the real evidence graph.  Four accepted judgements are more
    than the current premium tier needs (it requires a non-empty validated
    judgement set) while avoiding a 2,000-token secondary reservation for each
    report.
    """
    routed = _rotate_models(config, prompt, secondary_only=True)
    return _budget._ORIGINAL_KEY_JUDGEMENTS_LLM_CALL(
        routed,
        prompt,
        max_tokens=min(FACTORY_KEY_JUDGEMENT_TOKENS, int(max_tokens or FACTORY_KEY_JUDGEMENT_TOKENS)),
        attempts=attempts,
        sleep_fn=sleep_fn,
    )


def h3_only_heading_set(content: str) -> set[str]:
    """Make raw generation preflight match the actual LLM HTML sanitizer.

    The sanitizer accepts <h3> but unwraps <h2>.  Counting <h2> in preflight
    allowed a response with an <h2>References</h2> tail to be declared complete,
    only for the sanitizer to remove that heading and the authoritative public
    gate to reject the final artifact.  Count exactly what can survive.
    """
    soup = BeautifulSoup(content or "", "html.parser")
    headings: set[str] = set()
    for node in soup.find_all("h3"):
        canonical = _contract._canonical_heading(" ".join(node.stripped_strings))
        if canonical:
            headings.add(canonical)
    return headings


def factory_candidate_discovery_limit(max_posts: int) -> int:
    """Expose a broad global candidate pool while keeping work bounded."""
    requested = max(1, int(max_posts or 1))
    return min(300, max(200, requested * 40))


def factory_nvd_discover(self, state: PublicationState) -> list[DiscoveredArticle]:
    """Collect the full recent CRITICAL/HIGH NVD window available per query.

    The previous ten-record cap was appropriate for five publication slots but
    artificially suppressed CVE factory supply before the scheduler could make
    a global decision.  Each severity request is already capped at 20 records,
    so this remains a bounded maximum of 40 candidates and changes no evidence
    semantics.
    """
    critical = self._fetch_by_severity("CRITICAL", state)
    high = self._fetch_by_severity("HIGH", state)
    return (critical + high)[:40]


def classify_factory_family(article: DiscoveredArticle) -> str:
    if _scheduler.is_non_threat_editorial(article):
        return "non_intelligence"
    text = " ".join(
        str(value or "")
        for value in (article.title, article.summary, article.full_content, " ".join(article.labels or []))
    ).lower()
    source = str(article.source or "").lower()

    if re.search(r"\b(?:zero[ -]?day|0[ -]?day)\b", text):
        return "zero_day"
    if source == "ransomware_intel" or "ransomware" in text or "extortion" in text:
        return "ransomware"
    if source == "breach_intel" or re.search(r"\b(?:data breach|breach notice|data exposure|records exposed|data leak)\b", text):
        return "breach"
    if source == "threat_actor_intel":
        return "campaign"
    if re.search(r"\b(?:phishing|spearphishing|business email compromise|\bbec\b)\b", text):
        return "phishing"
    if re.search(r"\b(?:supply[ -]?chain|package compromise|dependency compromise|npm package|pypi package)\b", text):
        return "supply_chain"
    if re.search(r"\b(?:prompt injection|large language model|\bllm\b|ai security|model security|agentic ai)\b", text):
        return "ai_security"
    if re.search(r"\b(?:malware|trojan|backdoor|infostealer|information stealer|loader|botnet|rootkit|wiper|rat\b)\b", text):
        return "malware"
    if re.search(r"\b(?:cyber incident|security incident|intrusion|compromised systems?|incident response)\b", text):
        return "incident"
    if re.search(r"\b(?:campaign|threat actor|apt\d*|nation[ -]?state|intrusion set|threat cluster)\b", text):
        return "campaign"
    if source in {"nvd", "cisa_kev"} or article.cve_id or re.search(r"\bCVE-\d{4}-\d{4,}\b", text, re.IGNORECASE):
        return "vulnerability"
    if source == "cisa_advisory" and not re.search(r"\b(?:malware|campaign|ransomware|breach|threat actor|apt\d*)\b", text):
        return "vulnerability"
    return "threat_analysis"


_MALWARE_RE = re.compile(
    r"\b(?:malware|trojan|backdoor|infostealer|information stealer|loader|"
    r"botnet|rootkit|wiper|remote access trojan|\brat\b)\b",
    re.IGNORECASE,
)
_CAMPAIGN_RE = re.compile(
    r"\b(?:campaign|operation|wave|cluster|distribution campaign|malspam|"
    r"mass exploitation|targeting campaign)\b",
    re.IGNORECASE,
)
_ATTACK_RE = re.compile(
    r"\b(?:attack|attacks|attacked|infection|infected|compromise|compromised|"
    r"intrusion|deployed|deployment|execution|payload delivered|initial access)\b",
    re.IGNORECASE,
)
_BREACH_RE = re.compile(
    r"\b(?:data breach|breach notice|records exposed|accounts exposed|"
    r"data exposure|data leak|exfiltrat(?:e|ed|ion))\b",
    re.IGNORECASE,
)
_CVE_ANY_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _delivery_class_from_fields(
    *,
    title: object = "",
    summary: object = "",
    labels: object = (),
    source: object = "",
    report_family: object = "",
    cves: object = (),
) -> Optional[str]:
    """Map real publication evidence to one paid-customer delivery class.

    This classifier is deliberately conservative and single-valued so a single
    report cannot falsely satisfy several daily SLA classes. It never creates
    intelligence; it only describes already-discovered/published evidence.
    """
    if isinstance(labels, (list, tuple, set)):
        label_text = " ".join(str(value or "") for value in labels)
    else:
        label_text = str(labels or "")
    text = " ".join(
        str(value or "")
        for value in (title, summary, label_text, report_family)
    ).lower()
    source_key = str(source or "").strip().lower()

    if source_key == "ransomware_intel" or re.search(r"\b(?:ransomware|extortion group|leak site victim)\b", text):
        return "ransomware"
    if source_key == "breach_intel" or _BREACH_RE.search(text):
        return "breach"

    malware = bool(_MALWARE_RE.search(text))
    if malware and _CAMPAIGN_RE.search(text):
        return "malware_campaign"
    if malware and _ATTACK_RE.search(text):
        return "malware_attack"
    if malware:
        return "malware"

    has_cve = bool(cves) or bool(_CVE_ANY_RE.search(text))
    if source_key in {"nvd", "cisa_kev"} or has_cve:
        return None
    if source_key == "cisa_advisory" and classify_text_as_vulnerability(text):
        return None

    # Non-vulnerability strategic intelligence (APT/campaign/incident/phishing/
    # cloud/identity/supply-chain/AI security/general CTI) satisfies the broad
    # threat-analysis service class.
    return "threat_analysis"


def classify_text_as_vulnerability(text: str) -> bool:
    """Conservative CISA/general advisory vulnerability discriminator."""
    return bool(re.search(
        r"\b(?:vulnerabilit(?:y|ies)|security flaw|remote code execution|"
        r"privilege escalation|authentication bypass|zero[ -]?day|cve-)\b",
        str(text or ""),
        re.IGNORECASE,
    )) and not bool(re.search(
        r"\b(?:malware|campaign|ransomware|data breach|breach notice|"
        r"threat actor|apt\d*|phishing|intrusion)\b",
        str(text or ""),
        re.IGNORECASE,
    ))


def classify_delivery_class(article: DiscoveredArticle) -> Optional[str]:
    if _scheduler.is_non_threat_editorial(article):
        return None
    return _delivery_class_from_fields(
        title=article.title,
        summary=" ".join(filter(None, [article.summary, article.full_content or ""])),
        labels=article.labels or [],
        source=article.source,
        report_family="",
        cves=[article.cve_id] if article.cve_id else [],
    )


def _entry_delivery_class(entry: dict) -> Optional[str]:
    return _delivery_class_from_fields(
        title=entry.get("source_title"),
        summary="",
        labels=entry.get("labels") or [],
        source=entry.get("source"),
        report_family=entry.get("report_family"),
        cves=entry.get("cves") or [],
    )


def _family_balanced_select(
    pool: list[DiscoveredArticle],
    slots: int,
    preferred_delivery_classes: tuple[str, ...] = (),
) -> list[DiscoveredArticle]:
    if slots <= 0 or not pool:
        return []

    groups: dict[str, list[DiscoveredArticle]] = defaultdict(list)
    for article in pool:
        groups[classify_factory_family(article)].append(article)
    for family in groups:
        groups[family].sort(key=_scheduler._priority_key, reverse=True)

    selected: list[DiscoveredArticle] = []
    selected_ids: set[int] = set()

    # Reserve publication capacity for paid-customer delivery classes still
    # missing today. One real candidate satisfies at most one class. If a class
    # has no candidate, its slot is NOT held empty; normal factory throughput
    # immediately receives the capacity.
    for delivery_class in preferred_delivery_classes:
        if len(selected) >= slots:
            break
        candidates = [
            article for article in pool
            if id(article) not in selected_ids
            and classify_delivery_class(article) == delivery_class
        ]
        if not candidates:
            continue
        candidates.sort(key=_scheduler._priority_key, reverse=True)
        chosen = candidates[0]
        selected.append(chosen)
        selected_ids.add(id(chosen))

    # Remove SLA-reserved objects from family buckets before normal balancing.
    if selected_ids:
        for family in list(groups):
            groups[family] = [article for article in groups[family] if id(article) not in selected_ids]

    # Critical global intelligence gets first refusal after unsatisfied customer
    # delivery classes. CVE/vulnerability keeps a guaranteed lane whenever
    # capacity remains, so this P0 restores coverage without disabling CVE intel.
    for family in ("zero_day", "vulnerability"):
        bucket = groups.get(family) or []
        if bucket and len(selected) < slots:
            chosen = bucket.pop(0)
            selected.append(chosen)
            selected_ids.add(id(chosen))

    # Rotate the remaining family order by the current 15-minute UTC slot so
    # malware/breach/incident/campaign/phishing/supply-chain/AI intelligence
    # cannot be starved by a permanently fixed first-five family order.
    rotation = int(time.time() // 900) % len(_FACTORY_FAMILY_ORDER)
    order = _FACTORY_FAMILY_ORDER[rotation:] + _FACTORY_FAMILY_ORDER[:rotation]

    while len(selected) < slots:
        progressed = False
        for family in order:
            bucket = groups.get(family) or []
            if bucket:
                chosen = bucket.pop(0)
                selected.append(chosen)
                selected_ids.add(id(chosen))
                progressed = True
                if len(selected) >= slots:
                    break
        if not progressed:
            break

    return selected[:slots]


def select_factory_publication_batch(
    retry_articles: list[DiscoveredArticle],
    fresh_articles: list[DiscoveredArticle],
    max_posts: int,
):
    """High-throughput family-fair scheduler with unchanged Blogger burst cap."""
    max_posts = max(0, min(FACTORY_WRITE_BURST, int(max_posts or 0)))
    if max_posts == 0:
        return _scheduler.PublicationSelection([], {
            "candidate_count": 0,
            "fresh_candidates": 0,
            "retry_candidates": 0,
            "fresh_selected": 0,
            "retry_selected": 0,
            "strategic_selected": 0,
            "vulnerability_selected": 0,
            "canonical_selected": 0,
            "selected_families": {},
            "selected_sources": {},
            "delivery_sla_required": list(FACTORY_DAILY_DELIVERY_CLASSES),
            "delivery_sla_delivered_before": sorted(_ACTIVE_DAILY_DELIVERED),
            "delivery_sla_missing_before": sorted(set(FACTORY_DAILY_DELIVERY_CLASSES) - set(_ACTIVE_DAILY_DELIVERED)),
            "selected_delivery_classes": {},
            "delivery_sla_missing_after_selection": sorted(set(FACTORY_DAILY_DELIVERY_CLASSES) - set(_ACTIVE_DAILY_DELIVERED)),
            "non_intelligence_filtered": 0,
        })

    fresh_all = _scheduler._dedupe_fresh(list(fresh_articles))
    retry_all = _scheduler._remove_retry_duplicates(list(retry_articles), fresh_all)
    non_intelligence_filtered = sum(
        1 for article in [*fresh_all, *retry_all]
        if _scheduler.is_non_threat_editorial(article)
    )
    fresh = [article for article in fresh_all if not _scheduler.is_non_threat_editorial(article)]
    retry = [article for article in retry_all if not _scheduler.is_non_threat_editorial(article)]

    # Preserve the proven 3-fresh/2-retry shape. At factory cadence the larger
    # retry store drains continuously without allowing old failures to suppress
    # the global fresh-intelligence lane.
    retry_cap = min(2, max_posts // 2) if fresh else max_posts
    fresh_floor = max_posts - retry_cap if fresh else 0

    delivered_before = set(_ACTIVE_DAILY_DELIVERED) if _DAILY_DELIVERY_SLA_ACTIVE else set()
    missing_before = [
        family for family in FACTORY_DAILY_DELIVERY_CLASSES
        if family not in delivered_before
    ]

    fresh_selected = _family_balanced_select(
        fresh,
        min(fresh_floor, len(fresh)),
        tuple(missing_before),
    )
    satisfied_by_fresh = {
        delivery for article in fresh_selected
        if (delivery := classify_delivery_class(article))
    }
    still_missing = [family for family in missing_before if family not in satisfied_by_fresh]

    retry_selected = _family_balanced_select(
        retry,
        min(retry_cap, len(retry)),
        tuple(still_missing),
    )
    selected = fresh_selected + retry_selected

    if len(selected) < max_posts:
        satisfied = {
            delivery for article in selected
            if (delivery := classify_delivery_class(article))
        }
        still_missing = [family for family in missing_before if family not in satisfied]
        extra_fresh = _family_balanced_select(
            _scheduler._without_selected(fresh, fresh_selected),
            max_posts - len(selected),
            tuple(still_missing),
        )
        fresh_selected.extend(extra_fresh)
        selected.extend(extra_fresh)

    if len(selected) < max_posts:
        satisfied = {
            delivery for article in selected
            if (delivery := classify_delivery_class(article))
        }
        still_missing = [family for family in missing_before if family not in satisfied]
        extra_retry = _family_balanced_select(
            _scheduler._without_selected(retry, retry_selected),
            max_posts - len(selected),
            tuple(still_missing),
        )
        retry_selected.extend(extra_retry)
        selected.extend(extra_retry)

    selected = selected[:max_posts]
    family_counts = Counter(classify_factory_family(a) for a in selected)
    source_counts = Counter(str(a.source or "unknown") for a in selected)
    delivery_counts = Counter(
        delivery for article in selected
        if (delivery := classify_delivery_class(article))
    )
    delivered_after_selection = delivered_before | set(delivery_counts)
    metrics = {
        "candidate_count": len(fresh) + len(retry),
        "fresh_candidates": len(fresh),
        "retry_candidates": len(retry),
        "fresh_selected": sum(1 for a in selected if a in fresh_selected),
        "retry_selected": sum(1 for a in selected if a in retry_selected),
        "strategic_selected": sum(1 for a in selected if classify_factory_family(a) in _STRATEGIC_FACTORY_FAMILIES),
        "vulnerability_selected": family_counts.get("vulnerability", 0),
        "canonical_selected": sum(1 for a in selected if _scheduler.is_canonical_report(a)),
        "selected_families": dict(family_counts),
        "selected_sources": dict(source_counts),
        "delivery_sla_required": list(FACTORY_DAILY_DELIVERY_CLASSES),
        "delivery_sla_delivered_before": sorted(delivered_before),
        "delivery_sla_missing_before": sorted(set(FACTORY_DAILY_DELIVERY_CLASSES) - delivered_before),
        "selected_delivery_classes": dict(delivery_counts),
        "delivery_sla_missing_after_selection": sorted(
            set(FACTORY_DAILY_DELIVERY_CLASSES) - delivered_after_selection
        ),
        "non_intelligence_filtered": non_intelligence_filtered,
    }
    return _scheduler.PublicationSelection(selected, metrics)


def factory_add_to_retry_queue(self: PublicationState, article: DiscoveredArticle, error: str) -> None:
    queue: list[dict] = self._state.setdefault("retry_queue", [])
    existing_attempts = next(
        (int(q.get("attempts", 1) or 1) for q in queue if q.get("content_hash") == article.content_hash),
        0,
    )
    queue = [q for q in queue if q.get("content_hash") != article.content_hash]
    queue.append({
        **article.to_dict(),
        "last_error": error,
        "attempts": existing_attempts + 1,
        "added_at": datetime.now(timezone.utc).isoformat(),
    })
    limit = max(100, int(os.environ.get("CDB_FACTORY_RETRY_QUEUE_LIMIT", FACTORY_RETRY_QUEUE_LIMIT)))
    self._state["retry_queue"] = queue[-limit:]
    self.save()


def factory_get_retry_queue(self: PublicationState) -> list[dict]:
    attempts = max(3, int(os.environ.get("CDB_FACTORY_RETRY_ATTEMPTS", FACTORY_RETRY_ATTEMPTS)))
    return [
        item for item in self._state.get("retry_queue", [])
        if int(item.get("attempts", 1) or 1) <= attempts
    ]


def _published_today_utc(state_file: str) -> int:
    path = Path(state_file)
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    today = datetime.now(timezone.utc).date()
    count = 0
    for entry in data.get("posts", {}).values():
        raw = str(entry.get("published_at") or "")
        if not raw:
            continue
        try:
            timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            if timestamp.astimezone(timezone.utc).date() == today:
                count += 1
        except Exception:
            continue
    return count


def _published_delivery_classes_today(state_file: str) -> set[str]:
    """Return customer delivery classes successfully published today (UTC)."""
    path = Path(state_file)
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()

    today = datetime.now(timezone.utc).date()
    delivered: set[str] = set()
    for entry in data.get("posts", {}).values():
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("published_at") or "")
        if not raw:
            continue
        try:
            timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            if timestamp.astimezone(timezone.utc).date() != today:
                continue
        except Exception:
            continue
        delivery_class = _entry_delivery_class(entry)
        if delivery_class:
            delivered.add(delivery_class)
    return delivered


def _daily_delivery_sla_enabled() -> bool:
    value = os.environ.get("CDB_DAILY_DELIVERY_SLA_ENABLED", "true").strip().lower()
    return value not in {"0", "false", "off", "no"}


def factory_write_run_report(report: dict, logs_dir: str) -> None:
    if _ORIGINAL_WRITE_RUN_REPORT is None:
        raise RuntimeError("factory throughput report writer is not installed")
    published_today = _published_today_utc(_ACTIVE_STATE_FILE)
    delivered_today = _published_delivery_classes_today(_ACTIVE_STATE_FILE)
    missing_today = set(FACTORY_DAILY_DELIVERY_CLASSES) - delivered_today
    report["factory_throughput"] = {
        "daily_floor": FACTORY_DAILY_FLOOR,
        "daily_goal": FACTORY_DAILY_GOAL,
        "published_today_utc": published_today,
        "scheduled_runs_per_day": FACTORY_RUNS_PER_DAY,
        "max_blogger_writes_per_run": min(FACTORY_WRITE_BURST, _ACTIVE_MAX_POSTS),
        "theoretical_daily_write_capacity": FACTORY_RUNS_PER_DAY * min(FACTORY_WRITE_BURST, _ACTIVE_MAX_POSTS),
        "floor_progress_pct": round((published_today / FACTORY_DAILY_FLOOR) * 100, 2),
        "goal_progress_pct": round((published_today / FACTORY_DAILY_GOAL) * 100, 2),
        "daily_delivery_sla": {
            "enabled": _daily_delivery_sla_enabled(),
            "required_classes": list(FACTORY_DAILY_DELIVERY_CLASSES),
            "delivered_classes_utc": sorted(delivered_today),
            "missing_classes_utc": sorted(missing_today),
            "met": not missing_today,
            "fabrication_allowed": False,
            "policy": "prioritize real source-backed candidates; never manufacture an event to fill a class",
        },
    }
    _ORIGINAL_WRITE_RUN_REPORT(report, logs_dir)


def factory_run_pipeline(config, dry_run: bool = False) -> dict:
    global _ACTIVE_STATE_FILE, _ACTIVE_MAX_POSTS
    global _DAILY_DELIVERY_SLA_ACTIVE, _ACTIVE_DAILY_DELIVERED
    if _ORIGINAL_RUN_PIPELINE is None:
        raise RuntimeError("factory throughput pipeline wrapper is not installed")

    _ACTIVE_STATE_FILE = str(config.state_file)
    _ACTIVE_MAX_POSTS = int(config.max_posts_per_run)
    previous_active = _DAILY_DELIVERY_SLA_ACTIVE
    previous_delivered = _ACTIVE_DAILY_DELIVERED
    _DAILY_DELIVERY_SLA_ACTIVE = _daily_delivery_sla_enabled()
    _ACTIVE_DAILY_DELIVERED = frozenset(
        _published_delivery_classes_today(_ACTIVE_STATE_FILE)
        if _DAILY_DELIVERY_SLA_ACTIVE else set()
    )
    try:
        return _ORIGINAL_RUN_PIPELINE(config, dry_run=dry_run)
    finally:
        # Tests and nested callers must never inherit one run's daily state.
        _DAILY_DELIVERY_SLA_ACTIVE = previous_active
        _ACTIVE_DAILY_DELIVERED = previous_delivered


def install_factory_throughput_overrides(main_module) -> None:
    """Install high-throughput controls after all premium safety layers."""
    global _ORIGINAL_TRY_PROVIDER, _ORIGINAL_PREMIUM_CALL, _ORIGINAL_NVD_DISCOVER
    global _ORIGINAL_ADD_RETRY, _ORIGINAL_GET_RETRY, _ORIGINAL_WRITE_RUN_REPORT
    global _ORIGINAL_RUN_PIPELINE, _INSTALLED

    if _INSTALLED:
        return

    # Match raw preflight to the sanitizer: only exact surviving <h3> headings
    # can satisfy the 25-section contract.
    _contract._normalized_heading_set = h3_only_heading_set

    # Candidate breadth and category fairness are scheduling concerns only;
    # publication eligibility remains entirely downstream and fail closed.
    main_module.candidate_discovery_limit = factory_candidate_discovery_limit
    main_module.select_publication_batch = select_factory_publication_batch
    main_module.classify_publication_family = classify_factory_family

    _ORIGINAL_NVD_DISCOVER = _nvd.NVDCVESource.discover
    _nvd.NVDCVESource.discover = factory_nvd_discover

    _ORIGINAL_ADD_RETRY = PublicationState.add_to_retry_queue
    _ORIGINAL_GET_RETRY = PublicationState.get_retry_queue
    PublicationState.add_to_retry_queue = factory_add_to_retry_queue
    PublicationState.get_retry_queue = factory_get_retry_queue

    # Replace one global 65-second clock with the same safety interval scoped
    # to the actual model quota key.  The existing cooldown wrapper remains
    # inside this wrapper and therefore retains provider-declared long resets.
    _ORIGINAL_TRY_PROVIDER = _llm._try_provider
    _llm._try_provider = model_aware_try_provider
    _budget._pace_premium_request = _no_global_pace

    _ORIGINAL_PREMIUM_CALL = _premium._premium_llm_call
    _premium._premium_llm_call = balanced_premium_llm

    _key_judgements._MAX_JUDGEMENTS_PER_ARTICLE = min(
        int(_key_judgements._MAX_JUDGEMENTS_PER_ARTICLE),
        FACTORY_KEY_JUDGEMENT_MAX,
    )
    _key_judgements.call_llm = balanced_key_judgements_llm

    _ORIGINAL_WRITE_RUN_REPORT = main_module._write_run_report
    _ORIGINAL_RUN_PIPELINE = main_module.run_pipeline
    main_module._write_run_report = factory_write_run_report
    main_module.run_pipeline = factory_run_pipeline

    logger.info(
        "Global CTI factory throughput runtime installed",
        extra={
            "daily_floor": FACTORY_DAILY_FLOOR,
            "daily_goal": FACTORY_DAILY_GOAL,
            "runs_per_day": FACTORY_RUNS_PER_DAY,
            "write_burst": FACTORY_WRITE_BURST,
            "retry_queue_limit": FACTORY_RETRY_QUEUE_LIMIT,
            "retry_attempts": FACTORY_RETRY_ATTEMPTS,
            "key_judgement_tokens": FACTORY_KEY_JUDGEMENT_TOKENS,
        },
    )
    _INSTALLED = True
