"""Commercial publication scheduling for the Blogger syndication pipeline.

The discovery layer intentionally collects from heterogeneous sources. This
module owns the *finite Blogger write budget* and prevents a high-volume source
(such as NVD) or the durable retry queue from monopolising every slot.

Policy invariants for a normal five-post run:
- reserve at least 60% of available slots for strategic intelligence when
  sufficient strategic candidates exist;
- cap vulnerability-only content at 40% when strategic candidates exist;
- reserve at least three slots for fresh content when fresh candidates exist;
- cap retry consumption at two slots while sufficient fresh content exists;
- prefer canonical CYBERDUDEBIVASH report URLs within a report family;
- preserve throughput: when one lane has insufficient candidates, unused slots
  are immediately returned to the other lane.

This is scheduling only. It never bypasses the existing evidence-integrity,
publication, fetch-back, retry, or authentication gates.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from .content_discovery import DiscoveredArticle


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_NON_WORD_RE = re.compile(r"[^a-z0-9]+")

# P0-CTI-RELEVANCE-2026-09-22:
# High-confidence editorial/non-threat subjects that must not enter the paid
# threat-intelligence publication queue merely because their body mentions
# malware, SOC, threat hunting, CVEs, or incident-response job duties.
_NON_THREAT_PRIMARY_PATTERNS = (
    re.compile(r"\bcybersecurity jobs? available\b", re.IGNORECASE),
    re.compile(r"\b(?:job openings?|jobs? roundup|career opportunities?|careers? roundup|we(?:'|’)re hiring|hiring now)\b", re.IGNORECASE),
    re.compile(r"\b(?:salary guide|resume tips?|interview tips?|how to get hired)\b", re.IGNORECASE),
    re.compile(r"\b(?:webinar|conference|summit|event registration|podcast episode)\b", re.IGNORECASE),
    re.compile(r"\b(?:training course|bootcamp|exam prep|certification training)\b", re.IGNORECASE),
)

# Strong primary-subject CTI signals. If one of these is present in the title
# or concise summary, it can override an incidental editorial term (for
# example, "Security conference website breached").
_PRIMARY_CTI_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}|zero[ -]?day|0[ -]?day|vulnerabilit(?:y|ies)|security flaw|"
    r"exploit(?:ed|ation)?|ransomware|malware|trojan|backdoor|infostealer|loader|botnet|"
    r"rootkit|wiper|data breach|breach notice|data leak|exfiltrat(?:e|ed|ion)|phishing|"
    r"intrusion|compromise(?:d)?|cyber attack|attack campaign|threat actor|APT\d*|"
    r"nation[ -]?state|supply[ -]?chain compromise|prompt injection|AI security|"
    r"incident response|security incident)\b",
    re.IGNORECASE,
)

_STRUCTURED_CTI_SOURCES = frozenset({
    "nvd", "cisa_kev", "cisa_advisory", "ransomware_intel", "breach_intel",
    "threat_actor_intel", "github_advisories", "msrc", "cisco_psirt",
})

_CANONICAL_HOSTS = {
    "blog.cyberdudebivash.in",
    "cti.cyberdudebivash.in",
}

_STRATEGIC_FAMILY_ORDER = (
    "zero_day",
    "malware",
    "ransomware",
    "breach",
    "campaign",
    "threat_analysis",
)

_STRATEGIC_FAMILIES = frozenset(_STRATEGIC_FAMILY_ORDER)


@dataclass(frozen=True)
class PublicationSelection:
    articles: list[DiscoveredArticle]
    metrics: dict


def candidate_discovery_limit(max_posts: int) -> int:
    """Return a bounded pre-scheduling candidate budget.

    ContentDiscoveryEngine historically truncates before the publisher sees
    the result. Running it with a wider *candidate* budget allows this module
    to enforce cross-family fairness while keeping enrichment/network work
    bounded. Own canonical RSS is merged separately, so a global-RSS burst
    cannot hide a just-generated first-party report.
    """
    requested = max(1, int(max_posts or 1))
    return min(100, max(50, requested * 10))


def is_canonical_report(article: DiscoveredArticle) -> bool:
    try:
        host = (urlparse(article.url).hostname or "").lower()
    except Exception:
        return False
    return host in _CANONICAL_HOSTS


def _text(article: DiscoveredArticle) -> str:
    return " ".join(
        str(part)
        for part in (
            article.title,
            article.summary,
            article.full_content or "",
            " ".join(str(label) for label in (article.labels or [])),
        )
        if part
    ).lower()


def primary_subject_text(article: DiscoveredArticle) -> str:
    """Return only fields that describe the article's primary subject.

    Long-form body text is intentionally excluded. A jobs roundup may mention
    malware analysis, threat hunting and incident response dozens of times in
    role descriptions; those mentions are not evidence that the article itself
    is malware or incident intelligence.
    """
    return " ".join(
        str(part)
        for part in (
            article.title,
            article.summary,
            " ".join(str(label) for label in (article.labels or [])),
        )
        if part
    ).lower()


def is_cti_relevant(article: DiscoveredArticle) -> bool:
    """Fail closed for obvious non-threat editorial content.

    This is deliberately conservative: structured CTI sources and explicit CVE
    records always remain eligible, and ambiguous security research remains
    eligible for downstream ReportX/evidence validation. Only high-confidence
    non-threat primary subjects are rejected here.
    """
    source = str(article.source or "").strip().lower()
    if source in _STRUCTURED_CTI_SOURCES or article.cve_id:
        return True

    primary = primary_subject_text(article)
    title = str(article.title or "")
    has_cti_subject = bool(_PRIMARY_CTI_RE.search(primary))
    if any(pattern.search(title) for pattern in _NON_THREAT_PRIMARY_PATTERNS):
        return has_cti_subject
    return True


def _cves(article: DiscoveredArticle) -> set[str]:
    values = {match.upper() for match in _CVE_RE.findall(_text(article))}
    if article.cve_id:
        values.add(str(article.cve_id).upper())
    return values


def classify_publication_family(article: DiscoveredArticle) -> str:
    """Map an article to the scheduler's commercial delivery family.

    The classifier deliberately uses only evidence already present on the
    discovered article. It does not infer a malware family from unrelated
    metadata and it does not change ReportX's own publication-family label.
    """
    text = primary_subject_text(article)
    source = str(article.source or "").lower()

    if re.search(r"\b(?:zero[ -]?day|0[ -]?day)\b", text):
        return "zero_day"
    if source == "ransomware_intel" or "ransomware" in text:
        return "ransomware"
    if source == "breach_intel" or re.search(
        r"\b(?:data breach|breach notice|data exposure|data leak|exfiltrat(?:e|ed|ion))\b",
        text,
    ):
        return "breach"
    if re.search(
        r"\b(?:malware|trojan|backdoor|infostealer|information stealer|loader|botnet|rootkit|wiper)\b",
        text,
    ):
        return "malware"
    if source == "threat_actor_intel" or re.search(
        r"\b(?:campaign|threat actor|apt\d*|nation[ -]?state|intrusion set|cluster)\b",
        text,
    ):
        return "campaign"

    # Vulnerability lane comes after explicit zero-day/malware/campaign
    # semantics so a CVE-backed active campaign can still reach the strategic
    # reserve rather than being reduced to a generic vulnerability record.
    if source in {"nvd", "cisa_kev"} or article.cve_id or _CVE_RE.search(text):
        return "vulnerability"
    if source == "cisa_advisory" and not re.search(
        r"\b(?:malware|campaign|ransomware|breach|threat actor|apt\d*)\b",
        text,
    ):
        return "vulnerability"

    return "threat_analysis"


def _normalised_title(article: DiscoveredArticle) -> str:
    return _NON_WORD_RE.sub(" ", str(article.title or "").lower()).strip()


def _published_epoch(article: DiscoveredArticle) -> float:
    raw = str(article.published_at or "").strip()
    if not raw:
        return 0.0
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return 0.0


def _priority_key(article: DiscoveredArticle) -> tuple[int, float, str]:
    # `sorted(..., reverse=True)` => canonical first, then newest.
    return (
        1 if is_canonical_report(article) else 0,
        _published_epoch(article),
        str(article.content_hash or ""),
    )


def _identity(article: DiscoveredArticle) -> tuple[str, str]:
    return (str(article.content_hash or ""), str(article.url or ""))


def _dedupe_fresh(articles: list[DiscoveredArticle]) -> list[DiscoveredArticle]:
    """Dedupe without suppressing a material CISA KEV update.

    Canonical reports are considered before external candidates. Exact URL,
    hash, and normalised-title duplicates collapse. A canonical report for a
    CVE also suppresses an NVD duplicate for that CVE, but never suppresses a
    CISA KEV record because KEV is a distinct exploitation-status update.
    """
    ordered = sorted(
        enumerate(articles),
        key=lambda pair: (1 if is_canonical_report(pair[1]) else 0, -pair[0]),
        reverse=True,
    )
    canonical_cves: set[str] = set()
    for _, article in ordered:
        if is_canonical_report(article):
            canonical_cves.update(_cves(article))

    seen_hashes: set[str] = set()
    seen_urls: set[str] = set()
    seen_titles: set[str] = set()
    result: list[DiscoveredArticle] = []

    for _, article in ordered:
        if not is_cti_relevant(article):
            continue
        content_hash = str(article.content_hash or "").strip()
        url = str(article.url or "").strip().lower()
        title = _normalised_title(article)

        if content_hash and content_hash in seen_hashes:
            continue
        if url and url in seen_urls:
            continue
        if title and title in seen_titles:
            continue
        if str(article.source or "").lower() == "nvd" and (_cves(article) & canonical_cves):
            continue

        result.append(article)
        if content_hash:
            seen_hashes.add(content_hash)
        if url:
            seen_urls.add(url)
        if title:
            seen_titles.add(title)

    return result


def _remove_retry_duplicates(
    retry_articles: list[DiscoveredArticle],
    fresh_articles: list[DiscoveredArticle],
) -> list[DiscoveredArticle]:
    fresh_hashes = {str(a.content_hash or "").strip() for a in fresh_articles}
    fresh_urls = {str(a.url or "").strip().lower() for a in fresh_articles}
    fresh_titles = {_normalised_title(a) for a in fresh_articles}

    result: list[DiscoveredArticle] = []
    seen: set[tuple[str, str, str]] = set()
    for article in retry_articles:
        if not is_cti_relevant(article):
            continue
        content_hash = str(article.content_hash or "").strip()
        url = str(article.url or "").strip().lower()
        title = _normalised_title(article)
        if content_hash in fresh_hashes or url in fresh_urls or (title and title in fresh_titles):
            continue
        identity = (content_hash, url, title)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(article)
    return result


def _round_robin_strategic(
    articles: list[DiscoveredArticle],
    count: int,
) -> list[DiscoveredArticle]:
    groups: dict[str, list[DiscoveredArticle]] = defaultdict(list)
    for article in articles:
        groups[classify_publication_family(article)].append(article)
    for family in groups:
        groups[family].sort(key=_priority_key, reverse=True)

    selected: list[DiscoveredArticle] = []
    while len(selected) < count:
        progressed = False
        for family in _STRATEGIC_FAMILY_ORDER:
            bucket = groups.get(family) or []
            if bucket:
                selected.append(bucket.pop(0))
                progressed = True
                if len(selected) >= count:
                    break
        if not progressed:
            break
    return selected


def _balanced_select(pool: list[DiscoveredArticle], slots: int) -> list[DiscoveredArticle]:
    if slots <= 0 or not pool:
        return []

    unique = _dedupe_fresh(pool)
    strategic = [a for a in unique if classify_publication_family(a) in _STRATEGIC_FAMILIES]
    vulnerability = [a for a in unique if classify_publication_family(a) == "vulnerability"]

    # If enough strategic intelligence exists, vulnerability-only records may
    # consume at most 40% of this sub-batch. If strategic supply is low, the
    # unused reserve is returned immediately to preserve publication throughput.
    strategic_target = min(len(strategic), math.ceil(slots * 0.60))
    selected = _round_robin_strategic(strategic, strategic_target)
    selected_ids = {id(a) for a in selected}

    vulnerability.sort(key=_priority_key, reverse=True)
    vulnerability_capacity = slots - len(selected)
    selected.extend(vulnerability[:vulnerability_capacity])

    # Fill any capacity left by a thin vulnerability lane with additional
    # strategic items, preserving family diversity and canonical priority.
    if len(selected) < slots:
        strategic_remaining = [a for a in strategic if id(a) not in selected_ids]
        selected.extend(_round_robin_strategic(strategic_remaining, slots - len(selected)))

    # Defensive final fill for future classifier families.
    if len(selected) < slots:
        selected_keys = {_identity(a) for a in selected}
        remaining = [a for a in unique if _identity(a) not in selected_keys]
        remaining.sort(key=_priority_key, reverse=True)
        selected.extend(remaining[: slots - len(selected)])

    return selected[:slots]


def _without_selected(
    pool: list[DiscoveredArticle],
    selected: list[DiscoveredArticle],
) -> list[DiscoveredArticle]:
    selected_keys = {_identity(a) for a in selected}
    return [article for article in pool if _identity(article) not in selected_keys]


def _enforce_global_strategic_reserve(
    selected: list[DiscoveredArticle],
    fresh: list[DiscoveredArticle],
    retry: list[DiscoveredArticle],
    max_posts: int,
) -> list[DiscoveredArticle]:
    """Enforce the 60% strategic reserve across both origin lanes.

    Fresh and retry quotas are selected independently first. Without this
    final cross-lane pass, a two-item vulnerability retry allocation could
    dilute a three-item fresh batch from 60% strategic to only 40% strategic.
    Replacement prefers unselected *fresh* strategic intelligence and evicts
    retry vulnerability records before fresh ones, preserving the fresh floor.
    """
    if not selected:
        return selected

    all_candidates = fresh + retry
    strategic_candidates = [
        article
        for article in all_candidates
        if classify_publication_family(article) in _STRATEGIC_FAMILIES
    ]
    target = min(len(strategic_candidates), math.ceil(max_posts * 0.60), len(selected))
    current = sum(
        1 for article in selected
        if classify_publication_family(article) in _STRATEGIC_FAMILIES
    )
    deficit = target - current
    if deficit <= 0:
        return selected

    selected_keys = {_identity(article) for article in selected}
    replacement_fresh = [
        article for article in fresh
        if _identity(article) not in selected_keys
        and classify_publication_family(article) in _STRATEGIC_FAMILIES
    ]
    replacement_retry = [
        article for article in retry
        if _identity(article) not in selected_keys
        and classify_publication_family(article) in _STRATEGIC_FAMILIES
    ]
    replacement_fresh.sort(key=_priority_key, reverse=True)
    replacement_retry.sort(key=_priority_key, reverse=True)
    replacements = replacement_fresh + replacement_retry

    retry_keys = {_identity(article) for article in retry}
    victims = [
        (index, article)
        for index, article in enumerate(selected)
        if classify_publication_family(article) == "vulnerability"
    ]
    # Evict retry vulnerability items first; within an origin lane evict
    # non-canonical/older items before canonical/newer ones.
    victims.sort(
        key=lambda pair: (
            0 if _identity(pair[1]) in retry_keys else 1,
            1 if is_canonical_report(pair[1]) else 0,
            _published_epoch(pair[1]),
        )
    )

    for replacement, (index, _) in zip(replacements[:deficit], victims[:deficit]):
        selected[index] = replacement

    return selected


def select_publication_batch(
    retry_articles: list[DiscoveredArticle],
    fresh_articles: list[DiscoveredArticle],
    max_posts: int,
) -> PublicationSelection:
    """Select a quota-safe, commercially balanced Blogger publication batch."""
    max_posts = max(0, int(max_posts or 0))
    if max_posts == 0:
        return PublicationSelection([], {
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
        })

    fresh_relevance_blocked = sum(1 for article in fresh_articles if not is_cti_relevant(article))
    retry_relevance_blocked = sum(1 for article in retry_articles if not is_cti_relevant(article))
    fresh = _dedupe_fresh(list(fresh_articles))
    retry = _remove_retry_duplicates(list(retry_articles), fresh)

    if fresh:
        retry_cap = min(2, max_posts // 2)
        fresh_floor = max_posts - retry_cap
    else:
        retry_cap = max_posts
        fresh_floor = 0

    fresh_selected = _balanced_select(fresh, min(fresh_floor, len(fresh)))
    retry_selected = _balanced_select(retry, min(retry_cap, len(retry)))
    selected = fresh_selected + retry_selected

    # Preserve throughput. Fresh work gets first refusal on unused capacity;
    # only after it is exhausted may retries exceed the normal retry cap.
    if len(selected) < max_posts:
        fresh_remaining = _without_selected(fresh, fresh_selected)
        extra_fresh = _balanced_select(fresh_remaining, max_posts - len(selected))
        fresh_selected.extend(extra_fresh)
        selected.extend(extra_fresh)

    if len(selected) < max_posts:
        retry_remaining = _without_selected(retry, retry_selected)
        extra_retry = _balanced_select(retry_remaining, max_posts - len(selected))
        retry_selected.extend(extra_retry)
        selected.extend(extra_retry)

    selected = _enforce_global_strategic_reserve(
        selected[:max_posts], fresh, retry, max_posts
    )
    families = Counter(classify_publication_family(a) for a in selected)
    sources = Counter(str(a.source or "unknown") for a in selected)
    fresh_keys = {_identity(article) for article in fresh}
    retry_keys = {_identity(article) for article in retry}

    metrics = {
        "candidate_count": len(fresh) + len(retry),
        "fresh_candidates": len(fresh),
        "retry_candidates": len(retry),
        "relevance_blocked": fresh_relevance_blocked + retry_relevance_blocked,
        "fresh_relevance_blocked": fresh_relevance_blocked,
        "retry_relevance_blocked": retry_relevance_blocked,
        "fresh_selected": sum(1 for a in selected if _identity(a) in fresh_keys),
        "retry_selected": sum(1 for a in selected if _identity(a) in retry_keys),
        "strategic_selected": sum(
            1 for a in selected if classify_publication_family(a) in _STRATEGIC_FAMILIES
        ),
        "vulnerability_selected": sum(
            1 for a in selected if classify_publication_family(a) == "vulnerability"
        ),
        "canonical_selected": sum(1 for a in selected if is_canonical_report(a)),
        "selected_families": dict(sorted(families.items())),
        "selected_sources": dict(sorted(sources.items())),
    }
    return PublicationSelection(selected, metrics)
