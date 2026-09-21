"""SENTINEL APEX evidence-safe Rapid Intelligence publication lane v19.3.

P0 production recovery for the 2026-09-07 Blogger freshness outage.

The premium 2,200-word / 18-paragraph / 18-list-item contract is a commercial
long-form product gate, not an evidence-integrity gate. Production was coupling
that premium contract to every Blogger publication and therefore withholding
fresh, source-backed intelligence even when the underlying ReportX integrity
controls passed.

v19.3 separates the two concerns without weakening either one:

* authoritative/direct-source and first-party canonical intelligence can take a
  RAPID_INTELLIGENCE lane;
* Rapid Intelligence still executes AuthorityTransformer's complete ReportX
  evidence graph, contradiction, exploitation, quantitative-claim, artifact
  binding, Dossier v8, v19.1 and v19.2 fail-closed controls;
* only PremiumAuthorityTransformer's *additional* long-form structural gate is
  not applied to the rapid lane;
* the rapid lane deliberately bypasses external LLM generation and uses the
  deterministic evidence compiler / renderer, preserving scarce free-provider
  quota for premium dossiers;
* Blogger fetch-back remains fail-closed, but rapid artifacts are verified
  against a distinct rapid-product floor rather than the premium 2,200-word
  floor;
* premium candidates continue through the unchanged premium transformer and
  unchanged premium Blogger verification path.

This module must install strictly after v19.2 so the current v8 repair-before-
fail-closed chain remains authoritative.
"""
from __future__ import annotations

from collections import Counter
from contextvars import ContextVar
import os
import re
import time
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from . import authority_transformer as _authority
from . import cti_dossier_v8 as _v8
from . import cti_publication_recovery_v19_2 as _v19_2
from . import premium_publication as _premium
from . import rss_aggregator as _rss
from .blogger_publisher import BloggerPublisher
from .content_discovery import DiscoveredArticle
from .logger import setup_logger

logger = setup_logger("rapid_intel_lane_v19_3")

MARKER = "CDB-RAPID-INTEL-LANE-V19-3"
RAPID_LABEL = "Rapid Intelligence"
RAPID_QUALITY_BAND = "RAPID_INTELLIGENCE_VERIFIED"
RAPID_MIN_VISIBLE_WORDS = 700
RAPID_MIN_DISTINCT_HEADINGS = 6
RAPID_MIN_SOURCE_WORDS = 24
# Named publishers from the hand-maintained GlobalRSSAggregator feed set can
# use the rapid lane only when the feed itself supplies materially richer
# source evidence. This closes the malware/campaign delivery gap during LLM
# quota saturation without treating an anonymous RSS connector as a publisher.
RAPID_MIN_CURATED_RSS_SOURCE_WORDS = 80
_CURATED_RSS_PUBLISHERS = frozenset(
    str(feed.name or "").strip().casefold()
    for feed in _rss._GLOBAL_FEEDS
    if str(feed.name or "").strip()
)

_AUTHORITATIVE_CONNECTORS = frozenset({
    "nvd",
    "cisa_kev",
    "cisa_advisory",
    "ransomware_intel",
    "breach_intel",
})
_FIRST_PARTY_HOSTS = frozenset({
    "blog.cyberdudebivash.in",
    "cti.cyberdudebivash.in",
    "intel.cyberdudebivash.com",
})
_AUTHORITATIVE_HOSTS = frozenset({
    "nvd.nist.gov",
    "cisa.gov",
    "www.cisa.gov",
})

_RAPID_ACTIVE: ContextVar[bool] = ContextVar("cdb_rapid_intel_active", default=False)
_INSTALL_ATTR = "__cdb_rapid_intel_lane_v19_3__"
_ORIGINAL_AUTHORITY_LLM: Optional[Callable] = None
_ORIGINAL_V8_GATE: Optional[Callable] = None
_ORIGINAL_WRITE_RUN_REPORT: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "rapid_eligible": 0,
    "rapid_transformed": 0,
    "premium_routed": 0,
    "provider_calls_bypassed": 0,
    "rapid_published": 0,
    "rapid_fetchback_verified": 0,
    "rapid_fetchback_repaired": 0,
    "rapid_reverted_to_draft": 0,
    "cross_node_blocks_scrubbed": 0,
    "cross_node_repair_classes": Counter(),
    "eligibility_reasons": Counter(),
}


def _enabled() -> bool:
    value = os.getenv("CDB_RAPID_INTEL_ENABLED", "true").strip().lower()
    return value not in {"0", "false", "off", "no"}


def _source_words(article: DiscoveredArticle) -> int:
    raw = str(article.full_content or article.summary or "")
    soup = BeautifulSoup(raw, "html.parser")
    text = " ".join(soup.stripped_strings)
    return len(re.findall(r"\b[\w][\w'./:+-]*\b", text, flags=re.UNICODE))


def rapid_lane_eligibility(article: DiscoveredArticle) -> tuple[bool, str]:
    """Return whether an article may use the rapid product lane.

    Eligibility is intentionally narrow. It does *not* make an article
    publishable by itself; the full base AuthorityTransformer integrity chain
    still decides that. This classifier only decides whether a candidate that
    passes those hard controls must additionally satisfy the premium long-form
    structural contract.
    """
    if not _enabled():
        return False, "disabled"

    try:
        parsed = urlsplit(str(article.url or ""))
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return False, "invalid_url"
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return False, "invalid_url"

    if _source_words(article) < RAPID_MIN_SOURCE_WORDS:
        return False, "source_too_thin"

    source = str(article.source or "").strip().lower()
    if source in _AUTHORITATIVE_CONNECTORS:
        return True, f"authoritative_connector:{source}"
    if host in _FIRST_PARTY_HOSTS:
        return True, f"first_party_canonical:{host}"
    if host in _AUTHORITATIVE_HOSTS and (article.cve_id or source.startswith("cisa") or source == "nvd"):
        return True, f"authoritative_host:{host}"

    # P0-DAILY-THREAT-COVERAGE-2026-09-21:
    # Malware/campaign/threat-analysis reports are primarily discovered through
    # the repository's curated global RSS publisher list. Requiring premium LLM
    # capacity for every one of those candidates allowed provider TPD saturation
    # to starve those paid-customer report classes while structured CVEs kept
    # flowing. A named RSS publisher may therefore use Rapid Intelligence when
    # the feed provides >=80 visible source words. The complete base ReportX /
    # Dossier fail-closed chain still runs; this only bypasses the *additional*
    # premium long-form structural/LLM dependency.
    if source == "global_rss":
        publisher = str(article.source_publisher or "").strip()
        publisher_key = publisher.casefold()
        if (
            publisher_key in _CURATED_RSS_PUBLISHERS
            and _source_words(article) >= RAPID_MIN_CURATED_RSS_SOURCE_WORDS
        ):
            return True, f"curated_rss:{publisher}"

    return False, "premium_default"


def _lane_aware_call_llm(*args, **kwargs):
    """Reserve provider capacity by making rapid publication deterministic."""
    if _RAPID_ACTIVE.get():
        _RUNTIME["provider_calls_bypassed"] += 1
        return None
    if _ORIGINAL_AUTHORITY_LLM is None:
        raise RuntimeError("v19.3 LLM routing wrapper is not installed")
    return _ORIGINAL_AUTHORITY_LLM(*args, **kwargs)


setattr(_lane_aware_call_llm, _INSTALL_ATTR, True)


def _with_rapid_label(labels: list) -> list:
    values = [str(value) for value in (labels or []) if str(value).strip()]
    if RAPID_LABEL not in values:
        values.append(RAPID_LABEL)
    # Blogger allows at most 20 labels. Preserve the rapid product identity even
    # when the source already arrived with 20 labels.
    if len(values) > 20:
        values = values[:19] + [RAPID_LABEL]
    return values


class RapidAwareAuthorityTransformer(_premium.PremiumAuthorityTransformer):
    """Route eligible intelligence around only the premium structural gate."""

    def transform(self, article: DiscoveredArticle) -> dict:
        eligible, reason = rapid_lane_eligibility(article)
        if not eligible:
            _RUNTIME["premium_routed"] += 1
            return super().transform(article)

        _RUNTIME["rapid_eligible"] += 1
        _RUNTIME["eligibility_reasons"][reason] += 1
        original_labels = list(article.labels or [])
        token = _RAPID_ACTIVE.set(True)
        try:
            article.labels = _with_rapid_label(original_labels)
            # Deliberately call the base transformer, not PremiumAuthorityTransformer.
            # The base transformer is where all ReportX / Dossier integrity gates,
            # contradiction handling and certified-artifact hashing execute. The
            # only skipped control is PremiumAuthorityTransformer's additional
            # 2200/18/18 long-form product gate.
            transformed = _authority.AuthorityTransformer.transform(self, article)
        finally:
            article.labels = original_labels
            _RAPID_ACTIVE.reset(token)

        transformed["labels"] = _with_rapid_label(list(transformed.get("labels") or []))
        transformed["publication_lane"] = "RAPID_INTELLIGENCE"
        transformed["public_quality_band"] = RAPID_QUALITY_BAND
        transformed["rapid_public_ready"] = True
        transformed["enterprise_public_ready"] = False
        transformed["rapid_lane_reason"] = reason
        transformed["rapid_provider_generation_bypassed"] = True
        _RUNTIME["rapid_transformed"] += 1
        logger.info(
            "Evidence-safe Rapid Intelligence candidate passed base publication gates",
            extra={
                "marker": MARKER,
                "title": article.title[:80],
                "reason": reason,
                "content_source": transformed.get("content_source"),
                "product_tier": transformed.get("product_tier"),
                "achieved_tier": transformed.get("achieved_tier"),
            },
        )
        return transformed



def _rapid_live_assessment(
    live_post: dict,
    intended_title: str,
    intended_content: str,
    intended_labels: list[str],
) -> _premium.LiveArtifactAssessment:
    live_content = str(live_post.get("content") or "")
    live_title = str(live_post.get("title") or "")
    live_labels = {str(value) for value in (live_post.get("labels") or [])}
    expected_labels = {str(value) for value in intended_labels}
    defects: list[str] = []

    if live_title != intended_title:
        defects.append("title_mismatch")
    if live_labels != expected_labels:
        defects.append("labels_mismatch")
    if RAPID_LABEL not in live_labels:
        defects.append("rapid_lane_label_missing")

    expected_words = _premium._word_count(intended_content)
    live_words = _premium._word_count(live_content)
    word_retention = (live_words / expected_words) if expected_words else 0.0
    if expected_words and word_retention < _premium.MIN_WORD_RETENTION:
        defects.append(f"word_retention_below_{_premium.MIN_WORD_RETENTION:.2f}")
    if live_words < RAPID_MIN_VISIBLE_WORDS:
        defects.append("live_copy_below_rapid_word_floor")

    expected_headings = {
        _premium._normalized_heading(value)
        for value in _premium._headings(intended_content)
    }
    live_headings = {
        _premium._normalized_heading(value)
        for value in _premium._headings(live_content)
    }
    heading_retention = (
        len(expected_headings & live_headings) / len(expected_headings)
        if expected_headings else 1.0
    )
    if len(live_headings) < RAPID_MIN_DISTINCT_HEADINGS:
        defects.append("live_copy_below_rapid_heading_floor")
    if heading_retention < _premium.MIN_HEADING_RETENTION:
        defects.append(f"heading_retention_below_{_premium.MIN_HEADING_RETENTION:.2f}")

    for marker, defect in (
        ('data-report-id="CDB-CTI-', "provenance_marker_stripped"),
        ("CDB_SOURCE_URL:", "source_url_marker_stripped"),
    ):
        if marker in intended_content and marker not in live_content:
            defects.append(defect)

    return _premium.LiveArtifactAssessment(
        verified=not defects,
        defects=tuple(sorted(set(defects))),
        exact_content_match=(live_content == intended_content),
        expected_words=expected_words,
        live_words=live_words,
        word_retention=word_retention,
        heading_retention=heading_retention,
    )


class RapidAwareVerifiedBloggerPublisher(_premium.VerifiedBloggerPublisher):
    """Keep premium fetch-back unchanged; use a distinct floor for rapid CTI."""

    def publish_post(
        self,
        title: str,
        content: str,
        labels: list[str],
        is_draft: bool = False,
        image_url: Optional[str] = None,
    ) -> dict:
        if RAPID_LABEL not in {str(value) for value in labels}:
            return super().publish_post(
                title=title,
                content=content,
                labels=labels,
                is_draft=is_draft,
                image_url=image_url,
            )

        # Call the proven Blogger API publisher directly. Calling super() here
        # would invoke the premium 2,200-word fetch-back floor before we can apply
        # the intentionally distinct rapid-product verification contract.
        post = BloggerPublisher.publish_post(
            self,
            title=title,
            content=content,
            labels=labels,
            is_draft=is_draft,
            image_url=image_url,
        )
        if is_draft:
            return post

        post_id = str(post.get("id") or "")
        if not post_id:
            raise _premium.BloggerPublishError(
                "Blogger create response did not include a post id; rapid live artifact cannot be verified"
            )

        last: Optional[_premium.LiveArtifactAssessment] = None
        repaired = False
        for attempt in range(_premium.VERIFY_ATTEMPTS):
            if attempt:
                time.sleep(_premium.VERIFY_DELAY_SECONDS * attempt)
            live = self.get_post(post_id)
            last = _rapid_live_assessment(live, title, content, labels)
            if last.verified:
                _RUNTIME["rapid_published"] += 1
                _RUNTIME["rapid_fetchback_verified"] += 1
                logger.info(
                    "Blogger Rapid Intelligence artifact fetch-back verified",
                    extra={
                        "marker": MARKER,
                        "post_id": post_id,
                        "exact_content_match": last.exact_content_match,
                        "word_retention": round(last.word_retention, 4),
                        "heading_retention": round(last.heading_retention, 4),
                        "repaired": repaired,
                    },
                )
                return post
            if not repaired:
                self._repair_post(post_id, title, content, labels, image_url, last.defects)
                repaired = True
                _RUNTIME["rapid_fetchback_repaired"] += 1

        defects = list(last.defects if last else ("fetch_back_not_evaluated",))
        self._revert_to_draft(post_id)
        _RUNTIME["rapid_reverted_to_draft"] += 1
        raise _premium.BloggerPublishError(
            "Blogger live Rapid Intelligence artifact failed fetch-back verification after bounded repair; "
            f"post {post_id} was reverted to draft; defects={defects}"
        )


def _repair_cross_node_prompt_leakage(soup: BeautifulSoup) -> int:
    """Close v19.2's cross-node/code/pre leakage gap without weakening v8.

    v8 evaluates one flattened visible-text stream. v19.2 originally repaired
    individual NavigableString nodes and deliberately skipped code/pre, so a
    phrase split by inline markup (``<strong>Let me</strong> write``) or placed
    in a visible code/pre node could survive repair and then be correctly blocked
    by v8. For a block containing an already-recognized v19.2 scratch signature,
    this pass reconstructs only that block's visible text, removes only the same
    bounded signatures, and then lets v19.2 + the original v8 gate re-check the
    complete artifact. Unknown leakage remains fail-closed.
    """
    changed = 0
    aggregate: Counter = Counter()
    containers = ("p", "li", "blockquote", "td", "th", "pre", "code", "h1", "h2", "h3", "h4", "h5", "h6")

    for tag in list(soup.find_all(containers)):
        if tag.parent is None:
            continue
        combined = re.sub(r"\s+", " ", tag.get_text(" ", strip=False)).strip()
        if not combined:
            continue
        cleaned, repairs = _v19_2._clean_text_node(combined)
        if not repairs:
            continue
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        tag.clear()
        if cleaned:
            tag.append(cleaned)
        else:
            tag.decompose()
        changed += 1
        aggregate.update(repairs)

    if changed:
        _RUNTIME["cross_node_blocks_scrubbed"] += changed
        _RUNTIME["cross_node_repair_classes"].update(aggregate)
    return changed


def _v19_3_v8_gate(soup: BeautifulSoup) -> None:
    if _ORIGINAL_V8_GATE is None:
        raise RuntimeError("v19.3 residual prompt-recovery wrapper is not installed")
    _repair_cross_node_prompt_leakage(soup)
    # The current gate here is v19.2's wrapper, which itself runs its narrow
    # node-level repair and then the original v8 fail-closed gate. This call is
    # mandatory; v19.3 never converts an unresolved prompt leak into a pass.
    _ORIGINAL_V8_GATE(soup)


setattr(_v19_3_v8_gate, _INSTALL_ATTR, True)


def telemetry_snapshot() -> dict:
    return {
        "version": "v19.3",
        "marker": MARKER,
        "enabled": _enabled(),
        "rapid_eligible": int(_RUNTIME["rapid_eligible"]),
        "rapid_transformed": int(_RUNTIME["rapid_transformed"]),
        "premium_routed": int(_RUNTIME["premium_routed"]),
        "provider_calls_bypassed": int(_RUNTIME["provider_calls_bypassed"]),
        "rapid_published": int(_RUNTIME["rapid_published"]),
        "rapid_fetchback_verified": int(_RUNTIME["rapid_fetchback_verified"]),
        "rapid_fetchback_repaired": int(_RUNTIME["rapid_fetchback_repaired"]),
        "rapid_reverted_to_draft": int(_RUNTIME["rapid_reverted_to_draft"]),
        "cross_node_blocks_scrubbed": int(_RUNTIME["cross_node_blocks_scrubbed"]),
        "cross_node_repair_classes": dict(_RUNTIME["cross_node_repair_classes"]),
        "eligibility_reasons": dict(_RUNTIME["eligibility_reasons"]),
        "rapid_min_visible_words": RAPID_MIN_VISIBLE_WORDS,
        "rapid_min_distinct_headings": RAPID_MIN_DISTINCT_HEADINGS,
        "premium_quality_floors_changed": False,
        "reportx_integrity_gates_changed": False,
        "v8_fail_closed_gate_preserved": True,
        "paid_provider_policy_changed": False,
        "pricing_changed": False,
        "billing_changed": False,
        "telemetry_contains_prompts": False,
        "telemetry_contains_response_content": False,
        "telemetry_contains_credentials": False,
        "telemetry_contains_pii": False,
    }


def _write_run_report(report: dict, logs_dir: str) -> None:
    if _ORIGINAL_WRITE_RUN_REPORT is None:
        raise RuntimeError("v19.3 run-report wrapper is not installed")
    report["rapid_intel_lane_v19_3"] = telemetry_snapshot()
    _ORIGINAL_WRITE_RUN_REPORT(report, logs_dir)


setattr(_write_run_report, _INSTALL_ATTR, True)


def install_rapid_intel_lane_v19_3(main_module) -> None:
    """Install the rapid-product lane strictly outside v19.2."""
    global _ORIGINAL_AUTHORITY_LLM, _ORIGINAL_V8_GATE, _ORIGINAL_WRITE_RUN_REPORT, _INSTALLED
    if _INSTALLED:
        return

    if main_module.AuthorityTransformer is not _premium.PremiumAuthorityTransformer:
        raise RuntimeError(
            "v19.3 requires PremiumAuthorityTransformer to be the active transformer before lane separation"
        )
    if main_module.BloggerPublisher is not _premium.VerifiedBloggerPublisher:
        raise RuntimeError(
            "v19.3 requires VerifiedBloggerPublisher to be the active publisher before lane separation"
        )

    current_llm = _authority.call_llm
    if not getattr(current_llm, _INSTALL_ATTR, False):
        _ORIGINAL_AUTHORITY_LLM = current_llm
        _authority.call_llm = _lane_aware_call_llm

    current_v8_gate = _v8._gate_customer_visible_integrity
    if not getattr(current_v8_gate, _INSTALL_ATTR, False):
        _ORIGINAL_V8_GATE = current_v8_gate
        _v8._gate_customer_visible_integrity = _v19_3_v8_gate
    else:
        raise RuntimeError("v19.3 v8 gate wrapper unexpectedly already present before installation")

    current_writer = main_module._write_run_report
    if not getattr(current_writer, _INSTALL_ATTR, False):
        _ORIGINAL_WRITE_RUN_REPORT = current_writer
        main_module._write_run_report = _write_run_report

    main_module.AuthorityTransformer = RapidAwareAuthorityTransformer
    main_module.BloggerPublisher = RapidAwareVerifiedBloggerPublisher

    if _authority.call_llm is not _lane_aware_call_llm:
        raise RuntimeError("v19.3 failed to bind rapid-aware provider routing")
    if _v8._gate_customer_visible_integrity is not _v19_3_v8_gate:
        raise RuntimeError("v19.3 failed to bind residual prompt-recovery wrapper")
    if main_module._write_run_report is not _write_run_report:
        raise RuntimeError("v19.3 failed to bind run-report telemetry")
    if main_module.AuthorityTransformer is not RapidAwareAuthorityTransformer:
        raise RuntimeError("v19.3 failed to bind rapid-aware transformer")
    if main_module.BloggerPublisher is not RapidAwareVerifiedBloggerPublisher:
        raise RuntimeError("v19.3 failed to bind rapid-aware Blogger verifier")

    _INSTALLED = True
    logger.info(
        "SENTINEL APEX evidence-safe Rapid Intelligence lane v19.3 installed",
        extra={
            "marker": MARKER,
            "rapid_min_visible_words": RAPID_MIN_VISIBLE_WORDS,
            "rapid_min_distinct_headings": RAPID_MIN_DISTINCT_HEADINGS,
            "premium_quality_floors_changed": False,
            "reportx_integrity_gates_changed": False,
            "v8_fail_closed_gate_preserved": True,
        },
    )
