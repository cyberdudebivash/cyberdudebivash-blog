"""SENTINEL APEX™ ASTRA Revenue Intelligence Engine v18.

Production objective
--------------------
Convert the existing evidence-first Intel Factory into a commercially optimized
publication system without weakening any ReportX, Dossier, source-provenance,
provider-budget, or Blogger fetch-back control.

v18 is deliberately additive and model-agnostic. It contributes four bounded
capabilities:

1. Commercial-value scheduling
   Rank candidates *within* the existing canonical/family/freshness policy by
   customer utility and productization potential. This score is internal only;
   it is never represented as threat severity, exploit probability, customer
   exposure, or financial impact.
2. ASTRA targeted continuation
   When a genuine LLM-authored candidate is close to, but below, the unchanged
   premium semantic contract, use the existing v16/v17 free-provider mesh for
   up to two evidence-bounded continuation passes. No gate is lowered and no
   deterministic filler can manufacture source depth.
3. Commercial entitlement presentation
   Surface the repository's already-enforced Free / API Starter / SOC Pro /
   Enterprise capabilities contextually inside the final dossier. This creates
   a conversion path without inventing a second billing or entitlement system.
4. Revenue/yield observability
   Persist only aggregate, non-secret telemetry: commercial-priority bands,
   continuation outcomes, and generated CTA recommendations. Browser click and
   conversion attribution remains owned by the existing conversion-engine.js +
   GA4 layer through UTM-tagged links.

Safety invariants
-----------------
- premium_publication.MIN_VISIBLE_WORDS / MIN_PARAGRAPHS / MIN_LIST_ITEMS and
  all ReportX/Dossier integrity controls remain authoritative and unchanged;
- only normalized public source evidence determines whether continuation is
  eligible; previously generated report prose is never promoted to raw evidence;
- continuation cannot introduce duplicate canonical headings, model scratchpad,
  prompt text, synthetic IOCs/CVEs/ATT&CK mappings, exploitation claims,
  attribution, remediation facts, or customer-specific exposure;
- v18 never changes ALLOW_PAID_LLM or provider credentials/routing policy;
- commercial priority is a delivery/business score, not a security/risk score;
- presentation is fail-open and deterministic; Dossier v8 remains the final
  fail-closed content-integrity authority before this presentation layer.
"""
from __future__ import annotations

import html as _html
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Tag

from . import authority_transformer as _authority
from . import generation_evidence_admission as _admission
from . import key_judgements as _key_judgements
from . import premium_capacity_allocator_v13 as _capacity
from . import premium_publication as _premium
from . import premium_yield_contract_guard as _yield
from . import publication_scheduler as _scheduler
from .logger import setup_logger

logger = setup_logger("astra_revenue_intelligence_v18")

MARKER = "CDB-ASTRA-REVENUE-INTELLIGENCE-V18"
PRESENTATION_MARKER = "CDB-ASTRA-COMMERCIAL-V18"
_INSTALL_ATTR = "__cdb_astra_revenue_v18__"
_PRESENTATION_ATTR = "__cdb_astra_revenue_presentation_v18__"

CONTINUATION_MAX_TOKENS = 1600
MAX_CONTINUATION_PASSES = 2
MIN_SOURCE_WORDS_FOR_CONTINUATION = 250
MIN_STRUCTURED_FIELDS_FOR_CONTINUATION = 4
MAX_PROMPT_CHARS = 52_000
MAX_EXISTING_BODY_CHARS = 18_000

PRICING_URL = "https://blog.cyberdudebivash.in/pricing.html"
API_DASHBOARD_URL = "https://blog.cyberdudebivash.in/api-dashboard.html"
API_DOCS_URL = "https://blog.cyberdudebivash.in/api.html"
ENTERPRISE_URL = "https://blog.cyberdudebivash.in/enterprise.html"

_INNER_AUTHORITY_CALL: Optional[Callable] = None
_CONTINUATION_CALL: Optional[Callable] = None
_INNER_SELECT: Optional[Callable] = None
_INNER_PRIORITY_KEY: Optional[Callable] = None
_INNER_WRITE_RUN_REPORT: Optional[Callable] = None
_INNER_ASSEMBLE_HTML: Optional[Callable] = None
_RUNTIME_INSTALLED = False
_PRESENTATION_INSTALLED = False

_RUNTIME = {
    "selection_runs": 0,
    "candidate_scores_computed": 0,
    "selected_scores_sum": 0,
    "selected_scores_count": 0,
    "selected_score_max": 0,
    "selected_bands": Counter(),
    "selected_readiness_bands": Counter(),
    "continuation_candidates": 0,
    "continuation_attempts": 0,
    "continuation_fragments": 0,
    "continuation_successes": 0,
    "continuation_provider_successes": Counter(),
    "continuation_skips": Counter(),
    "continuation_rejections": Counter(),
    "commercial_panels_rendered": 0,
    "recommended_tiers": Counter(),
}

_META_LEAK_RE = re.compile(
    r"(?:\bthe user wants\b|\bi need to\b|\bi should\b|\blet me (?:think|plan|draft)\b|"
    r"\bsystem (?:prompt|instruction|message)\b|\bdeveloper (?:prompt|instruction|message)\b|"
    r"\bchain[- ]of[- ]thought\b|\btoken budget\b|\bword count target\b)",
    re.IGNORECASE,
)

_VALUE_TERMS = (
    "indicator", "ioc", "sha256", "sha-256", "malware", "ransomware",
    "detection", "sigma", "yara", "campaign", "threat actor", "cve-",
)

_FAMILY_WEIGHT = {
    "zero_day": 28,
    "ransomware": 26,
    "malware": 24,
    "breach": 22,
    "campaign": 22,
    "vulnerability": 16,
    "threat_analysis": 10,
}


@dataclass(frozen=True)
class CommercialPriority:
    """Internal delivery priority; never a threat/customer risk score."""

    score: int
    band: str
    reasons: tuple[str, ...]
    family: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "band": self.band,
            "reasons": list(self.reasons),
            "family": self.family,
            "semantics": "commercial_delivery_priority_not_threat_risk",
        }


def _safe_float(value: object) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _published_age_hours(article: Any) -> Optional[float]:
    raw = str(getattr(article, "published_at", None) or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)
    return max(0.0, age.total_seconds() / 3600.0)


def generation_readiness(article: Any) -> tuple[int, int, int]:
    """Estimate whether source evidence can support the unchanged premium gate.

    This is a scheduling hint only. It never grants publication permission and
    never changes ReportX/premium quality thresholds. The intent is to spend a
    finite free-provider generation budget on the source-backed candidates most
    likely to survive the existing 2,200-word / 18-paragraph / 18-list-item
    contract instead of repeatedly transforming obviously thin inputs first.

    Returns (band, source_words, structured_fields), where higher is better.
    """
    try:
        source_words = int(_capacity._source_word_count(article))
    except Exception:
        source_words = 0
    try:
        structured = int(_capacity._structured_evidence_count(article))
    except Exception:
        structured = 0

    # Band 4 matches the capacity allocator provider-independent evidence
    # threshold. Lower bands preserve fallback supply; this is prioritization,
    # not filtering, so a thin but important source can still be attempted.
    if _capacity._provider_independent_candidate(article):
        band = 4
    elif source_words >= 1400 or (source_words >= 1000 and structured >= 6):
        band = 3
    elif source_words >= 800 or structured >= 6:
        band = 2
    elif source_words >= 350 or structured >= 4:
        band = 1
    else:
        band = 0
    return band, source_words, structured

def commercial_priority(article: Any) -> CommercialPriority:
    """Score finite publication capacity by customer/product utility.

    Every input is already present on DiscoveredArticle. No external inference,
    customer telemetry, or fabricated impact enters this calculation.
    """
    family = _scheduler.classify_publication_family(article)
    score = int(_FAMILY_WEIGHT.get(family, 10))
    reasons: list[str] = [f"family:{family}"]

    try:
        source_words = int(_capacity._source_word_count(article))
    except Exception:
        source_words = 0
    if source_words >= 1800:
        score += 18
        reasons.append("source_depth:very_high")
    elif source_words >= 1200:
        score += 14
        reasons.append("source_depth:high")
    elif source_words >= 700:
        score += 9
        reasons.append("source_depth:medium")
    elif source_words >= 350:
        score += 5
        reasons.append("source_depth:usable")

    try:
        structured = int(_capacity._structured_evidence_count(article))
    except Exception:
        structured = 0
    if structured:
        score += min(12, structured * 2)
        reasons.append(f"structured_fields:{structured}")

    if getattr(article, "kev_listed", None) is True:
        score += 14
        reasons.append("kev:confirmed")

    cvss = _safe_float(getattr(article, "cvss_score", None))
    if cvss is not None:
        if cvss >= 9.0:
            score += 8
            reasons.append("cvss:critical")
        elif cvss >= 7.0:
            score += 5
            reasons.append("cvss:high")

    epss = _safe_float(getattr(article, "epss_score", None))
    if epss is not None:
        if epss >= 0.50:
            score += 8
            reasons.append("epss:very_high")
        elif epss >= 0.10:
            score += 5
            reasons.append("epss:high")
        elif epss >= 0.01:
            score += 2
            reasons.append("epss:present")

    age_hours = _published_age_hours(article)
    if age_hours is not None:
        if age_hours <= 24:
            score += 10
            reasons.append("freshness:<24h")
        elif age_hours <= 72:
            score += 6
            reasons.append("freshness:<72h")
        elif age_hours <= 168:
            score += 3
            reasons.append("freshness:<7d")

    if _scheduler.is_canonical_report(article):
        # Canonical still owns the first element of the scheduler tuple. This
        # small score bonus only distinguishes canonical candidates from peers.
        score += 3
        reasons.append("canonical:first_party_handoff")

    raw = str(getattr(article, "full_content", None) or getattr(article, "summary", "") or "").lower()
    value_hits = sum(1 for term in _VALUE_TERMS if term in raw)
    if value_hits:
        score += min(5, value_hits)
        reasons.append(f"productizable_evidence_signals:{min(5, value_hits)}")

    score = max(0, min(100, int(score)))
    band = "P0" if score >= 75 else "P1" if score >= 60 else "P2" if score >= 40 else "P3"
    _RUNTIME["candidate_scores_computed"] += 1
    return CommercialPriority(score, band, tuple(reasons), family)


def _astra_priority_key(article: Any):
    if _INNER_PRIORITY_KEY is None:
        raise RuntimeError("ASTRA v18 scheduler priority is not installed")
    base = _INNER_PRIORITY_KEY(article)
    priority = commercial_priority(article)
    readiness_band, source_words, structured = generation_readiness(article)
    # Preserve the proven scheduler invariant: canonical first. Inside that
    # trust lane, generation feasibility comes before commercial score so the
    # hourly factory spends scarce transformation/provider work on evidence
    # capable of meeting the unchanged premium semantic contract. No candidate
    # is filtered or promoted past the publication gate by this ordering.
    evidence_density = min(9999, source_words) + min(99, structured) * 100
    if isinstance(base, tuple) and len(base) >= 3:
        return (base[0], readiness_band, evidence_density, priority.score, *base[1:])
    return (
        0,
        readiness_band,
        evidence_density,
        priority.score,
        0.0,
        str(getattr(article, "content_hash", "") or ""),
    )


def _astra_select_publication_batch(retry_articles, fresh_articles, max_posts: int):
    if _INNER_SELECT is None:
        raise RuntimeError("ASTRA v18 selection wrapper is not installed")
    selection = _INNER_SELECT(retry_articles, fresh_articles, max_posts)
    _RUNTIME["selection_runs"] += 1

    priorities = [commercial_priority(article) for article in selection.articles]
    readiness = [generation_readiness(article) for article in selection.articles]
    scores = [item.score for item in priorities]
    bands = Counter(item.band for item in priorities)
    readiness_bands = Counter(f"R{item[0]}" for item in readiness)
    for item in priorities:
        _RUNTIME["selected_bands"][item.band] += 1
    for band, count in readiness_bands.items():
        _RUNTIME["selected_readiness_bands"][band] += count
    if scores:
        _RUNTIME["selected_scores_sum"] += sum(scores)
        _RUNTIME["selected_scores_count"] += len(scores)
        _RUNTIME["selected_score_max"] = max(int(_RUNTIME["selected_score_max"]), max(scores))

    metrics = dict(selection.metrics)
    metrics.update({
        "astra_revenue_v18": True,
        "commercial_priority_semantics": "delivery_value_not_threat_risk",
        "commercial_selected_average": round(sum(scores) / len(scores), 2) if scores else 0.0,
        "commercial_selected_max": max(scores) if scores else 0,
        "commercial_priority_bands": dict(sorted(bands.items())),
        "generation_readiness_bands": dict(sorted(readiness_bands.items())),
        "generation_readiness_semantics": "source_evidence_feasibility_not_publication_permission",
    })
    return _scheduler.PublicationSelection(list(selection.articles), metrics)


def _active_article() -> Any:
    try:
        return _admission._CURRENT_ARTICLE.get()
    except Exception:
        return None


def _source_evidence_sufficient(article: Any) -> bool:
    try:
        words = int(_capacity._source_word_count(article))
    except Exception:
        words = 0
    try:
        structured = int(_capacity._structured_evidence_count(article))
    except Exception:
        structured = 0
    return words >= MIN_SOURCE_WORDS_FOR_CONTINUATION or structured >= MIN_STRUCTURED_FIELDS_FOR_CONTINUATION


def _fragment_headings(fragment: str) -> set[str]:
    soup = BeautifulSoup(fragment or "", "html.parser")
    result: set[str] = set()
    for node in soup.find_all(["h2", "h3"]):
        label = " ".join(node.stripped_strings).strip()
        if label:
            try:
                result.add(_yield._canonical_heading(label))
            except Exception:
                result.add(_premium._normalized_heading(label))
    return result


def _safe_continuation_fragment(raw: str, existing: str) -> Optional[str]:
    if not raw or _META_LEAK_RE.search(raw):
        _RUNTIME["continuation_rejections"]["meta_or_prompt_leak"] += 1
        return None

    sanitized = _authority._sanitize_llm_html(raw)
    if not sanitized or _META_LEAK_RE.search(sanitized):
        _RUNTIME["continuation_rejections"]["empty_or_meta_after_sanitize"] += 1
        return None

    existing_headings = _fragment_headings(existing)
    fragment_headings = _fragment_headings(sanitized)
    mandatory = set(getattr(_yield, "_MANDATORY_NORMALIZED", ()))
    duplicate_canonical = (existing_headings & fragment_headings & mandatory)
    if duplicate_canonical:
        _RUNTIME["continuation_rejections"]["duplicate_canonical_heading"] += 1
        return None

    visible = _premium._visible_text(sanitized).strip()
    if len(visible.split()) < 20:
        _RUNTIME["continuation_rejections"]["insubstantial_fragment"] += 1
        return None
    return sanitized.strip()


def _continuation_prompt(original_prompt: str, existing: str, pass_index: int) -> str:
    metrics = _yield._semantic_metrics(existing)
    missing = sorted(_yield._missing_mandatory(existing))
    need_words = max(0, _premium.MIN_VISIBLE_WORDS - int(metrics["visible_words"]))
    need_paragraphs = max(0, _premium.MIN_PARAGRAPHS - int(metrics["substantive_paragraphs"]))
    need_items = max(0, _premium.MIN_LIST_ITEMS - int(metrics["substantive_list_items"]))
    missing_text = ", ".join(missing) if missing else "NONE"
    source_context = (original_prompt or "")[-MAX_PROMPT_CHARS:]
    existing_context = (existing or "")[-MAX_EXISTING_BODY_CHARS:]
    heading_rule = (
        "If you add a missing canonical section, use its EXACT <h3> heading from the missing-heading list. "
        "Do not emit any canonical heading that already exists."
        if missing
        else
        "All canonical headings already exist. Return body-level <p>, <ul>/<ol>, <li>, or evidence-safe table fragments only; emit NO headings."
    )
    return f"""{source_context}

ASTRA TARGETED CONTINUATION PASS {pass_index} — EVIDENCE-BOUND RECOVERY
You are extending an already-generated public CTI dossier. Return ONLY additional HTML fragments.
This is not a request to rewrite, summarize, or repeat the existing report.

UNCHANGED PUBLIC CONTRACT DEFICIT
- visible words still required: {need_words}
- substantive paragraphs still required: {need_paragraphs}
- substantive list items still required: {need_items}
- missing canonical headings: {missing_text}

BOUNDARIES
- Use ONLY evidence already supplied in the source-data portion of this prompt.
- Preserve distinctions between observed/reported fact, assessment, inference, scenario, forecast, and unknown.
- Never invent an IOC, CVE property, ATT&CK mapping, exploitation state, affected version, patch/remediation fact, victim impact, attribution, statistic, customer exposure, customer compromise, regulatory applicability, or financial loss.
- If a material fact is absent, state "Not established in cited evidence." and provide the evidence/telemetry/collection step that would resolve the gap.
- Add decision-useful depth in detection validation, hunting, exposure validation, response decision criteria, remediation verification, intelligence gaps, or executive decisions only where supported.
- Do not include References, metadata, report IDs, source hashes, prompts, drafting notes, token/word-count discussion, or model reasoning.
- {heading_rule}

EXISTING REPORT — DO NOT REPEAT
{existing_context}
"""


def astra_quality_aware_authority_llm(
    config,
    prompt: str,
    max_tokens: int = 3000,
    attempts=None,
    sleep_fn=time.sleep,
):
    """Run the established provider mesh, then bounded evidence-safe recovery."""
    if _INNER_AUTHORITY_CALL is None or _CONTINUATION_CALL is None:
        raise RuntimeError("ASTRA v18 continuation runtime is not installed")

    ledger = attempts if attempts is not None else []
    kwargs = {"max_tokens": max_tokens, "attempts": ledger}
    if sleep_fn is not None:
        kwargs["sleep_fn"] = sleep_fn
    result = _INNER_AUTHORITY_CALL(config, prompt, **kwargs)
    if not result:
        _RUNTIME["continuation_skips"]["no_initial_generation"] += 1
        return result

    content, provider = result
    if _yield.strict_yield_contract_complete(content):
        _RUNTIME["continuation_skips"]["initial_contract_complete"] += 1
        return result

    article = _active_article()
    if article is None:
        _RUNTIME["continuation_skips"]["no_active_article_context"] += 1
        return result
    if not _source_evidence_sufficient(article):
        _RUNTIME["continuation_skips"]["insufficient_source_evidence"] += 1
        return result

    _RUNTIME["continuation_candidates"] += 1
    combined = content
    for pass_index in range(1, MAX_CONTINUATION_PASSES + 1):
        if _yield.strict_yield_contract_complete(combined):
            break
        _RUNTIME["continuation_attempts"] += 1
        continuation_prompt = _continuation_prompt(prompt, combined, pass_index)
        continuation_ledger = ledger
        continuation_result = _CONTINUATION_CALL(
            config,
            continuation_prompt,
            max_tokens=CONTINUATION_MAX_TOKENS,
            attempts=continuation_ledger,
            sleep_fn=sleep_fn,
        )
        if not continuation_result:
            _RUNTIME["continuation_rejections"]["provider_unavailable"] += 1
            continue

        fragment_raw, continuation_provider = continuation_result
        fragment = _safe_continuation_fragment(fragment_raw, combined)
        if not fragment:
            continue
        combined = combined.rstrip() + "\n" + fragment
        _RUNTIME["continuation_fragments"] += 1
        _RUNTIME["continuation_provider_successes"][str(continuation_provider or "unknown")] += 1

        if _yield.strict_yield_contract_complete(combined):
            _RUNTIME["continuation_successes"] += 1
            logger.info(
                "ASTRA v18 targeted continuation reached unchanged premium contract",
                extra={
                    "pass": pass_index,
                    "initial_provider": str(provider),
                    "continuation_provider": str(continuation_provider),
                    "metrics": _yield._semantic_metrics(combined),
                },
            )
            return combined, provider

    logger.warning(
        "ASTRA v18 continuation exhausted; downstream premium gate remains authoritative",
        extra={"metrics": _yield._semantic_metrics(combined), "passes": MAX_CONTINUATION_PASSES},
    )
    return combined, provider


def _utm(url: str, *, content: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update({
        "utm_source": "sentinel_apex_report",
        "utm_medium": "cti_dossier",
        "utm_campaign": "astra_revenue_v18",
        "utm_content": content,
    })
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _recommended_tier(article: Any, context: Any) -> tuple[str, str, str]:
    family = str(getattr(context, "family", None) or "").strip().lower()
    scheduler_family = _scheduler.classify_publication_family(article)
    high_ops = {
        "ransomware_claim", "ransomware_reporting", "threat_actor", "cisa_kev",
        "cve_advisory", "cisa_advisory",
    }
    if family in high_ops or scheduler_family in {"zero_day", "ransomware", "malware", "campaign"}:
        return "pro", "SOC PRO", "IOC + detection + higher-rate operational intelligence"
    if scheduler_family in {"vulnerability", "breach"}:
        return "pro", "SOC PRO", "Full operational API depth + detection intelligence"
    return "starter", "API STARTER", "Higher-rate API access for automation and enrichment"


def _commercial_panel_html(article: Any, context: Any) -> str:
    tier, label, rationale = _recommended_tier(article, context)
    _RUNTIME["recommended_tiers"][tier] += 1
    report_id = str(getattr(context, "report_id", None) or "").strip()
    family = str(getattr(context, "family", None) or _scheduler.classify_publication_family(article))
    primary_url = _utm(PRICING_URL, content=f"{tier}_{family}")
    starter_url = _utm(API_DASHBOARD_URL, content=f"starter_{family}")
    pro_url = _utm(PRICING_URL, content=f"pro_{family}")
    enterprise_url = _utm(PRICING_URL, content=f"enterprise_{family}")
    docs_url = _utm(API_DOCS_URL, content=f"api_docs_{family}")
    safe_report_id = _html.escape(report_id or "REPORTX", quote=True)
    safe_family = _html.escape(family or "general_intelligence", quote=True)

    return f"""
<section class="cdbv18-commercial" data-astra-revenue-v18="true" data-report-id="{safe_report_id}" data-report-family="{safe_family}" aria-label="SENTINEL APEX commercial intelligence access tiers">
  <div class="cdbv18-kicker"><span>ASTRA REVENUE INTELLIGENCE // PRODUCT ACCESS</span><b>PUBLIC DOSSIER → OPERATIONAL INTELLIGENCE</b></div>
  <div class="cdbv18-boundary">This public dossier remains source-linked intelligence. Customer exposure or compromise is never inferred here. Paid tiers add authenticated operational delivery, not stronger factual certainty.</div>
  <div class="cdbv18-grid">
    <article><small>PUBLIC</small><strong>PUBLIC DOSSIER</strong><p>Source-linked analysis, provenance, evidence boundaries, executive and SOC decision support.</p><a href="{_html.escape(docs_url, quote=True)}" target="_blank" rel="noopener" data-cdb-v18-cta="api_docs" data-cdb-tier="free">API DOCUMENTATION</a></article>
    <article><small>₹999 / MONTH</small><strong>API STARTER</strong><p>5,000 API calls/day, weekly intelligence digest, and a single authenticated API key.</p><a href="{_html.escape(starter_url, quote=True)}" target="_blank" rel="noopener" data-cdb-v18-cta="api_starter" data-cdb-tier="starter">GET API ACCESS</a></article>
    <article class="recommended"><small>RECOMMENDED · ₹1,499 / MONTH</small><strong>SOC PRO</strong><p>25,000 API calls/day plus IOC access, detection intelligence, and authenticated full-intel API depth.</p><a href="{_html.escape(pro_url, quote=True)}" target="_blank" rel="noopener" data-cdb-v18-cta="soc_pro" data-cdb-tier="pro">UNLOCK SOC PRO</a></article>
    <article><small>₹4,999 / MONTH</small><strong>ENTERPRISE</strong><p>STIX 2.1 export, bulk intelligence access, extended API capacity, and priority support.</p><a href="{_html.escape(enterprise_url, quote=True)}" target="_blank" rel="noopener" data-cdb-v18-cta="enterprise" data-cdb-tier="enterprise">ENTERPRISE ACCESS</a></article>
  </div>
  <div class="cdbv18-primary"><span>{_html.escape(rationale)}</span><a href="{_html.escape(primary_url, quote=True)}" target="_blank" rel="noopener" data-cdb-v18-cta="recommended" data-cdb-tier="{_html.escape(tier, quote=True)}">VIEW {label} OPTIONS →</a></div>
</section>"""


def _commercial_styles() -> str:
    return r"""<style id="cdb-astra-revenue-v18-css">
.cdbv18-commercial{position:relative;margin:18px 0;padding:17px;border:1px solid rgba(255,181,44,.24);border-radius:14px;background:linear-gradient(145deg,rgba(8,17,29,.98),rgba(4,9,16,.98));box-shadow:0 20px 60px rgba(0,0,0,.25);overflow:hidden}.cdbv18-kicker{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:12px;color:#ffb52c;font:850 9px/1.35 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.cdbv18-kicker b{padding:5px 8px;border:1px solid rgba(255,181,44,.18);border-radius:999px;color:#ffd78a!important;font-size:7px;white-space:nowrap}.cdbv18-boundary{padding:10px 12px;margin-bottom:11px;border-left:3px solid #29d9ff;background:rgba(41,217,255,.045);color:#d8e8f3;font-size:10px;line-height:1.55}.cdbv18-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.cdbv18-grid article{padding:12px;border:1px solid rgba(145,173,197,.14);border-radius:10px;background:rgba(0,0,0,.22);display:flex;flex-direction:column;min-height:170px}.cdbv18-grid article.recommended{border-color:rgba(255,181,44,.42);box-shadow:inset 0 0 26px rgba(255,181,44,.035)}.cdbv18-grid small{color:#8ea6bd;font:800 7px/1.25 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.cdbv18-grid strong{display:block;margin:8px 0 5px;color:#eef8ff!important;font-size:11px}.cdbv18-grid p{margin:0 0 10px!important;color:#b9cad8!important;font-size:9px!important;line-height:1.5!important;flex:1}.cdbv18-grid a,.cdbv18-primary a{display:inline-block;padding:7px 9px;border:1px solid rgba(41,217,255,.22);border-radius:7px;color:#29d9ff!important;text-decoration:none!important;font:850 7px/1.1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em;text-align:center}.cdbv18-grid .recommended a{border-color:rgba(255,181,44,.35);color:#ffcf70!important}.cdbv18-primary{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:10px;padding:10px 12px;border:1px solid rgba(255,181,44,.15);border-radius:9px;background:rgba(255,181,44,.025)}.cdbv18-primary span{color:#d8e6f0;font-size:9px;line-height:1.45}.cdbv18-primary a{border-color:rgba(255,181,44,.3);color:#ffd078!important;white-space:nowrap}.cdbv18-grid a:hover,.cdbv18-primary a:hover{background:rgba(41,217,255,.07)}@media(max-width:1000px){.cdbv18-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:650px){.cdbv18-grid{grid-template-columns:1fr}.cdbv18-kicker,.cdbv18-primary{align-items:flex-start;flex-direction:column}.cdbv18-primary a{white-space:normal;width:100%}}@media(prefers-reduced-motion:reduce){.cdbv18-commercial *{scroll-behavior:auto!important;transition:none!important;animation:none!important}}@media print{.cdbv18-commercial{box-shadow:none!important;background:#fff!important;color:#111!important;break-inside:avoid}.cdbv18-grid strong,.cdbv18-grid p,.cdbv18-primary span{color:#111!important}}
</style>"""


def enhance_astra_revenue_presentation(rendered_html: str, article: Any = None, context: Any = None) -> str:
    if not rendered_html or PRESENTATION_MARKER in rendered_html:
        return rendered_html
    try:
        soup = BeautifulSoup(rendered_html, "html.parser")
        panel = BeautifulSoup(_commercial_panel_html(article, context), "html.parser")
        anchor = (
            soup.select_one(".cdbv10-capabilities")
            or soup.select_one(".cdbv10-panel:last-of-type")
            or soup.select_one(".cdbv9-framework")
            or soup.select_one(".cdbv8-ledger")
        )
        nodes = list(panel.contents)
        if anchor is not None:
            for node in reversed(nodes):
                anchor.insert_after(node)
        else:
            for node in nodes:
                soup.append(node)
        soup.insert(0, BeautifulSoup(_commercial_styles(), "html.parser"))
        _RUNTIME["commercial_panels_rendered"] += 1
        return f"<!-- {PRESENTATION_MARKER} -->{soup}<!-- /{PRESENTATION_MARKER} -->"
    except Exception as exc:
        # Commercial presentation must never block a report that has already
        # passed the authoritative intelligence gates.
        logger.warning("ASTRA v18 commercial presentation skipped", extra={"error": type(exc).__name__})
        return rendered_html


def _astra_patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url=None):
    if _INNER_ASSEMBLE_HTML is None:
        raise RuntimeError("ASTRA v18 presentation is not installed")
    rendered = _INNER_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return enhance_astra_revenue_presentation(rendered, article, context)


setattr(_astra_patched_assemble_html, _PRESENTATION_ATTR, True)


def telemetry_snapshot() -> dict:
    count = int(_RUNTIME["selected_scores_count"])
    average = (float(_RUNTIME["selected_scores_sum"]) / count) if count else 0.0
    return {
        "version": "v18",
        "marker": MARKER,
        "commercial_priority_semantics": "delivery_value_not_threat_risk",
        "selection_runs": int(_RUNTIME["selection_runs"]),
        "candidate_scores_computed": int(_RUNTIME["candidate_scores_computed"]),
        "selected_score_average": round(average, 2),
        "selected_score_max": int(_RUNTIME["selected_score_max"]),
        "selected_priority_bands": dict(_RUNTIME["selected_bands"]),
        "selected_generation_readiness_bands": dict(_RUNTIME["selected_readiness_bands"]),
        "generation_readiness_semantics": "source_evidence_feasibility_not_publication_permission",
        "continuation_candidates": int(_RUNTIME["continuation_candidates"]),
        "continuation_attempts": int(_RUNTIME["continuation_attempts"]),
        "continuation_fragments": int(_RUNTIME["continuation_fragments"]),
        "continuation_successes": int(_RUNTIME["continuation_successes"]),
        "continuation_provider_successes": dict(_RUNTIME["continuation_provider_successes"]),
        "continuation_skips": dict(_RUNTIME["continuation_skips"]),
        "continuation_rejections": dict(_RUNTIME["continuation_rejections"]),
        "commercial_panels_rendered": int(_RUNTIME["commercial_panels_rendered"]),
        "recommended_tiers": dict(_RUNTIME["recommended_tiers"]),
        "public_quality_floor": {
            "visible_words": int(_premium.MIN_VISIBLE_WORDS),
            "distinct_headings": int(_premium.MIN_DISTINCT_HEADINGS),
            "substantive_paragraphs": int(_premium.MIN_PARAGRAPHS),
            "substantive_list_items": int(_premium.MIN_LIST_ITEMS),
        },
        "pricing_source_of_truth": "api/_lib/payment-utils.js + api/_lib/middleware.js",
        "browser_conversion_attribution": "conversion-engine.js + GA4 + astra_revenue_v18 UTM",
        "server_side_clicks_claimed": False,
        "telemetry_contains_prompts": False,
        "telemetry_contains_response_content": False,
        "telemetry_contains_credentials": False,
    }


def write_run_report_with_v18_telemetry(report: dict, logs_dir: str) -> None:
    if _INNER_WRITE_RUN_REPORT is None:
        raise RuntimeError("ASTRA v18 run-report telemetry is not installed")
    report["astra_revenue_intelligence_v18"] = telemetry_snapshot()
    _INNER_WRITE_RUN_REPORT(report, logs_dir)


def install_astra_revenue_runtime_v18(main_module) -> None:
    """Install after v17 so the full existing provider mesh remains inner."""
    global _INNER_AUTHORITY_CALL, _CONTINUATION_CALL, _INNER_SELECT
    global _INNER_PRIORITY_KEY, _INNER_WRITE_RUN_REPORT, _RUNTIME_INSTALLED
    if _RUNTIME_INSTALLED:
        return

    _INNER_AUTHORITY_CALL = _authority.call_llm
    _CONTINUATION_CALL = _key_judgements.call_llm
    _INNER_SELECT = main_module.select_publication_batch
    _INNER_PRIORITY_KEY = _scheduler._priority_key
    _INNER_WRITE_RUN_REPORT = main_module._write_run_report

    _scheduler._priority_key = _astra_priority_key
    main_module.select_publication_batch = _astra_select_publication_batch
    _authority.call_llm = astra_quality_aware_authority_llm
    main_module._write_run_report = write_run_report_with_v18_telemetry

    if _authority.call_llm is not astra_quality_aware_authority_llm:
        raise RuntimeError("ASTRA v18 failed to bind authority LLM runtime")
    if main_module.select_publication_batch is not _astra_select_publication_batch:
        raise RuntimeError("ASTRA v18 failed to bind commercial selection runtime")
    if main_module._write_run_report is not write_run_report_with_v18_telemetry:
        raise RuntimeError("ASTRA v18 failed to bind run-report telemetry")

    # Explicitly prove at install time that the release did not lower quality.
    if (
        _premium.MIN_VISIBLE_WORDS != 2200
        or _premium.MIN_DISTINCT_HEADINGS != 18
        or _premium.MIN_PARAGRAPHS != 18
        or _premium.MIN_LIST_ITEMS != 18
    ):
        raise RuntimeError("ASTRA v18 refuses installation because the authoritative public quality floor changed")

    _RUNTIME_INSTALLED = True
    logger.info(
        "SENTINEL APEX ASTRA Revenue Intelligence Engine v18 runtime installed",
        extra={
            "marker": MARKER,
            "commercial_priority_is_risk_score": False,
            "continuation_max_passes": MAX_CONTINUATION_PASSES,
            "continuation_max_tokens": CONTINUATION_MAX_TOKENS,
            "quality_floor_lowered": False,
            "paid_provider_policy_changed": False,
        },
    )


def install_astra_revenue_presentation_v18(main_module) -> None:
    """Install after Dossier v10 so commercial packaging is the outer display layer."""
    global _INNER_ASSEMBLE_HTML, _PRESENTATION_INSTALLED
    if _PRESENTATION_INSTALLED:
        return
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        transformer = _authority.AuthorityTransformer
    current = transformer._assemble_html
    if getattr(current, _PRESENTATION_ATTR, False):
        _PRESENTATION_INSTALLED = True
        return
    _INNER_ASSEMBLE_HTML = current
    transformer._assemble_html = _astra_patched_assemble_html
    if transformer._assemble_html is not _astra_patched_assemble_html:
        raise RuntimeError("ASTRA v18 failed to bind commercial presentation")
    _PRESENTATION_INSTALLED = True
    logger.info(
        "SENTINEL APEX ASTRA v18 commercial entitlement presentation installed",
        extra={
            "marker": PRESENTATION_MARKER,
            "existing_entitlement_system_reused": True,
            "new_billing_system_created": False,
            "conversion_attribution": "UTM + existing conversion-engine.js",
        },
    )
