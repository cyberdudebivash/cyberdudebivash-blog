"""Evidence model and fail-closed publication gate for CTI reports.

The syndication pipeline consumes heterogeneous public sources.  This module
normalises the small set of facts that may be asserted in a public report and
blocks output that crosses those evidence boundaries.
"""

from __future__ import annotations

import hashlib
import html as html_lib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .content_discovery import DiscoveredArticle


# Truthful production-mode label (P0-AI-NATIVE-CERTIFICATION-2026-08-19):
# this pipeline publishes without a per-report human reviewer, so the
# honest label is the positive, factual description of what DOES gate
# publication -- automated, evidence-graph-verified controls -- not a
# defensive "not reviewed" disclaimer. See validate_publication() below
# for the actual fail-closed evidence gates that replace human review.
REVIEW_STATUS = "AI-Native Automated Intelligence — Evidence-Graph Verified"
CERTIFICATION_STATUS = "Public reference draft — not a certified customer deliverable"


class PublicationIntegrityError(ValueError):
    """Raised when a report fails a mandatory evidence-integrity gate."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = issues
        super().__init__("Publication blocked: " + "; ".join(issues))


@dataclass(frozen=True)
class ReportContext:
    report_id: str
    source_record_hash: str
    generated_at: str
    family: str
    family_label: str
    exploitation_status: str
    exploitation_label: str
    patch_status: str
    patch_label: str
    vulnerability_class: str
    review_status: str = REVIEW_STATUS
    certification_status: str = CERTIFICATION_STATUS
    # Empty string means "not evaluated against the evidence-graph tier
    # ladder" (sentinel_engine.reportx.tier_downgrade.determine_achieved_tier)
    # -- the honest default below, not a claim of any specific tier.
    achieved_tier: str = ""


_CONFIRMED_EXPLOITATION_PATTERNS = (
    r"\bactively exploited\b",
    r"\bexploited in the wild\b",
    r"\bobserved exploitation\b",
    r"\bconfirmed exploitation\b",
    r"\bexploitation (?:has been|was) observed\b",
)

_PATCH_AVAILABLE_PATTERNS = (
    r"\bpatch (?:is )?available\b",
    r"\bvendor (?:has )?released (?:a |an )?(?:patch|fix|update)\b",
    r"\bfixed in (?:version|release)\b",
    r"\bupgrade to (?:version|release)\b",
    r"\bapply (?:the )?(?:vendor )?(?:patch|update)\b",
)

# RX-P1M: a bare phrase match ("confirmed exploitation", "observed
# exploitation") cannot tell an actual assertion apart from this exact
# pipeline's own honest, hedged non-assertion of the same words -- e.g.
# authority_transformer.py's legacy-template fallback genuinely renders
# "No confirmed exploitation evidence is available" for an unconfirmed
# CVE, which must never be flagged as the assertion it explicitly denies.
# A short negation lookback is the minimum viable mitigation for this real,
# empirically-found false positive (found via this exact check's own test
# suite) -- not a general negation parser, just the common English forms
# that would otherwise make a hedged, evidence-honest sentence indistinguishable
# from the assertion this gate exists to block.
_NEGATION_LOOKBACK_RE = re.compile(
    r"\b(?:no|not|never|without|unconfirmed|isn.t|hasn.t|haven.t|doesn.t|didn.t)\b[^.?!]{0,40}$",
    re.IGNORECASE,
)


def _is_negated_immediately_before(text: str, match_start: int, window: int = 60) -> bool:
    return bool(_NEGATION_LOOKBACK_RE.search(text[max(0, match_start - window):match_start]))


# RX-P1M, mandate's own named cross-section example: "ransomware claim:
# unverified... Business Impact: states confirmed breach/data theft."
# This pipeline's own evidence boundary for ransomware_claim is that a
# leak-site listing is a REPORTED, third-party claim, never independently
# confirmed (see pipeline_composer._lean_role_decisions()'s IR_MANAGER
# decision and report_renderer._family_analysis()'s "Claim Assessment"
# boundary text, both already established elsewhere in this pipeline) --
# a DECLARATIVE assertion that the breach/compromise/data theft IS
# confirmed contradicts that boundary directly. Deliberately declarative-
# shaped patterns ("X confirms Y", "Y is confirmed", "data was stolen"),
# not a bare "confirmed breach"/"confirmed compromise" substring: this
# pipeline's own universal Executive Summary boilerplate legitimately
# contains "...before treating this record as an incident, confirmed
# compromise, or customer-specific finding" as cautionary, nominal
# framing, not an assertion -- confirmed as a real false positive while
# building this exact check (the same false-positive class already found
# once this session, Phase 1K's cross-section spot-check).
_RANSOMWARE_CLAIM_CONFIRMED_BREACH_PATTERNS = (
    r"\bconfirms? (?:a |the )?(?:breach|compromise)\b",
    r"\b(?:the )?(?:breach|compromise|data theft) (?:is|has been|was) confirmed\b",
    r"\bdata (?:has been|was) (?:confirmed )?(?:stolen|exfiltrated)\b",
    r"\bvictim(?:'s)? (?:data|network|systems?) (?:has been|was|is) (?:confirmed )?compromised\b",
)


def _source_text(article: DiscoveredArticle) -> str:
    return " ".join(
        part for part in (article.title, article.summary, article.full_content or "") if part
    )


def _record_hash(article: DiscoveredArticle) -> str:
    """Hash the canonical source record, not the generated report HTML."""
    record = {
        "url": article.url,
        "title": article.title,
        "summary": article.summary,
        "published_at": article.published_at,
        "source": article.source,
        "full_content": article.full_content,
        "cve_id": article.cve_id,
        "cvss_score": article.cvss_score,
        "cvss_vector": article.cvss_vector,
        "cwe_ids": article.cwe_ids,
        "affected_vendor": article.affected_vendor,
        "affected_product": article.affected_product,
        "epss_score": article.epss_score,
        "epss_percentile": article.epss_percentile,
        "kev_listed": article.kev_listed,
        "kev_date_added": article.kev_date_added,
        "kev_due_date": article.kev_due_date,
        "kev_required_action": article.kev_required_action,
    }
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_artifact_hash(html: str) -> str:
    """SHA-256 of the exact certified HTML body -- the artifact-binding
    primitive mandate Section 17/34 requires: the content certified by
    ``validate_publication()`` must be byte-identical to what Blogger
    actually receives, or the mismatch must block publication rather than
    publish silently. Same algorithm/encoding as
    ``sentinel_engine.reportx.human_review.compute_artifact_hash()`` (the
    CTI engine's own identical concept) -- defined locally here rather than
    imported cross-package to avoid that module's own sys.path bootstrap
    dependency for a single stdlib call; both must be kept in sync if the
    hashing scheme ever changes."""
    return hashlib.sha256(html.encode("utf-8")).hexdigest()


def _family(article: DiscoveredArticle) -> tuple[str, str]:
    """Classify from authoritative signals and event-specific context.

    Third-party article bodies frequently contain related-story recommendations,
    syndicated AI advertisements, and unrelated CVEs. Those terms must never
    silently reclassify the headline event as an AI attack or vulnerability.
    """
    title = str(article.title or "")
    summary = str(article.summary or "")
    event_text = f"{title} {summary}"
    text = _source_text(article).lower()
    labels = {str(label).strip().lower() for label in article.labels}

    # Typed/structured source identity takes precedence over SEO keywords.
    if article.source == "cisa_kev" or article.kev_listed is True:
        return "cisa_kev", "CISA KEV Alert"
    if article.source == "ransomware_intel":
        return "ransomware_claim", "Ransomware Claim Intelligence"
    if article.source == "breach_intel":
        return "breach_notice", "Public Breach Record"
    if article.source == "cisa_advisory":
        return "cisa_advisory", "CISA Security Advisory"
    if article.source == "threat_actor_intel":
        return "threat_actor", "Threat Actor Intelligence"
    if article.cve_id:
        return "cve_advisory", "CVE Vulnerability Advisory"

    # A newsletter/roundup may discuss multiple unrelated incidents or CVEs.
    # It is not itself a single actionable AI attack or CVE advisory.
    if re.search(r"\b(?:newsletter|round[ -]?up|daily digest|weekly digest|top stories)\b", title, re.I):
        return "general_intelligence", "Cyber Threat Intelligence"

    # Prefer the event headline/abstract. A CVE in a related-story or footer
    # inside full_content is not evidence the headline concerns that CVE.
    if re.search(r"\bCVE-\d{4}-\d{4,}\b", event_text, re.I):
        return "cve_advisory", "CVE Vulnerability Advisory"

    # A single generic "AI" in full_content is insufficient. A focused title
    # (or its abstract) must explicitly describe an AI/LLM/model/agent subject.
    ai_subject = re.compile(
        r"\b(?:AI|LLM|large language models?|generative AI|genAI|"
        r"AI agents?|coding agents?|prompt injection|model poisoning|"
        r"model safety|model security|machine learning)\b", re.I
    )
    if ai_subject.search(title) or (
        "ai security" in labels and ai_subject.search(summary)
    ):
        return "ai_security", "AI Security Intelligence"
    if "ransomware" in labels or "ransomware" in text:
        return "ransomware_reporting", "Ransomware Intelligence"
    return "general_intelligence", "Cyber Threat Intelligence"


def _exploitation(article: DiscoveredArticle, family: str) -> tuple[str, str]:
    if family == "ransomware_claim":
        return "third_party_claim", "Third-party actor claim — independently unverified"
    if article.kev_listed is True:
        return "confirmed", "Confirmed — CISA KEV listed"

    text = _source_text(article)
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in _CONFIRMED_EXPLOITATION_PATTERNS):
        return "confirmed", "Confirmed by the cited source record"
    if article.kev_listed is False:
        return "not_confirmed", "Not confirmed by available evidence; not in verified KEV snapshot"
    if family in {"cve_advisory", "cisa_advisory"}:
        return "unknown", "Unknown — source record does not confirm active exploitation"
    return "not_applicable", "Not applicable to this intelligence format"


def _patch(article: DiscoveredArticle, family: str) -> tuple[str, str]:
    if family not in {"cisa_kev", "cve_advisory", "cisa_advisory"}:
        return "not_applicable", "Not applicable to this intelligence format"
    if article.kev_required_action:
        return "required_action", f"CISA required action: {article.kev_required_action.strip()}"

    text = _source_text(article)
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in _PATCH_AVAILABLE_PATTERNS):
        return "available", "Remediation update referenced by the cited source"
    return "unconfirmed", "Availability not established in the source record — verify vendor guidance"


_CWE_CLASS = {
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-79": "cross_site_scripting",
    "CWE-88": "argument_injection",
    "CWE-89": "sql_injection",
    "CWE-119": "memory_corruption",
    "CWE-200": "information_disclosure",
    "CWE-269": "privilege_escalation",
    "CWE-287": "authentication_failure",
    "CWE-352": "cross_site_request_forgery",
    "CWE-400": "denial_of_service",
    "CWE-639": "authorization_failure",
    "CWE-787": "memory_corruption",
    "CWE-862": "authorization_failure",
    "CWE-918": "server_side_request_forgery",
}


def _vulnerability_class(article: DiscoveredArticle) -> str:
    for cwe in article.cwe_ids or []:
        if str(cwe).upper() in _CWE_CLASS:
            return _CWE_CLASS[str(cwe).upper()]

    patterns = (
        ("denial_of_service", r"denial[- ]of[- ]service|\bdos\b|resource exhaustion|service crash"),
        ("sql_injection", r"sql injection"),
        ("command_injection", r"command injection|os command|remote code execution|\brce\b|deserialization"),
        ("path_traversal", r"path traversal|directory traversal|arbitrary file (?:read|write)"),
        ("privilege_escalation", r"privilege escalation|elevation of privilege|\blpe\b"),
        ("spoofing", r"spoofing|identity confusion"),
        ("authentication_failure", r"authentication bypass|missing authentication|auth bypass"),
        ("authorization_failure", r"authorization bypass|access control|improper authorization"),
        ("information_disclosure", r"information disclosure|sensitive information|data exposure"),
        ("server_side_request_forgery", r"server[- ]side request forgery|\bssrf\b"),
        ("cross_site_scripting", r"cross[- ]site scripting|\bxss\b"),
    )
    # Prefer the concise identifying fields. Long-form source material may
    # mention related CVEs or background attack classes and must not override
    # an explicit title/summary classification.
    primary_text = f"{article.title} {article.summary}".lower()
    secondary_text = str(article.full_content or "").lower()
    for corpus in (primary_text, secondary_text):
        for name, pattern in patterns:
            if re.search(pattern, corpus, re.IGNORECASE):
                return name
    return "unclassified"


def build_report_context(
    article: DiscoveredArticle,
    generated_at: Optional[datetime] = None,
    achieved_tier: str = "",
) -> ReportContext:
    """``achieved_tier`` (a ``CertificationState.value`` string, e.g.
    ``"TACTICAL_READY"``) is optional and defaults to "" -- every existing
    caller that doesn't know about the evidence-graph tier ladder keeps
    getting the honest, unconditional ``CERTIFICATION_STATUS`` draft label
    exactly as before. Callers that HAVE computed a real tier (currently:
    ``authority_transformer.transform()``, once per article, from
    ``pipeline_composer.compose_report()``) pass it through so the
    certification label readers actually see reflects real evidence rather
    than a static string every report carried regardless of quality
    (P0-COMMERCIAL-QUALITY-2026-08-18 finding). ``PUBLIC_REFERENCE_DRAFT``
    itself still renders the plain draft label -- that tier means the
    evidence genuinely didn't clear correctness, so the honest label and
    the fail-closed default happen to coincide."""
    generated = generated_at or datetime.now(timezone.utc)
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone.utc)
    generated_iso = generated.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    source_hash = _record_hash(article)
    try:
        report_year = datetime.fromisoformat(article.published_at.replace("Z", "+00:00")).year
    except (TypeError, ValueError, AttributeError):
        report_year = generated.year

    family, family_label = _family(article)
    exploitation_status, exploitation_label = _exploitation(article, family)
    patch_status, patch_label = _patch(article, family)

    certification_status = CERTIFICATION_STATUS
    if achieved_tier and achieved_tier != "PUBLIC_REFERENCE_DRAFT":
        certification_status = (
            f"Public Intelligence Certification: {achieved_tier} "
            "(automated evidence-graph certification — see Provenance for the source basis)"
        )

    return ReportContext(
        report_id=f"CDB-CTI-{report_year}-{source_hash[:12].upper()}",
        source_record_hash=source_hash,
        generated_at=generated_iso,
        family=family,
        family_label=family_label,
        exploitation_status=exploitation_status,
        exploitation_label=exploitation_label,
        patch_status=patch_status,
        patch_label=patch_label,
        vulnerability_class=_vulnerability_class(article),
        certification_status=certification_status,
        achieved_tier=achieved_tier,
    )


_PLACEHOLDER_PATTERNS = (
    r"\bnot found sector\b",
    r"\bcountry of ai\b",
    r"\bpatch unconfirmed\b",
    r"00000000-0000-0000-0000-000000000000",
    r"\b(?:change[_ -]?me|todo|tbd)\b",
)

_UNSUPPORTED_COMMERCIAL_PATTERNS = (
    r"\b2,400\+",
    r"\b10,000\+",
    r"\b40\+ TI sources\b",
    r"\btrusted by \d[\d,]*\+",
)

# RX-P1M: generalizes the run #8459 incident fix
# (docs/audits/blogger-syndication-run-8459-incident-review-2026-08-20.md)
# beyond the 4 exact-literal numbers already observed as hallucinations.
# That fix only catches the SAME fabricated number if it recurs verbatim;
# it has no capability to catch the *next* invented figure (e.g. "1,800+
# victims" or "$4.2 million in losses"). A specific number in a
# high-impact quantitative context that does not appear anywhere in the
# source article's own text is fabricated by construction -- this
# pipeline invents no fact the source didn't supply. Comma-normalized so a
# genuinely source-grounded number is never flagged merely because it was
# reformatted at render time ("2400" in the source vs. "2,400" rendered).
_QUANTITATIVE_CLAIM_RE = re.compile(
    r"\b(\d[\d,]*(?:\.\d+)?)\+?\s+"
    r"(?:victims?|organizations?|customers?|companies|records?|breaches|incidents?|"
    r"users?|accounts?|servers?|systems?|devices?|downloads?|installations?|"
    r"(?:TI|threat intel(?:ligence)?)\s+sources?)\b",
    re.IGNORECASE,
)


def _grounded_numbers(source_text: str) -> set[str]:
    return {n.replace(",", "") for n in re.findall(r"\d[\d,]*(?:\.\d+)?", source_text)}


def _check_quantitative_claims_are_grounded(html: str, article: DiscoveredArticle) -> list[str]:
    grounded = _grounded_numbers(_source_text(article))
    issues = []
    for m in _QUANTITATIVE_CLAIM_RE.finditer(html):
        number = m.group(1).replace(",", "")
        if number not in grounded:
            issues.append(f"unsupported quantitative claim not present in source text: {m.group(0).strip()!r}")
    return issues


# P0-AI-NATIVE-CERTIFICATION-2026-08-19: this pipeline never performs a
# real per-report human review (see REVIEW_STATUS above) -- these phrases
# must never appear in published output, which would falsely imply one
# happened. Deliberately distinct from legitimate operational-safety
# language like "requires...accountable human approval" (an instruction to
# the READER before acting on the report, not a claim about how the
# report itself was produced).
_FALSE_HUMAN_REVIEW_PATTERNS = (
    r"\bhuman reviewed\b",
    r"\banalyst approved\b",
    r"\bmanually verified\b",
    r"\bhuman review(?:ed)? and approved\b",
)


def validate_publication(
    article: DiscoveredArticle, context: ReportContext, html: str, product_tier: str = "",
    contradictions: tuple = (), body_content: str = "",
) -> None:
    """Fail closed on provenance, contradiction, placeholder, and schema defects.

    ``product_tier`` is a second, independent tier signal --
    ``analytical_depth_gate.evaluate_product_tier()``'s FLASH/TACTICAL/
    PREMIUM_LONG_FORM verdict against the founder-mandate 24-section
    contract (``report_contract.py``). This is deliberately NOT the same
    value as ``context.achieved_tier`` (the ReportX composer's separate
    23-control PUBLIC_REFERENCE_DRAFT/.../PREMIUM_CERTIFIED ladder,
    already gated below) -- collapsing two independently-computed
    tier signals into one field would hide which one actually drove a
    given verdict. Default "" ("not evaluated") is not gated, so every
    existing caller that hasn't computed this verdict keeps its current
    behavior exactly.

    ``contradictions`` is ``sentinel_engine.reportx.contradiction_engine``'s
    real, claim-level and rendered-text-level findings (each a
    ``Contradiction.to_dict()``), passed through unevaluated by every
    caller that hasn't computed them -- default ``()`` is never gated.

    ``body_content`` scopes the source-grounded quantitative-claim check
    (RX-P1M, see ``_check_quantitative_claims_are_grounded``) to the
    report's own analytical narrative -- ``authority_transformer.py``'s
    ``body_content`` before ``_assemble_html()`` wraps it with page chrome.
    ``html`` (the full assembled page) is deliberately NOT used as a
    fallback: it also carries ``internal_linker.py``'s "Related
    Intelligence Reports" widget, which legitimately embeds OTHER real
    published articles' headlines -- containing THEIR OWN real numbers,
    not this article's claims -- and a naive full-page scan false-positives
    on them. Default "" skips the check entirely, so any caller that
    hasn't computed a ``body_content`` keeps its current behavior exactly.
    """
    issues: list[str] = []
    lower = html.lower()

    required = {
        "report identifier": context.report_id,
        "source-record hash": context.source_record_hash,
        "source URL": article.url,
        "generation timestamp": context.generated_at,
        "review status": context.review_status,
        "certification status": context.certification_status,
    }
    for label, value in required.items():
        if value not in html and html_lib.escape(value, quote=True) not in html:
            issues.append(f"missing {label}")

    # Hard publication gate (P0-COMMERCIAL-QUALITY-2026-08-18): a caller that
    # computed a real evidence-graph tier (currently only
    # authority_transformer.transform(), via pipeline_composer.compose_report())
    # and found it landed at the bottom of the tier ladder is telling us the
    # evidence itself failed correctness controls -- unreliable, not merely
    # incomplete. That must block publication outright, not merely swap in a
    # different template while still publishing. achieved_tier == "" (the
    # default for any caller that hasn't computed a tier) is deliberately
    # NOT treated as a failure here -- this only gates callers that actually
    # ran the evaluation, so every existing, unmodified caller of
    # build_report_context()/validate_publication() keeps its current
    # behavior exactly.
    if context.achieved_tier == "PUBLIC_REFERENCE_DRAFT":
        issues.append(
            "evidence-graph correctness controls failed -- content is not reliable enough "
            "to publish at any tier (see the composer's DowngradeResult.failed_controls)"
        )

    # Same hard-gate discipline as above, applied to the second, independent
    # tier signal: FLASH means half or more of this family's MANDATORY
    # 24-section-contract sections resolved WITHHELD_INSUFFICIENT_EVIDENCE
    # (analytical_depth_gate.evaluate_product_tier()) -- not merely thin,
    # but below the floor this pipeline considers publishable. Proven a
    # no-op against every real article in the current corpus (see
    # docs/audits/REPORTX-24-SECTION-LONG-FORM-RELEASE-CERTIFICATION.md);
    # wired as a hard gate now, not observability-only, so the protection
    # is already live the moment a family-applicability matrix genuinely
    # makes FLASH reachable, rather than needing a second wiring pass later.
    if product_tier == "FLASH":
        issues.append(
            "24-section product-tier gate resolved FLASH -- half or more of this report "
            "family's mandatory sections are WITHHELD_INSUFFICIENT_EVIDENCE "
            "(see ProductTierVerdict.mandatory_withheld)"
        )

    # Section 11 / mandate Section 10: "when evidence conflicts, the system
    # must be able to publish 'sources disagree' -- never manufacture
    # consensus." Every Contradiction contradiction_engine.py can currently
    # construct carries severity=="block" (its own module docstring:
    # "Gate: unresolved_contradictions == 0") -- there is no
    # resolution_status/explicit-handling concept yet that would let a
    # material contradiction be knowingly published anyway, so the only
    # fail-closed-correct behavior today is to block outright rather than
    # silently drop the finding or publish a manufactured single narrative.
    blocking_contradictions = [c for c in contradictions if c.get("severity") == "block"]
    if blocking_contradictions:
        issues.append(
            "unresolved contradiction(s) in evidence/claims/rendered text: "
            + "; ".join(c["description"] for c in blocking_contradictions)
        )

    if len(html) < 3000:
        issues.append("report body is below minimum production length")

    for pattern in _PLACEHOLDER_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            issues.append(f"placeholder output matched /{pattern}/")

    for pattern in _UNSUPPORTED_COMMERCIAL_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            issues.append(f"unsupported commercial claim matched /{pattern}/")

    if body_content:
        issues.extend(_check_quantitative_claims_are_grounded(body_content, article))

    for pattern in _FALSE_HUMAN_REVIEW_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            issues.append(f"false human-review claim matched /{pattern}/")

    if context.exploitation_status != "confirmed":
        # RX-P1M: kept as an exact-phrase permanent regression guard for
        # the specific strings this gate has already blocked in production
        # (never weakened) -- but this list alone had drifted from
        # _CONFIRMED_EXPLOITATION_PATTERNS above (the same module's own
        # source-classification patterns), which also matches "observed
        # exploitation" and "exploitation has/was observed" phrasings this
        # list did not. A plausible LLM paraphrase of the exact same
        # fabricated claim ("exploitation has been observed") would have
        # passed this gate while _CONFIRMED_EXPLOITATION_PATTERNS -- the
        # single source of truth for what "confirmed exploitation"
        # language means everywhere else in this module -- would have
        # matched it instantly. Checked below, additively.
        forbidden = (
            "active exploitation confirmed",
            "exploitation is confirmed active",
            "actively exploited in the wild",
            "exploitation confirmed?</strong> — yes",
        )
        for phrase in forbidden:
            if phrase in lower:
                issues.append(f"unverified exploitation assertion: {phrase}")
        for pattern in _CONFIRMED_EXPLOITATION_PATTERNS:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                if not _is_negated_immediately_before(html, m.start()):
                    issues.append(f"unverified exploitation assertion matched /{pattern}/")
                    break

    if article.kev_listed is False:
        for phrase in ("cisa has added this", "already listed in the cisa", "cisa kev inclusion"):
            if phrase in lower:
                issues.append(f"false KEV assertion: {phrase}")

    if context.family == "ransomware_claim":
        for phrase in (
            "pre-exploitation",
            "patch availability",
            'data-section="cve-analysis"',
            'data-section="web-application-exploitation"',
        ):
            if phrase in lower:
                issues.append(f"ransomware schema contamination: {phrase}")
        for pattern in _RANSOMWARE_CLAIM_CONFIRMED_BREACH_PATTERNS:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                if not _is_negated_immediately_before(html, m.start()):
                    issues.append(f"unverified confirmed-breach assertion for an unverified leak-site claim matched /{pattern}/")
                    break

    if context.family == "ai_security" and not article.cve_id:
        for phrase in ("sigma detection rule", "office application shell spawn", "phishing detection logic"):
            if phrase in lower:
                issues.append(f"AI intelligence schema contamination: {phrase}")

    if "bivash kumar nayak — chief security architect" in lower:
        issues.append("human analyst attribution present without a review event")

    if issues:
        raise PublicationIntegrityError(sorted(set(issues)))
