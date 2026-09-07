"""SENTINEL APEX CTI Integrity + Revenue Compiler v19.1.

Final fail-closed presentation layer installed after ASTRA v19.
It repairs deterministic presentation inconsistencies found in the live
CVE-2026-83959 dossier, then re-validates the rendered artifact before it is
allowed to reach Blogger.

This layer never invents threat facts, severity, exploitation, IOCs, ATT&CK,
customer exposure, detections, or commercial outcomes. It only:
- canonicalizes presentation from already-rendered evidence;
- removes unsupported artifact claims from summary surfaces;
- labels source-only technical prose as general context;
- downgrades the public display label when evidence is source-only;
- normalizes corroboration / operational-depth labels;
- assigns CYBERDUDEBIVASH public distribution as TLP:CLEAR;
- enforces v19 direct-checkout links for paid CTAs;
- converts assessment mailto CTAs to the existing enterprise inquiry form;
- cleans semantic safety annotations out of related-report titles; and
- fails closed if contradictions survive the repair pass.
"""
from __future__ import annotations

from collections import Counter
import re
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from bs4 import BeautifulSoup, NavigableString, Tag

from . import authority_transformer as _authority
from .astra_cash_conversion_v19 import PAID_TIERS, direct_checkout_url
from .logger import setup_logger
from .report_integrity import PublicationIntegrityError

logger = setup_logger("cti_integrity_revenue_v19_1")

MARKER = "CDB-CTI-INTEGRITY-REVENUE-V19-1"
_INSTALL_ATTR = "__cdb_cti_integrity_revenue_v19_1__"
NEUTRAL_OG_URL = "https://blog.cyberdudebivash.in/og-image.png"
PUBLIC_TLP = "TLP:CLEAR"
SOURCE_ONLY_LABEL = "SOURCE_ONLY_PRELIMINARY"

_INNER_ASSEMBLE_HTML: Optional[Callable] = None
_INNER_WRITE_RUN_REPORT: Optional[Callable] = None
_INNER_OG_BUILDER: Optional[Callable] = None
_INSTALLED = False

_RUNTIME = {
    "reports_seen": 0,
    "reports_repaired": 0,
    "summaries_sanitized": 0,
    "source_only_labels": 0,
    "technical_context_labels": 0,
    "severity_urls_repaired": 0,
    "tlp_assignments": 0,
    "corroboration_normalized": 0,
    "operational_depth_normalized": 0,
    "related_titles_cleaned": 0,
    "service_links_rewritten": 0,
    "paid_links_repaired": 0,
    "publication_blocks": 0,
    "block_reasons": Counter(),
}

_CANONICAL_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"})

_ARTIFACT_PATTERNS = {
    "ioc": re.compile(r"\bIOCs?\b|\bindicator pack\b", re.I),
    "sigma": re.compile(r"\bSIGMA(?:\s+rules?|\s+pack)?\b", re.I),
    "yara": re.compile(r"\bYARA(?:\s+rules?|\s+pack)?\b", re.I),
    "attack_chain": re.compile(r"\battack chain\b", re.I),
    "attack_mapping": re.compile(r"\bMITRE\s+ATT&?CK(?:\s+mapping)?\b", re.I),
}

_RELATED_TITLE_GARBAGE = (
    re.compile(r"\s+not established as actively exploited in cited evidence\s+", re.I),
    re.compile(r"\s+not established in cited evidence\s+", re.I),
    re.compile(r"\s+WITHHELD_INSUFFICIENT_EVIDENCE\s+", re.I),
    re.compile(r"\s+V8\s+(?=Zero-Day\b)", re.I),
)


def _normalize(text: str) -> str:
    value = re.sub(r"\s+", " ", text or "").strip().lower()
    value = value.replace("–", "-").replace("—", "-")
    value = re.sub(r"^[\s\d.():-]+", "", value).strip()
    aliases = {
        "mitre attack assessment": "mitre att&ck assessment",
        "mitre att ck assessment": "mitre att&ck assessment",
        "indicators / observables": "indicators & observables",
        "evidence and source assessment": "evidence & source assessment",
    }
    return aliases.get(value, value)


def _heading(soup: BeautifulSoup, semantic: str) -> Optional[Tag]:
    wanted = _normalize(semantic)
    for heading in soup.find_all(["h2", "h3"]):
        if _normalize(heading.get_text(" ", strip=True)) == wanted:
            return heading
    return None


def _section_nodes(heading: Optional[Tag]) -> list[Tag]:
    if heading is None:
        return []
    nodes: list[Tag] = []
    sibling = heading.next_sibling
    while sibling is not None:
        nxt = sibling.next_sibling
        if isinstance(sibling, Tag) and sibling.name in {"h2", "h3"}:
            break
        if isinstance(sibling, Tag):
            nodes.append(sibling)
        sibling = nxt
    return nodes


def _section_text(soup: BeautifulSoup, semantic: str) -> str:
    return re.sub(
        r"\s+",
        " ",
        " ".join(node.get_text(" ", strip=True) for node in _section_nodes(_heading(soup, semantic))),
    ).strip()


def _replace_section_body(soup: BeautifulSoup, semantic: str, text: str) -> bool:
    heading = _heading(soup, semantic)
    if heading is None:
        return False
    nodes = _section_nodes(heading)
    for node in nodes:
        node.decompose()
    paragraph = soup.new_tag("p")
    paragraph["data-cdb-v19-1-sanitized"] = "true"
    paragraph.string = text
    heading.insert_after(paragraph)
    return True


def _verified_facts(soup: BeautifulSoup) -> list[str]:
    heading = _heading(soup, "verified facts")
    facts: list[str] = []
    for node in _section_nodes(heading):
        for item in node.find_all("li"):
            text = re.sub(r"\s+", " ", item.get_text(" ", strip=True)).strip()
            if text and text not in facts:
                facts.append(text)
    return facts


def _is_source_only(soup: BeautifulSoup) -> bool:
    facts = _verified_facts(soup)
    if not facts or len(facts) > 2:
        return False
    prefixes = ("source publisher:", "source published:")
    return all(item.lower().startswith(prefixes) for item in facts)


def _section_is_not_established(soup: BeautifulSoup, semantic: str) -> bool:
    body = _section_text(soup, semantic).lower()
    return not body or any(
        token in body
        for token in (
            "not established in cited evidence",
            "not established",
            "withheld_insufficient_evidence",
        )
    )


def _section_html(soup: BeautifulSoup, semantic: str) -> str:
    return " ".join(str(node) for node in _section_nodes(_heading(soup, semantic)))


def _capabilities(soup: BeautifulSoup) -> dict[str, bool]:
    indicators_missing = _section_is_not_established(soup, "indicators & observables")
    attack_missing = _section_is_not_established(soup, "mitre att&ck assessment")
    detection_html = _section_html(soup, "detection engineering guidance")
    hunting_html = _section_html(soup, "threat hunting queries")
    detection_text = BeautifulSoup(detection_html, "html.parser").get_text("\n", strip=True)
    hunting_text = BeautifulSoup(hunting_html, "html.parser").get_text("\n", strip=True)

    has_sigma = bool(
        re.search(r"(?im)^\s*title\s*:\s*.+$", detection_text)
        and re.search(r"(?im)^\s*(?:detection|logsource)\s*:\s*$", detection_text)
    )
    has_yara = bool(re.search(r"(?im)\brule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", detection_text))
    has_hunt_query = bool(
        re.search(r"(?im)\b(DeviceProcessEvents|SecurityEvent|index\s*=|from\s+\w+|where\s+\w+|search\s+\w+)\b", hunting_text)
        or "<pre" in hunting_html.lower()
    )
    has_attack_mapping = (not attack_missing) and bool(re.search(r"\bT\d{4}(?:\.\d{3})?\b", _section_text(soup, "mitre att&ck assessment")))
    return {
        "ioc": not indicators_missing,
        "sigma": has_sigma,
        "yara": has_yara,
        "attack_chain": has_attack_mapping,
        "attack_mapping": has_attack_mapping,
        "hunt_query": has_hunt_query,
    }


def _title(soup: BeautifulSoup, article: Any = None) -> str:
    if article is not None:
        candidate = str(getattr(article, "title", "") or "").strip()
        if candidate:
            return candidate
    h1 = soup.find("h1")
    return h1.get_text(" ", strip=True) if h1 else "SENTINEL APEX intelligence record"


def _safe_summary(title: str, family_label: str, caps: dict[str, bool]) -> str:
    absent: list[str] = []
    if not caps["ioc"]:
        absent.append("source-backed IOCs")
    if not caps["attack_mapping"]:
        absent.append("ATT&CK mappings")
    if not (caps["sigma"] or caps["yara"]):
        absent.append("executable detection artifacts")
    tail = ""
    if absent:
        if len(absent) == 1:
            joined = absent[0]
        else:
            joined = ", ".join(absent[:-1]) + " or " + absent[-1]
        tail = f" {joined.capitalize()} are not established in this record."
    return (
        f"{title}. Source-linked {family_label} with evidence-bounded analysis, "
        f"exposure validation, SOC decision support, and retained provenance.{tail}"
    )


def _sanitize_summary_surfaces(soup: BeautifulSoup, article: Any, context: Any, caps: dict[str, bool]) -> bool:
    summary = _section_text(soup, "executive summary")
    unsupported = []
    for key, pattern in _ARTIFACT_PATTERNS.items():
        if pattern.search(summary) and not caps.get(key, False):
            unsupported.append(key)
    if not unsupported:
        return False

    family = str(getattr(context, "family_label", "") or getattr(context, "family", "") or "cyber threat intelligence")
    safe = _safe_summary(_title(soup, article), family, caps)
    changed = _replace_section_body(soup, "executive summary", safe)

    brief = soup.select_one(".cdbv8-brief-grid article:first-of-type p")
    if brief is not None:
        brief.string = safe
        changed = True

    if changed:
        _RUNTIME["summaries_sanitized"] += 1
    return changed


def _label_technical_context(soup: BeautifulSoup, source_only: bool) -> bool:
    if not source_only:
        return False
    heading = _heading(soup, "technical analysis")
    if heading is None:
        return False
    if heading.find_next_sibling(attrs={"data-cdb-v19-1-evidence-class": "general_context"}) is not None:
        return False
    notice = soup.new_tag("div")
    notice["class"] = ["cdbv19-1-evidence-class"]
    notice["data-cdb-v19-1-evidence-class"] = "general_context"
    notice.string = (
        "EVIDENCE CLASS // GENERAL VULNERABILITY-CLASS CONTEXT. The displayed evidence ledger "
        "does not establish CVE-specific exploit mechanics beyond its source-linked claims. "
        "Treat prerequisites, parser path, memory-corruption consequences, execution potential, "
        "and mitigation behavior as unresolved for this CVE until authoritative upstream evidence "
        "is collected."
    )
    heading.insert_after(notice)
    _RUNTIME["technical_context_labels"] += 1
    return True


def _replace_flash_ready_public_label(soup: BeautifulSoup, source_only: bool) -> bool:
    if not source_only:
        return False
    changed = False
    for node in list(soup.find_all(string=re.compile(r"\bFLASH_READY\b"))):
        if not isinstance(node, NavigableString) or node.parent is None or node.parent.name in {"script", "style"}:
            continue
        node.replace_with(re.sub(r"\bFLASH_READY\b", SOURCE_ONLY_LABEL, str(node)))
        changed = True
    if changed:
        _RUNTIME["source_only_labels"] += 1
    return changed


def _set_labeled_value(soup: BeautifulSoup, label: str, value: str) -> int:
    wanted = label.strip().upper()
    changed = 0
    for span in soup.find_all(["span", "b"]):
        if span.get_text(" ", strip=True).upper() != wanted:
            continue
        parent = span.parent
        if parent is None:
            continue
        target = parent.find("strong")
        if target is not None and target.get_text(" ", strip=True) != value:
            target.string = value
            changed += 1
    return changed


def _normalize_corroboration(soup: BeautifulSoup, source_only: bool) -> bool:
    if not source_only:
        return False
    changed = _set_labeled_value(soup, "CORROBORATION", "SINGLE SOURCE")
    if changed:
        _RUNTIME["corroboration_normalized"] += changed
    return bool(changed)


def _normalize_operational_depth(soup: BeautifulSoup, source_only: bool, caps: dict[str, bool]) -> bool:
    changed = 0
    detection_state = "EXECUTABLE" if (caps["sigma"] or caps["yara"]) else "GUIDANCE_ONLY"
    hunting_state = "EXECUTABLE_QUERY" if caps["hunt_query"] else "GUIDANCE_ONLY"
    playbook_state = "GENERIC_VALIDATION_PLAYBOOK" if source_only else "PRESENT"
    changed += _set_labeled_value(soup, "DETECTION", detection_state)
    changed += _set_labeled_value(soup, "HUNTING", hunting_state)
    changed += _set_labeled_value(soup, "SOC PLAYBOOK", playbook_state)
    if changed:
        _RUNTIME["operational_depth_normalized"] += changed
    return bool(changed)


def _canonical_severity(soup: BeautifulSoup, context: Any = None) -> str:
    for card in soup.select(".cdbd-kpi"):
        label = card.find("span")
        value = card.find("strong")
        if label and value and label.get_text(" ", strip=True).upper() == "SEVERITY":
            candidate = value.get_text(" ", strip=True).upper()
            return candidate if candidate in _CANONICAL_SEVERITIES else "UNSPECIFIED"
    candidate = str(getattr(context, "severity", "") or "").strip().upper()
    return candidate if candidate in _CANONICAL_SEVERITIES else "UNSPECIFIED"


def _repair_og_images(soup: BeautifulSoup, severity: str) -> bool:
    changed = False
    for img in soup.find_all("img"):
        src = str(img.get("src") or "")
        if "/api/og?" not in src:
            continue
        if severity == "UNSPECIFIED":
            img["src"] = NEUTRAL_OG_URL
            changed = True
            _RUNTIME["severity_urls_repaired"] += 1
            continue
        parsed = urlparse(src)
        query = parse_qs(parsed.query, keep_blank_values=True)
        current = (query.get("severity") or [""])[0].upper()
        if current == severity:
            continue
        query["severity"] = [severity]
        flattened = []
        for key, values in query.items():
            for item in values:
                flattened.append((key, item))
        img["src"] = urlunparse(parsed._replace(query=urlencode(flattened)))
        changed = True
        _RUNTIME["severity_urls_repaired"] += 1
    return changed


def _assign_public_tlp(soup: BeautifulSoup) -> bool:
    changed = False
    for card in soup.select(".cdbd-kpi"):
        label = card.find("span")
        value = card.find("strong")
        if not (label and value and label.get_text(" ", strip=True).upper() == "TLP"):
            continue
        if value.get_text(" ", strip=True).upper() not in {"TLP:CLEAR", "CLEAR"}:
            value.string = PUBLIC_TLP
            card["data-cdb-distribution-assigned-by"] = "CYBERDUDEBIVASH"
            changed = True
    if changed:
        _RUNTIME["tlp_assignments"] += 1
    return changed


def _repair_paid_ctas(soup: BeautifulSoup, context: Any = None) -> bool:
    panel = soup.select_one(".cdbv18-commercial[data-astra-revenue-v18='true']")
    if panel is None:
        return False
    family = str(panel.get("data-report-family") or getattr(context, "family", "") or "general_intelligence")
    changed = False
    for anchor in panel.select("a[data-cdb-tier]"):
        tier = str(anchor.get("data-cdb-tier") or "").strip().lower()
        if tier not in PAID_TIERS:
            continue
        href = str(anchor.get("href") or "")
        if "/buy.html?" in href and "utm_campaign=astra_cash_conversion_v19" in href:
            continue
        cta = str(anchor.get("data-cdb-v18-cta") or "paid_cta")
        anchor["href"] = direct_checkout_url(tier, family, cta)
        anchor["data-cdb-v19-direct-checkout"] = "true"
        anchor["data-cdb-v19-plan"] = tier
        changed = True
        _RUNTIME["paid_links_repaired"] += 1
    return changed


def _rewrite_service_intake(soup: BeautifulSoup, context: Any = None) -> bool:
    report_id = str(getattr(context, "report_id", "") or "").strip()
    changed = False
    for anchor in soup.find_all("a"):
        text = anchor.get_text(" ", strip=True).lower()
        href = str(anchor.get("href") or "")
        if not href.lower().startswith("mailto:"):
            continue
        if "request vulnerability scan" not in text and "request this assessment" not in text:
            continue
        query = urlencode({
            "service": "vulnerability_assessment",
            "report_id": report_id,
            "utm_source": "sentinel_apex_report",
            "utm_medium": "cti_dossier",
            "utm_campaign": "astra_cash_conversion_v19_1",
            "utm_content": "assessment_request",
        })
        anchor["href"] = f"https://blog.cyberdudebivash.in/contact.html?{query}#inquiry-form-card"
        anchor["data-cdb-v19-1-service-intake"] = "true"
        changed = True
        _RUNTIME["service_links_rewritten"] += 1
    return changed


def _clean_related_titles(soup: BeautifulSoup) -> bool:
    heading = None
    for node in soup.find_all(["h3", "h4"]):
        if "related intelligence reports" in node.get_text(" ", strip=True).lower():
            heading = node
            break
    if heading is None:
        return False
    changed = False
    sibling = heading.next_sibling
    while sibling is not None:
        nxt = sibling.next_sibling
        if isinstance(sibling, Tag) and sibling.name in {"h2", "h3", "h4"}:
            break
        if isinstance(sibling, Tag):
            for anchor in sibling.find_all("a"):
                label = re.sub(r"\s+", " ", anchor.get_text(" ", strip=True)).strip()
                cleaned = label
                for pattern in _RELATED_TITLE_GARBAGE:
                    cleaned = pattern.sub(" ", cleaned)
                cleaned = re.sub(r"\s+", " ", cleaned).strip(" -–—")
                if cleaned and cleaned != label:
                    anchor.string = cleaned
                    changed = True
                    _RUNTIME["related_titles_cleaned"] += 1
        sibling = nxt
    return changed


def _inject_integrity_note(soup: BeautifulSoup, source_only: bool) -> bool:
    if soup.select_one("[data-cdb-v19-1-integrity-note='true']") is not None:
        return False
    anchor = soup.select_one(".cdbv18-commercial") or soup.select_one(".cdbv8-control")
    if anchor is None:
        return False
    note = soup.new_tag("div")
    note["class"] = ["cdbv19-1-integrity-note"]
    note["data-cdb-v19-1-integrity-note"] = "true"
    note.string = (
        "PUBLIC INTELLIGENCE INTEGRITY // Severity, corroboration, artifact availability, "
        "technical evidence class, information-sharing label, and paid delivery links are "
        "canonicalized from the rendered evidence product."
        + (" Source-only evidence is labeled preliminary." if source_only else "")
    )
    anchor.insert_before(note)
    return True


def _validate_final(soup: BeautifulSoup, severity: str, source_only: bool, caps: dict[str, bool]) -> None:
    issues: list[str] = []

    summary = _section_text(soup, "executive summary")
    for key, pattern in _ARTIFACT_PATTERNS.items():
        if pattern.search(summary) and not caps.get(key, False):
            issues.append(f"executive summary claims unsupported artifact: {key}")

    if severity == "UNSPECIFIED":
        bad_og = [str(img.get("src") or "") for img in soup.find_all("img") if "/api/og?" in str(img.get("src") or "")]
        if bad_og:
            issues.append("unknown canonical severity still uses a severity-bearing dynamic OG card")
    else:
        for img in soup.find_all("img"):
            src = str(img.get("src") or "")
            if "/api/og?" not in src:
                continue
            query = parse_qs(urlparse(src).query)
            if (query.get("severity") or [""])[0].upper() != severity:
                issues.append("dynamic OG severity differs from canonical severity")
                break

    if source_only and "FLASH_READY" in soup.get_text(" ", strip=True):
        issues.append("source-only public artifact still exposes FLASH_READY")

    for card in soup.select(".cdbd-kpi"):
        label = card.find("span")
        value = card.find("strong")
        if label and value and label.get_text(" ", strip=True).upper() == "TLP":
            if value.get_text(" ", strip=True).upper() != PUBLIC_TLP:
                issues.append("public report does not expose canonical TLP:CLEAR distribution label")

    panel = soup.select_one(".cdbv18-commercial[data-astra-revenue-v18='true']")
    if panel is not None:
        for anchor in panel.select("a[data-cdb-tier]"):
            tier = str(anchor.get("data-cdb-tier") or "").strip().lower()
            if tier in PAID_TIERS:
                href = str(anchor.get("href") or "")
                if "/buy.html?" not in href or "utm_campaign=astra_cash_conversion_v19" not in href:
                    issues.append(f"paid {tier} CTA bypasses v19 direct checkout")

    if issues:
        _RUNTIME["publication_blocks"] += 1
        _RUNTIME["block_reasons"].update(issues)
        raise PublicationIntegrityError(issues)


def enforce_cti_integrity_revenue_v19_1(rendered_html: str, article: Any = None, context: Any = None) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html

    _RUNTIME["reports_seen"] += 1
    soup = BeautifulSoup(rendered_html, "html.parser")
    source_only = _is_source_only(soup)
    caps = _capabilities(soup)
    severity = _canonical_severity(soup, context)

    changed = False
    changed |= _sanitize_summary_surfaces(soup, article, context, caps)
    changed |= _label_technical_context(soup, source_only)
    changed |= _replace_flash_ready_public_label(soup, source_only)
    changed |= _normalize_corroboration(soup, source_only)
    changed |= _normalize_operational_depth(soup, source_only, caps)
    changed |= _repair_og_images(soup, severity)
    changed |= _assign_public_tlp(soup)
    changed |= _repair_paid_ctas(soup, context)
    changed |= _rewrite_service_intake(soup, context)
    changed |= _clean_related_titles(soup)
    changed |= _inject_integrity_note(soup, source_only)

    _validate_final(soup, severity, source_only, caps)

    if changed:
        _RUNTIME["reports_repaired"] += 1
    return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url=None):
    if _INNER_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI integrity/revenue v19.1 is not installed")
    rendered = _INNER_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return enforce_cti_integrity_revenue_v19_1(rendered, article, context)


setattr(_patched_assemble_html, _INSTALL_ATTR, True)


def _patched_og_builder(*args, **kwargs):
    if _INNER_OG_BUILDER is None:
        raise RuntimeError("CTI integrity/revenue v19.1 OG wrapper is not installed")
    severity = kwargs.get("severity")
    if severity is None and len(args) >= 3:
        severity = args[2]
    canonical = str(severity or "").strip().upper()
    if canonical not in _CANONICAL_SEVERITIES:
        return NEUTRAL_OG_URL
    return _INNER_OG_BUILDER(*args, **kwargs)


setattr(_patched_og_builder, _INSTALL_ATTR, True)


def telemetry_snapshot() -> dict:
    return {
        "version": "v19.1",
        "marker": MARKER,
        "reports_seen": int(_RUNTIME["reports_seen"]),
        "reports_repaired": int(_RUNTIME["reports_repaired"]),
        "summaries_sanitized": int(_RUNTIME["summaries_sanitized"]),
        "source_only_labels": int(_RUNTIME["source_only_labels"]),
        "technical_context_labels": int(_RUNTIME["technical_context_labels"]),
        "severity_urls_repaired": int(_RUNTIME["severity_urls_repaired"]),
        "tlp_assignments": int(_RUNTIME["tlp_assignments"]),
        "corroboration_normalized": int(_RUNTIME["corroboration_normalized"]),
        "operational_depth_normalized": int(_RUNTIME["operational_depth_normalized"]),
        "related_titles_cleaned": int(_RUNTIME["related_titles_cleaned"]),
        "service_links_rewritten": int(_RUNTIME["service_links_rewritten"]),
        "paid_links_repaired": int(_RUNTIME["paid_links_repaired"]),
        "publication_blocks": int(_RUNTIME["publication_blocks"]),
        "block_reasons": dict(_RUNTIME["block_reasons"]),
        "public_tlp": PUBLIC_TLP,
        "source_only_public_label": SOURCE_ONLY_LABEL,
        "prices_changed": False,
        "payment_system_changed": False,
        "reportx_tier_engine_changed": False,
        "provider_policy_changed": False,
        "telemetry_contains_pii": False,
        "telemetry_contains_credentials": False,
    }


def _write_run_report(report: dict, logs_dir: str) -> None:
    if _INNER_WRITE_RUN_REPORT is None:
        raise RuntimeError("CTI integrity/revenue v19.1 run-report wrapper is not installed")
    report["cti_integrity_revenue_v19_1"] = telemetry_snapshot()
    _INNER_WRITE_RUN_REPORT(report, logs_dir)


def install_cti_integrity_revenue_v19_1(main_module) -> None:
    """Install strictly after v19 as the final rendered-artifact authority."""
    global _INNER_ASSEMBLE_HTML, _INNER_WRITE_RUN_REPORT, _INNER_OG_BUILDER, _INSTALLED
    if _INSTALLED:
        return

    transformer = getattr(main_module, "AuthorityTransformer", None) or _authority.AuthorityTransformer
    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        _INSTALLED = True
        return

    _INNER_ASSEMBLE_HTML = current
    _INNER_WRITE_RUN_REPORT = main_module._write_run_report
    _INNER_OG_BUILDER = _authority._build_dynamic_og_image_url

    transformer._assemble_html = _patched_assemble_html
    main_module._write_run_report = _write_run_report
    _authority._build_dynamic_og_image_url = _patched_og_builder

    if transformer._assemble_html is not _patched_assemble_html:
        raise RuntimeError("v19.1 failed to bind final rendered-artifact integrity wrapper")
    if main_module._write_run_report is not _write_run_report:
        raise RuntimeError("v19.1 failed to bind telemetry wrapper")
    if _authority._build_dynamic_og_image_url is not _patched_og_builder:
        raise RuntimeError("v19.1 failed to bind canonical severity social-card wrapper")

    _INSTALLED = True
    logger.info(
        "SENTINEL APEX CTI Integrity + Revenue Compiler v19.1 installed",
        extra={
            "marker": MARKER,
            "public_tlp": PUBLIC_TLP,
            "source_only_label": SOURCE_ONLY_LABEL,
            "billing_changed": False,
            "reportx_tier_engine_changed": False,
        },
    )
