"""SENTINEL APEX CTI Dossier Presentation v5.

Final-stage presentation and semantic convergence layer for Blogger intelligence
reports. It executes after ReportX/evidence compilation and before the exact
artifact hash is computed, so the certified bytes are the same bytes submitted
to Blogger. It never creates threat facts, scores, ATT&CK mappings, IOCs or
compliance claims. Metadata displayed in the command deck is derived only from
canonical structured fields or already-rendered evidence.
"""
from __future__ import annotations

import html as _html
import re
from typing import Any, Optional

from bs4 import BeautifulSoup, Tag

MARKER = "CDB-CTI-DOSSIER-V5"
ROOT_CLASS = "cdb-cti-dossier"
VISUAL_SYSTEM = "CDB-ENTERPRISE-INTEL-V6"
_ORIGINAL_ASSEMBLE_HTML = None

# Presentation-only tokens. These labels/colors never change ReportX family,
# severity, evidence, confidence, or publication decisions; they only map
# already-known structured classification/labels to a consistent visual theme.
_FAMILY_PRESENTATION = {
    "cve_advisory": ("VULNERABILITY / CVE", "#8b5cf6", "#38bdf8"),
    "cisa_kev": ("KNOWN EXPLOITED VULNERABILITY", "#f97316", "#ef4444"),
    "cisa_advisory": ("SECURITY ADVISORY", "#22d3ee", "#6366f1"),
    "ransomware_claim": ("RANSOMWARE / EXTORTION CLAIM", "#ff4055", "#f97316"),
    "ransomware_reporting": ("RANSOMWARE INTELLIGENCE", "#f43f5e", "#fb7185"),
    "breach_notice": ("DATA BREACH", "#06b6d4", "#14b8a6"),
    "threat_actor": ("THREAT ACTOR / CAMPAIGN", "#a855f7", "#6366f1"),
    "ai_security": ("AI SECURITY", "#22d3ee", "#8b5cf6"),
    "malware": ("MALWARE INTELLIGENCE", "#f59e0b", "#fb7185"),
    "phishing": ("PHISHING / SOCIAL ENGINEERING", "#eab308", "#f97316"),
    "supply_chain": ("SUPPLY-CHAIN INTELLIGENCE", "#22c55e", "#14b8a6"),
    "general_intelligence": ("THREAT ANALYSIS", "#3b82f6", "#22d3ee"),
}

_SECTION_TONES = {
    "executive summary": "executive",
    "key judgements": "executive",
    "verified facts": "evidence",
    "evidence & source assessment": "evidence",
    "timeline & chronology": "timeline",
    "enterprise exposure assessment": "exposure",
    "technical analysis": "technical",
    "report-type deep dive": "technical",
    "mitre att&ck assessment": "technical",
    "indicators & observables": "ioc",
    "detection engineering guidance": "soc",
    "detection validation & required telemetry": "soc",
    "threat hunting queries": "soc",
    "soc analyst playbook": "soc",
    "incident response & containment decision plan": "response",
    "remediation & validation plan": "remediation",
    "executive decision matrix": "executive",
    "executive recommendations": "executive",
    "intelligence gaps & collection requirements": "gaps",
    "analytic confidence & limitations": "confidence",
    "references": "provenance",
    "provenance and certification": "provenance",
}

_SEVERITY_RE = re.compile(
    r"(?:severity(?:\s+of\s+this\s+threat)?\s+is\s+assessed\s+as|severity\s*[:\-]|priority\s*[:\-])\s*"
    r"(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b",
    re.IGNORECASE,
)
_CONFIDENCE_RE = re.compile(
    r"(?:overall\s+analytical\s+confidence|analytic\s+confidence|confidence(?:\s+in\s+severity\s+rating)?)"
    r"\s*(?:is|:)?\s*(HIGH|MEDIUM|LOW)\b",
    re.IGNORECASE,
)
_TLP_RE = re.compile(r"\b(TLP:(?:CLEAR|GREEN|AMBER(?:\+STRICT)?|RED))\b", re.IGNORECASE)

_CANONICAL_HEADINGS = {
    "executive summary",
    "key judgements",
    "verified facts",
    "threat classification",
    "threat severity assessment",
    "evidence & source assessment",
    "timeline & chronology",
    "business impact",
    "enterprise exposure assessment",
    "technical analysis",
    "report-type deep dive",
    "mitre att&ck assessment",
    "indicators & observables",
    "detection engineering guidance",
    "detection validation & required telemetry",
    "threat hunting queries",
    "soc analyst playbook",
    "incident response & containment decision plan",
    "remediation & validation plan",
    "executive decision matrix",
    "executive recommendations",
    "intelligence gaps & collection requirements",
    "analytic confidence & limitations",
    "forecast & outlook",
    "references",
}


def _plain(report_html: str) -> str:
    soup = BeautifulSoup(report_html or "", "html.parser")
    return re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()


def _first(pattern: re.Pattern[str], text: str, default: str) -> str:
    match = pattern.search(text)
    return match.group(1).upper() if match else default


def _safe(value: Any, fallback: str = "NOT EXPOSED") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _normalize_heading(text: str) -> str:
    cleaned = re.sub(r"^[\s\d.\-–—:]+", "", text or "").strip().lower()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def _presentation_family(article: Any, context: Any) -> str:
    """Return a visual family key using only existing structured state/labels."""
    family = str(getattr(context, "family", None) or "general_intelligence").strip().lower()
    if family != "general_intelligence":
        return family if family in _FAMILY_PRESENTATION else "general_intelligence"

    labels = " ".join(str(value or "") for value in (getattr(article, "labels", None) or [])).lower()
    if "ransomware" in labels:
        return "ransomware_reporting"
    if "malware" in labels:
        return "malware"
    if "data breach" in labels or "breach" in labels:
        return "breach_notice"
    if "phishing" in labels:
        return "phishing"
    if "supply chain" in labels or "supply-chain" in labels:
        return "supply_chain"
    if "ai security" in labels:
        return "ai_security"
    if "threat actor" in labels or "campaign" in labels:
        return "threat_actor"
    return "general_intelligence"


def _family_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-") or "general-intelligence"


def _delivery_mode(article: Any) -> str:
    labels = {str(value or "").strip().lower() for value in (getattr(article, "labels", None) or [])}
    return "RAPID INTELLIGENCE" if "rapid intelligence" in labels else "STANDARD INTELLIGENCE"


def _corroboration_state(report_html: str) -> str:
    """Surface only corroboration language already present in the report."""
    plain = _plain(report_html).lower()
    if re.search(r"\bindependent(?:ly)? corroborat(?:ed|ion)\b", plain):
        return "INDEPENDENT CORROBORATION"
    if ("single-source" in plain or "single source" in plain) and (
        "gap" in plain or "uncorroborated" in plain or "corroboration" in plain
    ):
        return "SINGLE-SOURCE / OPEN GAP"
    return "NOT EXPLICITLY ASSERTED"


def _source_publisher(report_html: str, article: Any) -> str:
    publisher = _safe(getattr(article, "source_publisher", None), "")
    if publisher:
        return publisher
    plain = _plain(report_html)
    match = re.search(r"Source publisher\s*:\s*([^|•\n]{2,120}?)(?=\s+Source published|$)", plain, re.I)
    if match:
        return match.group(1).strip()
    return _safe(getattr(article, "source", None), "SOURCE LINKED")


def _severity_from_structured(article: Any) -> Optional[str]:
    score = getattr(article, "cvss_score", None)
    if score is None:
        return None
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    if value > 0:
        return "LOW"
    return None


def _metadata(report_html: str, article: Any, context: Any) -> dict[str, str]:
    """Resolve customer-facing metadata without inferring missing facts."""
    plain = _plain(report_html)
    report_id = _safe(getattr(context, "report_id", None))
    certification = _safe(getattr(context, "certification_status", None), "EVIDENCE BOUNDED")
    severity = _severity_from_structured(article) or _first(_SEVERITY_RE, plain, "UNSPECIFIED")
    confidence = _first(_CONFIDENCE_RE, plain, "UNSPECIFIED")

    category = "CYBER THREAT INTELLIGENCE"
    labels = getattr(article, "labels", None) or []
    if labels:
        category = str(labels[0]).strip() or category

    generated = "NOT EXPOSED"
    gen = re.search(r"Generated UTC\s*([0-9T:+.\-Z]{10,40})", plain, re.I)
    if gen:
        generated = gen.group(1)

    family = _presentation_family(article, context)
    family_label, accent, accent_alt = _FAMILY_PRESENTATION.get(
        family, _FAMILY_PRESENTATION["general_intelligence"]
    )
    source_value = _source_publisher(report_html, article)
    source_linked = bool(
        str(getattr(article, "url", None) or "").strip()
        or str(getattr(article, "source", None) or "").strip()
        or str(getattr(article, "source_publisher", None) or "").strip()
    )

    return {
        "title": _safe(getattr(article, "title", None), "Threat Intelligence Report"),
        "report_id": report_id,
        "severity": severity,
        "confidence": confidence,
        "tlp": _first(_TLP_RE, plain, "NOT ASSIGNED"),
        "category": category,
        "source": source_value,
        "generated": generated,
        "certification": certification,
        "family": family,
        "family_slug": _family_slug(family),
        "family_label": family_label,
        "accent": accent,
        "accent_alt": accent_alt,
        "source_state": "SOURCE-LINKED" if source_linked else "SOURCE NOT EXPOSED",
        "corroboration": _corroboration_state(report_html),
        "delivery_mode": _delivery_mode(article),
        "claim_boundary": (
            "CLAIM-BOUND"
            if family == "ransomware_claim"
            else "PUBLIC-RECORD BOUND"
            if family == "breach_notice"
            else "EVIDENCE-BOUND"
        ),
    }


def _kpi(label: str, value: str, extra: str = "") -> str:
    return (
        f'<div class="cdbd-kpi {extra}"><span>{_html.escape(label)}</span>'
        f'<strong>{_html.escape(value)}</strong></div>'
    )


def _status_led(label: str, value: str, tone: str = "cyan") -> str:
    safe_tone = tone if tone in {"cyan", "green", "amber", "violet"} else "cyan"
    return (
        f'<div class="cdbd-led cdbd-led-{safe_tone}">'
        f'<i aria-hidden="true"></i><span>{_html.escape(label)}</span>'
        f'<strong>{_html.escape(value)}</strong></div>'
    )


def _command_deck(meta: dict[str, str]) -> str:
    sev = meta["severity"].lower()
    family_class = f"cdbd-family-{meta['family_slug']}"
    source_tone = "green" if meta["source_state"] == "SOURCE-LINKED" else "amber"
    corroboration_tone = (
        "green" if meta["corroboration"] == "INDEPENDENT CORROBORATION"
        else "amber" if meta["corroboration"] == "SINGLE-SOURCE / OPEN GAP"
        else "cyan"
    )
    delivery_tone = "violet" if meta["delivery_mode"] == "RAPID INTELLIGENCE" else "cyan"
    return f"""
<section class="cdbd-command report-hero cdbd-sev-{_html.escape(sev)} {_html.escape(family_class)}"
  data-cdb-component="report-hero" data-report-family="{_html.escape(meta['family'], quote=True)}"
  aria-label="Sentinel APEX intelligence command deck">
  <div class="cdbd-eyebrow"><span>CYBERDUDEBIVASH® INTEL FACTORY</span><span>SENTINEL APEX™ // ENTERPRISE ADVANCED CTI DOSSIER</span></div>
  <div class="cdbd-badge-row">
    <span class="family-badge">{_html.escape(meta['family_label'])}</span>
    <span class="priority-chip">{_html.escape(meta['severity'])}</span>
    <span class="confidence-pill">CONFIDENCE · {_html.escape(meta['confidence'])}</span>
  </div>
  <div class="cdbd-title">{_html.escape(meta['title'])}</div>
  <div class="cdbd-identity"><span>{_html.escape(meta['category'])}</span><i></i><span>{_html.escape(meta['report_id'])}</span></div>
  <div class="cdbd-kpis metadata-grid" data-cdb-component="metadata-grid">
    {_kpi('SEVERITY', meta['severity'], 'cdbd-kpi-severity')}
    {_kpi('CONFIDENCE', meta['confidence'])}
    {_kpi('TLP', meta['tlp'])}
    {_kpi('SOURCE', meta['source'])}
    {_kpi('GENERATED UTC', meta['generated'])}
    {_kpi('CERTIFICATION', meta['certification'])}
  </div>
  <div class="cdbd-leds status-led-group" data-cdb-component="status-led-group" aria-label="Evidence and delivery status indicators">
    {_status_led('SOURCE', meta['source_state'], source_tone)}
    {_status_led('EVIDENCE', meta['claim_boundary'], 'cyan')}
    {_status_led('CORROBORATION', meta['corroboration'], corroboration_tone)}
    {_status_led('DELIVERY', meta['delivery_mode'], delivery_tone)}
    {_status_led('INTEGRITY', 'FAIL-CLOSED GATES ACTIVE', 'green')}
  </div>
  <div class="cdbd-trust"><b></b><span>EVIDENCE-PRESERVING PRESENTATION</span><span>NO SYNTHETIC VISUAL METRICS</span><span>REPORTX BOUNDARIES RETAINED</span></div>
</section>"""


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:72] or "section"


def _section_nodes(heading: Tag) -> list[Tag]:
    nodes: list[Tag] = []
    level = int(heading.name[1]) if heading.name and heading.name.startswith("h") else 3
    sibling = heading.next_sibling
    while sibling is not None:
        nxt = sibling.next_sibling
        if isinstance(sibling, Tag) and sibling.name in {"h2", "h3"}:
            other_level = int(sibling.name[1])
            if other_level <= level:
                break
        if isinstance(sibling, Tag):
            nodes.append(sibling)
        sibling = nxt
    return nodes


def _find_heading(soup: BeautifulSoup, semantic: str) -> Optional[Tag]:
    for heading in soup.find_all(["h2", "h3"]):
        if _normalize_heading(heading.get_text(" ", strip=True)) == semantic:
            return heading
    return None


def _clip_visible(text: str, limit: int = 260) -> str:
    clean = re.sub(r"\s+", " ", text or "").strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit + 1].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"


def _section_excerpt(soup: BeautifulSoup, semantic: str, limit: int = 260) -> str:
    heading = _find_heading(soup, semantic)
    if heading is None:
        return ""
    text = " ".join(node.get_text(" ", strip=True) for node in _section_nodes(heading))
    return _clip_visible(text, limit)


def _quick_snapshot_html(soup: BeautifulSoup) -> str:
    """Reuse already-rendered canonical prose; never synthesize a new finding."""
    specs = (
        ("EXECUTIVE TAKEAWAY", ("executive summary", "key judgements"), "executive"),
        ("SOC ACTION", ("soc analyst playbook", "detection engineering guidance"), "soc"),
        ("EXPOSURE DECISION", ("enterprise exposure assessment",), "exposure"),
        ("INTELLIGENCE GAPS", ("intelligence gaps & collection requirements",), "gaps"),
        ("REMEDIATION & VALIDATION", ("remediation & validation plan",), "remediation"),
    )
    cards: list[str] = []
    for label, semantics, tone in specs:
        excerpt = ""
        source_semantic = ""
        for semantic in semantics:
            excerpt = _section_excerpt(soup, semantic)
            if excerpt:
                source_semantic = semantic
                break
        if not excerpt:
            continue
        cards.append(
            f'<article class="cdbd-snapshot-card callout-box cdbd-tone-{tone}" '
            f'data-cdb-component="callout-box" data-source-section="{_html.escape(source_semantic, quote=True)}">'
            f'<span>{_html.escape(label)}</span><p>{_html.escape(excerpt)}</p></article>'
        )
    if not cards:
        return ""
    return (
        '<section class="cdbd-snapshot quick-snapshot-card" '
        'data-cdb-component="quick-snapshot-card" aria-label="Executive and SOC situation snapshot">'
        '<div class="cdbd-snapshot-head"><span>SITUATION SNAPSHOT</span>'
        '<b>DERIVED ONLY FROM CANONICAL REPORT SECTIONS</b></div>'
        f'<div class="cdbd-snapshot-grid">{"".join(cards)}</div></section>'
    )


def _dedupe_semantic_sections(soup: BeautifulSoup) -> None:
    """Keep one customer-facing canonical section for duplicated headings.

    Production reports historically contain an LLM analysis followed by a
    deterministic ReportX/evidence-safe canonical section set. When a heading
    repeats, the later section wins because it is downstream of ReportX gates.
    The earlier duplicate is removed with its body so contradictory versions do
    not coexist in the customer artifact.
    """
    by_key: dict[str, list[Tag]] = {}
    for heading in soup.find_all(["h2", "h3"]):
        key = _normalize_heading(heading.get_text(" ", strip=True))
        if key in _CANONICAL_HEADINGS:
            by_key.setdefault(key, []).append(heading)
    for headings in by_key.values():
        if len(headings) < 2:
            continue
        for heading in headings[:-1]:
            for node in _section_nodes(heading):
                node.decompose()
            heading.decompose()


def _decorate_structure(soup: BeautifulSoup) -> list[tuple[str, str]]:
    """Add semantic visual classes/anchors after semantic convergence."""
    _dedupe_semantic_sections(soup)
    nav: list[tuple[str, str]] = []
    used: dict[str, int] = {}
    for heading in soup.find_all(["h2", "h3"]):
        label = re.sub(r"\s+", " ", heading.get_text(" ", strip=True)).strip()
        if not label:
            continue
        semantic = _normalize_heading(label)
        base = _slug(label)
        used[base] = used.get(base, 0) + 1
        anchor = base if used[base] == 1 else f"{base}-{used[base]}"
        if not heading.get("id"):
            heading["id"] = anchor
        else:
            anchor = str(heading["id"])
        # Keep the historical single class intact for existing downstream tests;
        # semantic component/tone data attributes are additive.
        heading["class"] = list(heading.get("class", [])) + ["cdbd-section-title"]
        heading["data-cdb-component"] = "section-card"
        tone = _SECTION_TONES.get(semantic, "standard")
        heading["data-cdb-tone"] = tone

        body_nodes = _section_nodes(heading)
        for index, node in enumerate(body_nodes):
            node["class"] = list(node.get("class", [])) + ["cdbd-section-content"]
            if index == 0 and semantic in _SECTION_TONES:
                node["data-cdb-component"] = "callout-box"

        if len(nav) < 32:
            nav.append((anchor, label))

    for table in soup.find_all("table"):
        table["class"] = list(table.get("class", [])) + ["cdbd-matrix"]
        previous = table.find_previous(["h2", "h3"])
        if previous is not None and _normalize_heading(previous.get_text(" ", strip=True)) == "indicators & observables":
            table["class"] = list(table.get("class", [])) + ["ioc-table"]
            table["data-cdb-component"] = "ioc-table"

    detection_sections = {
        "detection engineering guidance",
        "detection validation & required telemetry",
        "threat hunting queries",
        "soc analyst playbook",
    }
    for block in soup.find_all(["pre", "code"]):
        block["class"] = list(block.get("class", [])) + ["cdbd-telemetry"]
        previous = block.find_previous(["h2", "h3"])
        if previous is not None and _normalize_heading(previous.get_text(" ", strip=True)) in detection_sections:
            block["class"] = list(block.get("class", [])) + ["detection-code-block"]
            block["data-cdb-component"] = "detection-code-block"
    return nav


def _nav_html(nav: list[tuple[str, str]]) -> str:
    if not nav:
        return ""
    links = "".join(
        f'<a href="#{_html.escape(anchor, quote=True)}">{_html.escape(label[:48])}</a>'
        for anchor, label in nav
    )
    return f'<nav class="cdbd-nav" aria-label="Report navigation"><b>INTEL DOSSIER</b><div>{links}</div></nav>'


def _styles() -> str:
    return r"""<style id="cdb-cti-dossier-v5-css">
.cdb-cti-dossier{--bg:#03070c;--s:#07111c;--p:#0b1827;--p2:#102238;--line:rgba(64,211,255,.23);--cyan:#29d9ff;--blue:#4b7dff;--violet:#a26dff;--green:#3de292;--amber:#ffb52c;--orange:#ff7a18;--red:#ff4055;--text:#eff8ff;--muted:#9bb0c3;--family-accent:var(--cyan);--family-accent-alt:var(--blue);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.78;background:radial-gradient(circle at 8% 0,rgba(41,217,255,.085),transparent 32rem),radial-gradient(circle at 92% 12%,rgba(162,109,255,.07),transparent 34rem),var(--bg);padding:clamp(14px,2.6vw,32px);border:1px solid rgba(41,217,255,.12);border-radius:18px;box-shadow:0 28px 90px rgba(0,0,0,.32)}
.cdb-cti-dossier *{box-sizing:border-box}.cdb-cti-dossier a{color:var(--cyan)!important;text-underline-offset:3px}.cdb-cti-dossier a:focus-visible{outline:3px solid var(--family-accent);outline-offset:3px;border-radius:4px}
.cdbd-family-cve-advisory{--family-accent:#8b5cf6;--family-accent-alt:#38bdf8}.cdbd-family-cisa-kev{--family-accent:#f97316;--family-accent-alt:#ef4444}.cdbd-family-cisa-advisory{--family-accent:#22d3ee;--family-accent-alt:#6366f1}.cdbd-family-ransomware-claim,.cdbd-family-ransomware-reporting{--family-accent:#ff4055;--family-accent-alt:#f97316}.cdbd-family-breach-notice{--family-accent:#06b6d4;--family-accent-alt:#14b8a6}.cdbd-family-threat-actor{--family-accent:#a855f7;--family-accent-alt:#6366f1}.cdbd-family-ai-security{--family-accent:#22d3ee;--family-accent-alt:#8b5cf6}.cdbd-family-malware{--family-accent:#f59e0b;--family-accent-alt:#fb7185}.cdbd-family-phishing{--family-accent:#eab308;--family-accent-alt:#f97316}.cdbd-family-supply-chain{--family-accent:#22c55e;--family-accent-alt:#14b8a6}.cdbd-family-general-intelligence{--family-accent:#3b82f6;--family-accent-alt:#22d3ee}
.cdbd-command{position:relative;overflow:hidden;background:linear-gradient(135deg,rgba(12,27,45,.98),rgba(3,7,12,.99));border:1px solid var(--line);border-top:4px solid var(--family-accent);border-radius:16px;padding:clamp(22px,4vw,44px);margin:0 0 16px;box-shadow:0 20px 65px rgba(0,0,0,.36)}.cdbd-command:after{content:"";position:absolute;width:460px;height:460px;right:-140px;bottom:-330px;border-radius:50%;background:radial-gradient(circle,color-mix(in srgb,var(--family-accent) 20%,transparent),transparent 68%);pointer-events:none}.cdbd-sev-critical{border-top-color:var(--red)}.cdbd-sev-high{border-top-color:var(--orange)}.cdbd-sev-medium{border-top-color:var(--amber)}
.cdbd-eyebrow{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--cyan);font:800 11px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.14em}.cdbd-badge-row{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}.family-badge,.priority-chip,.confidence-pill{display:inline-flex;align-items:center;min-height:30px;padding:6px 10px;border-radius:999px;font:850 10px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em}.family-badge{border:1px solid color-mix(in srgb,var(--family-accent) 50%,transparent);background:color-mix(in srgb,var(--family-accent) 10%,transparent);color:#fff}.priority-chip{border:1px solid rgba(255,181,44,.35);background:rgba(255,181,44,.07);color:#ffd477}.confidence-pill{border:1px solid rgba(41,217,255,.25);background:rgba(41,217,255,.055);color:#bcefff}
.cdbd-title{max-width:1100px;margin:18px 0 11px;color:#fff;font-size:clamp(29px,4.6vw,54px);line-height:1.07;font-weight:900;letter-spacing:-.035em;text-wrap:balance}.cdbd-identity{display:flex;gap:10px;align-items:center;flex-wrap:wrap;color:var(--muted);font:700 11px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.07em;text-transform:uppercase}.cdbd-identity i{width:6px;height:6px;border-radius:50%;background:var(--family-accent);box-shadow:0 0 10px color-mix(in srgb,var(--family-accent) 62%,transparent)}
.cdbd-kpis{position:relative;z-index:1;display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin-top:28px}.cdbd-kpi{min-height:82px;padding:13px;border:1px solid rgba(142,166,189,.18);border-radius:11px;background:rgba(0,0,0,.25);display:flex;flex-direction:column;justify-content:space-between;min-width:0}.cdbd-kpi span{color:var(--muted);font:800 10px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.11em}.cdbd-kpi strong{color:#fff!important;font-size:13px;line-height:1.3;overflow-wrap:anywhere}.cdbd-kpi-severity strong{color:var(--orange)!important}.cdbd-sev-critical .cdbd-kpi-severity strong{color:var(--red)!important}.cdbd-sev-medium .cdbd-kpi-severity strong{color:var(--amber)!important}
.cdbd-leds{position:relative;z-index:1;display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin-top:10px}.cdbd-led{min-width:0;padding:10px 11px;border:1px solid rgba(142,166,189,.15);border-radius:10px;background:rgba(0,0,0,.18);display:grid;grid-template-columns:10px 1fr;column-gap:8px;row-gap:4px;align-items:center}.cdbd-led i{grid-row:1/3;width:8px;height:8px;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px rgba(41,217,255,.7)}.cdbd-led span{color:var(--muted);font:800 9px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.cdbd-led strong{color:#fff!important;font-size:10px;line-height:1.35;overflow-wrap:anywhere}.cdbd-led-green i{background:var(--green);box-shadow:0 0 12px rgba(61,226,146,.65)}.cdbd-led-amber i{background:var(--amber);box-shadow:0 0 12px rgba(255,181,44,.62)}.cdbd-led-violet i{background:var(--violet);box-shadow:0 0 12px rgba(162,109,255,.62)}
.cdbd-trust{position:relative;z-index:1;display:flex;align-items:center;gap:13px;flex-wrap:wrap;margin-top:15px;color:var(--muted);font:750 10px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.07em}.cdbd-trust b{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 14px rgba(61,226,146,.7)}
.cdbd-snapshot{margin:0 0 18px;padding:14px;border:1px solid rgba(142,166,189,.15);border-radius:14px;background:linear-gradient(145deg,rgba(8,20,33,.92),rgba(4,10,17,.94));box-shadow:0 16px 40px rgba(0,0,0,.18)}.cdbd-snapshot-head{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:11px}.cdbd-snapshot-head span{color:var(--family-accent);font:900 10px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.13em}.cdbd-snapshot-head b{color:var(--muted)!important;font:800 9px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em}.cdbd-snapshot-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px}.cdbd-snapshot-card{min-width:0;padding:13px;border:1px solid rgba(142,166,189,.14);border-top:3px solid var(--family-accent);border-radius:10px;background:rgba(0,0,0,.2)}.cdbd-snapshot-card span{display:block;margin-bottom:8px;color:var(--family-accent);font:850 9px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em}.cdbd-snapshot-card p{margin:0!important;color:#e4edf6!important;font-size:12px!important;line-height:1.6!important}.cdbd-tone-soc{border-top-color:var(--cyan)}.cdbd-tone-exposure{border-top-color:var(--amber)}.cdbd-tone-gaps{border-top-color:var(--violet)}.cdbd-tone-remediation{border-top-color:var(--green)}
.cdbd-nav{position:sticky;top:7px;z-index:25;display:flex;align-items:center;gap:10px;margin:0 0 20px;padding:10px 12px;border:1px solid var(--line);border-radius:11px;background:rgba(3,7,12,.94);backdrop-filter:blur(14px)}.cdbd-nav>b{flex:0 0 auto;color:var(--cyan)!important;font:850 10px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.cdbd-nav>div{display:flex;gap:6px;overflow-x:auto;scrollbar-width:thin;padding-bottom:2px}.cdbd-nav a{flex:0 0 auto;padding:7px 10px;border:1px solid rgba(142,166,189,.15);border-radius:999px;background:var(--p);color:#b6c6d6!important;text-decoration:none!important;font-size:10px;font-weight:750;white-space:nowrap}.cdbd-nav a:hover{color:#fff!important;border-color:var(--family-accent)}
.cdbd-body{max-width:1160px;margin:0 auto}.cdb-cti-dossier .cdbd-section-title{--section-accent:var(--family-accent);scroll-margin-top:74px;margin:30px 0 13px!important;padding:14px 17px!important;color:#fff!important;background:linear-gradient(90deg,color-mix(in srgb,var(--section-accent) 10%,transparent),rgba(11,24,39,.78))!important;border:1px solid color-mix(in srgb,var(--section-accent) 25%,transparent)!important;border-left:4px solid var(--section-accent)!important;border-radius:10px!important;font-size:clamp(18px,2vw,23px)!important;line-height:1.3!important;letter-spacing:-.01em!important}.cdbd-section-title[data-cdb-tone=evidence]{--section-accent:var(--green)}.cdbd-section-title[data-cdb-tone=soc]{--section-accent:var(--cyan)}.cdbd-section-title[data-cdb-tone=exposure]{--section-accent:var(--amber)}.cdbd-section-title[data-cdb-tone=response]{--section-accent:var(--orange)}.cdbd-section-title[data-cdb-tone=remediation]{--section-accent:var(--green)}.cdbd-section-title[data-cdb-tone=gaps]{--section-accent:var(--violet)}.cdbd-section-title[data-cdb-tone=provenance]{--section-accent:#94a3b8}.cdb-cti-dossier h4{color:var(--cyan)!important}.cdb-cti-dossier p{color:#dce8f4!important;margin:10px 0 15px!important;font-size:15px!important;line-height:1.78!important}.cdb-cti-dossier strong{color:#fff!important}.cdb-cti-dossier ul,.cdb-cti-dossier ol{margin:12px 0 19px!important;padding:15px 19px 15px 36px!important;border:1px solid rgba(142,166,189,.13)!important;border-left:3px solid color-mix(in srgb,var(--family-accent) 45%,transparent)!important;border-radius:0 10px 10px 0!important;background:rgba(11,24,39,.5)!important}.cdb-cti-dossier li{color:#dce8f4!important;margin:7px 0!important;font-size:14px!important;line-height:1.7!important}.cdb-cti-dossier li::marker{color:var(--family-accent)}.cdb-cti-dossier blockquote{padding:17px 20px!important;border:1px solid rgba(255,181,44,.22)!important;border-left:4px solid var(--amber)!important;border-radius:10px!important;background:rgba(255,181,44,.055)!important;color:#fff!important}.cdbd-section-title[data-cdb-tone]+.cdbd-section-content[data-cdb-component=callout-box]{padding:15px 17px!important;border:1px solid rgba(142,166,189,.14)!important;border-radius:11px!important;background:rgba(9,22,36,.52)!important}
.cdb-cti-dossier table{width:100%!important;border-collapse:separate!important;border-spacing:0!important;display:table!important;margin:18px 0 23px!important;border:1px solid var(--line)!important;border-radius:12px!important;overflow:hidden!important;background:var(--p)!important;box-shadow:0 14px 34px rgba(0,0,0,.16)}.cdb-cti-dossier th{padding:13px!important;background:#0a1c2d!important;color:var(--cyan)!important;border:0!important;border-bottom:1px solid var(--line)!important;text-align:left!important;font:850 10px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace!important;letter-spacing:.07em!important;text-transform:uppercase}.cdb-cti-dossier td{padding:13px!important;color:#dce8f4!important;border:0!important;border-bottom:1px solid rgba(142,166,189,.11)!important;vertical-align:top!important;font-size:13.5px!important;line-height:1.65!important}.cdb-cti-dossier tr:last-child td{border-bottom:0!important}.cdb-cti-dossier tr:hover td{background:rgba(41,217,255,.035)!important}.cdb-cti-dossier .ioc-table{border-color:color-mix(in srgb,var(--family-accent) 35%,transparent)!important}.cdb-cti-dossier pre{padding:16px!important;overflow:auto!important;border:1px solid var(--line)!important;border-radius:11px!important;background:#02060a!important;color:#bcefff!important;font-size:12.5px!important;line-height:1.65!important}.cdb-cti-dossier code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace!important;background:#06131d!important;color:#aef0ff!important;border:1px solid rgba(41,217,255,.13)!important;border-radius:5px!important;padding:2px 5px!important}.cdb-cti-dossier .detection-code-block{border-left:4px solid var(--cyan)!important}.cdb-cti-dossier img,.cdb-cti-dossier svg{max-width:100%!important;height:auto}.cdb-cti-dossier hr{border:0!important;border-top:1px solid rgba(142,166,189,.18)!important;margin:28px 0!important}
@media(max-width:1100px){.cdbd-snapshot-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.cdbd-leds{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:980px){.cdbd-kpis{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:640px){.cdb-cti-dossier{padding:10px;border-radius:0}.cdbd-command{padding:19px 14px}.cdbd-eyebrow span{display:block;width:100%;margin-bottom:3px}.cdbd-kpis,.cdbd-leds{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbd-kpi{min-height:70px}.cdbd-snapshot-grid{grid-template-columns:1fr}.cdbd-nav{top:0;border-radius:8px}.cdb-cti-dossier table{display:block!important;overflow-x:auto!important}.cdbd-title{font-size:30px}.cdbd-trust{gap:7px}.cdb-cti-dossier p{font-size:14px!important}}
@media(prefers-reduced-motion:reduce){.cdb-cti-dossier *{scroll-behavior:auto!important}}@media(forced-colors:active){.cdb-cti-dossier,.cdbd-command,.cdbd-snapshot,.cdbd-kpi,.cdbd-led{forced-color-adjust:auto;border-color:CanvasText}.cdbd-led i,.cdbd-trust b{box-shadow:none}.family-badge,.priority-chip,.confidence-pill{border:1px solid CanvasText}}
@media print{.cdb-cti-dossier{background:#fff!important;color:#111!important;padding:0!important;border:0!important;box-shadow:none!important}.cdbd-nav{display:none!important}.cdbd-command,.cdbd-snapshot{background:#fff!important;box-shadow:none!important;break-inside:avoid}.cdbd-title,.cdbd-kpi strong,.cdbd-led strong,.cdb-cti-dossier .cdbd-section-title,.cdb-cti-dossier strong{color:#111!important}.cdb-cti-dossier p,.cdb-cti-dossier li,.cdb-cti-dossier td{color:#222!important}.cdb-cti-dossier ul,.cdb-cti-dossier ol,.cdb-cti-dossier table,.cdb-cti-dossier .cdbd-section-title{background:#fff!important;break-inside:avoid}.cdbd-kpi,.cdbd-led,.cdbd-snapshot-card{background:#fff!important;border-color:#cbd5e1!important}}
</style>"""


def decorate_cti_dossier(report_html: str, article: Any, context: Any) -> str:
    """Converge and decorate an already-composed report. Idempotent and fail-open."""
    if not report_html or MARKER in report_html:
        return report_html
    try:
        soup = BeautifulSoup(report_html, "html.parser")
        nav = _decorate_structure(soup)
        snapshot = _quick_snapshot_html(soup)
        original = str(soup)
        meta = _metadata(original, article, context)
        return (
            f"<!-- {MARKER} --><!-- {VISUAL_SYSTEM} -->{_styles()}"
            f"<article class=\"{ROOT_CLASS}\" data-cdb-visual-system=\"{VISUAL_SYSTEM}\">"
            f"{_command_deck(meta)}{snapshot}{_nav_html(nav)}<div class=\"cdbd-body\">{original}</div>"
            f"</article><!-- /{MARKER} -->"
        )
    except Exception:
        return report_html


def _patched_assemble_html(self, article, body_content: str, seo_data: dict, context, image_url: Optional[str] = None):
    if _ORIGINAL_ASSEMBLE_HTML is None:
        raise RuntimeError("CTI dossier presentation layer is not installed")
    rendered = _ORIGINAL_ASSEMBLE_HTML(self, article, body_content, seo_data, context, image_url)
    return decorate_cti_dossier(rendered, article, context)


def install_cti_dossier_presentation(main_module) -> None:
    """Install strictly last, wrapping the complete production renderer stack."""
    global _ORIGINAL_ASSEMBLE_HTML
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    if getattr(transformer._assemble_html, "__name__", "") == "_patched_assemble_html":
        return
    _ORIGINAL_ASSEMBLE_HTML = transformer._assemble_html
    transformer._assemble_html = _patched_assemble_html
