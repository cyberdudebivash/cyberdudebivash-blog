"""SENTINEL APEX CTI Dossier v12 — assurance-style SOC/CTI reading experience.

Presentation-only: trusted report context + existing canonical headings. This is
NOT a SOC 2 audit, certification, attestation, control test, or customer incident.
Install after v11; v8 and v19.x evidence and commercial gates remain authoritative.
"""
from __future__ import annotations

import html
import re
from typing import Any, Optional
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, Tag

MARKER = "CDB-CTI-DOSSIER-V12"
_INSTALL_ATTR = "__cdb_cti_dossier_v12__"
_INNER_ASSEMBLE = None

# Only stable, canonical document sections get jump links. Never synthesize
# absent evidence sections just to make a fuller-looking dossier.
_SECTIONS = (
    ("Executive brief", ("executive summary", "executive intelligence", "executive assessment")),
    ("Evidence", ("verified facts", "evidence & source assessment", "evidence and source assessment")),
    ("Technical analysis", ("technical analysis", "threat analysis", "vulnerability analysis")),
    ("Detection", ("detection engineering guidance", "detection guidance", "detection engineering")),
    ("Exposure", ("exposure assessment", "enterprise exposure", "business impact")),
    ("Response", ("soc response", "response playbook", "mitigation & remediation")),
    ("Sources", ("references", "source references", "source ledger", "primary references")),
)

_FAMILY_FOCUS = {
    "ai_security": (
        "AI agent / model trust boundary",
        "Inventory models, connected tools and delegated privileges. Validate source-backed activity against model/agent traces.",
    ),
    "cve_advisory": (
        "Affected asset / vendor remediation",
        "Verify affected version, configuration, reachability and vendor remediation against the enterprise inventory.",
    ),
    "cisa_kev": (
        "KEV-driven exposure and remediation",
        "Confirm asset applicability and the official KEV action before assigning a remediation owner.",
    ),
    "cisa_advisory": (
        "Advisory-driven exposure",
        "Validate the cited technology and affected configuration before changing controls.",
    ),
    "ransomware_claim": (
        "Third-party claim verification",
        "Do not elevate a public leak-site claim to a confirmed breach without independent enterprise evidence.",
    ),
    "ransomware_reporting": (
        "Ransomware-relevant controls",
        "Prioritize sourced TTPs, protected backups, identity and endpoint telemetry over generic indicator matches.",
    ),
    "breach_notice": (
        "Third-party data-impact assessment",
        "Map any confirmed vendor, customer or shared-data relationship before inferring organizational exposure.",
    ),
}
_DEFAULT_FOCUS = (
    "Source-grounded SOC relevance",
    "Validate the cited event against current assets, identity boundaries and available security telemetry.",
)


def _text(value: Any, limit: int = 160) -> str:
    """Bound/unify metadata without introducing unsupported evidence."""
    return re.sub(r"\s+", " ", str(value or "").strip())[:limit]


def _heading_key(s: str) -> str:
    return re.sub(r"[^a-z0-9& ]", "", re.sub(r"\s+", " ", s.lower())).strip()


def _safe_source_url(article: Any) -> str:
    candidate = str(getattr(article, "url", "") or "")
    try:
        url = urlsplit(candidate)
        if url.scheme in {"https", "http"} and url.hostname and not url.username and not url.password:
            return candidate
    except ValueError:
        pass
    return ""


def _navigation(soup: BeautifulSoup) -> str:
    links: list[str] = []
    assigned = set()
    for label, candidates in _SECTIONS:
        for heading in soup.find_all(["h2", "h3"]):
            if isinstance(heading, Tag) and _heading_key(heading.get_text(" ", strip=True)) in candidates:
                if id(heading) in assigned:
                    continue
                assigned.add(id(heading))
                dest = str(heading.get("id") or f"cdbv12-section-{len(links)+1}")
                if not heading.get("id"):
                    heading["id"] = dest
                links.append(
                    f'<a href="#{html.escape(dest, quote=True)}">{html.escape(label)}</a>'
                )
                break
    return '<nav class="cdbv12-nav" aria-label="Jump to intelligence dossier sections">' + "".join(links) + "</nav>" if links else ""


def _cover(article: Any, context: Any, navigation: str) -> str:
    family = _text(getattr(context, "family", "general_intelligence"), 60)
    family_label = _text(getattr(context, "family_label", "Cyber Threat Intelligence"), 100)
    report_id = _text(getattr(context, "report_id", ""), 90) or "NOT ASSIGNED"
    compiled = _text(getattr(context, "generated_at", ""), 55) or "NOT RECORDED"
    pub_date = _text(getattr(article, "published_at", ""), 55) or "NOT RECORDED"
    source = _text(getattr(article, "source", ""), 80) or "NOT IDENTIFIED"
    fingerprint = str(getattr(context, "source_record_hash", "") or "")
    fingerprint = fingerprint[:12].lower() if re.fullmatch(r"[0-9a-fA-F]{64}", fingerprint) else "NOT AVAILABLE"
    exploitation = _text(getattr(context, "exploitation_label", ""), 140) or "NOT ESTABLISHED"
    headline = _text(getattr(article, "title", ""), 260) or "Source-linked intelligence report"
    focus, action = _FAMILY_FOCUS.get(family, _DEFAULT_FOCUS)
    source_url = _safe_source_url(article)
    source_link = (
        f'<a href="{html.escape(source_url, quote=True)}" rel="noopener noreferrer" target="_blank">Open primary record ↗</a>'
        if source_url else "<span>Source URL not provided in record</span>"
    )
    return f'''<section class="cdbv12-cover" data-cdb-cti-v12="true" aria-label="SENTINEL APEX SOC and CTI report briefing">
  <div class="cdbv12-overline"><span>SENTINEL APEX™ / CYBERDUDEBIVASH® ECOSYSTEM</span><span>PUBLIC • ENTERPRISE CTI DOSSIER</span></div>
  <div class="cdbv12-intro"><div><p class="cdbv12-eyebrow">SOC ANALYST BRIEF / {html.escape(family_label.upper())}</p>
    <h2>{html.escape(headline)}</h2>
    <p class="cdbv12-sub">Decision-oriented intelligence with source provenance, defensive validation and clearly bounded uncertainty.</p>
  </div><div class="cdbv12-status"><b>PUBLIC INTELLIGENCE</b><span>Customer exposure: NOT ASSESSED</span><span>Incident determination: NOT MADE</span></div></div>
  <div class="cdbv12-grid" aria-label="Intelligence record identity">
    <div><small>REPORT ID</small><strong>{html.escape(report_id)}</strong></div>
    <div><small>INTELLIGENCE SOURCE</small><strong>{html.escape(source)}</strong></div>
    <div><small>SOURCE DATE (SUPPLIED)</small><strong>{html.escape(pub_date)}</strong></div>
    <div><small>REPORT COMPILED</small><strong>{html.escape(compiled)}</strong></div>
    <div><small>SOURCE HASH PREFIX</small><strong>{html.escape(fingerprint)}</strong></div>
    <div><small>EXPLOITATION ASSESSMENT</small><strong>{html.escape(exploitation)}</strong></div>
  </div>
  {navigation}
  <div class="cdbv12-brief"><div><span>ANALYST DECISION FOCUS</span><h3>{html.escape(focus)}</h3><p>{html.escape(action)}</p></div>
    <div><span>PRIMARY-SOURCE ENTRY</span><p>{source_link}</p><p>Source-record SHA-256 prefix is a traceability aid, not evidence of external verification.</p></div></div>
  <p class="cdbv12-boundary"><strong>Assurance boundary:</strong> Structured for SOC and CTI evidence review. This publication is not an AICPA SOC 2 report, independent attestation, audit opinion, completed control test, or proof of compromise. Validate technical assertions and enterprise relevance against source documents and customer telemetry.</p>
</section>'''


_STYLES = r'''<style id="cdb-cti-dossier-v12-css">
.cdbv12-cover{margin:20px 0 26px; padding:clamp(16px,3vw,30px); color:#eaf4ff!important; background:radial-gradient(ellipse at top right,rgba(29,118,175,.16),transparent 65%),linear-gradient(145deg,#071523,#0b1927 60%,#07121d);border:1px solid #24435c;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.22);font:400 14px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;overflow:hidden}
.cdbv12-cover *{box-sizing:border-box}.cdbv12-overline{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;color:#83d9f4!important;letter-spacing:.08em;font-size:10px;font-weight:800}
.cdbv12-intro{display:grid;grid-template-columns:minmax(0,1fr) 205px;gap:20px;align-items:start;margin:26px 0}.cdbv12-eyebrow{margin:0 0 10px!important;color:#61cced!important;font:800 10px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.11em}.cdbv12-intro h2{font:800 clamp(20px,3vw,29px)/1.26 system-ui,-apple-system,Segoe UI,sans-serif!important;margin:0!important;color:#fff!important;border:0!important;padding:0!important;overflow-wrap:anywhere}.cdbv12-sub{color:#acc7df!important;font-size:13px!important;margin:10px 0 0!important}
.cdbv12-status{padding:13px;border:1px solid rgba(125,211,252,.28);border-radius:11px;background:rgba(15,35,54,.8)}.cdbv12-status b{display:block;color:#79d2f1!important;font-size:10px;margin-bottom:9px;letter-spacing:.08em}.cdbv12-status span{display:block;color:#dbeafe!important;font-size:11px;margin:5px 0}
.cdbv12-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:rgba(109,170,205,.18);border:1px solid rgba(109,170,205,.18);border-radius:12px;overflow:hidden}.cdbv12-grid>div{background:#0a1d2d;padding:13px;min-width:0}.cdbv12-grid small{display:block;color:#81a6bd!important;font-size:9px;letter-spacing:.09em;font-weight:800}.cdbv12-grid strong{display:block;color:#eff8ff!important;margin-top:6px;font:700 12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
.cdbv12-nav{display:flex;flex-wrap:wrap;gap:7px;margin:18px 0}.cdbv12-nav a{color:#a7e5fd!important;text-decoration:none!important;border:1px solid rgba(125,211,252,.22);background:rgba(125,211,252,.05);padding:7px 10px;min-height:34px;border-radius:7px;font-size:11px;font-weight:700}.cdbv12-nav a:hover,.cdbv12-nav a:focus-visible{background:rgba(125,211,252,.14);outline-offset:2px}
.cdbv12-brief{display:grid;grid-template-columns:1.35fr 1fr;gap:12px}.cdbv12-brief>div{background:rgba(3,12,21,.55);border:1px solid rgba(125,211,252,.16);border-radius:11px;padding:15px}.cdbv12-brief span{font-size:10px;color:#67d0ef;letter-spacing:.09em;font-weight:800}.cdbv12-brief h3{font:750 17px/1.35 system-ui,-apple-system,Segoe UI,sans-serif!important;color:#f4fbff!important;margin:7px 0!important}.cdbv12-brief p{color:#d3e5f5!important;margin:7px 0!important;font-size:12px!important}.cdbv12-brief a{color:#87dfff!important;text-decoration:underline!important;overflow-wrap:anywhere}.cdbv12-boundary{margin:15px 0 0!important;padding:12px;border-left:3px solid #8ab2d0;background:rgba(142,174,200,.08);color:#c4d4e4!important;font-size:11px!important;line-height:1.65!important}
@media(max-width:750px){.cdbv12-intro{grid-template-columns:1fr}.cdbv12-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cdbv12-brief{grid-template-columns:1fr}}@media(max-width:440px){.cdbv12-grid{grid-template-columns:1fr}}@media(prefers-reduced-motion:reduce){.cdbv12-cover *{scroll-behavior:auto}}@media print{.cdbv12-cover{background:#fff!important;color:#111!important;box-shadow:none!important;border:1px solid #555;break-inside:avoid}.cdbv12-cover *{color:#111!important;background:#fff!important}.cdbv12-nav a{color:#111!important}}
</style>'''


def enhance_cti_dossier_v12(rendered_html: str, article: Any, context: Any) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    soup = BeautifulSoup(rendered_html, "html.parser")
    if soup.select_one('[data-cdb-cti-v12="true"]'):
        return rendered_html
    anchor = soup.select_one(".cdbd-command")
    if anchor is None:
        return rendered_html  # Do not modify unknown layouts.
    nav = _navigation(soup)
    parsed = BeautifulSoup(_cover(article, context, nav), "html.parser")
    cover = parsed.select_one(".cdbv12-cover")
    if cover is None:
        return rendered_html
    anchor.insert_before(cover)
    if not soup.select_one("#cdb-cti-dossier-v12-css"):
        soup.insert(0, BeautifulSoup(_STYLES, "html.parser"))
    return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"


def _patched_assemble(self: Any, article: Any, body_content: str, seo_data: dict,
                      context: Any, image_url: Optional[str] = None) -> str:
    if _INNER_ASSEMBLE is None:
        raise RuntimeError("CTI v12 presentation was not installed")
    rendered = _INNER_ASSEMBLE(self, article, body_content, seo_data, context, image_url)
    try:
        return enhance_cti_dossier_v12(rendered, article, context)
    except Exception:
        return rendered  # Cannot bypass existing v8 or later final publication gates.


setattr(_patched_assemble, _INSTALL_ATTR, True)


def install_cti_dossier_v12(main_module: Any) -> None:
    global _INNER_ASSEMBLE
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return
    _INNER_ASSEMBLE = current
    transformer._assemble_html = _patched_assemble
