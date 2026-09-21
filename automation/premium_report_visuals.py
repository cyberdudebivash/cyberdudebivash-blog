"""Fortune-500-grade deterministic presentation layer for SENTINEL APEX reports.

Presentation only:
- derives visual state from already-verified article/context fields;
- never changes factual text, evidence semantics, quality gates, or publication gates;
- uses static HTML/CSS only for Blogger compatibility and predictable rendering.
"""

from __future__ import annotations

import html
import re
from typing import Optional

from .content_discovery import DiscoveredArticle
from .report_integrity import ReportContext


_FAMILY_ACCENTS = {
    "cve_advisory": ("#7c3aed", "#c4b5fd", "VULNERABILITY"),
    "cisa_kev": ("#dc2626", "#fecaca", "KNOWN EXPLOITED"),
    "cisa_advisory": ("#2563eb", "#bfdbfe", "SECURITY ADVISORY"),
    "ransomware_claim": ("#e11d48", "#fecdd3", "RANSOMWARE CLAIM"),
    "ransomware_reporting": ("#db2777", "#fbcfe8", "RANSOMWARE INTEL"),
    "breach_notice": ("#0891b2", "#bae6fd", "DATA BREACH"),
    "threat_actor": ("#d97706", "#fde68a", "THREAT ACTOR"),
    "ai_security": ("#06b6d4", "#a5f3fc", "AI SECURITY"),
    "general_intelligence": ("#2563eb", "#bfdbfe", "THREAT INTELLIGENCE"),
}


def _esc(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _family_visual(context: ReportContext) -> tuple[str, str, str]:
    return _FAMILY_ACCENTS.get(
        str(context.family or "").lower(),
        ("#2563eb", "#bfdbfe", str(context.family_label or "THREAT INTELLIGENCE").upper()),
    )


def _severity_from_article(article: DiscoveredArticle) -> tuple[str, str]:
    score = article.cvss_score
    if score is None:
        text = " ".join(
            str(v or "") for v in (article.title, article.summary, article.full_content or "")
        )
        match = re.search(
            r"\bCVSS(?:\s+(?:v?3(?:\.1)?))?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
            text,
            re.IGNORECASE,
        )
        if match:
            try:
                score = float(match.group(1))
            except ValueError:
                score = None
    if score is None:
        return "UNRATED", "#64748b"
    if score >= 9:
        return "CRITICAL", "#dc2626"
    if score >= 7:
        return "HIGH", "#ea580c"
    if score >= 4:
        return "MEDIUM", "#ca8a04"
    return "LOW", "#2563eb"


def premium_report_style_block() -> str:
    """Reusable Blogger-safe visual design system. No JS and no remote assets."""
    return """
<style id="cdb-premium-report-v1">
.cdb-premium-report{
  --cdb-bg:#071018;--cdb-surface:#0b1621;--cdb-card:#0e1b27;--cdb-card-2:#101f2d;
  --cdb-border:#244052;--cdb-text:#edf7fb;--cdb-muted:#9bb3c2;--cdb-subtle:#6f8999;
  --cdb-accent:#2563eb;--cdb-accent-soft:#bfdbfe;
  color:var(--cdb-text);font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  font-size:15px;line-height:1.72;letter-spacing:.002em;
}
.cdb-premium-report *{box-sizing:border-box}
.cdb-premium-report a{color:#7dd3fc;text-decoration-thickness:1px;text-underline-offset:3px}
.cdb-report-shell{max-width:1080px;margin:0 auto}
.cdb-report-hero{
  position:relative;overflow:hidden;margin:18px 0 22px;padding:26px;
  border:1px solid #31506a;
  border:1px solid color-mix(in srgb,var(--cdb-accent) 48%,#244052);
  border-radius:18px;background:linear-gradient(145deg,#0d1a25,#08131d 72%);
  background:
    radial-gradient(circle at 88% 12%,color-mix(in srgb,var(--cdb-accent) 19%,transparent),transparent 34%),
    linear-gradient(145deg,#0d1a25,#08131d 72%);
  box-shadow:0 18px 46px rgba(0,0,0,.28);
}
.cdb-report-hero:before{
  content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--cdb-accent);
  box-shadow:0 0 22px color-mix(in srgb,var(--cdb-accent) 62%,transparent)
}
.cdb-kicker{font:800 11px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.16em;text-transform:uppercase;color:var(--cdb-accent-soft)}
.cdb-report-title{margin:10px 0 8px;color:#fff;font-size:clamp(1.65rem,4vw,2.45rem);line-height:1.15;letter-spacing:-.025em;font-weight:850}
.cdb-report-deck{margin:0;color:#bcd0dc;font-size:.98rem;max-width:900px}
.cdb-chip-row{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}
.cdb-chip{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #2c4658;border-radius:999px;background:#0b1722;color:#dbeaf2;font:700 11px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.035em}
.cdb-chip-accent{border-color:#466079;border-color:color-mix(in srgb,var(--cdb-accent) 60%,#2c4658);color:var(--cdb-accent-soft)}
.cdb-led{width:8px;height:8px;border-radius:50%;display:inline-block;background:currentColor;box-shadow:0 0 11px currentColor}
.cdb-meta-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 24px}
.cdb-meta-card{padding:13px 14px;background:#0b1722;border:1px solid #22394a;border-radius:12px;min-width:0}
.cdb-meta-label{color:#7994a5;font:800 10px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.11em;text-transform:uppercase}
.cdb-meta-value{margin-top:6px;color:#f0f7fb;font-weight:750;font-size:13px;overflow-wrap:anywhere}
.cdb-snapshot{margin:0 0 26px;padding:18px;border:1px solid #2a4658;border-radius:15px;background:linear-gradient(145deg,#0c1924,#09141e)}
.cdb-snapshot h3{margin:0 0 13px!important;color:#fff!important;font-size:17px!important;letter-spacing:.01em!important;text-transform:none!important}
.cdb-snapshot-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.cdb-snapshot-item{padding:12px 13px;border:1px solid #213a4b;border-radius:10px;background:#0d1b27}
.cdb-snapshot-key{color:#7f9aaa;font:800 10px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;text-transform:uppercase;letter-spacing:.1em}
.cdb-snapshot-val{margin-top:5px;color:#e9f4f8;font-size:13px;font-weight:680;line-height:1.5}
.cdb-section-card{margin:30px 0!important;padding:0 0 18px;border:1px solid #223c4d;border-radius:15px;overflow:hidden;background:linear-gradient(180deg,#0d1923,#09131c);box-shadow:0 10px 30px rgba(0,0,0,.18)}
.cdb-section-card>div:first-child{margin:0!important;padding:12px 17px!important;border-left-width:4px!important}
.cdb-panel{border-radius:11px!important;background:#0b1722!important;border-color:#294455!important}
.cdb-bullet{margin:8px 0!important;padding:11px 14px!important;background:#0b1722!important;border-radius:0 8px 8px 0!important}
.cdb-premium-report h3{
  margin:28px 0 12px;padding:11px 14px;border-left:4px solid var(--cdb-accent);border-radius:0 8px 8px 0;
  background:linear-gradient(90deg,color-mix(in srgb,var(--cdb-accent) 14%,#0b1722),#0b1722);
  color:#f5fbff;font-size:18px;line-height:1.35;letter-spacing:-.01em
}
.cdb-premium-report p{color:#d5e4eb;margin:10px 0}
.cdb-premium-report strong{color:#fff}
.cdb-premium-report ul,.cdb-premium-report ol{padding-left:24px;color:#d5e4eb}
.cdb-premium-report li{margin:7px 0}
.cdb-premium-report table{display:block;width:100%;overflow-x:auto;border-collapse:separate;border-spacing:0;margin:18px 0;border:1px solid #294657;border-radius:11px;background:#0a151f}
.cdb-premium-report th{background:#102331;color:#dff7ff;font-size:12px;text-align:left;letter-spacing:.035em}
.cdb-premium-report th,.cdb-premium-report td{padding:11px 12px;border-bottom:1px solid #203a4b;border-right:1px solid #203a4b;vertical-align:top}
.cdb-premium-report tr:last-child td{border-bottom:0}
.cdb-premium-report pre{position:relative;overflow-x:auto;margin:15px 0;padding:17px;border:1px solid #31505f;border-radius:11px;background:#061019;color:#bff8df;font:12px/1.65 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.cdb-premium-report code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.cdb-callout{margin:18px 0;padding:15px 17px;border:1px solid #315266;border-left:5px solid var(--cdb-accent);border-radius:10px;background:#0c1a26}
.cdb-callout-title{font:850 11px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--cdb-accent-soft)}
.cdb-callout-body{margin-top:7px;color:#dcebf2}
.cdb-report-provenance{margin-top:26px;padding-top:18px;border-top:1px solid #294454}
@media(max-width:760px){
  .cdb-report-hero{padding:20px 17px;border-radius:14px}
  .cdb-meta-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .cdb-snapshot-grid{grid-template-columns:1fr}
  .cdb-premium-report{font-size:14px;line-height:1.68}
  .cdb-section-card{border-radius:12px}
}
@media(max-width:440px){.cdb-meta-grid{grid-template-columns:1fr}.cdb-report-title{font-size:1.55rem}}
@media(prefers-reduced-motion:reduce){.cdb-premium-report *{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style>
"""


def build_report_hero(
    article: DiscoveredArticle,
    context: ReportContext,
    *,
    detection_status: str,
    product_tier: str,
    content_source: str,
) -> str:
    accent, accent_soft, family_badge = _family_visual(context)
    severity, severity_color = _severity_from_article(article)
    source_label = article.source_publisher or article.source or "Source supplied"
    published = article.published_at or "Not supplied"

    tier = str(product_tier or "UNCLASSIFIED").replace("_", " ")
    route = (
        "RAPID INTELLIGENCE"
        if any("rapid" in str(value).lower() for value in (article.labels or []))
        else str(content_source or "standard").replace("_", " ").upper()
    )

    chips = [
        (family_badge, accent_soft, True),
        (severity, severity_color, True),
        (f"Tier: {tier}", "#a7f3d0", False),
        (f"Detection: {str(detection_status or 'not supplied').replace('_', ' ').upper()}", "#bae6fd", False),
        ("SOURCE-BACKED", "#86efac", False),
        ("EVIDENCE-GRAPH CONTROLLED", "#c4b5fd", False),
        (route, "#fde68a", False),
    ]
    chip_html = "".join(
        f'<span class="cdb-chip{" cdb-chip-accent" if accented else ""}" style="color:{color}"><span class="cdb-led" aria-hidden="true"></span>{_esc(label)}</span>'
        for label, color, accented in chips
    )

    meta = [
        ("Report ID", context.report_id),
        ("Source", source_label),
        ("Source Published", published),
        ("Generated UTC", context.generated_at),
    ]
    meta_html = "".join(
        f'<div class="cdb-meta-card"><div class="cdb-meta-label">{_esc(k)}</div><div class="cdb-meta-value">{_esc(v)}</div></div>'
        for k, v in meta
    )

    snapshot_rows = [
        ("Intelligence family", context.family_label),
        ("Evidence status", context.review_status),
        ("Exploitation", context.exploitation_label),
        ("Patch / remediation", context.patch_label),
    ]
    snapshot_html = "".join(
        f'<div class="cdb-snapshot-item"><div class="cdb-snapshot-key">{_esc(k)}</div><div class="cdb-snapshot-val">{_esc(v)}</div></div>'
        for k, v in snapshot_rows
    )

    deck = (
        f"Source-backed enterprise intelligence from {source_label}. "
        "Review the evidence status, verified facts, and decision guidance before taking customer-specific action."
    )

    return (
        f'<div class="cdb-report-shell" style="--cdb-accent:{accent};--cdb-accent-soft:{accent_soft}">'
        f'<header class="cdb-report-hero">'
        f'<div class="cdb-kicker">CYBERDUDEBIVASH® SENTINEL APEX · Enterprise Intelligence</div>'
        f'<div class="cdb-report-title">{_esc(article.title)}</div>'
        f'<p class="cdb-report-deck">{_esc(deck)}</p>'
        f'<div class="cdb-chip-row">{chip_html}</div>'
        f'</header>'
        f'<div class="cdb-meta-grid">{meta_html}</div>'
        f'<section class="cdb-snapshot" aria-label="Quick situation snapshot">'
        f'<h3>Quick Situation Snapshot</h3><div class="cdb-snapshot-grid">{snapshot_html}</div>'
        f'</section>'
        f'</div>'
    )


def wrap_premium_report(body_html: str, *, accent: str, accent_soft: str) -> str:
    """Wrap unchanged report body so all content paths share one visual contract."""
    return (
        f'<div class="cdb-premium-report" style="--cdb-accent:{_esc(accent)};--cdb-accent-soft:{_esc(accent_soft)}">'
        f'<div class="cdb-report-shell">{body_html}</div></div>'
    )


def family_accent(context: ReportContext) -> tuple[str, str]:
    accent, soft, _ = _family_visual(context)
    return accent, soft
