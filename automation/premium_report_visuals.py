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
    """SENTINEL APEX report experience v2: static, Blogger-safe, accessible CSS."""
    return """
<style id="cdb-premium-report-v1">
.cdb-premium-report{
  --cdb-bg:#050b12;--cdb-surface:#08131d;--cdb-surface-2:#0b1925;--cdb-card:#0d1c29;
  --cdb-border:#284354;--cdb-border-strong:#3a5b6d;--cdb-text:#edf7fb;--cdb-muted:#9eb5c3;
  --cdb-subtle:#738e9f;--cdb-accent:#2563eb;--cdb-accent-soft:#bfdbfe;--cdb-green:#5ee6a8;
  color:var(--cdb-text);font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
  font-size:15.5px;line-height:1.76;letter-spacing:.002em;counter-reset:cdb-section;
  text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;
}
.cdb-premium-report *{box-sizing:border-box}
.cdb-premium-report ::selection{background:var(--cdb-accent);color:#fff}
.cdb-premium-report a{color:#7dd3fc;text-decoration-thickness:1px;text-underline-offset:3px;overflow-wrap:anywhere}
.cdb-premium-report a:focus-visible{outline:3px solid var(--cdb-accent-soft);outline-offset:3px;border-radius:4px}
.cdb-report-shell{width:min(1120px,100%);margin:0 auto}
.cdb-report-hero{
  position:relative;overflow:hidden;margin:20px 0 16px;padding:30px;
  border:1px solid #31506a;border:1px solid color-mix(in srgb,var(--cdb-accent) 48%,#244052);
  border-radius:22px;background:linear-gradient(145deg,#0e1e2c,#07111a 72%);
  background:
    radial-gradient(circle at 92% 10%,color-mix(in srgb,var(--cdb-accent) 22%,transparent),transparent 30%),
    radial-gradient(circle at 4% 110%,rgba(41,217,255,.08),transparent 31%),
    linear-gradient(145deg,#0e1e2c,#07111a 72%);
  box-shadow:0 24px 72px rgba(0,0,0,.34),inset 0 1px 0 rgba(255,255,255,.035);
}
.cdb-report-hero:before{
  content:"";position:absolute;left:0;top:0;bottom:0;width:5px;background:var(--cdb-accent);
  box-shadow:0 0 26px color-mix(in srgb,var(--cdb-accent) 68%,transparent)
}
.cdb-report-hero:after{
  content:"";position:absolute;right:-54px;top:-54px;width:180px;height:180px;border:1px solid rgba(255,255,255,.045);
  border-radius:50%;box-shadow:0 0 0 28px rgba(255,255,255,.015),0 0 0 58px rgba(255,255,255,.008);pointer-events:none
}
.cdb-hero-grid{position:relative;z-index:1;display:grid;grid-template-columns:minmax(0,1fr) 255px;gap:28px;align-items:stretch}
.cdb-hero-main{min-width:0}
.cdb-kicker{font:850 11px/1.25 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.16em;text-transform:uppercase;color:var(--cdb-accent-soft)}
.cdb-report-title{margin:11px 0 11px;color:#fff;font-size:clamp(1.8rem,4.2vw,2.8rem);line-height:1.1;letter-spacing:-.035em;font-weight:860;max-width:880px}
.cdb-report-deck{margin:0;color:#c1d2dc;font-size:1rem;line-height:1.65;max-width:820px}
.cdb-chip-row{display:flex;flex-wrap:wrap;gap:8px;margin-top:20px}
.cdb-chip{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #2c4658;border-radius:999px;background:rgba(7,18,28,.82);color:#dbeaf2;font:750 10.5px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.04em;white-space:normal}
.cdb-chip-accent{border-color:#466079;border-color:color-mix(in srgb,var(--cdb-accent) 60%,#2c4658);color:var(--cdb-accent-soft)}
.cdb-led{width:8px;height:8px;flex:0 0 8px;border-radius:50%;display:inline-block;background:currentColor;box-shadow:0 0 12px currentColor}
.cdb-hero-aside{display:flex;flex-direction:column;justify-content:space-between;min-width:0;padding:17px;border:1px solid rgba(142,180,202,.18);border-radius:16px;background:linear-gradient(180deg,rgba(7,18,28,.82),rgba(8,24,35,.7));box-shadow:inset 0 1px 0 rgba(255,255,255,.035)}
.cdb-signal-overline{color:#7996a8;font:850 9px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.14em;text-transform:uppercase}
.cdb-signal-primary{display:flex;align-items:center;gap:9px;margin-top:11px;font:900 22px/1.1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.025em}
.cdb-signal-orb{width:11px;height:11px;flex:0 0 11px;border-radius:50%;background:currentColor;box-shadow:0 0 18px currentColor}
.cdb-signal-family{margin-top:10px;color:#eef8fd;font-size:12px;font-weight:800;line-height:1.4;text-transform:uppercase;letter-spacing:.055em}
.cdb-signal-note{margin-top:16px;padding-top:13px;border-top:1px solid rgba(142,180,202,.14);color:#91aaba;font-size:11px;line-height:1.55}
.cdb-governance-rail{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px;margin:10px 0 12px}
.cdb-governance-step{position:relative;padding:10px 11px;border:1px solid #213a4b;border-radius:10px;background:#081722;color:#b8ccd8;font:800 9px/1.35 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em;text-align:center}
.cdb-governance-step:not(:last-child):after{content:"›";position:absolute;right:-8px;top:50%;transform:translateY(-50%);z-index:2;color:var(--cdb-accent-soft);font-size:16px}
.cdb-reading-map{display:flex;gap:7px;overflow-x:auto;margin:0 0 12px;padding:9px;border:1px solid #213a4b;border-radius:12px;background:#07131d;scrollbar-width:thin}
.cdb-reading-map span{flex:1 0 auto;min-width:112px;padding:7px 9px;border-radius:8px;background:#0a1a26;color:#91aaba;font:800 9px/1.25 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.065em;text-align:center}
.cdb-reading-map b{color:var(--cdb-accent-soft);font-weight:900}
.cdb-meta-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 12px}
.cdb-meta-card{padding:14px;background:linear-gradient(180deg,#0b1925,#08141e);border:1px solid #223d4e;border-radius:12px;min-width:0;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.cdb-meta-label{color:#7894a6;font:850 9.5px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.11em;text-transform:uppercase}
.cdb-meta-value{margin-top:6px;color:#f0f7fb;font-weight:760;font-size:12.5px;line-height:1.45;overflow-wrap:anywhere}
.cdb-snapshot{margin:0 0 12px;padding:18px;border:1px solid #2a4658;border-radius:15px;background:linear-gradient(145deg,#0c1a26,#08141e)}
.cdb-snapshot-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}
.cdb-snapshot h3{margin:0!important;padding:0!important;border:0!important;background:none!important;color:#fff!important;font-size:17px!important;letter-spacing:.005em!important;text-transform:none!important}
.cdb-snapshot-tag{padding:5px 8px;border:1px solid rgba(94,230,168,.22);border-radius:999px;background:rgba(94,230,168,.05);color:#8af3bd;font:850 8px/1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.09em;white-space:nowrap}
.cdb-snapshot-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:9px}
.cdb-snapshot-item{padding:12px 13px;border:1px solid #213a4b;border-radius:10px;background:#0b1a26;min-width:0}
.cdb-snapshot-key{color:#7f9aaa;font:850 9px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;text-transform:uppercase;letter-spacing:.095em}
.cdb-snapshot-val{margin-top:6px;color:#e9f4f8;font-size:12.5px;font-weight:680;line-height:1.5;overflow-wrap:anywhere}
.cdb-decision-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:0 0 26px}
.cdb-decision-cell{padding:13px;border:1px solid #284556;border-radius:11px;background:linear-gradient(180deg,#0c1b27,#08151f);min-width:0}
.cdb-decision-cell span{display:block;color:#7f9aaa;font:850 9px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.09em;text-transform:uppercase}
.cdb-decision-cell strong{display:block;margin-top:6px;color:#f3f9fc;font-size:11.5px;line-height:1.48;overflow-wrap:anywhere}
.cdb-section-card{margin:32px 0!important;padding:0 18px 18px!important;border:1px solid #244354;border-radius:16px;overflow:hidden;background:linear-gradient(180deg,#0d1b27,#08131c);box-shadow:0 14px 38px rgba(0,0,0,.2),inset 0 1px 0 rgba(255,255,255,.02)}
.cdb-section-card>div:first-child{margin:0 -18px 15px!important;padding:13px 18px!important;border-left-width:4px!important;background:linear-gradient(90deg,#102332,#0a1722)!important}
.cdb-panel{border-radius:11px!important;background:#0b1823!important;border-color:#2b4a5b!important}
.cdb-bullet{margin:8px 0!important;padding:11px 14px!important;background:#0a1823!important;border-radius:0 8px 8px 0!important}
.cdb-premium-report h2{margin:34px 0 14px;color:#fff;font-size:21px;line-height:1.25;letter-spacing:-.015em}
.cdb-premium-report h3{
  counter-increment:cdb-section;display:grid;grid-template-columns:34px minmax(0,1fr);align-items:center;gap:10px;
  margin:30px 0 13px;padding:12px 14px;border:1px solid #274656;border-left:4px solid var(--cdb-accent);border-radius:10px;
  background:linear-gradient(90deg,#0c1d2a,#09151f);background:linear-gradient(90deg,color-mix(in srgb,var(--cdb-accent) 12%,#0c1d2a),#09151f);
  color:#f5fbff;font-size:18px;line-height:1.35;letter-spacing:-.01em
}
.cdb-premium-report h3:before{content:counter(cdb-section,decimal-leading-zero);display:grid;place-items:center;width:30px;height:30px;border:1px solid #365468;border-radius:8px;background:#07131d;color:var(--cdb-accent-soft);font:900 9px/1 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.05em}
.cdb-premium-report h4{margin:22px 0 8px;color:#eaf5fb;font-size:15px;line-height:1.4}
.cdb-premium-report p{max-width:84ch;color:#d7e5ec;margin:10px 0 13px;line-height:1.78}
.cdb-premium-report strong{color:#fff;font-weight:780}
.cdb-premium-report em{color:#c8d9e2}
.cdb-premium-report ul,.cdb-premium-report ol{max-width:90ch;padding-left:25px;color:#d7e5ec}
.cdb-premium-report li{margin:8px 0;padding-left:2px}
.cdb-premium-report li::marker{color:var(--cdb-accent-soft);font-weight:800}
.cdb-premium-report blockquote{margin:18px 0;padding:14px 17px;border-left:4px solid var(--cdb-accent);border-radius:0 10px 10px 0;background:#0a1823;color:#d9e8ef}
.cdb-premium-report hr{height:1px;border:0;background:linear-gradient(90deg,transparent,#2e4c5f,transparent);margin:28px 0}
.cdb-premium-report table{display:block;width:100%;overflow-x:auto;border-collapse:separate;border-spacing:0;margin:19px 0;border:1px solid #2b4a5b;border-radius:12px;background:#08141e;box-shadow:0 10px 30px rgba(0,0,0,.13)}
.cdb-premium-report thead{background:#102735}
.cdb-premium-report th{background:#102735;color:#e6f8ff;font-size:11.5px;text-align:left;letter-spacing:.045em;text-transform:none}
.cdb-premium-report th,.cdb-premium-report td{padding:12px 13px;border-bottom:1px solid #203b4b;border-right:1px solid #203b4b;vertical-align:top;line-height:1.55;min-width:110px}
.cdb-premium-report tbody tr:nth-child(even){background:rgba(255,255,255,.018)}
.cdb-premium-report tbody tr:hover{background:rgba(125,211,252,.035)}
.cdb-premium-report tr:last-child td{border-bottom:0}
.cdb-premium-report th:last-child,.cdb-premium-report td:last-child{border-right:0}
.cdb-premium-report pre{position:relative;overflow-x:auto;margin:16px 0;padding:18px;border:1px solid #315364;border-radius:12px;background:#041019;color:#bff8df;font:12px/1.66 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
.cdb-premium-report code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
.cdb-premium-report :not(pre)>code{padding:2px 5px;border:1px solid #294657;border-radius:5px;background:#07141e;color:#bdefff;font-size:.92em}
.cdb-premium-report img{max-width:100%;height:auto;border-radius:12px}
.cdb-premium-report details{margin:14px 0;border:1px solid #294657;border-radius:10px;background:#081722;padding:10px 13px}
.cdb-premium-report summary{cursor:pointer;color:#eaf5fb;font-weight:760}
.cdb-callout{margin:18px 0;padding:16px 18px;border:1px solid #315266;border-left:5px solid var(--cdb-accent);border-radius:11px;background:#0b1a26;box-shadow:0 10px 26px rgba(0,0,0,.13)}
.cdb-callout-title{font:850 10.5px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--cdb-accent-soft)}
.cdb-callout-body{margin-top:7px;color:#dcebf2}
.cdb-report-provenance{margin-top:28px;padding-top:18px;border-top:1px solid #294454}
@media(max-width:900px){
  .cdb-hero-grid{grid-template-columns:1fr}.cdb-hero-aside{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .cdb-signal-note{margin-top:0;padding-top:0;padding-left:14px;border-top:0;border-left:1px solid rgba(142,180,202,.14)}
  .cdb-snapshot-grid,.cdb-decision-strip{grid-template-columns:repeat(2,minmax(0,1fr))}
}
@media(max-width:760px){
  .cdb-report-hero{padding:22px 18px;border-radius:16px}.cdb-report-title{font-size:clamp(1.55rem,8vw,2.15rem)}
  .cdb-meta-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.cdb-governance-rail{grid-template-columns:repeat(2,minmax(0,1fr))}
  .cdb-governance-step:not(:last-child):after{display:none}.cdb-premium-report{font-size:14.5px;line-height:1.72}
  .cdb-section-card{border-radius:12px}.cdb-premium-report h3{grid-template-columns:30px minmax(0,1fr);font-size:16.5px}
  .cdb-premium-report h3:before{width:27px;height:27px}
}
@media(max-width:520px){
  .cdb-meta-grid,.cdb-snapshot-grid,.cdb-decision-strip{grid-template-columns:1fr}.cdb-hero-aside{grid-template-columns:1fr}
  .cdb-signal-note{padding-left:0;padding-top:12px;border-left:0;border-top:1px solid rgba(142,180,202,.14)}
  .cdb-report-hero{padding:19px 15px}.cdb-chip{font-size:10px}.cdb-reading-map{margin-left:-1px;margin-right:-1px}
  .cdb-section-card{padding:0 14px 15px!important}.cdb-section-card>div:first-child{margin-left:-14px!important;margin-right:-14px!important}
  .cdb-premium-report th,.cdb-premium-report td{padding:10px 11px;font-size:12px}
}
@media(prefers-reduced-motion:reduce){.cdb-premium-report *{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
@media(prefers-contrast:more){
  .cdb-premium-report{--cdb-text:#fff;--cdb-muted:#c9dce6}.cdb-section-card,.cdb-meta-card,.cdb-snapshot,.cdb-decision-cell{border-color:#527287}
}
@media print{
  .cdb-report-hero,.cdb-meta-card,.cdb-snapshot,.cdb-decision-cell,.cdb-section-card,.cdb-panel,.cdb-callout{box-shadow:none!important;background:#fff!important;color:#111!important;border-color:#b8c1c7!important;break-inside:avoid}
  .cdb-report-title,.cdb-premium-report h2,.cdb-premium-report h3,.cdb-premium-report strong,.cdb-meta-value,.cdb-snapshot-val,.cdb-decision-cell strong{color:#111!important}
  .cdb-report-deck,.cdb-premium-report p,.cdb-premium-report li{color:#222!important}.cdb-reading-map{display:none}.cdb-premium-report a{color:#111!important}
}
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

    tier = str(product_tier or "UNCLASSIFIED").replace("_", " ").upper()
    detection = str(detection_status or "not supplied").replace("_", " ").upper()
    route = (
        "RAPID INTELLIGENCE"
        if any("rapid" in str(value).lower() for value in (article.labels or []))
        else str(content_source or "standard").replace("_", " ").upper()
    )

    chips = [
        (family_badge, accent_soft, True),
        (severity, severity_color, True),
        (f"TIER · {tier}", "#a7f3d0", False),
        ("SOURCE-BACKED", "#86efac", False),
        ("EVIDENCE-GRAPH CONTROLLED", "#c4b5fd", False),
        (route, "#fde68a", False),
    ]
    chip_html = "".join(
        f'<span class="cdb-chip{" cdb-chip-accent" if accented else ""}" style="color:{color}">'
        f'<span class="cdb-led" aria-hidden="true"></span>{_esc(label)}</span>'
        for label, color, accented in chips
    )

    meta = [
        ("Report ID", context.report_id),
        ("Source", source_label),
        ("Source Published", published),
        ("Generated UTC", context.generated_at),
    ]
    meta_html = "".join(
        f'<div class="cdb-meta-card"><div class="cdb-meta-label">{_esc(k)}</div>'
        f'<div class="cdb-meta-value">{_esc(v)}</div></div>'
        for k, v in meta
    )

    snapshot_rows = [
        ("Intelligence family", context.family_label),
        ("Evidence governance", context.review_status),
        ("Analysis route", route),
        ("Delivery tier", tier),
    ]
    snapshot_html = "".join(
        f'<div class="cdb-snapshot-item"><div class="cdb-snapshot-key">{_esc(k)}</div>'
        f'<div class="cdb-snapshot-val">{_esc(v)}</div></div>'
        for k, v in snapshot_rows
    )

    decision_rows = [
        ("Exploitation", context.exploitation_label),
        ("Remediation", context.patch_label),
        ("Detection", detection),
        ("Customer-specific status", "INTERNAL VALIDATION REQUIRED"),
    ]
    decision_html = "".join(
        f'<div class="cdb-decision-cell"><span>{_esc(k)}</span><strong>{_esc(v)}</strong></div>'
        for k, v in decision_rows
    )

    governance = "".join(
        f'<div class="cdb-governance-step">{_esc(step)}</div>'
        for step in ("SOURCE RECORD", "EVIDENCE GRAPH", "REPORTX / DOSSIER", "FAIL-CLOSED GATE")
    )
    reading_map = "".join(
        f'<span><b>{idx:02d}</b> · {_esc(label)}</span>'
        for idx, label in enumerate(
            ("EXECUTIVE", "EVIDENCE", "TECHNICAL", "SOC / IR", "DECISIONS", "PROVENANCE"),
            start=1,
        )
    )

    deck = (
        f"Source-backed enterprise intelligence from {source_label}. "
        "The report separates public-source evidence, analytical assessment, operational guidance, "
        "and customer-specific validation so decision-makers can scan quickly without losing provenance."
    )

    return (
        f'<div class="cdb-report-shell" data-experience="sentinel-apex-v2" '
        f'style="--cdb-accent:{accent};--cdb-accent-soft:{accent_soft}">'
        f'<header class="cdb-report-hero" data-family="{_esc(context.family)}">'
        f'<div class="cdb-hero-grid"><div class="cdb-hero-main">'
        f'<div class="cdb-kicker">CYBERDUDEBIVASH® SENTINEL APEX · ENTERPRISE INTELLIGENCE DOSSIER</div>'
        f'<div class="cdb-report-title">{_esc(article.title)}</div>'
        f'<p class="cdb-report-deck">{_esc(deck)}</p>'
        f'<div class="cdb-chip-row">{chip_html}</div></div>'
        f'<aside class="cdb-hero-aside" aria-label="Intelligence posture">'
        f'<div><div class="cdb-signal-overline">INTELLIGENCE POSTURE</div>'
        f'<div class="cdb-signal-primary" style="color:{severity_color}"><span class="cdb-signal-orb" aria-hidden="true"></span>{_esc(severity)}</div>'
        f'<div class="cdb-signal-family">{_esc(family_badge)}</div></div>'
        f'<div class="cdb-signal-note">Evidence-bounded public intelligence. Customer exposure or compromise is not inferred without internal validation.</div>'
        f'</aside></div></header>'
        f'<div class="cdb-governance-rail" aria-label="Publication governance path">{governance}</div>'
        f'<nav class="cdb-reading-map" aria-label="Report reading map">{reading_map}</nav>'
        f'<div class="cdb-meta-grid">{meta_html}</div>'
        f'<section class="cdb-snapshot" aria-label="Quick situation snapshot">'
        f'<div class="cdb-snapshot-head"><h3>Quick Situation Snapshot</h3>'
        f'<span class="cdb-snapshot-tag">SOURCE-LINKED · EVIDENCE-BOUNDED</span></div>'
        f'<div class="cdb-snapshot-grid">{snapshot_html}</div></section>'
        f'<section class="cdb-decision-strip" aria-label="Operational decision state">{decision_html}</section>'
        f'</div>'
    )

def wrap_premium_report(body_html: str, *, accent: str, accent_soft: str) -> str:
    """Wrap unchanged report body so all content paths share one visual contract."""
    return (
        f'<div class="cdb-premium-report" data-report-experience="v2" style="--cdb-accent:{_esc(accent)};--cdb-accent-soft:{_esc(accent_soft)}">'
        f'<div class="cdb-report-shell">{body_html}</div></div>'
    )


def family_accent(context: ReportContext) -> tuple[str, str]:
    accent, soft, _ = _family_visual(context)
    return accent, soft
