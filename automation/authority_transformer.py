"""
CYBERDUDEBIVASH® SENTINEL APEX — Authority Content Transformer
Transforms source articles into enterprise-grade threat intelligence reports.
LLM priority: Groq → DeepSeek → OpenRouter → Anthropic → template fallback.
"""

import base64
import html as _html_escape
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode

from bs4 import BeautifulSoup

from .analytical_depth_gate import LLM_AUTHORED_SOURCES, evaluate_product_tier
from .category_mapper import primary_category
from .config import Config
from .content_discovery import DiscoveredArticle
from .download_center import build_mitre_navigator_layer
from .internal_linker import InternalLinker
from .key_judgements import KeyJudgement, generate_key_judgements
from .llm_client import call_llm
from .logger import setup_logger
from .industry_intelligence import detect_industries, get_industry_profile
from .monetization_injector import MonetizationInjector
from .product_recommendations import SERVICES as _CATALOG_SERVICES, recommend_services
from .report_integrity import (
    ReportContext,
    build_report_context,
    compute_artifact_hash,
    validate_publication,
)
from .premium_report_visuals import (
    build_report_hero,
    family_accent,
    premium_report_style_block,
    wrap_premium_report,
)
from .report_renderer import (
    _attack_section,
    _bullets,
    _detection_package,
    _detection_section,
    _esc,
    _family_analysis,
    _KNOWN_PUBLISHER_DOMAINS,
    _panel,
    _provenance,
    _section,
    render_evidence_report,
)
from .seo_optimizer import SEOOptimizer, _extract_cve_ids, _extract_cvss
from .social_preview_certifier import certify_metadata

logger = setup_logger("authority_transformer")


# Internal prioritization artifacts that leak into RSS summaries from the source
# platform (e.g. "Score 100/100 CRITICAL — CVSS 8 —"). These are pipeline-internal
# scoring labels, not analyst content — they contradict the report's own severity
# assessment and must never appear in published intelligence.
_SCORE_ARTIFACT_RE = re.compile(
    r"Score\s*\d{1,3}\s*/\s*100\s*(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)?"
    r"\s*[—–\-]*\s*(?:CVSS\s*[\d.]{1,4})?\s*[—–\-]*\s*",
    re.IGNORECASE,
)


def _sanitize_summary(text: str) -> str:
    """Strip internal scoring artifacts and collapse whitespace in source summaries."""
    if not text:
        return text
    cleaned = _SCORE_ARTIFACT_RE.sub("", text)
    return re.sub(r"\s{2,}", " ", cleaned).strip()


# RX-PR0 follow-up (CodeRabbit): the analyst prompt (_build_analyst_prompt)
# tells the LLM to use only these tags and explicitly "NO inline styles on
# individual elements, only structure" — this allowlist enforces that
# contract server-side rather than trusting the model (or a prompt-injected
# source article) to follow it. The deterministic template path does not use
# this — its HTML is self-authored, not model output.
_LLM_HTML_ALLOWED_TAGS = frozenset({
    "h3", "p", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td",
    "pre", "code", "strong", "em", "b", "i", "br", "a",
})
_LLM_HTML_REMOVE_ENTIRELY = frozenset({
    "script", "style", "iframe", "object", "embed", "link", "meta", "form",
    "input", "button", "svg", "video", "audio", "source", "noscript",
})


def _sanitize_llm_html(raw_html: str) -> str:
    """Reduce LLM-authored HTML to the fixed tag allowlist the prompt requests.

    Untrusted source-article text is embedded in the analyst prompt, so the
    model's output is not implicitly trusted — this strips anything outside
    the prompt's own contract (structure tags only, no attributes, no
    scripts/styles/embeds) before it ever reaches _assemble_html().
    """
    if not raw_html:
        return raw_html
    soup = BeautifulSoup(raw_html, "html.parser")
    for tag in soup.find_all(_LLM_HTML_REMOVE_ENTIRELY):
        tag.decompose()
    for tag in soup.find_all(True):
        if tag.name not in _LLM_HTML_ALLOWED_TAGS:
            tag.unwrap()
            continue
        if tag.name == "a":
            href = tag.attrs.get("href", "")
            tag.attrs = {"href": href, "target": "_blank", "rel": "noopener noreferrer"} if re.match(r"^https?://", href, re.IGNORECASE) else {}
        else:
            tag.attrs = {}
    return str(soup)


# Real, fixed count of SIEM platforms this pipeline generates detection
# queries for — single source of truth shared by the multi-SIEM query pack
# (_template_enhance) and the Trust Center's "Supported SIEM Platforms" stat.
SIEM_PLATFORM_LABELS = {
    "splunk": "Splunk SPL",
    "elastic": "Elastic EQL",
    "sentinel": "Microsoft Sentinel KQL",
    "qradar": "IBM QRadar AQL",
    "chronicle": "Google Chronicle YARA-L",
}


# ─────────────────────────────────────────────────────────────────────────────
# CATEGORY PALETTE — maps to SVG banner color schemes
# ─────────────────────────────────────────────────────────────────────────────
_CATEGORY_PALETTE = {
    "Ransomware":    {"bg1": "#1a0a00", "bg2": "#2d1200", "accent": "#f59e0b", "badge": "#b45309"},
    "Zero-Day":      {"bg1": "#1a0005", "bg2": "#2d0010", "accent": "#ef4444", "badge": "#b91c1c"},
    "CVE":           {"bg1": "#1a0005", "bg2": "#2d0010", "accent": "#ef4444", "badge": "#b91c1c"},
    "AI Security":   {"bg1": "#0d0a1a", "bg2": "#180d2d", "accent": "#a855f7", "badge": "#7c3aed"},
    "APT":           {"bg1": "#1a001a", "bg2": "#2d002d", "accent": "#ec4899", "badge": "#be185d"},
    "Nation-State":  {"bg1": "#1a001a", "bg2": "#2d002d", "accent": "#ec4899", "badge": "#be185d"},
    "Threat Intel":  {"bg1": "#001a1a", "bg2": "#002d2d", "accent": "#00d4ff", "badge": "#0284c7"},
    "Default":       {"bg1": "#00080f", "bg2": "#001220", "accent": "#00d4ff", "badge": "#0284c7"},
}


def _get_palette(labels: list) -> dict:
    text = " ".join(labels).lower()
    if "ransomware" in text:
        return _CATEGORY_PALETTE["Ransomware"]
    if "zero-day" in text or "zero day" in text or "0day" in text:
        return _CATEGORY_PALETTE["Zero-Day"]
    if "ai security" in text or "llm" in text or "prompt injection" in text:
        return _CATEGORY_PALETTE["AI Security"]
    if "apt" in text or "nation-state" in text:
        return _CATEGORY_PALETTE["APT"]
    if "cve" in text or "vulnerability" in text:
        return _CATEGORY_PALETTE["CVE"]
    if "threat intel" in text:
        return _CATEGORY_PALETTE["Threat Intel"]
    return _CATEGORY_PALETTE["Default"]


# ─────────────────────────────────────────────────────────────────────────────
# SVG THUMBNAIL GENERATOR
# Produces a 1200×630 branded banner embedded as a data URI <img> tag.
# This becomes data:post.firstImageUrl in Blogger — fixes missing thumbnails.
# ─────────────────────────────────────────────────────────────────────────────

# Bumped only when api/og.js's rendered layout actually changes (e.g. this
# Intelligence Card v3 redesign) — a fixed, deterministic cache-key
# differentiator so Vercel's long-lived edge cache (s-maxage=1yr) doesn't
# keep serving a stale old-design PNG at a URL it already cached, without
# fragmenting the cache per-request the way a timestamp or random value
# would. Every card of the same design version shares this one value.
OG_CARD_VERSION = "3"


def _format_og_date(published_at: Optional[str]) -> str:
    """Short display date for the OG card footer, e.g. "24 AUG 2026". Falls
    back to today (UTC) when published_at is missing or unparseable — never
    raises, since a slightly-off fallback date is harmless where a broken
    image render is not (same fail-soft discipline as api/og.js itself)."""
    if published_at:
        try:
            dt = datetime.fromisoformat(str(published_at).replace("Z", "+00:00"))
            return dt.strftime("%d %b %Y").upper()
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).strftime("%d %b %Y").upper()


def _build_dynamic_og_image_url(config: Config, title: str, severity: Optional[str],
                                 cve_id: str, cvss: Optional[str], type_label: str,
                                 report_id: Optional[str] = None, published_at: Optional[str] = None,
                                 ransomware_group: Optional[str] = None,
                                 ransomware_sector: Optional[str] = None,
                                 kev_listed: Optional[bool] = None,
                                 epss_pct: Optional[float] = None) -> str:
    """Same satori/resvg-rendered card the Vercel-side generators use
    (api/og.js) — mirrors its documented query contract exactly (title,
    severity, cve, cvss, type, reportId, date, actor, sector, kev, epss; see
    api/og.js's own docstring) rather than inventing a parallel image
    system. A parity port, not a duplication: Python can't require() the
    Node module, so the query-string contract is the shared interface,
    matching how detection-engine.js/sigma_builder.py mirror each other
    elsewhere in this repo.

    report_id reuses the platform's one canonical report-identity scheme
    (report_integrity.build_report_context()'s "CDB-CTI-{year}-{hash}") —
    never a second ID invented here. actor/sector/kev_listed/epss_pct are
    sent only when the source record actually supplied them (DiscoveredArticle.
    ransomware_group/ransomware_sector/kev_listed/epss_score, already
    None-when-unknown by that dataclass's own contract, the same fields
    _build_risk_command_center already renders into the article body) —
    this function fabricates no attribution, victim, or risk data of its
    own; when a field is absent the card simply omits that element.
    kev_listed follows the platform's no-negative-claim discipline: only
    True renders anything (a KEV ribbon); False/None are both silently
    omitted, matching _build_risk_command_center's own KEV tile semantics —
    this endpoint never prints a "Not Listed" claim on the share card."""
    params = {"title": title, "severity": severity or "HIGH", "type": type_label,
              "date": _format_og_date(published_at), "v": OG_CARD_VERSION}
    if cve_id:
        params["cve"] = cve_id
    if cvss:
        params["cvss"] = cvss
    if report_id:
        params["reportId"] = report_id
    if ransomware_group:
        params["actor"] = ransomware_group
    if ransomware_sector:
        params["sector"] = ransomware_sector
    if kev_listed is True:
        params["kev"] = "true"
    if epss_pct is not None:
        params["epss"] = f"{epss_pct:.1f}"
    return f"{config.source_base_url}/api/og?{urlencode(params)}"


def _generate_svg_thumbnail(title: str, labels: list, cvss: Optional[str] = None,
                             image_url: Optional[str] = None) -> str:
    """Return the post's lead <img> tag — first in the body, so Blogger's own
    "first image in post" detection turns it into data:blog.postImageUrl,
    which the live theme uses for og:image/twitter:image.

    When image_url is given (the api/og.js-backed URL _build_dynamic_og_image_url
    already computes), the tag points at that real, externally-fetchable HTTPS
    resource. This matters because every social crawler that renders a link
    preview — LinkedIn, X/Twitter, Facebook, Slack, Telegram — requires
    og:image to be a fetchable URL and silently drops the tag when it is a
    data: URI, which is exactly what made shared cti.cyberdudebivash.in report
    links preview with a title and description but no image. Falls back to
    embedding the SVG banner below as a base64 data URI when no image_url is
    available (still correct for on-page/in-app rendering, just not for
    external link-preview crawlers)."""
    alt_text = _html_escape.escape(title[:80], quote=True)
    if image_url:
        safe_src = _html_escape.escape(image_url, quote=True)
        return (
            f'<img src="{safe_src}" '
            f'alt="{alt_text}" '
            f'width="1200" height="630" '
            f'style="width:100%;max-width:1200px;height:auto;display:block;margin:0 auto 24px;border-radius:8px" '
            f'loading="eager"/>'
        )

    palette = _get_palette(labels)
    bg1 = palette["bg1"]
    bg2 = palette["bg2"]
    accent = palette["accent"]
    badge_bg = palette["badge"]

    category = re.sub(r"[^A-Za-z0-9 .&+/-]", " ", labels[0]).upper().strip() if labels else "THREAT INTEL"
    # Truncate and wrap title for SVG text
    title_clean = re.sub(r"[<>&\"']", " ", title).strip()
    words = title_clean.split()
    line1 = " ".join(words[:7])
    line2 = " ".join(words[7:13]) if len(words) > 7 else ""
    line3 = " ".join(words[13:18]) + ("…" if len(words) > 18 else "") if len(words) > 13 else ""

    cvss_badge = ""
    if cvss:
        try:
            score = float(cvss)
        except (ValueError, TypeError):
            score = 0.0
        cvss_color = "#ef4444" if score >= 9.0 else "#f59e0b" if score >= 7.0 else "#22c55e"
        cvss_badge = f"""
  <rect x="980" y="20" width="200" height="56" rx="6" fill="{cvss_color}" opacity="0.95"/>
  <text x="1080" y="43" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="11" font-weight="700" letter-spacing="1">CVSS SCORE</text>
  <text x="1080" y="65" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="22" font-weight="900">{cvss}</text>
"""

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:{bg1}"/>
      <stop offset="100%" style="stop-color:{bg2}"/>
    </linearGradient>
    <linearGradient id="accent_grad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:{accent};stop-opacity:0.8"/>
      <stop offset="100%" style="stop-color:{accent};stop-opacity:0.2"/>
    </linearGradient>
  </defs>
  <!-- Background -->
  <rect width="1200" height="630" fill="url(#bg)"/>
  <!-- Grid overlay -->
  <g stroke="{accent}" stroke-width="0.4" opacity="0.08">
    <line x1="0" y1="105" x2="1200" y2="105"/>
    <line x1="0" y1="210" x2="1200" y2="210"/>
    <line x1="0" y1="315" x2="1200" y2="315"/>
    <line x1="0" y1="420" x2="1200" y2="420"/>
    <line x1="0" y1="525" x2="1200" y2="525"/>
    <line x1="150" y1="0" x2="150" y2="630"/>
    <line x1="300" y1="0" x2="300" y2="630"/>
    <line x1="450" y1="0" x2="450" y2="630"/>
    <line x1="600" y1="0" x2="600" y2="630"/>
    <line x1="750" y1="0" x2="750" y2="630"/>
    <line x1="900" y1="0" x2="900" y2="630"/>
    <line x1="1050" y1="0" x2="1050" y2="630"/>
  </g>
  <!-- Glow orbs -->
  <circle cx="200" cy="150" r="200" fill="{accent}" opacity="0.04"/>
  <circle cx="1000" cy="480" r="250" fill="{accent}" opacity="0.04"/>
  <!-- Left accent bar -->
  <rect x="0" y="0" width="6" height="630" fill="url(#accent_grad)"/>
  <!-- Bottom accent bar -->
  <rect x="0" y="600" width="1200" height="30" fill="{accent}" opacity="0.12"/>
  <!-- Shield icon -->
  <path d="M60 80 L90 68 L120 80 L120 108 Q120 126 90 136 Q60 126 60 108 Z" fill="none" stroke="{accent}" stroke-width="2.5" opacity="0.9"/>
  <path d="M78 102 L87 111 L106 90" stroke="{accent}" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <!-- Brand name -->
  <text x="134" y="93" fill="{accent}" font-family="Arial,sans-serif" font-size="13" font-weight="900" letter-spacing="2">CYBERDUDEBIVASH®</text>
  <text x="134" y="113" fill="{accent}" font-family="Arial,sans-serif" font-size="10" letter-spacing="3" opacity="0.7">SENTINEL APEX</text>
  <!-- Category badge -->
  <rect x="26" y="160" width="{min(len(category) * 11 + 24, 280)}" height="32" rx="4" fill="{badge_bg}" opacity="0.9"/>
  <text x="38" y="181" fill="white" font-family="Arial,sans-serif" font-size="12" font-weight="700" letter-spacing="1.5">{category[:22]}</text>
  <!-- Title lines -->
  <text x="26" y="260" fill="white" font-family="Arial,sans-serif" font-size="38" font-weight="900" opacity="0.95">{line1}</text>
  {"<text x='26' y='310' fill='white' font-family='Arial,sans-serif' font-size='38' font-weight='900' opacity='0.95'>" + line2 + "</text>" if line2 else ""}
  {"<text x='26' y='360' fill='white' font-family='Arial,sans-serif' font-size='38' font-weight='900' opacity='0.95'>" + line3 + "</text>" if line3 else ""}
  <!-- Divider -->
  <rect x="26" y="420" width="200" height="3" rx="2" fill="{accent}" opacity="0.7"/>
  <!-- Tagline -->
  <text x="26" y="460" fill="{accent}" font-family="Arial,sans-serif" font-size="14" letter-spacing="2" opacity="0.8">ENTERPRISE THREAT INTELLIGENCE REPORT</text>
  <!-- Bottom meta -->
  <text x="26" y="590" fill="white" font-family="Arial,sans-serif" font-size="11" opacity="0.5">blog.cyberdudebivash.in  |  intel.cyberdudebivash.com</text>
  {cvss_badge}
</svg>"""

    svg_b64 = base64.b64encode(svg.encode("utf-8")).decode("utf-8")
    return (
        f'<img src="data:image/svg+xml;base64,{svg_b64}" '
        f'alt="{alt_text}" '
        f'width="1200" height="630" '
        f'style="width:100%;max-width:1200px;height:auto;display:block;margin:0 auto 24px;border-radius:8px" '
        f'loading="eager"/>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# EXECUTIVE RISK COMMAND CENTER
# A data-driven dashboard of real, verified fields (CVSS, EPSS, CISA KEV —
# see automation/enrichment.py). Rendered once in _assemble_html() so it
# appears identically whether the body came from the LLM path or the
# template fallback, instead of being duplicated in both. Any field without
# a genuine source is omitted rather than estimated — this platform's own
# governance prohibits fabricated cybersecurity intelligence, and a sparse
# dashboard is more trustworthy than a complete but partly-invented one.
# ─────────────────────────────────────────────────────────────────────────────

def _risk_tile(label: str, value: str, color: str = "#00d4ff", sub: str = "") -> str:
    safe_label = _html_escape.escape(str(label))
    safe_value = _html_escape.escape(str(value))
    safe_sub = _html_escape.escape(str(sub))
    sub_html = f'<div style="color:#64748b;font-size:10px;margin-top:4px;line-height:1.4">{safe_sub}</div>' if sub else ""
    return (
        f'<div style="flex:1;min-width:150px;background:#050d1a;border:1px solid {color}33;'
        f'border-radius:6px;padding:14px 16px">'
        f'<div style="color:{color};font-size:10px;font-weight:700;font-family:monospace;'
        f'letter-spacing:1.3px;margin-bottom:6px;text-transform:uppercase">{safe_label}</div>'
        f'<div style="color:#e2e8f0;font-size:20px;font-weight:900">{safe_value}</div>'
        f'{sub_html}</div>'
    )


def _build_trust_stats_block(config: Config) -> str:
    """Compact stats strip using only real, computed numbers — reads the
    same publication state file the syndication pipeline already writes
    (data/published_posts.json). Returns "" if the file is missing/corrupt
    rather than showing a fabricated count."""
    try:
        with open(config.state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        return ""

    total_published = state.get("total_published")
    if not isinstance(total_published, int) or total_published <= 0:
        return ""

    unique_cves: set = set()
    for entry in state.get("posts", {}).values():
        unique_cves.update(entry.get("cves", []))

    stats = [("Threat Reports Published", f"{total_published:,}")]
    if unique_cves:
        stats.append(("Unique CVEs Tracked", f"{len(unique_cves):,}"))
    # Real, derived — one Sigma detection rule is generated per report today.
    stats.append(("Detection Rules Generated", f"{total_published:,}"))
    # Real, fixed constant — see SIEM_PLATFORM_LABELS.
    stats.append(("Supported SIEM Platforms", str(len(SIEM_PLATFORM_LABELS))))

    tiles = "".join(
        f'<div style="flex:1;min-width:150px;text-align:center;padding:10px">'
        f'<div style="color:#00d4ff;font-size:22px;font-weight:900">{value}</div>'
        f'<div style="color:#64748b;font-size:10px;font-weight:700;text-transform:uppercase;'
        f'letter-spacing:1px;margin-top:2px">{label}</div></div>'
        for label, value in stats
    )
    return (
        f'<div style="margin:20px 0;padding:6px 0;background:#00080f;border-top:1px solid #1e3a5f33;'
        f'border-bottom:1px solid #1e3a5f33;display:flex;flex-wrap:wrap;justify-content:center">{tiles}</div>'
    )


def _build_recommended_services_block(labels: list, config: Config) -> str:
    """Data-driven service recommendation — see automation/product_recommendations.py
    for the rules table. Reuses the exact .apex-services CSS classes from
    monetization_injector.py so this renders identically and inherits the
    same click-tracking analytics-engine.js already applies to CTAs."""
    services = recommend_services(labels, max_results=3)
    if not services:
        return ""

    items = "".join(
        f'<div class="apex-svc-item"><strong>{svc["name"]}</strong><span>{svc["description"]}</span></div>'
        for svc in services
    )
    return (
        f'<div class="apex-services">'
        f'<h4>🎯 Recommended For This Threat</h4>'
        f'<div class="apex-services-grid">{items}</div>'
        f'<div style="margin-top:14px">'
        f'<a class="apex-btn apex-btn-primary" href="mailto:{config.contact_email}">Request This Assessment →</a>'
        f'<a class="apex-btn apex-btn-secondary" style="margin-left:8px" href="{config.corporate_url}" target="_blank" rel="noopener">View All Services →</a>'
        f'</div></div>'
    )


def _build_industry_intelligence_block(title: str, summary: str) -> str:
    """Only the industries genuinely referenced in the article text — see
    automation/industry_intelligence.py. Returns "" (never a padded list
    of all 9 sectors) when nothing is detected."""
    industry_keys = detect_industries(title, summary)
    if not industry_keys:
        return ""

    cards = []
    for key in industry_keys:
        profile = get_industry_profile(key)
        if not profile:
            continue
        service_names = ", ".join(
            _CATALOG_SERVICES[s]["name"] for s in profile.get("services", []) if s in _CATALOG_SERVICES
        )
        services_line = (
            f'<p style="margin:0"><strong style="color:#94a3b8">Relevant Services:</strong> {service_names}</p>'
            if service_names else ""
        )
        cards.append(
            f'<div style="background:#050d1a;border:1px solid #1e3a5f44;border-radius:6px;padding:16px 20px;margin-bottom:10px">'
            f'<div style="color:#00d4ff;font-size:13px;font-weight:800;margin-bottom:10px">{profile["name"]}</div>'
            f'<div style="font-size:12.5px;color:#cbd5e1;line-height:1.7">'
            f'<p style="margin:0 0 8px"><strong style="color:#94a3b8">Risk Profile:</strong> {profile["risk_profile"]}</p>'
            f'<p style="margin:0 0 8px"><strong style="color:#94a3b8">Common Targets:</strong> {profile["common_targets"]}</p>'
            f'<p style="margin:0 0 8px"><strong style="color:#94a3b8">Typical Attack Paths:</strong> {profile["attack_paths"]}</p>'
            f'<p style="margin:0 0 8px"><strong style="color:#94a3b8">Compliance Mapping:</strong> {profile["compliance_mapping"]}</p>'
            f'<p style="margin:0 0 8px"><strong style="color:#94a3b8">Priority Actions:</strong> {profile["priority_actions"]}</p>'
            f'{services_line}'
            f'</div></div>'
        )

    if not cards:
        return ""

    return (
        f'{_sh_module_level("Industry Impact Intelligence", "#a855f7")}'
        f'{"".join(cards)}'
    )


def _sh_module_level(title: str, color: str = "#00d4ff") -> str:
    """Module-level equivalent of the nested _sh() helper inside
    _template_enhance — used by sections rendered in _assemble_html, which
    runs for both the LLM and template content paths and can't reach the
    nested closure."""
    return (
        f'<div style="margin:32px 0 14px;padding:10px 18px;'
        f'background:linear-gradient(90deg,#0a1628,#050d1a);'
        f'border-left:3px solid {color};font-size:11px;font-weight:700;'
        f'color:{color};letter-spacing:2.5px;text-transform:uppercase;'
        f'font-family:monospace">&#9658; {title}</div>'
    )


def _derive_severity(article: DiscoveredArticle, cvss: Optional[str]) -> tuple:
    """Real CVSS-based severity only — prefers article.cvss_score (enrichment)
    over the regex-extracted string. Returns (None, None) if no score is
    known at all, rather than guessing. Shared by the Risk Command Center
    and the Executive Decision Center so severity is computed in one place."""
    cvss_score: Optional[float] = article.cvss_score
    if cvss_score is None and cvss:
        try:
            cvss_score = float(cvss)
        except (ValueError, TypeError):
            cvss_score = None

    if cvss_score is None:
        return None, None
    if cvss_score >= 9.0:
        return "CRITICAL", "#ef4444"
    if cvss_score >= 7.0:
        return "HIGH", "#f59e0b"
    if cvss_score >= 4.0:
        return "MEDIUM", "#22c55e"
    return "LOW", "#3b82f6"


def _build_executive_decision_center(category: str, cve_id: Optional[str], severity: Optional[str], config: Config) -> str:
    """Audience-targeted summaries — CEO/Board/CISO/SOC/DevSecOps/Cloud —
    derived from the same verified category/severity/CVE facts every other
    section uses, re-angled per audience rather than repeated verbatim."""
    threat_ref = cve_id or category
    sev_phrase = f"a {severity.lower()}-severity" if severity else "a"

    is_technical_category = category in {"Vulnerabilities", "Zero-Day", "CISA KEV", "Supply Chain", "Cloud Security", "DevSecOps"}
    is_operational_category = category in {"Ransomware", "APT", "Data Breach", "Malware Research"}

    audiences = [
        {
            "role": "CEO Summary",
            "color": "#00d4ff",
            "text": (
                f"{threat_ref} represents {sev_phrase} business risk requiring executive awareness. "
                f"The security team is assessing exposure and will escalate if customer-facing systems, revenue operations, "
                f"or contractual/regulatory obligations are implicated. No board notification is warranted at this stage unless "
                f"the CISO's assessment confirms material impact."
            ),
        },
        {
            "role": "Board Summary",
            "color": "#a855f7",
            "text": (
                f"This is a security operations matter tracked under the organization's standard vulnerability/incident management "
                f"process. {threat_ref} does not currently meet the threshold for board-level reporting; it will be escalated "
                f"per the incident severity matrix if that changes. Recommend noting in the next routine security update."
            ),
        },
        {
            "role": "CISO Summary",
            "color": "#ef4444",
            "text": (
                f"{threat_ref} ({category}{f', severity {severity}' if severity else ''}) requires a documented remediation or "
                f"detection-coverage decision. Confirm exposure against the asset inventory, assign an owner, and set a "
                f"remediation SLA consistent with severity. Track to closure in the vulnerability/risk register."
            ),
        },
        {
            "role": "SOC Summary",
            "color": "#f59e0b",
            "text": (
                f"Deploy the Sigma/multi-SIEM detection queries in this report to your monitoring stack and validate against "
                f"recent telemetry for prior activity. Treat as a monitoring priority "
                + ("during active-triage rotation given the operational nature of this threat." if is_operational_category
                   else "and correlate with vulnerability scan results for affected assets.")
            ),
        },
        {
            "role": "DevSecOps Summary",
            "color": "#22c55e",
            "text": (
                (
                    f"If {threat_ref} affects components in your CI/CD pipeline, container images, or infrastructure-as-code, "
                    f"gate deployments on a patched/updated dependency version and add a policy check to prevent regression."
                ) if is_technical_category else
                (
                    f"No direct pipeline/build-system exposure implied by this report's category ({category}), but confirm "
                    f"no affected components are referenced in current infrastructure-as-code or container base images."
                )
            ),
        },
        {
            "role": "Cloud Summary",
            "color": "#3b82f6",
            "text": (
                (
                    f"Review cloud asset inventory (compute, storage, identity) for exposure to {threat_ref}. Apply cloud-native "
                    f"WAF/network controls as a compensating measure if patching requires a maintenance window."
                ) if category == "Cloud Security" else
                f"Cross-reference {threat_ref} against internet-facing cloud assets even if the primary category is {category} — "
                f"cloud-hosted instances of on-prem-style vulnerabilities are a common blind spot."
            ),
        },
    ]

    cards = "".join(
        f'<div style="flex:1;min-width:220px;background:#050d1a;border:1px solid {a["color"]}33;border-radius:6px;padding:14px 16px">'
        f'<div style="color:{a["color"]};font-size:11px;font-weight:800;font-family:monospace;letter-spacing:1px;'
        f'text-transform:uppercase;margin-bottom:8px">{a["role"]}</div>'
        f'<div style="color:#cbd5e1;font-size:12.5px;line-height:1.7">{a["text"]}</div></div>'
        for a in audiences
    )
    return (
        f'{_sh_module_level("Executive Decision Center", "#00d4ff")}'
        f'<div style="display:flex;flex-wrap:wrap;gap:10px">{cards}</div>'
    )


def _build_mitre_navigator_download(body_content: str, title: str) -> str:
    """Client-side data-URI download link for the MITRE ATT&CK Navigator
    layer — same technique already used for the SVG thumbnail, so this
    needs zero new hosting/backend infrastructure and works identically on
    Blogger and on-site pages. Returns "" if the report cites no techniques."""
    layer = build_mitre_navigator_layer(body_content, title)
    if not layer:
        return ""

    layer_json = json.dumps(layer, indent=2)
    b64 = base64.b64encode(layer_json.encode("utf-8")).decode("utf-8")
    return (
        f'<div style="margin:16px 0;text-align:center">'
        f'<a href="data:application/json;base64,{b64}" download="mitre-navigator-layer.json" '
        f'style="display:inline-block;padding:9px 18px;border-radius:5px;font-size:13px;font-weight:700;'
        f'text-decoration:none;letter-spacing:.5px;background:transparent;border:1px solid #a855f7;color:#a855f7">'
        f'⬇ Download MITRE ATT&CK Navigator Layer ({len(layer["techniques"])} techniques)</a></div>'
    )


def _build_risk_command_center(article: DiscoveredArticle, cves: list, cvss: Optional[str]) -> str:
    """Executive dashboard of verified CVSS/EPSS/KEV data. Returns "" if nothing real is known."""
    cve_id = article.cve_id or (cves[0] if cves else None)

    sev, sev_color = _derive_severity(article, cvss)
    cvss_score: Optional[float] = article.cvss_score
    if cvss_score is None and cvss:
        try:
            cvss_score = float(cvss)
        except (ValueError, TypeError):
            cvss_score = None

    tiles = []
    if cve_id:
        tiles.append(_risk_tile("CVE ID", cve_id, "#00d4ff"))
    if article.ransomware_group:
        tiles.append(_risk_tile("Threat Actor", article.ransomware_group, "#ef4444"))
    if article.ransomware_sector:
        tiles.append(_risk_tile("Sector", article.ransomware_sector, "#a855f7"))
    if article.ransomware_country:
        tiles.append(_risk_tile("Country", article.ransomware_country, "#64748b"))
    if cvss_score is not None:
        tiles.append(_risk_tile("CVSS Score", f"{cvss_score:.1f}", sev_color, sev))
    if article.epss_score is not None:
        pct = article.epss_score * 100
        epss_color = "#ef4444" if pct >= 50 else "#f59e0b" if pct >= 10 else "#22c55e"
        sub = f"{article.epss_percentile * 100:.0f}th percentile" if article.epss_percentile is not None else "30-day exploit probability"
        tiles.append(_risk_tile("EPSS Score", f"{pct:.1f}%", epss_color, sub))
    if article.kev_listed is True:
        due_note = f"Remediation due {article.kev_due_date}" if article.kev_due_date else "Active exploitation confirmed"
        tiles.append(_risk_tile("CISA KEV", "LISTED", "#ef4444", due_note))
    elif article.kev_listed is False:
        tiles.append(
            _risk_tile(
                "CISA KEV",
                "Not Listed",
                "#22c55e",
                "Not present in the verified catalog snapshot; this does not prove absence of exploitation",
            )
        )
    else:
        tiles.append(
            _risk_tile(
                "CISA KEV",
                "Unknown",
                "#64748b",
                "Unknown or unavailable; no negative claim is made",
            )
        )
    if article.affected_vendor or article.affected_product:
        vp = (article.affected_product or article.affected_vendor or "")[:32]
        tiles.append(_risk_tile("Affected", vp, "#a855f7"))

    if not tiles:
        return ""

    dashboard_html = '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px">' + "\n".join(tiles) + "</div>"

    # Decision panel — conclusions derived from the verified fields above,
    # never independently invented.
    decisions = []
    if article.kev_listed is True:
        decisions.append(("Exploitation confirmed?", "YES — CISA KEV listed", "#ef4444"))
        decisions.append(("Urgent remediation?", "YES — follow the cited CISA/vendor action", "#ef4444"))
    elif cvss_score is not None and cvss_score >= 9.0:
        decisions.append(("Urgent exposure review?", "YES — CVSS ≥ 9.0 (Critical)", "#ef4444"))
    if article.kev_required_action:
        decisions.append(("CISA required action", article.kev_required_action[:200], "#f59e0b"))

    decision_html = ""
    if decisions:
        rows = "\n".join(
            f'<div style="margin:5px 0;padding:9px 14px;background:#050d1a;border-left:3px solid {c};'
            f'border-radius:0 4px 4px 0;font-size:12.5px;color:#cbd5e1;line-height:1.6">'
            f'<strong style="color:{c}">{_html_escape.escape(str(q))}</strong> &mdash; {_html_escape.escape(str(a))}</div>'
            for q, a, c in decisions
        )
        decision_html = rows

    return (
        f'<div style="margin:0 0 24px;padding:16px 18px;background:#00080f;border:1px solid #1e3a5f55;border-radius:8px">'
        f'<div style="color:#00d4ff;font-size:11px;font-weight:700;font-family:monospace;letter-spacing:2px;'
        f'text-transform:uppercase;margin-bottom:12px">&#9632; Executive Risk Command Center</div>'
        f'{dashboard_html}{decision_html}</div>'
    )


# ─────────────────────────────────────────────────────────────────────────────
# LLM PROMPT — 18-SECTION ENTERPRISE INTELLIGENCE REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _build_analyst_prompt(article: DiscoveredArticle) -> str:
    return f"""You are the CYBERDUDEBIVASH® SENTINEL APEX Principal Threat Intelligence Analyst. You produce intelligence at the level of Mandiant, CrowdStrike Intelligence, Unit 42, Microsoft MSTIC, and Recorded Future. Every sentence must be operationally actionable for SOC analysts, CISOs, detection engineers, and threat hunters.

ARTICLE TITLE: {article.title}
ARTICLE URL: {article.url}
ARTICLE CONTENT (up to 5000 characters):
{(article.full_content or article.summary)[:5000]}
LABELS/CATEGORY: {', '.join(article.labels)}

Generate a comprehensive intelligence report with EXACTLY these sections in HTML format (use <h3>, <p>, <ul>, <li>, <table>, <tr>, <th>, <td> — NO inline styles on individual elements, only structure):

<h3>Executive Summary</h3>
[3 sentences. Board-level language. State: what happened, who is affected, what must be decided NOW. Quantify risk, financial exposure, or operational impact only where the article supports it. No generic statements.]

<h3>Verified Facts</h3>
[Bullet list of facts directly stated or confirmed in the article. Each bullet: fact — source. Nothing inferred. Do NOT pad with speculation. If only 3 facts are confirmed, list 3.]

<h3>Threat Classification</h3>
[Single structured paragraph: threat type, affected sectors, geographic scope, exploitation status (active/PoC/theoretical), attacker motivation where stated. Label all analyst assessments with confidence level: HIGH/MEDIUM/LOW.]

<h3>Threat Severity Assessment</h3>
[Severity: CRITICAL/HIGH/MEDIUM/LOW with explicit rationale tied to: exploitability, scope of impact, prevalence, CVSS where available. Use a <ul> list with one factor per bullet. State confidence level for each factor.]

<h3>Business Impact</h3>
[Concrete enterprise risk SPECIFIC to this threat: operational disruption scenario, regulatory liability (GDPR, NIS2, DORA, SOC 2) with penalty ranges if applicable, financial exposure class, reputational damage pathway. Write for CISOs and risk committees — no generic "organizations may face" language.]

<h3>Technical Analysis</h3>
[Deep breakdown using only what the article states: attack vector, exploitation chain, affected components, versions, root cause or vulnerability class. For CVEs: CWE classification, CVSS vector string if available, affected versions. For malware: delivery mechanism, execution flow, persistence method. Do NOT extrapolate beyond the article's content.]

<h3>CVE Analysis</h3>
[ONLY if CVEs are explicitly present in the article. CVE ID, affected product/version, vulnerability class (CWE), attack vector, authentication requirement, patch availability. Use <ul> items. If no CVEs, OMIT this section entirely.]

<h3>MITRE ATT&CK Mapping</h3>
<ul>[Map ONLY techniques directly evidenced by the article content. Format each as: Tactic → Technique ID: Technique Name — one sentence rationale tied to specific article content. Do NOT pad with generic techniques. For OT/ICS incidents, use MITRE ATT&CK for ICS (T0xxx) techniques.]</ul>

<h3>IOC Intelligence</h3>
[If the article contains explicit IOCs (IPs, domains, hashes, URLs, extension IDs, registry keys): list them with type and value. If none are published: state "No public IOCs confirmed at time of publication" then describe the behavioral IOC categories defenders should build hunt rules around — specific to this threat type, NOT generic. Minimum 4 behavioral indicators.]

<h3>Detection Engineering Guidance</h3>
[Specific, actionable detection logic: log sources, Event IDs (Windows Security, Sysmon, etc.), telemetry fields, and detection rationale. Tailored to this specific threat — not a generic log source list. Write for SIEM engineers deploying in Splunk, Elastic, or Microsoft Sentinel.]

<h3>Sigma Rules</h3>
[Generate 1-2 syntactically correct Sigma detection rules in YAML format inside a <pre><code> block. Rules must be specific to the attack technique described — title, id (use uuid format), status, description, logsource, detection logic, condition, falsepositives, tags (MITRE ATT&CK txxxx format), level. Rules must be deployable — not template placeholders.]

<h3>Threat Hunting Queries</h3>
<ul>[5 specific hunt hypotheses with: hypothesis — log source/data source. Each must be specific to THIS threat, not generic cybersecurity hunting. Include the specific field names or Event IDs to query.]</ul>

<h3>SOC Analyst Playbook</h3>
<ul>[Triage steps in priority order: P0 (immediate — 0-1hr), P1 (urgent — 1-4hr), P2 (same-day). For each: specific action with the exact tool/log/system to check. Write for L1/L2 analysts on shift — not security architects.]</ul>

<h3>Executive Decision Matrix</h3>
<table>
<tr><th>Priority</th><th>Decision Required</th><th>Owner</th><th>Timeline</th></tr>
[3-5 rows with specific decisions the organization must make about this threat — patch approval, vendor communication, IR activation, board notification, regulatory disclosure. Base on what the article actually describes.]
</table>

<h3>Executive Recommendations</h3>
<ul>[Phased 90-day guidance specific to this threat: Day 1–7 (immediate technical response), Day 8–30 (structural improvements), Day 31–90 (strategic program changes). Each bullet must be tied to this specific threat.]</ul>

<h3>MSSP Opportunities</h3>
[Specific guidance for MSSPs: client notification priority (which client segments are exposed), detection rule deployment (which rules to push), threat hunting activation (specific hypotheses), advisory content. Position CYBERDUDEBIVASH® SENTINEL APEX as the intelligence source.]

<h3>Sentinel APEX Intelligence Correlation</h3>
[How CYBERDUDEBIVASH® SENTINEL APEX detects and correlates this threat class. Reference: live CVE tracking engine, MITRE ATT&CK correlation, real-time IOC feed integration, the Sigma/YARA detection rule library, threat hunting workbench. Do not state a specific rule count or any other statistic not present in the source article. Be specific to this threat type.]

<h3>AI Security Impact</h3>
[INCLUDE ONLY if the article explicitly discusses AI/LLM/ML systems, AI infrastructure, or AI-assisted attacks. Reference OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF 1.0 with specific LLM vulnerability identifiers. OMIT ENTIRELY if not AI-related.]

<h3>Predictive Intelligence</h3>
[Based ONLY on what the article describes: most likely next threat actor moves or exploitation escalation within 30/90/180 days. Label each prediction with confidence level: HIGH/MEDIUM/LOW and one-sentence rationale. Do NOT speculate beyond what the article's context supports.]

<h3>Long-Term Strategic Risk</h3>
[How this specific threat fits the evolving landscape over 6-18 months. Regulatory trajectory, threat actor capability evolution, supply chain implications, or infrastructure targeting patterns — grounded in the article's content.]

<h3>References</h3>
<ul>[Source article URL first, then 2-4 authoritative references: NVD entry, CISA advisory, vendor security bulletin, MITRE ATT&CK technique page. Format: Name — URL. Only include references that are directly relevant to this specific threat.]</ul>

ABSOLUTE RULES — VIOLATIONS WILL BREAK ENTERPRISE TRUST:
- NEVER fabricate CVE IDs, CVSS scores, threat actor names, malware capabilities, exploit code, or IOC values not explicitly in the article
- NEVER invent statistics, victim counts, or financial figures unless stated in the article
- NEVER attribute attacks to nation-states or specific groups without explicit article support — if attribution is present in the article, label it as ANALYST ASSESSMENT with confidence level
- NEVER use generic phrases: "organizations should monitor", "threat actors may", "it is important to", "in today's landscape"
- NEVER pad MITRE ATT&CK with techniques not evidenced in the article
- ALL analyst assessments must carry explicit confidence labels: (HIGH CONFIDENCE), (MEDIUM CONFIDENCE), (LOW CONFIDENCE)
- Sigma rules must be syntactically valid and deployable — no placeholder values
- Write at senior intelligence analyst level — every sentence earns its place
- Return ONLY the HTML sections, no preamble, no suffix, no explanation
"""


def _render_key_judgements_html(key_judgements: tuple) -> str:
    """RX-P1F: renders validated KeyJudgement records using report_renderer.py's
    existing section/bullet primitives -- the same visual system
    pipeline_composer.py's role/reliability sections already use, not a
    new one. Every judgement rendered here has already passed
    key_judgements.validate_key_judgements(); this function only escapes
    and lays out text, it does not re-evaluate anything."""
    items = []
    for kj in key_judgements:
        parts = [f"<strong>{_esc(kj.judgement)}</strong> "
                 f"<span style=\"color:#64748b\">[{_esc(kj.confidence)} CONFIDENCE]</span>"]
        if kj.verification_status:
            parts.append(f" <span style=\"color:#64748b\">[{_esc(kj.verification_status)}]</span>")
        if kj.reasoning_basis:
            parts.append(f"<br><span style=\"color:#94a3b8\">Basis: {_esc(kj.reasoning_basis)}</span>")
        if kj.decision_relevance:
            parts.append(f"<br><span style=\"color:#94a3b8\">Relevance: {_esc(kj.decision_relevance)}</span>")
        if kj.limitations:
            parts.append(f"<br><span style=\"color:#64748b\">Limitations: {_esc('; '.join(kj.limitations))}</span>")
        if kj.what_would_change_the_judgement:
            parts.append(
                f"<br><span style=\"color:#64748b\">Would change with: "
                f"{_esc(kj.what_would_change_the_judgement)}</span>"
            )
        items.append("".join(parts))
    return _section("Key Judgements", _bullets(items, "#00d4ff"), "#00d4ff")


def _render_hunt_hypotheses_html(hunt_hypotheses: tuple) -> str:
    """RX-P1I fix: mirrors pipeline_composer.compose_report()'s own inline
    hunt-hypothesis renderer (same section title, colors, and field order)
    so the two content paths produce visually identical output -- but reads
    the ``HuntHypothesis.to_dict()`` dict shape ``_ComposerOutcome.
    hunt_hypotheses`` actually stores, not the dataclass. Needed because
    transform()'s LLM-authored path (body_content = the sanitized raw LLM
    HTML) never included composer_outcome.html at all, so its embedded
    hunt_html was silently dropped even though hunt_hypothesis_count was
    still passed to evaluate_product_tier() -- a report could show Section
    14 as COMPLETE while the actually-published page had no hunt content.
    Called unconditionally in transform(), same pattern as
    _render_key_judgements_html() above, so both paths get the same
    content regardless of which one authored the narrative body."""
    return "".join(
        _section(
            f"Threat Hunting — {h['hypothesis_id']}",
            _panel(f'<p style="margin:0"><strong>Hypothesis:</strong> {_esc(h["statement"])}</p>')
            + _bullets(["<strong>Required telemetry:</strong> " + _esc(t) for t in h["required_telemetry"]]
                       + ["<strong>Pivot:</strong> " + _esc(p) for p in h["pivot_opportunities"]]
                       + ["<strong>Expected if true:</strong> " + _esc(e) for e in h["expected_observations"]]
                       + ["<strong>Negative indicator:</strong> " + _esc(n) for n in h["negative_indicators"]]
                       + ["<strong>False-positive risk:</strong> " + _esc(f) for f in h["false_positive_considerations"]],
                       "#a855f7")
            + _panel(
                f'<p style="margin:0 0 8px"><strong>Success criteria:</strong> {_esc(h["success_criteria"])}</p>'
                f'<p style="margin:0 0 8px"><strong>Escalation criteria:</strong> {_esc(h["escalation_criteria"])}</p>'
                f'<p style="margin:0 0 8px"><strong>Confidence:</strong> {_esc(h["confidence"])} &mdash; '
                f'<strong>Maturity:</strong> {_esc(h["maturity"])} (not independently confirmed by execution '
                f'against real telemetry)</p>'
                f'<p style="margin:0"><strong>Limitations:</strong> {_esc(h["limitations"])}</p>'
            ),
            "#a855f7",
        )
        for h in hunt_hypotheses
    )


def _render_attack_mappings_html(attack_mappings: tuple) -> str:
    """RX-P1I (structured ATT&CK): same duplication-avoidance reasoning as
    _render_hunt_hypotheses_html() immediately above -- mirrors
    pipeline_composer._render_attack_mappings_html()'s own visual output
    exactly (same section title, colors, field order), but reads the
    AttackMapping.to_dict() shape _ComposerOutcome.attack_mappings actually
    stores. Called unconditionally in transform(), guarded the same way,
    so every content path shows the same structured ATT&CK data rather
    than only the composer path."""
    if not attack_mappings:
        return ""
    rows = []
    for m in attack_mappings:
        rows.append(_panel(
            f'<p style="margin:0 0 6px"><strong>{_esc(m["technique_id"])} &mdash; {_esc(m["technique_name"])}</strong> '
            f'<span style="color:#94a3b8">({_esc(", ".join(m["tactics"]))})</span></p>'
            f'<p style="margin:0 0 6px;font-family:monospace;font-size:11px;color:#a855f7">'
            f'STATUS: {_esc(m["status"])} &middot; CONFIDENCE: {_esc(m["confidence"])}</p>'
            f'<p style="margin:0 0 6px">{_esc(m["reasoning"])}</p>'
            + ("".join(f'<p style="margin:0;color:#64748b;font-size:12px">Limitation: {_esc(lim)}</p>' for lim in m["limitations"])),
            "#a855f7",
        ))
    return _section("Structured ATT&CK Assessment", "".join(rows), "#a855f7")


def _render_intelligence_gaps_html(intelligence_gaps: tuple) -> str:
    """RX-P1K: mirrors pipeline_composer.compose_report()'s own
    _render_intelligence_gaps_html() (same section title, color, bullet
    format), but reads the IntelligenceGap.to_dict() shape
    _ComposerOutcome.intelligence_gaps actually stores. Called
    unconditionally in transform(), guarded the same way as
    hunt_hypotheses/attack_mappings/role_decisions -- before this fix, the
    gap list was never rendered on ANY content path, including the
    composer's own (see pipeline_composer.py's matching RX-P1K comment)."""
    if not intelligence_gaps:
        return ""
    items = []
    for g in intelligence_gaps:
        line = f'<strong>{_esc(g["category"].replace("_", " ").title())}:</strong> {_esc(g["description"])}'
        if g.get("what_would_confirm_or_refute"):
            line += (f'<br><span style="color:#64748b">Would be resolved by: '
                     f'{_esc(g["what_would_confirm_or_refute"])}</span>')
        items.append(line)
    return _section("Intelligence Gaps", _bullets(items, "#f59e0b"), "#f59e0b")


def _render_role_decisions_html(role_decisions: tuple) -> str:
    """RX-P1J: same duplication-avoidance reasoning as
    _render_hunt_hypotheses_html()/_render_attack_mappings_html() above --
    mirrors pipeline_composer.compose_report()'s own role_html assembly
    (same section title, color, bullet format, escalation/limitations
    sub-lines), but reads the RoleDecision.to_dict() shape
    _ComposerOutcome.role_decisions actually stores. Called unconditionally
    in transform(), guarded the same way, so every content path shows the
    same structured role-decision data rather than only the composer path
    -- this is the exact RX-P1J production defect: role_decisions was
    computed and counted (Section 19 via evaluate_product_tier()) but never
    reached this function's own rendered output at all."""
    if not role_decisions:
        return ""
    from sentinel_engine.reportx.executive_products import ROLE_DISPLAY_LABELS, RoleAudience

    items = []
    for d in role_decisions:
        label = ROLE_DISPLAY_LABELS[RoleAudience(d["role"])]
        line = f'<strong>{_esc(label)}:</strong> {_esc(d["decision"])} <span style="color:#64748b">&mdash; {_esc(d["rationale"])}</span>'
        if d.get("escalation_condition"):
            line += f'<br><span style="color:#64748b">Escalate when: {_esc(d["escalation_condition"])}</span>'
        if d.get("limitations"):
            line += f'<br><span style="color:#64748b">Limitations: {_esc(d["limitations"])}</span>'
        items.append(line)
    return _section("Role-Based Decisions", _bullets(items, "#00d4ff"), "#00d4ff")


def _render_forecast_html(forecasts: tuple) -> str:
    """RX-P1K: mirrors pipeline_composer.compose_report()'s own
    _render_forecast_html() (same section title, color, field order), but
    reads the Forecast.to_dict()/WithheldForecast.to_dict() shape
    _ComposerOutcome.forecasts actually stores. Called unconditionally in
    transform(), guarded the same way as the other structured sections.
    Only a real, adequately-supported forecast renders customer-visible
    content -- a withheld entry (``d["withheld"]`` present and true, or no
    confidence_rationale/supporting_observation_claim_ids) renders
    nothing, matching every other WITHHELD section's own "silent omission"
    convention in this pipeline."""
    if not forecasts:
        return ""
    real = [
        f for f in forecasts
        if not f.get("withheld") and f.get("supporting_observation_claim_ids") and f.get("confidence_rationale")
    ]
    if not real:
        return ""
    forecast = real[0]
    rows = (
        f'<p style="margin:0 0 8px"><strong>Judgment:</strong> {_esc(forecast["judgment"])}</p>'
        f'<p style="margin:0 0 8px"><strong>Time horizon:</strong> {_esc(forecast["time_horizon"])}</p>'
        f'<p style="margin:0 0 8px"><strong>Confidence:</strong> {_esc(forecast["confidence"])} '
        f'&mdash; {_esc(forecast["confidence_rationale"])}</p>'
    )
    if forecast.get("assumptions"):
        rows += _bullets(["<strong>Assumption:</strong> " + _esc(a) for a in forecast["assumptions"]], "#eab308")
    if forecast.get("what_would_change_assessment"):
        rows += _bullets(
            ["<strong>Would change this assessment:</strong> " + _esc(w) for w in forecast["what_would_change_assessment"]],
            "#eab308",
        )
    return _section("Forecast / Outlook", _panel(rows, "#eab308"), "#eab308")


def _extract_article_iocs(article: DiscoveredArticle) -> list:
    """RX-P1K-16: Sentinel-APEX/engine/sentinel_engine/ioc_extractor.py is a
    real, tested, false-positive-hardened IOC extractor already used on the
    separate Sentinel APEX CTI platform (normalizer.py, quality.py,
    report_ingest.py) but never imported by this pipeline at all -- Section
    16 (Indicators/Observables) was permanently WITHHELD for every article
    regardless of family, the same certified-but-dormant-module defect
    class already found four times this mandate (hunt_hypotheses,
    attack_mapping, role_decisions, forecast). Unlike those four, IOC
    extraction has no dependency on the composer's evidence graph or
    family -- it's a pure, deterministic scan of the article's own raw
    source text, so it needs no reportx_composer duplication guard and no
    family gate (Section 16 is OPTIONAL for every family with a reconciled
    matrix -- see report_contract.py). Runs against (article.full_content
    or article.summary), the same "richest available raw text" convention
    already used elsewhere in this file (see _build_analyst_prompt's
    identical fallback) -- never against LLM-authored or template-generated
    prose, which could in principle echo a fabricated value; this only
    ever finds what is literally present in the real, already-sourced
    article text, the same integrity property _extract_cve_ids() already
    relies on. Returns [] (never raises) if the engine package can't be
    imported, matching _composer_enhance()'s own fail-safe convention."""
    try:
        import sys
        from pathlib import Path

        engine_path = str(Path(__file__).resolve().parents[1] / "Sentinel-APEX" / "engine")
        if engine_path not in sys.path:
            sys.path.insert(0, engine_path)

        from sentinel_engine.ioc_extractor import DEFAULT_ALLOWLIST, extract_iocs

        text = article.full_content or article.summary or ""
        allowlist = DEFAULT_ALLOWLIST | _KNOWN_PUBLISHER_DOMAINS
        return [
            {"value": ioc.value, "type": ioc.type.value, "context": ioc.context}
            for ioc in extract_iocs(text, allowlist=allowlist)
        ]
    except Exception as e:
        logger.warning("IOC extraction failed", extra={"error": str(e)[:200]})
        return []


def _render_iocs_html(iocs: list) -> str:
    """RX-P1K-16: renders extracted indicators grouped by type, always
    defanged via ioc_extractor.defang() before publication -- models.py's
    own IOC docstring requires this ("Rendering for publication must go
    through ioc_extractor.defang"): a live, clickable indicator published
    on a public blog is itself an operational hazard, not merely a
    citation style choice. Called unconditionally in transform(), like
    _extract_article_iocs() above -- see that function's own docstring for
    why no reportx_composer duplication guard is needed here."""
    if not iocs:
        return ""
    try:
        import sys
        from pathlib import Path

        engine_path = str(Path(__file__).resolve().parents[1] / "Sentinel-APEX" / "engine")
        if engine_path not in sys.path:
            sys.path.insert(0, engine_path)

        from sentinel_engine.ioc_extractor import defang
        from sentinel_engine.models import IOCType
    except Exception as e:
        logger.warning("IOC rendering failed", extra={"error": str(e)[:200]})
        return ""

    _labels = {
        IOCType.SHA256.value: "SHA-256", IOCType.SHA1.value: "SHA-1", IOCType.MD5.value: "MD5",
        IOCType.IPV4.value: "IPv4", IOCType.DOMAIN.value: "Domain", IOCType.URL.value: "URL",
        IOCType.EMAIL.value: "Email", IOCType.CVE.value: "CVE", IOCType.REGISTRY_KEY.value: "Registry Key",
    }
    by_type: dict = {}
    for ioc in iocs:
        by_type.setdefault(ioc["type"], []).append(ioc["value"])

    rows = ""
    for ioc_type, values in by_type.items():
        defanged = [defang(v, IOCType(ioc_type)) for v in values]
        rows += _bullets(
            [f'<strong>{_esc(_labels.get(ioc_type, ioc_type))}:</strong> {_esc(v)}' for v in defanged],
            "#f97316",
        )
    note = _panel(
        "<em>Indicators are defanged for safe display (e.g. hxxp:// / [.]) -- "
        "refang before use in blocking or detection tooling.</em>",
        "#f97316",
    )
    return _section("Indicators / Observables", rows + note, "#f97316")


# ─────────────────────────────────────────────────────────────────────────────
# TEMPLATE FALLBACK — full 18-section structure when all LLM providers fail
# ─────────────────────────────────────────────────────────────────────────────

def _legacy_template_enhance(article: DiscoveredArticle, config: Config) -> str:
    article.summary = _sanitize_summary(article.summary)
    cves = _extract_cve_ids(article.title + " " + article.summary)
    cvss = _extract_cvss(article.title + " " + article.summary)
    category = primary_category(article.labels)

    cve_str = ", ".join(cves) if cves else "this vulnerability"
    cvss_str = f"CVSS {cvss}" if cvss else "elevated"

    text = (article.title + " " + article.summary).lower()
    is_ransomware = "ransomware" in text
    # Standalone-abbreviation checks use \b word boundaries, not bare "x " substrings —
    # "ai "/"ot "/"ato " as plain substrings false-positive on "Dubai "/"Mumbai ",
    # "not "/"hot "/"robot "/every other word ending in -ot, and "NATO " respectively.
    is_ai = bool(re.search(r"\bai\b", text)) or "llm" in text or "prompt injection" in text or "owasp" in text or "large language model" in text or "generative ai" in text
    is_apt = "apt" in text or "nation-state" in text or "nation state" in text or "state-sponsored" in text or "volt typhoon" in text or "lazarus" in text or "apt28" in text
    is_cve = bool(cves) or "vulnerability" in text or "cve" in text
    is_patch = "patch" in text or "update" in text or "cisa" in text or "kev" in text
    # Canonical evidence classification (report_integrity.py) — reused below
    # for the KEV/exploitation-status labels rather than re-deriving them
    # from the is_* text heuristics above, so this template and
    # render_evidence_report() never disagree on the same underlying facts.
    context = build_report_context(article)
    # "critical infrastructure" deliberately excluded — too broad, triggers on APT/ransomware reports
    is_ot = bool(re.search(r"\bot\b", text)) or "ics" in text or "scada" in text or "plc" in text or "operational technology" in text or "industrial control" in text or "hmi" in text or "historian" in text or "modbus" in text or "dnp3" in text or "ethernet/ip" in text or "s7comm" in text or "food processing" in text or "water treatment" in text or "energy sector" in text or "oil and gas" in text or "power grid" in text or "manufacturing plant" in text
    is_supply_chain = "supply chain" in text or "software supply" in text or "dependency" in text or "npm" in text or "pypi" in text or "open source" in text or "package" in text
    is_ato = "credential stuffing" in text or "account takeover" in text or bool(re.search(r"\bato\b", text)) or "combo list" in text or "brute force" in text or "password spray" in text
    is_extension = "browser extension" in text or "chrome extension" in text or "firefox addon" in text or "web store" in text or "extension id" in text

    # Severity determination
    if cvss:
        try:
            score = float(cvss)
        except (ValueError, TypeError):
            score = 0.0
        severity = "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM"
        severity_color = "#ef4444" if score >= 9.0 else "#f59e0b" if score >= 7.0 else "#22c55e"
    elif is_ransomware or is_apt or (is_cve and is_patch) or is_ot:
        severity, severity_color = "HIGH", "#f59e0b"
    elif is_ato or is_extension or is_supply_chain:
        severity, severity_color = "HIGH", "#f59e0b"
    else:
        # Matches the CVSS-derived MEDIUM color above — previously #3b82f6 here,
        # a real inconsistency for two paths asserting the same severity label.
        severity, severity_color = "MEDIUM", "#22c55e"

    # MITRE ATT&CK mapping — priority: ransomware → APT → CVE → OT → ATO → extension → supply chain → general
    if is_ot and not is_ransomware and not is_apt and not is_cve:
        mitre_techniques = [
            "Initial Access → Exploit Public-Facing Application (T1190) / Drive-By Compromise (T0817 ICS): Remote exploitation of internet-exposed OT management interfaces",
            "Lateral Movement → Remote Services (T0866 ICS): Adversary pivoted from IT network to OT/ICS environment via unprotected IT-OT boundary",
            "Execution → Command-Line Interface (T0807 ICS): Execution of unauthorized commands on OT engineering workstations or HMI systems",
            "Persistence → Valid Accounts (T0859 ICS): Abuse of legitimate OT operator credentials for sustained access without triggering alarms",
            "Impact → Denial of Control (T0813 ICS): Disruption of industrial process control preventing operators from issuing commands to field devices",
            "Impact → Loss of Availability (T0826 ICS): OT systems rendered unavailable, halting production operations",
        ]
        sigma_logsource = "product: windows\n    category: network_connection"
        sigma_detection = """detection:
    selection:
        DestinationPort:
            - 102    # S7comm (Siemens PLC)
            - 502    # Modbus
            - 44818  # EtherNet/IP
            - 20000  # DNP3
            - 4840   # OPC-UA
        Initiated: 'true'
        SourceIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    filter_ot_zone:
        SourceIp|cidr:
            - '10.100.0.0/16'  # Known OT network range — adjust per environment
    condition: selection and not filter_ot_zone"""
        sigma_title = "Anomalous IT-to-OT Protocol Communication — Potential Lateral Movement"
        sigma_tags = "    - attack.lateral_movement\n    - attack.t0866\n    - attack.t0813"
        siem_queries = {
            "splunk": 'index=network sourcetype=firewall dest_port IN (102, 502, 44818, 20000, 4840)\n| where cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("192.168.0.0/16", src_ip)\n| where NOT cidrmatch("10.100.0.0/16", src_ip)\n| stats count by src_ip, dest_ip, dest_port',
            "elastic": 'network where destination.port in (102, 502, 44818, 20000, 4840) and\n  cidrMatch(source.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16") and\n  not cidrMatch(source.ip, "10.100.0.0/16")',
            "sentinel": 'DeviceNetworkEvents\n| where RemotePort in (102, 502, 44818, 20000, 4840)\n| where ipv4_is_in_range(LocalIP, "10.0.0.0/8") or ipv4_is_in_range(LocalIP, "172.16.0.0/12") or ipv4_is_in_range(LocalIP, "192.168.0.0/16")\n| where not(ipv4_is_in_range(LocalIP, "10.100.0.0/16"))',
            "qradar": "SELECT sourceip, destinationip, destinationport, COUNT(*) FROM events\nWHERE destinationport IN (102,502,44818,20000,4840)\nAND (INCIDR('10.0.0.0/8', sourceip) OR INCIDR('172.16.0.0/12', sourceip) OR INCIDR('192.168.0.0/16', sourceip))\nAND NOT INCIDR('10.100.0.0/16', sourceip)\nGROUP BY sourceip, destinationip, destinationport\nLAST 24 HOURS",
            "chronicle": 'rule ot_lateral_movement {\n  meta:\n    description = "Anomalous IT-to-OT protocol communication"\n    severity = "High"\n  events:\n    $e.metadata.event_type = "NETWORK_CONNECTION"\n    $e.target.port = 102 or $e.target.port = 502 or $e.target.port = 44818 or $e.target.port = 20000 or $e.target.port = 4840\n  condition:\n    $e\n}',
        }
        hunt_queries = [
            "IT-to-OT lateral movement — Firewall/network flow logs for connections from IT VLAN to OT VLAN on industrial protocols (Modbus/502, S7comm/102, DNP3/20000)",
            "OT credential abuse — Authentication logs on HMI and engineering workstations for logons outside scheduled maintenance windows",
            "PLC configuration changes — OT historian or SCADA audit logs for unexpected parameter modifications or logic uploads",
            "Remote access to OT — VPN/jump server logs for remote sessions connecting to OT engineering workstations during non-business hours",
            "IT-OT boundary probing — IDS/IPS alerts for port scans originating from IT network targeting OT IP ranges",
        ]
        soc_actions = [
            "P0 — Confirm IT/OT network boundary status: verify firewall rules between IT and OT VLANs are intact and no unauthorized pass-through rules exist",
            "P0 — Check OT system availability: contact OT operations team to confirm SCADA/HMI/PLC status and production continuity",
            "P1 — Pull authentication logs from OT engineering workstations and HMIs for the past 72 hours — look for logons from IT user accounts",
            "P1 — Review remote access logs (VPN, RDP, jump server) for sessions targeting OT IP ranges from non-OT users",
            "P2 — Engage OT security team or ICS security vendor for forensic review of PLC/controller configuration integrity",
            "P2 — Notify production operations leadership and prepare for potential emergency shutdown procedure if compromise is confirmed",
        ]
        mssp_block = "MSSPs serving manufacturing, energy, food/beverage, water/wastewater, or critical infrastructure clients must immediately assess IT/OT boundary controls and activate OT-specific threat hunting. Issue emergency advisory to all OT-connected clients with guidance on IT-OT network segmentation verification. CYBERDUDEBIVASH® SENTINEL APEX ICS threat intelligence provides MITRE ATT&CK for ICS technique mapping, OT-specific Sigma rules, and sector-specific incident analysis."

    elif is_ransomware:
        mitre_techniques = [
            "Initial Access → Phishing: Spearphishing Attachment (T1566.001) / Exploit Public-Facing Application (T1190): Primary entry via malicious email attachments or exploitation of internet-exposed VPN/RDP services",
            "Execution → Command and Scripting Interpreter: PowerShell (T1059.001): Encoded PowerShell commands deploy ransomware loader and facilitate lateral movement while evading command-line logging",
            "Defense Evasion → Indicator Removal: File Deletion (T1070.004) / Obfuscated Files (T1027): Anti-forensic cleanup of logs and obfuscated payloads to impede incident response and forensic analysis",
            "Discovery → Network Share Discovery (T1135) / Domain Trust Discovery (T1482): Enumeration of network shares and domain trusts to maximize encryption blast radius across connected systems",
            "Lateral Movement → Remote Services: SMB/Windows Admin Shares (T1021.002): Propagation across network using compromised domain credentials via SMB administrative shares",
            "Impact → Data Encrypted for Impact (T1486) / Inhibit System Recovery (T1490): File system encryption following shadow copy deletion to prevent recovery without ransom payment",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Double-extortion data staging and exfiltration before encryption — victim data posted to leak site if ransom unpaid",
        ]
        sigma_logsource = "product: windows\n    category: process_creation"
        sigma_detection = """detection:
    shadow_deletion:
        Image|endswith:
            - '\\vssadmin.exe'
            - '\\wmic.exe'
            - '\\wbadmin.exe'
            - '\\bcdedit.exe'
        CommandLine|contains:
            - 'delete shadows'
            - 'delete catalog'
            - 'recoveryenabled No'
            - 'shadowcopy delete'
    ransom_ps_staging:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - 'EncodedCommand'
            - 'FromBase64String'
            - 'IEX'
            - 'DownloadString'
    condition: shadow_deletion or ransom_ps_staging"""
        sigma_title = "Ransomware Pre-Encryption Activity — Shadow Deletion and PowerShell Staging"
        sigma_tags = "    - attack.impact\n    - attack.t1486\n    - attack.t1490\n    - attack.t1059.001"
        siem_queries = {
            "splunk": 'index=endpoint (Image IN ("*\\\\vssadmin.exe","*\\\\wmic.exe","*\\\\wbadmin.exe","*\\\\bcdedit.exe") CommandLine IN ("*delete shadows*","*delete catalog*","*recoveryenabled No*","*shadowcopy delete*"))\nOR (Image="*\\\\powershell.exe" CommandLine IN ("*EncodedCommand*","*FromBase64String*","*IEX*","*DownloadString*"))\n| table _time, host, Image, CommandLine, User',
            "elastic": 'process where (process.name in ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe") and\n  process.command_line : ("*delete shadows*","*delete catalog*","*recoveryenabled No*","*shadowcopy delete*"))\nor (process.name == "powershell.exe" and\n  process.command_line : ("*EncodedCommand*","*FromBase64String*","*IEX*","*DownloadString*"))',
            "sentinel": 'DeviceProcessEvents\n| where (FileName in~ ("vssadmin.exe","wmic.exe","wbadmin.exe","bcdedit.exe")\n    and ProcessCommandLine has_any ("delete shadows","delete catalog","recoveryenabled No","shadowcopy delete"))\n  or (FileName =~ "powershell.exe"\n    and ProcessCommandLine has_any ("EncodedCommand","FromBase64String","IEX","DownloadString"))',
            "qradar": "SELECT sourceip, username, processname, commandline FROM events\nWHERE processname IN ('vssadmin.exe','wmic.exe','wbadmin.exe','bcdedit.exe')\nAND (commandline ILIKE '%delete shadows%' OR commandline ILIKE '%shadowcopy delete%')\nLAST 24 HOURS",
            "chronicle": 'rule ransomware_shadow_deletion {\n  meta:\n    description = "Ransomware pre-encryption shadow copy deletion"\n    severity = "Critical"\n  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n    $e.target.process.file.full_path = /vssadmin\\.exe|wmic\\.exe|wbadmin\\.exe|bcdedit\\.exe/ nocase\n    $e.target.process.command_line = /delete shadows|shadowcopy delete/ nocase\n  condition:\n    $e\n}',
        }
        hunt_queries = [
            "Shadow copy deletion — Windows Security Event ID 4688 with CommandLine containing 'vssadmin delete shadows', 'wmic shadowcopy delete', or 'bcdedit /set recoveryenabled'",
            "SMB lateral propagation — Network flow analysis for a single endpoint establishing SMB connections (port 445) to >20 unique internal hosts within a 5-minute window",
            "Mass file extension change — EDR file system telemetry for >100 file rename/modify events per minute from a single process writing to unknown extensions",
            "Ransomware C2 beacon — DNS query logs for newly registered domains, high-entropy DGA-pattern names, or .onion proxy resolvers from workstation processes",
            "Privileged credential abuse — Windows Security Event ID 4624 (Type 3 network logon) using domain admin accounts originating from non-admin workstations during off-hours",
        ]
        soc_actions = [
            "P0 — If active encryption detected: immediately isolate affected hosts via VLAN quarantine or firewall ACL block; do NOT power off — preserve volatile memory for forensic imaging",
            "P0 — Identify patient-zero: use EDR lateral movement timeline to find earliest infected host; block all associated C2 indicators at perimeter firewall and DNS resolver",
            "P0 — Verify immutable backup integrity: confirm backups are accessible, unaffected by encryption, and that restoration has been tested within the past 90 days",
            "P1 — Enumerate SMB exposure: identify all hosts with open administrative shares (C$, ADMIN$) reachable from infected network segment; apply emergency micro-segmentation",
            "P1 — Activate IR retainer: engage incident response partner; begin forensic preservation (memory images, disk images) of confirmed and suspected affected systems",
            "P2 — Notify legal, compliance, and executive leadership; prepare for mandatory regulatory breach notification (GDPR: 72 hours, HIPAA: 60 days, state breach laws vary) if personal data affected",
        ]
        mssp_block = "MSSPs must immediately activate ransomware response protocols for all clients in high-risk sectors — healthcare, financial services, manufacturing, government, and critical infrastructure face the highest ransom payment rates and regulatory exposure. Push Sigma detection rules covering T1486, T1490, and T1021.002 to all client SIEMs within 1 hour of this advisory. Issue emergency client communication with host isolation procedures and backup verification checklist. CYBERDUDEBIVASH® SENTINEL APEX ransomware intelligence provides real-time C2 infrastructure feeds, RaaS affiliate TTP tracking, and sector-specific incident response playbooks."

    elif is_apt:
        mitre_techniques = [
            "Reconnaissance → Active Scanning (T1595) / Gather Victim Network Information (T1590): Systematic infrastructure mapping and open-source intelligence collection on target organization prior to active exploitation",
            "Initial Access → Exploit Public-Facing Application (T1190) / Trusted Relationship (T1199): Exploitation of internet-exposed services or compromise of trusted third-party vendors with privileged network access",
            "Persistence → Create or Modify System Process: Windows Service (T1543.003) / Scheduled Task (T1053.005): Long-term persistence via registered services or scheduled tasks executing under legitimate account context",
            "Defense Evasion → Masquerading: Rename System Utilities (T1036.003) / Signed Binary Proxy Execution (T1218): LOLBAS abuse and process name masquerading to blend malicious execution with legitimate OS operations",
            "Collection → Data from Local System (T1005) / Email Collection (T1114.001): Targeted collection of intellectual property, credentials, email archives, and strategic documents matching threat actor's collection objectives",
            "Exfiltration → Exfiltration Over Alternative Protocol (T1048) / Scheduled Transfer (T1029): Low-volume exfiltration via DNS tunneling, HTTPS to cloud storage, or time-delayed transfers to avoid volume-based detection",
        ]
        sigma_logsource = "product: windows\n    category: process_creation"
        sigma_detection = """detection:
    lolbas_net:
        Image|endswith:
            - '\\certutil.exe'
            - '\\mshta.exe'
            - '\\regsvr32.exe'
            - '\\bitsadmin.exe'
        CommandLine|contains:
            - 'http'
            - 'urlcache'
            - 'decode'
            - '/transfer'
    schtask_non_admin:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains:
            - '/create'
        User|not|contains:
            - 'SYSTEM'
            - 'Administrator'
    condition: lolbas_net or schtask_non_admin"""
        sigma_title = "APT Indicators — LOLBAS Network Access and Non-Admin Scheduled Task Creation"
        sigma_tags = "    - attack.defense_evasion\n    - attack.t1218\n    - attack.t1053.005\n    - attack.t1027"
        siem_queries = {
            "splunk": 'index=endpoint (Image IN ("*\\\\certutil.exe","*\\\\mshta.exe","*\\\\regsvr32.exe","*\\\\bitsadmin.exe") CommandLine IN ("*http*","*urlcache*","*decode*","*/transfer*"))\nOR (Image="*\\\\schtasks.exe" CommandLine="*/create*" NOT (User IN ("*SYSTEM*","*Administrator*")))\n| table _time, host, Image, CommandLine, User',
            "elastic": 'process where (process.name in ("certutil.exe","mshta.exe","regsvr32.exe","bitsadmin.exe") and\n  process.command_line : ("*http*","*urlcache*","*decode*","*/transfer*"))\nor (process.name == "schtasks.exe" and process.command_line : "*/create*" and\n  not user.name : ("*SYSTEM*","*Administrator*"))',
            "sentinel": 'DeviceProcessEvents\n| where (FileName in~ ("certutil.exe","mshta.exe","regsvr32.exe","bitsadmin.exe")\n    and ProcessCommandLine has_any ("http","urlcache","decode","/transfer"))\n  or (FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"\n    and AccountName !in~ ("SYSTEM","Administrator"))',
            "qradar": "SELECT sourceip, username, processname, commandline FROM events\nWHERE processname IN ('certutil.exe','mshta.exe','regsvr32.exe','bitsadmin.exe')\nAND commandline ILIKE '%http%'\nLAST 24 HOURS",
            "chronicle": 'rule apt_lolbas_network {\n  meta:\n    description = "LOLBAS binaries with outbound network activity"\n    severity = "High"\n  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n    $e.target.process.file.full_path = /certutil\\.exe|mshta\\.exe|regsvr32\\.exe|bitsadmin\\.exe/ nocase\n    $e.target.process.command_line = /http|urlcache|decode/ nocase\n  condition:\n    $e\n}',
        }
        hunt_queries = [
            "LOLBAS with outbound network connections — EDR process telemetry for certutil.exe, mshta.exe, regsvr32.exe, bitsadmin.exe with DestinationIP not in internal RFC1918 ranges",
            "Non-admin scheduled task creation — Windows Security Event ID 4698 (scheduled task created) attributed to non-SYSTEM, non-administrator user accounts or unusual parent process",
            "DNS tunneling — DNS query logs for TXT/NULL record type queries and subdomain strings exceeding 30 characters in entropy from workstation processes",
            "Unexpected service registration — Windows System Event ID 7045 (new service installed) outside documented change management windows or from non-administrative accounts",
            "LSASS memory access — EDR telemetry for processes other than SYSTEM/antivirus/EDR opening lsass.exe with PROCESS_VM_READ (0x0010) access rights",
        ]
        soc_actions = [
            "P0 — Initiate active threat hunt across all EDR-enrolled endpoints for campaign IOCs — expand search window to 90 days minimum to account for typical APT dwell time (average 197 days at discovery)",
            "P0 — Implement firewall and DNS block rules for all infrastructure associated with this threat actor; review egress filtering for anomalous HTTPS traffic to unusual geographic regions",
            "P1 — Conduct privileged account audit: enumerate all domain admin, service account, and local administrator account creations or modifications in the past 90 days versus change management records",
            "P1 — Analyze east-west traffic for C2 beacon patterns: regular connection intervals, HTTPS to cloud storage providers in unexpected regions, high-volume DNS TXT queries from specific hosts",
            "P2 — Targeted forensic review of externally-facing systems (VPN concentrators, web applications, email gateways) for initial access artifacts and webshell presence",
            "P2 — Brief CISO and general counsel on nation-state attribution context and assess obligations for regulatory or government notification applicable to your sector (CISA reporting, sector-specific ISACs)",
        ]
        mssp_block = "MSSPs must distribute an emergency client advisory covering this APT campaign's confirmed TTPs within 2 hours. Activate threat hunting teams on high-value client environments — prioritize financial services, defense contractors, critical infrastructure operators, government agencies, and technology sector clients matching the threat actor's known targeting profile. CYBERDUDEBIVASH® SENTINEL APEX APT intelligence provides real-time campaign tracking, infrastructure pivot analysis, and multi-client exposure correlation."

    elif is_cve:
        mitre_techniques = [
            f"Initial Access → Exploit Public-Facing Application (T1190): {cve_str} exploitation targeting internet-exposed instances to achieve unauthenticated or pre-auth remote access",
            "Privilege Escalation → Exploitation for Privilege Escalation (T1068): Post-exploitation local privilege escalation to SYSTEM/root from initial low-privileged access context",
            "Lateral Movement → Exploitation of Remote Services (T1210): Internal lateral movement using the same vulnerability class against adjacent systems sharing the vulnerable component",
            "Persistence → Server Software Component: Web Shell (T1505.003): Installation of web shell or backdoor on compromised host for persistent re-entry without re-exploitation",
            "Defense Evasion → Indicator Removal (T1070): Log clearing and evidence destruction to impede forensic investigation and delay detection of initial access",
        ]
        sigma_logsource = "category: webserver"
        sigma_detection = f"""detection:
    exploit_uri:
        c-uri|contains:
            - '../'
            - '%2e%2e'
            - 'cmd.exe'
            - '/etc/passwd'
            - ';id;'
            - '|whoami'
        sc-status:
            - 200
            - 500
    webshell_access:
        c-uri|endswith:
            - '.php'
            - '.aspx'
            - '.jsp'
        cs-method: 'POST'
        sc-bytes|gt: 0
    condition: exploit_uri or webshell_access"""
        sigma_title = f"Web Application Exploitation — {cve_str} Payload and Web Shell Activity"
        sigma_tags = "    - attack.initial_access\n    - attack.t1190\n    - attack.t1505.003"
        siem_queries = {
            "splunk": 'index=web (uri_query IN ("*../*","*%2e%2e*","*cmd.exe*","*/etc/passwd*","*;id;*","*|whoami*") status IN (200,500))\nOR (uri_path IN ("*.php","*.aspx","*.jsp") method="POST" bytes_out>0)\n| table _time, clientip, uri_path, uri_query, status',
            "elastic": 'network where url.path : ("*../*","*%2e%2e*","*/etc/passwd*") and http.response.status_code in (200,500)\nor (url.path : ("*.php","*.aspx","*.jsp") and http.request.method == "post" and http.response.body.bytes > 0)',
            "sentinel": 'W3CIISLog\n| where (csUriQuery has_any ("../", "%2e%2e", "cmd.exe", "/etc/passwd") and scStatus in (200,500))\n  or (csUriStem has_any (".php",".aspx",".jsp") and csMethod == "POST" and scBytes > 0)',
            "qradar": "SELECT sourceip, \"URL\", httpresponsecode FROM events\nWHERE \"URL\" ILIKE '%../%' OR \"URL\" ILIKE '%25%2e%2e%' OR \"URL\" ILIKE '%/etc/passwd%'\nLAST 24 HOURS",
            "chronicle": 'rule cve_web_exploitation {\n  meta:\n    description = "Web exploitation payload and web shell access patterns"\n    severity = "High"\n  events:\n    $e.metadata.event_type = "NETWORK_HTTP"\n    $e.network.http.method = "POST"\n    $e.target.url = /\\.php$|\\.aspx$|\\.jsp$/ nocase\n  condition:\n    $e\n}',
        }
        hunt_queries = [
            f"Exploitation payload patterns — Web access logs for {cve_str}-specific payload signatures in URI parameters, POST body, or HTTP headers (consult vendor advisory for exact patterns)",
            "Web server spawning shells — EDR process tree for web server process (httpd, nginx, IIS w3wp.exe, Tomcat) spawning cmd.exe, powershell.exe, bash, or sh as child processes",
            "Web shell presence — File integrity monitoring for new .php/.aspx/.jsp/.war files created in web root directories outside of scheduled deployment windows",
            "Post-exploitation lateral movement — SIEM correlation for outbound connections originating from DMZ/web server hosts to internal RFC1918 ranges on management protocols (WMI/445/3389/22)",
            f"Exploitation attempt timeline — WAF and IDS/IPS logs for 30-day retroactive search for {cve_str} payload patterns to identify pre-patch exploitation activity",
        ]
        soc_actions = [
            f"P0 — Apply vendor patch for {cve_str} immediately on all affected instances; if patch unavailable within 4 hours, implement WAF virtual patching rule and restrict access to authenticated users only",
            "P0 — Retroactive search: query SIEM, WAF, and web logs for the past 30 days for exploitation payload patterns — assume potential pre-patch exploitation and treat as active incident until ruled out",
            "P1 — Hunt for post-exploitation artifacts: web shells in web root directories, anomalous child processes from web server, new service registrations or scheduled tasks created by web server process account",
            "P1 — Block exploitation payload patterns at WAF and IPS/IDS layers; update all detection platform signatures with vendor-provided indicators",
            "P2 — Conduct full vulnerability scan of adjacent systems sharing the vulnerable component; prioritize internet-facing assets for immediate patching",
            "P2 — If exploitation confirmed: engage IR team, preserve forensic evidence, and assess regulatory breach notification obligations based on data exposed on compromised systems",
        ]
        mssp_block = f"MSSPs must immediately assess all client attack surfaces for {cve_str} exposure using asset inventory cross-reference. Issue P1 priority advisory to all clients in healthcare, financial services, technology, and government sectors — sectors with the highest concentration of internet-facing vulnerable applications. Provide WAF virtual patching rules for clients unable to patch immediately. CYBERDUDEBIVASH® SENTINEL APEX KEV integration provides real-time CISA KEV tracking with automated client exposure scoring against asset inventories."

    elif is_ato:
        mitre_techniques = [
            "Credential Access → Brute Force: Credential Stuffing (T1110.004): Automated credential stuffing using leaked combo lists from prior data breaches against consumer-facing authentication endpoints",
            "Resource Development → Compromise Accounts (T1586.001): Acquisition and validation of email/password pairs from criminal underground marketplaces",
            "Resource Development → Acquire Infrastructure: Botnet (T1583.006): Use of residential proxy networks to distribute authentication requests across thousands of IP addresses, evading IP-based rate limiting",
            "Initial Access → Valid Accounts: Cloud Accounts (T1078.004): Authentication to victim accounts using validated credentials obtained via credential stuffing",
            "Collection → Data from Cloud Storage (T1530): Access to stored payment methods, personal data, and account balances from compromised accounts",
            "Impact → Financial Theft (T1657): Monetization of compromised accounts via fraudulent transactions, gift card purchases, or account resale on criminal storefronts",
        ]
        sigma_logsource = "category: webserver\n    product: any"
        sigma_detection = """detection:
    high_velocity_single_ip:
        c-ip|exists: true
        cs-uri-stem|contains: '/login'
        sc-status: 200
    timeframe: 1m
    condition: high_velocity_single_ip | count(c-ip) by c-ip > 30
    distributed_low_velocity:
        cs-uri-stem|contains: '/login'
        sc-status:
            - 200
            - 401
            - 403
    timeframe: 10m
    condition: distributed_low_velocity | count() > 500"""
        sigma_title = "Credential Stuffing Attack — High-Volume Authentication Against Login Endpoint"
        sigma_tags = "    - attack.credential_access\n    - attack.t1110.004\n    - attack.t1078"
        siem_queries = {
            "splunk": 'index=web uri_path="*/login*"\n| bin _time span=1m\n| stats count by src_ip, _time\n| where count > 30',
            "elastic": 'network where url.path : "*/login*" and http.response.status_code in (200, 401, 403)\n// pair with a Kibana threshold rule: group by source.ip, >30 matches per 1m',
            "sentinel": 'SigninLogs\n| where AppDisplayName has "login"\n| summarize AttemptCount = count() by IPAddress, bin(TimeGenerated, 1m)\n| where AttemptCount > 30',
            "qradar": "SELECT sourceip, COUNT(*) AS attempts FROM events\nWHERE \"URL\" ILIKE '%/login%'\nGROUP BY sourceip\nHAVING COUNT(*) > 30\nLAST 10 MINUTES",
            "chronicle": 'rule credential_stuffing_velocity {\n  meta:\n    description = "High-volume authentication attempts from a single source"\n    severity = "Medium"\n  events:\n    $e.metadata.event_type = "USER_LOGIN"\n    $e.principal.ip = $src_ip\n  match:\n    $src_ip over 1m\n  condition:\n    #e > 30\n}',
        }
        hunt_queries = [
            "Single-IP velocity anomaly — Web access logs for >20 authentication attempts per minute from any single IP against login endpoints",
            "Distributed credential stuffing — Authentication logs for >500 login attempts in 10 minutes distributed across >100 unique IPs with <10% success rate",
            "Residential proxy ASN patterns — Threat intelligence enrichment of authenticating IPs to identify residential proxy provider ASNs (Luminati/Bright Data, Oxylabs, SmartProxy)",
            "Successful ATO sessions — Post-authentication activity analysis for accounts showing unusual: password changes, email updates, payment method access within 30 minutes of login",
            "Account enumeration — Authentication logs for high volumes of 'account not found' errors indicating username enumeration phase of stuffing attack",
        ]
        soc_actions = [
            "P0 — Determine attack scale: pull authentication logs for past 24-72 hours, count total attempts, success rate, unique IPs, and affected account count",
            "P0 — Implement emergency rate limiting: block IPs exceeding 10 authentication attempts per minute; activate CAPTCHA for all login attempts if not already enforced",
            "P1 — Identify compromised accounts: flag accounts with successful logins from IPs included in the attack traffic; force password reset and session invalidation",
            "P1 — Block residential proxy ASN ranges at WAF if business impact is acceptable — use threat intelligence to identify proxy provider CIDR blocks",
            "P2 — Notify affected users per breach notification requirements (GDPR 72-hour window, state breach notification laws); document breach scope",
            "P2 — Engage fraud operations team to review and reverse unauthorized transactions from confirmed ATO accounts",
        ]
        mssp_block = "MSSPs should immediately assess client exposure to credential stuffing based on customer-facing authentication surfaces. Deploy velocity-based detection rules to client SIEMs covering per-IP and distributed patterns. Activate ATO-specific threat hunting hypotheses for clients in financial services, gaming, e-commerce, and healthcare sectors — highest-value targets for credential stuffing monetization. CYBERDUDEBIVASH® SENTINEL APEX ATO intelligence includes residential proxy ASN lists, combo list breach source correlation, and ATO detection Sigma rule packs."

    elif is_extension:
        mitre_techniques = [
            "Persistence → Browser Extensions (T1176): Malicious or compromised browser extension installed across enterprise endpoints providing persistent access to browser context",
            "Execution → Scripting: JavaScript (T1059.007): Extension executes arbitrary JavaScript in the context of web pages visited by the victim, enabling session manipulation",
            "Credential Access → Input Capture: Web Portal Capture (T1056.003): Extension intercepts form submissions and keystrokes on banking, SaaS, and enterprise web portals",
            "Credential Access → Steal Web Session Cookie (T1539): Extension reads authentication cookies from browser storage for session hijacking of authenticated sessions",
            "Man-in-the-Browser (T1185): Extension modifies web page DOM to inject scripts, capture form data, or redirect authentication flows",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Captured credentials and session tokens exfiltrated to attacker-controlled infrastructure via extension background service worker",
        ]
        sigma_logsource = "product: windows\n    category: registry_event"
        sigma_detection = """detection:
    extension_install:
        EventType: 'SetValue'
        TargetObject|contains:
            - '\\SOFTWARE\\Google\\Chrome\\Extensions\\'
            - '\\SOFTWARE\\Chromium\\Extensions\\'
            - '\\SOFTWARE\\Microsoft\\Edge\\Extensions\\'
        Details|contains: 'update_url'
    filter_enterprise_managed:
        TargetObject|contains: '\\SOFTWARE\\Policies\\'
    condition: extension_install and not filter_enterprise_managed
    network_beacon:
        Initiated: 'true'
        Image|endswith:
            - '\\chrome.exe'
            - '\\msedge.exe'
        DestinationPort:
            - 443
            - 80
        DestinationHostname|re: '.*\\.(?:tk|ml|ga|cf|gq|top|xyz|club|icu)$'
    condition: network_beacon"""
        sigma_title = "Suspicious Browser Extension Activity — Unmanaged Install or Anomalous Network Beacon"
        sigma_tags = "    - attack.persistence\n    - attack.t1176\n    - attack.t1539"
        siem_queries = {
            "splunk": 'index=endpoint sourcetype=registry (TargetObject="*\\\\SOFTWARE\\\\Google\\\\Chrome\\\\Extensions\\\\*" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Edge\\\\Extensions\\\\*")\nNOT TargetObject="*\\\\SOFTWARE\\\\Policies\\\\*"\n| table _time, host, TargetObject, Details',
            "elastic": 'registry where registry.path : ("*\\\\Chrome\\\\Extensions\\\\*","*\\\\Edge\\\\Extensions\\\\*") and\n  not registry.path : "*\\\\Policies\\\\*"',
            "sentinel": 'DeviceRegistryEvents\n| where RegistryKey has_any (@"\\Chrome\\Extensions", @"\\Edge\\Extensions")\n| where RegistryKey !has @"\\Policies\\"',
            "qradar": "SELECT hostname, \"Registry Key\", \"Registry Value\" FROM events\nWHERE \"Registry Key\" ILIKE '%\\\\Extensions\\\\%'\nAND \"Registry Key\" NOT ILIKE '%\\\\Policies\\\\%'\nLAST 24 HOURS",
            "chronicle": 'rule unmanaged_extension_install {\n  meta:\n    description = "Browser extension installed outside enterprise policy path"\n    severity = "Medium"\n  events:\n    $e.metadata.event_type = "REGISTRY_MODIFICATION"\n    $e.target.registry.registry_key = /Extensions/ nocase\n    $e.target.registry.registry_key != /Policies/ nocase\n  condition:\n    $e\n}',
        }
        hunt_queries = [
            "Extension inventory audit — Chrome/Edge management telemetry or registry enumeration for all installed extension IDs across managed endpoints",
            "Suspicious extension network traffic — Proxy/DNS logs for web requests originating from browser processes to recently registered domains or suspicious TLDs (.tk/.ml/.ga)",
            "Extension permission escalation — Chrome management logs or extension inventory for extensions requesting access to 'all URLs' (<all_urls>), tabs API, or cookies API",
            "BYOD unmanaged extensions — MDM/endpoint inventory for devices with browser extensions not present in organization's approved extension list",
            "Extension update anomalies — Browser update logs for extensions that silently updated version and simultaneously increased permission scope",
        ]
        soc_actions = [
            "P0 — Identify the specific extension ID(s) mentioned in the report across all managed endpoints using endpoint management or registry scan",
            "P0 — Determine if Chrome Enterprise Browser Management policies restrict extension installation — if not, this is an immediate policy gap requiring emergency remediation",
            "P1 — Force-remove the identified extension via Chrome/Edge enterprise policy (ExtensionInstallBlocklist) across all managed endpoints within 4 hours",
            "P1 — For BYOD endpoints without management control: communicate removal instructions to end users with deadline and compliance tracking",
            "P2 — Review proxy logs for network activity from browser processes to suspicious destinations during the extension's installed period",
            "P2 — Audit all enterprise extensions against an approved allowlist; block installation of extensions not on the allowlist via Browser Management policy",
        ]
        mssp_block = "MSSPs should immediately push browser extension inventory queries to all client endpoints — prioritizing financial services, healthcare, legal, and technology sector clients where browser access to sensitive SaaS portals (banking portals, EHR systems, legal management systems) creates the highest credential theft risk. For clients without Chrome Enterprise Browser Management or equivalent policy control, issue emergency advisory requiring immediate deployment. CYBERDUDEBIVASH® SENTINEL APEX browser extension threat intelligence provides malicious extension ID feeds, permission-abuse pattern detection, and enterprise browser hardening guidance."

    elif is_supply_chain:
        mitre_techniques = [
            "Initial Access → Supply Chain Compromise (T1195.002): Malicious code injected into legitimate software package distributed to downstream consumers",
            "Execution → Software Deployment Tools (T1072): Malicious package executed automatically during build pipeline dependency resolution or developer environment setup",
            "Persistence → Event Triggered Execution (T1546): Malicious install scripts or lifecycle hooks in compromised package execute on installation",
            "Defense Evasion → Masquerading (T1036): Package masquerades as legitimate open-source dependency or typosquats popular package names",
            "Collection → Data from Local System (T1005): Malicious package harvests environment variables, SSH keys, cloud credentials, and source code from developer environments",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Harvested secrets exfiltrated to attacker infrastructure during installation or first run",
        ]
        sigma_logsource = "product: linux\n    category: process_creation"
        sigma_detection = """detection:
    pkg_install_net:
        Image|endswith:
            - '/node'
            - '/python'
            - '/pip'
            - '/npm'
        CommandLine|contains:
            - 'install'
        NetworkConnection: 'true'
        DestinationIp|cidr:
            - '0.0.0.0/0'
    filter_known_registries:
        DestinationHostname|endswith:
            - 'registry.npmjs.org'
            - 'pypi.org'
            - 'files.pythonhosted.org'
    condition: pkg_install_net and not filter_known_registries"""
        sigma_title = "Package Manager Network Connection to Non-Registry Host During Install"
        sigma_tags = "    - attack.initial_access\n    - attack.t1195.002\n    - attack.t1059"
        siem_queries = {
            "splunk": 'index=endpoint (Image IN ("*/node","*/python","*/pip","*/npm") CommandLine="*install*")\n| join type=inner host [search index=network]\n| where NOT (dest_host="*registry.npmjs.org*" OR dest_host="*pypi.org*" OR dest_host="*files.pythonhosted.org*")\n| table _time, host, Image, CommandLine, dest_host',
            "elastic": 'process where process.name in ("node","python","pip","npm") and process.command_line : "*install*"\n| network where not destination.domain in ("registry.npmjs.org","pypi.org","files.pythonhosted.org")',
            "sentinel": 'DeviceProcessEvents\n| where FileName in~ ("node","python","pip","npm") and ProcessCommandLine has "install"\n| join kind=inner DeviceNetworkEvents on DeviceId\n| where RemoteUrl !has_any ("registry.npmjs.org","pypi.org","files.pythonhosted.org")',
            "qradar": "SELECT hostname, processname, destinationhostname FROM events\nWHERE processname IN ('node','python','pip','npm')\nAND destinationhostname NOT ILIKE '%registry.npmjs.org%'\nAND destinationhostname NOT ILIKE '%pypi.org%'\nLAST 24 HOURS",
            "chronicle": 'rule supply_chain_nonregistry_install {\n  meta:\n    description = "Package manager network connection to a non-registry host during install"\n    severity = "High"\n  events:\n    $e.metadata.event_type = "NETWORK_CONNECTION"\n    $e.principal.process.file.full_path = /node$|python$|pip$|npm$/ nocase\n    $e.target.hostname != /registry\\.npmjs\\.org|pypi\\.org/ nocase\n  condition:\n    $e\n}',
        }
        hunt_queries = [
            "Malicious package install scripts — CI/CD pipeline logs for npm/pip install events that triggered outbound network connections to non-registry hosts",
            "Environment variable exfiltration — Process telemetry for package manager processes (node/python) making outbound DNS or HTTP requests containing 'AWS_', 'SECRET_', 'API_KEY' patterns",
            "Typosquat detection — Dependency manifest review across all projects for packages with names similar to popular libraries but with minor character differences",
            "Post-install script execution — Build system logs for packages that executed postinstall/setup.py scripts with network or file system activity",
            "Developer credential exposure — Secret scanning (git hooks, Trufflehog/GitLeaks) for environment variables or credential files present in build environments",
        ]
        soc_actions = [
            "P0 — Identify all systems that installed the affected package version: check package-lock.json, requirements.txt, and build logs across all repositories",
            "P0 — Rotate all secrets present on systems where the malicious package was installed: cloud credentials (AWS/Azure/GCP), API keys, SSH keys, JWT secrets",
            "P1 — Audit CI/CD pipeline logs for the affected package install timeframe — identify what data was accessible and whether exfiltration indicators exist",
            "P1 — Scan all repositories for the malicious package version in dependency manifests; enforce package version pinning in all projects",
            "P2 — Implement software composition analysis (SCA) in CI/CD pipeline to block builds with known-malicious package versions",
            "P2 — Review artifact repository (Artifactory/Nexus) proxying policies to enforce allowlisting of trusted package registries",
        ]
        mssp_block = "MSSPs should immediately scan client CI/CD environments and developer workstations for the affected package version. Issue advisory to all clients in software development, fintech, and technology sectors — highest exposure to supply chain attacks. CYBERDUDEBIVASH® SENTINEL APEX supply chain intelligence provides real-time malicious package feeds, CI/CD pipeline detection rules, and software composition analysis integration guidance."

    else:
        mitre_techniques = [
            "Initial Access → Phishing: Spearphishing Attachment (T1566.001) / Phishing Link (T1566.002): Social engineering via malicious email attachments or links as primary attack delivery mechanism",
            "Execution → User Execution: Malicious File (T1204.002): Victim-initiated execution of malicious document, script, or executable delivered via phishing or web-based delivery",
            "Defense Evasion → Obfuscated Files or Information (T1027): Payload obfuscation using encoding, encryption, or packing to evade signature-based antivirus and EDR detection",
            "Persistence → Registry Run Keys / Startup Folder (T1547.001): Persistence via Run key modification or startup folder placement for execution at system boot or user logon",
            "Exfiltration → Exfiltration Over C2 Channel (T1041): Data exfiltration channeled through the established C2 communication path to avoid triggering dedicated DLP/exfil detection",
        ]
        sigma_logsource = "product: windows\n    category: process_creation"
        sigma_detection = """detection:
    office_shell:
        ParentImage|endswith:
            - '\\outlook.exe'
            - '\\winword.exe'
            - '\\excel.exe'
            - '\\powerpnt.exe'
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
            - '\\wscript.exe'
            - '\\mshta.exe'
    encoded_ps:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - 'FromBase64String'
    condition: office_shell or encoded_ps"""
        sigma_title = "Office Application Shell Spawn and Encoded PowerShell Execution"
        sigma_tags = "    - attack.execution\n    - attack.t1204.002\n    - attack.t1059.001"
        siem_queries = {
            "splunk": 'index=endpoint (ParentImage IN ("*\\\\outlook.exe","*\\\\winword.exe","*\\\\excel.exe","*\\\\powerpnt.exe") Image IN ("*\\\\powershell.exe","*\\\\cmd.exe","*\\\\wscript.exe","*\\\\mshta.exe"))\nOR (Image="*\\\\powershell.exe" CommandLine IN ("*-EncodedCommand*","*-enc *","*FromBase64String*"))\n| table _time, host, ParentImage, Image, CommandLine',
            "elastic": 'process where (process.parent.name in ("outlook.exe","winword.exe","excel.exe","powerpnt.exe") and\n  process.name in ("powershell.exe","cmd.exe","wscript.exe","mshta.exe"))\nor (process.name == "powershell.exe" and\n  process.command_line : ("*-EncodedCommand*","*-enc *","*FromBase64String*"))',
            "sentinel": 'DeviceProcessEvents\n| where (InitiatingProcessFileName in~ ("outlook.exe","winword.exe","excel.exe","powerpnt.exe")\n    and FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe"))\n  or (FileName =~ "powershell.exe"\n    and ProcessCommandLine has_any ("-EncodedCommand","-enc ","FromBase64String"))',
            "qradar": "SELECT hostname, parentprocessname, processname, commandline FROM events\nWHERE parentprocessname IN ('outlook.exe','winword.exe','excel.exe','powerpnt.exe')\nAND processname IN ('powershell.exe','cmd.exe','wscript.exe','mshta.exe')\nLAST 24 HOURS",
            "chronicle": 'rule office_shell_spawn {\n  meta:\n    description = "Office application spawning a shell or encoded PowerShell execution"\n    severity = "High"\n  events:\n    $e.metadata.event_type = "PROCESS_LAUNCH"\n    $e.principal.process.file.full_path = /outlook\\.exe|winword\\.exe|excel\\.exe|powerpnt\\.exe/ nocase\n    $e.target.process.file.full_path = /powershell\\.exe|cmd\\.exe|wscript\\.exe|mshta\\.exe/ nocase\n  condition:\n    $e\n}',
        }
        hunt_queries = [
            "Office application shell spawn — EDR parent-child process telemetry for Outlook/Word/Excel/PowerPoint spawning PowerShell, cmd.exe, wscript.exe, or mshta.exe",
            "Encoded PowerShell execution — EDR process command-line telemetry for PowerShell.exe invoked with -EncodedCommand, -enc, or FromBase64String parameters",
            "Unusual scheduled task creation — Windows Security Event ID 4698 for scheduled tasks created during or immediately after suspicious email delivery timeframe",
            "Registry run key modification — Sysmon Event ID 13 (RegistryEvent value set) for HKCU/HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run modifications by non-administrative processes",
            "Beaconing C2 communication — Proxy and DNS logs for regular-interval connections (±5 second jitter) from endpoint processes to external hosts immediately following malicious email delivery",
        ]
        soc_actions = [
            "P0 — Identify all endpoints that may have received or interacted with the threat delivery vector (email link/attachment); pull email gateway delivery logs and endpoint execution telemetry",
            "P1 — Block threat delivery indicators at email gateway, web proxy, and DNS resolver; push associated file hashes to EDR block list across all managed endpoints",
            "P1 — Search SIEM/EDR for the MITRE technique indicators above across all endpoints for the past 72 hours — extend to 14 days if initial triage suggests earlier delivery",
            "P2 — Validate detection rule coverage for identified MITRE ATT&CK techniques in primary SIEM; deploy Sigma rules above if gaps exist",
            "P2 — Update threat intelligence platform and internal IOC sharing channels with all confirmed indicators; ensure downstream detection tools have received updated feeds",
        ]
        mssp_block = "MSSPs should issue a client advisory within 2 hours covering detection logic and recommended compensating controls. Validate client SIEM detection coverage against the MITRE techniques identified. Push Sigma rules above to all client SIEM platforms. CYBERDUDEBIVASH® SENTINEL APEX provides automated MSSP intelligence briefing generation with client-specific exposure analysis and pre-built detection rule packages."

    mitre_html = "\n".join(
        f'<div style="margin:6px 0;padding:10px 14px;background:#0a0f1a;border-left:3px solid #a855f7;border-radius:0 4px 4px 0;font-size:13px;color:#c4b5fd;line-height:1.7">{t}</div>'
        for t in mitre_techniques
    )
    hunt_html = "\n".join(
        (
            f'<div style="margin:6px 0;padding:10px 14px;background:#001a10;border-left:3px solid #22c55e;border-radius:0 4px 4px 0;font-size:13px;line-height:1.7">'
            f'<span style="color:#22c55e;font-family:monospace;font-size:11px;font-weight:700">[HUNT-{str(i + 1).zfill(2)}]</span>'
            f'&nbsp;<span style="color:#cbd5e1">{q}</span></div>'
        )
        for i, q in enumerate(hunt_queries)
    )
    _soc_badge_colors = {"P0": "#ef4444", "P1": "#f59e0b", "P2": "#3b82f6"}
    soc_html = "\n".join(
        (
            f'<div style="margin:6px 0;padding:10px 14px;background:#050d1a;border:1px solid #1e3a5f55;border-radius:4px;display:flex;gap:10px;align-items:flex-start">'
            f'<span style="background:{_soc_badge_colors.get(a[:2], "#3b82f6")};color:#fff;padding:3px 7px;border-radius:3px;font-size:10px;font-weight:900;font-family:monospace;white-space:nowrap;flex-shrink:0">{a[:2]}</span>'
            f'<span style="color:#cbd5e1;font-size:13px;line-height:1.6">{a.split(" — ", 1)[-1] if " — " in a else a}</span>'
            f'</div>'
        )
        for a in soc_actions
    )

    # Enterprise recommendations (phased, threat-specific)
    enterprise_recs = []
    enterprise_recs.append(f"<strong style='color:#00d4ff'>Day 1–7 (Immediate):</strong> {soc_actions[0] if soc_actions else 'Conduct asset inventory to identify all affected systems and apply available vendor patch or compensating control'}")
    if is_ransomware:
        enterprise_recs.append("<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Validate immutable backup architecture and test restoration procedures under simulated ransomware scenario; implement network micro-segmentation to limit blast radius of future encryption campaigns")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Conduct ransomware tabletop exercise with executive stakeholders; implement identity governance controls (PAM, MFA enforcement on all privileged accounts) to eliminate primary ransomware access vectors")
    elif is_apt:
        enterprise_recs.append("<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Deploy behavioral detection rules to SIEM covering LOLBAS abuse, scheduled task anomalies, and LSASS access patterns; implement privileged access workstation (PAW) architecture for all domain administrator activities")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Assess zero-trust network architecture maturity; evaluate threat intelligence program to ensure continuous monitoring of nation-state TTPs relevant to your sector and geographic exposure")
    elif is_cve:
        enterprise_recs.append(f"<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Conduct full vulnerability assessment of all {category} assets across the environment; implement vulnerability management SLA requiring all CRITICAL CVEs patched within 24 hours of NVD publication")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Integrate CISA KEV tracking with your vulnerability management platform; implement virtual patching capability (WAF rules) as a compensating control bridge between CVE disclosure and patch deployment")
    elif is_ot:
        enterprise_recs.append("<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Engage ICS security specialist to assess current IT/OT network segmentation architecture; implement OT-specific network monitoring (Claroty/Dragos/Nozomi) if not already deployed")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Develop and exercise an OT-specific incident response plan distinct from IT IR playbooks; assess IEC 62443 compliance posture for industrial network security governance")
    elif is_ato:
        enterprise_recs.append("<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Implement risk-based authentication scoring across all customer-facing portals; evaluate deployment of behavioral biometrics for high-value account actions (payment changes, address updates)")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Accelerate passwordless authentication migration for high-risk user populations; integrate breach credential monitoring (HaveIBeenPwned Enterprise, SpyCloud) to proactively identify compromised user credentials before ATO")
    elif is_supply_chain:
        enterprise_recs.append("<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Deploy software composition analysis (SCA) tooling in all CI/CD pipelines; implement artifact repository with dependency proxying to control which package registry sources are permitted")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Develop software bill of materials (SBOM) capability for all production applications; implement package signing verification in build pipelines aligned with SLSA framework requirements")
    elif is_extension:
        enterprise_recs.append("<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Deploy Chrome Enterprise Browser Management or equivalent; implement extension allowlist policy blocking all unreviewed extensions from installation on managed endpoints")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Evaluate enterprise browser security solution (Island, Talon, or vendor-managed browser) for high-risk user populations accessing sensitive SaaS applications from BYOD devices")
    else:
        enterprise_recs.append("<strong style='color:#f59e0b'>Day 8–30 (Short-term):</strong> Validate SIEM detection coverage against all MITRE ATT&CK techniques identified in this report; deploy updated Sigma rules to close identified detection gaps across all managed endpoints")
        enterprise_recs.append("<strong style='color:#a855f7'>Day 31–90 (Strategic):</strong> Conduct tabletop exercise simulating this specific attack scenario with SOC and executive stakeholders; evaluate CYBERDUDEBIVASH® SENTINEL APEX for continuous threat intelligence integration to reduce detection gap windows")
    if is_ai:
        enterprise_recs.insert(0, "<strong style='color:#ef4444'>Immediate — AI Security:</strong> Audit all production AI/LLM deployments against OWASP LLM Top 10 and MITRE ATLAS framework; implement input validation and output filtering on all AI pipeline touchpoints before next deployment cycle")
    ent_html = "\n".join(
        f'<div style="margin:6px 0;padding:10px 14px;background:#050d1a;border-left:3px solid #06b6d4;border-radius:0 4px 4px 0;font-size:13px;color:#cbd5e1;line-height:1.7">{r}</div>'
        for r in enterprise_recs
    )

    # IOC intelligence section — category-specific behavioral indicators
    if is_ransomware:
        ioc_behavioral = """<li><strong>Process behavioral IOC:</strong> Any process executing vssadmin.exe/wmic.exe with 'delete shadows' or 'shadowcopy delete' arguments — immediate triage required</li>
<li><strong>File system behavioral IOC:</strong> Mass file rename events (>100 files/minute) to unknown extensions from a single process — active encryption in progress</li>
<li><strong>Network behavioral IOC:</strong> SMB connections (port 445) from workstations to >15 unique internal hosts within 5 minutes — lateral movement phase</li>
<li><strong>DNS behavioral IOC:</strong> High-entropy domain queries or .onion proxy resolver connections from endpoints — C2 communication or ransom portal contact</li>
<li><strong>Registry behavioral IOC:</strong> Modifications to HKLM\\SYSTEM\\CurrentControlSet\\Services entries by non-SYSTEM processes — potential ransomware service persistence</li>"""
    elif is_apt:
        ioc_behavioral = """<li><strong>Process behavioral IOC:</strong> LOLBAS binaries (certutil.exe, mshta.exe, regsvr32.exe) establishing outbound network connections to non-Microsoft IP ranges</li>
<li><strong>Authentication behavioral IOC:</strong> Domain admin account logons from workstations (Event ID 4624 Type 3) during non-business hours or from previously unused source hosts</li>
<li><strong>Network behavioral IOC:</strong> Low-volume encrypted egress to cloud storage providers (AWS S3, Azure Blob, Google Drive) from servers not known to use these services</li>
<li><strong>DNS behavioral IOC:</strong> High-entropy subdomain strings in DNS queries (>30 chars) from workstations — potential DNS tunneling C2 channel</li>
<li><strong>Scheduled task behavioral IOC:</strong> New scheduled task creation (Event ID 4698) by non-SYSTEM accounts pointing to execution in %TEMP%, %APPDATA%, or unusual paths</li>"""
    elif is_ot:
        ioc_behavioral = """<li><strong>Network behavioral IOC:</strong> Connections from IT VLAN IP ranges to OT VLAN on industrial protocols — Modbus/502, S7comm/102, DNP3/20000, EtherNet/IP/44818</li>
<li><strong>Authentication behavioral IOC:</strong> IT user account credentials used to authenticate to OT HMI or engineering workstation systems outside scheduled maintenance windows</li>
<li><strong>OT process behavioral IOC:</strong> PLC parameter modifications or logic uploads outside of approved change management windows — requires OT historian/SCADA audit log review</li>
<li><strong>Remote access behavioral IOC:</strong> VPN or jump server sessions from IT administrators connecting to OT IP ranges during non-business hours or from unusual source geography</li>
<li><strong>OT network scanning behavioral IOC:</strong> Port scans targeting OT IP ranges originating from IT network — detected via IDS/IPS or network flow analysis on IT-OT boundary firewall</li>"""
    elif is_ato:
        ioc_behavioral = """<li><strong>Authentication velocity behavioral IOC:</strong> >20 authentication attempts per minute from a single IP against login endpoints — distributed per-IP below threshold but >500 total attempts in 10-minute window indicates distributed credential stuffing</li>
<li><strong>Proxy network behavioral IOC:</strong> Residential proxy ASN ranges authenticating at high volume — Luminati/Bright Data (AS58695), Oxylabs, SmartProxy networks are primary ATO infrastructure providers for bypassing IP rate limiting</li>
<li><strong>Account behavior behavioral IOC:</strong> Successful login followed within 30 minutes by password change, email address update, or payment method access from previously unused geographic region</li>
<li><strong>Session behavioral IOC:</strong> Multiple concurrent sessions for same account from distinct geographic regions or device fingerprints not matching account history — impossible travel scenario</li>
<li><strong>Enumeration behavioral IOC:</strong> High volume of 'account not found' (username enumeration) errors preceding a spike in successful authentications — indicates combo list validation phase before full stuffing wave</li>"""
    elif is_extension:
        ioc_behavioral = """<li><strong>Extension ID IOC:</strong> Presence of the specific extension ID in Chrome/Edge extension registry keys on managed endpoints — confirmed via registry scan or management platform query</li>
<li><strong>Network behavioral IOC:</strong> Browser process (chrome.exe/msedge.exe) establishing connections to recently registered domains or suspicious TLDs (.tk/.ml/.ga/.cf/.gq/.xyz) on port 443</li>
<li><strong>Permission behavioral IOC:</strong> Extension requesting access to <all_urls>, tabs API, cookies API, or webRequest API without corresponding enterprise policy authorization</li>
<li><strong>Update behavioral IOC:</strong> Extension version update event followed by immediate change in permission scope — silent permission escalation post-approval</li>
<li><strong>Data access behavioral IOC:</strong> Browser process reading cookie storage or form data immediately following navigation to authenticated SaaS portals (O365, Salesforce, banking portals)</li>"""
    elif is_supply_chain:
        ioc_behavioral = """<li><strong>Build pipeline IOC:</strong> Package manager process (node/python/pip/npm) establishing outbound network connections to non-registry hosts during package install phase</li>
<li><strong>Environment variable IOC:</strong> Process spawned by package install script making outbound HTTP/DNS requests containing patterns matching 'AWS_', 'SECRET_KEY', 'API_KEY', 'GITHUB_TOKEN'</li>
<li><strong>File system IOC:</strong> Unexpected files written to ~/.ssh, ~/.aws, ~/.config directories during package installation — potential credential harvesting</li>
<li><strong>Dependency manifest IOC:</strong> Package name with character substitution vs. known popular packages (typosquatting) — e.g., 'requets' vs 'requests', 'colourama' vs 'colorama'</li>
<li><strong>CI/CD pipeline IOC:</strong> Build job timing anomaly — significantly longer execution time than baseline during dependency installation phase indicates potential malicious script execution</li>"""
    elif is_cve:
        ioc_behavioral = """<li><strong>Exploitation attempt IOC:</strong> Web/application access logs showing anomalous requests against the vulnerable component — unexpected URI paths, oversized or malformed parameters, and unusual User-Agent strings returning 200/500 status codes</li>
<li><strong>Process behavioral IOC:</strong> The vulnerable service process spawning unexpected child processes (cmd.exe, powershell.exe, bash, sh) — primary post-exploitation signal for this vulnerability class</li>
<li><strong>Network behavioral IOC:</strong> Outbound connections initiated by the vulnerable service to external hosts it has no operational need to contact — reverse shell establishment or second-stage payload staging</li>
<li><strong>File system behavioral IOC:</strong> New executable, script, or web shell files written to application directories by the service account outside scheduled deployment windows</li>
<li><strong>Account behavioral IOC:</strong> New local or domain account creation, or privilege elevation events, correlated within minutes of anomalous requests to the vulnerable service</li>"""
    else:
        ioc_behavioral = """<li><strong>Email delivery IOC:</strong> Sender domain registered within past 30 days, mismatched Reply-To domain, or use of free email service to impersonate enterprise domains</li>
<li><strong>Process behavioral IOC:</strong> Office applications (Outlook, Word, Excel) spawning PowerShell, cmd.exe, wscript.exe, or mshta.exe as child processes following email attachment open</li>
<li><strong>Network behavioral IOC:</strong> Outbound connections from endpoints to domains registered <30 days ago or to hosting providers with high abuse rates (bulletproof hosting ASNs)</li>
<li><strong>Registry persistence IOC:</strong> Modifications to HKCU/HKLM Run keys by non-administrative processes or from Office application execution context</li>
<li><strong>DNS behavioral IOC:</strong> Rapid succession of DNS queries to high-entropy subdomains from a single endpoint immediately following user interaction with suspicious content</li>"""

    # AI security section — content decided here (is_ai gate), rendered after
    # _sh() is defined below so it matches every other section's styling
    # instead of the bare <h3>/<p> markup the rest of this template moved
    # away from in the 2026-07-06 trust & quality retrofit.
    _ai_section_body = (
        '<p style="margin:0 0 10px">This threat has direct operational implications for enterprise AI and LLM deployments. '
        'Organizations running large language models, AI agents, RAG pipelines, or AI-powered security tooling must assess '
        'their exposure across multiple attack surfaces.</p>'
        '<p style="margin:0 0 10px">Primary AI security risk vectors to evaluate against this threat: '
        '<strong>LLM01 (Prompt Injection)</strong> — adversarial input via data sources consumed by AI pipelines; '
        '<strong>LLM06 (Sensitive Information Disclosure)</strong> — training data or retrieval context exposure via crafted queries; '
        '<strong>LLM08 (Excessive Agency)</strong> — agentic AI systems with tool-use capabilities that can be leveraged post-compromise; '
        '<strong>LLM10 (Model Theft)</strong> — exfiltration of fine-tuned model weights or proprietary training data.</p>'
        '<p style="margin:0;color:#94a3b8;font-size:13px">Reference frameworks: OWASP LLM Top 10 2025, MITRE ATLAS '
        '(Adversarial Threat Landscape for AI Systems), NIST AI RMF 1.0. CYBERDUDEBIVASH® AI Security Hub provides enterprise '
        'AI security assessments, adversarial red teaming, and AI governance program development.</p>'
    ) if is_ai else ""

    # Long-term strategic risk — category-specific
    if is_ransomware:
        long_term_risk = "The ransomware ecosystem is maturing toward Ransomware-as-a-Service (RaaS) affiliate models with specialized initial access brokers (IABs) separating access acquisition from ransomware deployment. Triple-extortion tactics — encryption, data leak, and DDoS against victim or customers — are becoming standard across major ransomware groups. Organizations must transition from reactive patch-driven defenses to intelligence-driven prevention: continuous threat actor tracking, pre-disclosure vulnerability prioritization, and automated SIEM rule deployment against emerging TTPs."
    elif is_apt:
        long_term_risk = "Nation-state threat actors are demonstrating sustained operational patience — median dwell time at discovery averages 197 days (Mandiant M-Trends). The strategic threat is pre-positioning for intellectual property theft, critical infrastructure disruption, and potential kinetic operation support. Organizations in targeted sectors must operate on assumption-of-breach principles: continuous behavioral monitoring, privileged access governance, and zero-trust network architectures that limit blast radius of persistent implants."
    elif is_cve:
        long_term_risk = f"The window between CVE publication and weaponization continues to compress — threat actors are demonstrating exploitation capability within hours of CVE disclosure for high-value targets. Vulnerabilities like {cve_str} represent the most efficient initial access vector available. Organizations must integrate real-time CISA KEV tracking with automated asset-to-vulnerability correlation to operationalize patch prioritization before weaponization, not after. CYBERDUDEBIVASH® SENTINEL APEX KEV correlation provides risk scoring against your specific asset inventory at time of CVE publication."
    elif is_ot:
        long_term_risk = "OT/ICS targeting has expanded beyond energy and utilities to food, agriculture, water, and manufacturing sectors — any operator of time-critical production processes is now a viable target for disruption campaigns. The convergence of IT and OT networks has dramatically expanded the attack surface while OT systems remain on decade-long replacement cycles with minimal patching cadence. Sector-specific threat intelligence (CISA ICS-CERT advisories, Dragos Year in Review) indicates threat actor capability development against ICS-specific protocols is accelerating."
    elif is_ato:
        long_term_risk = "Account takeover economics are improving for attackers as credential combo lists become larger and cheaper, residential proxy infrastructure becomes more accessible, and AIO tooling (OpenBullet/SilverBullet) lowers technical barriers. Sectors with high-value accounts — financial services, gaming, healthcare, and e-commerce — face escalating ATO volumes. The most effective long-term defense is eliminating password-based authentication: FIDO2/passkey adoption removes the fundamental prerequisite for credential stuffing attacks."
    elif is_supply_chain:
        long_term_risk = "Software supply chain attacks represent the highest-leverage attack vector available to sophisticated threat actors — compromising a single widely-used package or build tool reaches thousands of downstream organizations simultaneously. Regulatory pressure (NIST SSDF, EO 14028, EU Cyber Resilience Act) is driving mandatory SBOM requirements and software supply chain security standards. Organizations that build proactive software composition analysis and SBOM generation capability now will be positioned to meet compliance requirements and reduce exposure as the threat vector continues to mature."
    elif is_extension:
        long_term_risk = "Browser extensions represent an undermonitored attack surface in enterprise security programs — most organizations have no visibility into which extensions are installed on managed endpoints, and zero visibility on BYOD. As enterprise operations increasingly run through browser-based SaaS applications, the browser becomes the most privileged execution context accessible to an attacker without requiring endpoint compromise. Enterprise browser security (managed browser deployment, extension governance, in-browser DLP) will become a standard security control tier alongside EDR and SASE."
    else:
        long_term_risk = "The threat landscape is accelerating toward AI-augmented attacks — automated reconnaissance, AI-generated phishing at scale, and AI-assisted vulnerability discovery are compressing the time from threat emergence to exploitation. Organizations that rely on periodic threat briefings and signature-based defenses will consistently lag attacker velocity. Intelligence-driven security operations — continuous behavioral monitoring, pre-disclosure threat intelligence, and automated detection deployment — represent the required evolution. CYBERDUDEBIVASH® SENTINEL APEX provides the intelligence layer to close this gap."

    # Pre-compute strings that contain backslashes (can't use in f-string expressions)
    _chrome_reg = r"HKCU/HKLM\SOFTWARE\Google\Chrome\Extensions"
    _ext_li = f'<li><strong>Browser extension telemetry:</strong> Chrome/Edge extension inventory from registry ({_chrome_reg}) via endpoint management; Chrome Enterprise Browser Management audit logs if deployed</li>' if is_extension else ''
    _cve_li = '<li><strong>Web application logs:</strong> Full URI with parameters, HTTP method, response code, response body size, and client IP — required for exploitation attempt detection and post-exploitation web shell activity identification</li>' if is_cve else ''
    _ato_li = '<li><strong>Authentication logs:</strong> Web application login events with IP, user agent, geolocation, and result — aggregated across all customer-facing authentication endpoints; requires correlation across sessions to detect distributed low-velocity attacks</li>' if is_ato else ''
    _cicd_li = '<li><strong>CI/CD pipeline logs:</strong> Package installation events with dependency resolution trace; build job timing anomalies; network connections made during build phase</li>' if is_supply_chain else ''
    _ot_li = '<li><strong>OT network monitoring:</strong> Industrial protocol analysis (Modbus, S7comm, DNP3) from network tap on IT-OT boundary switch — requires OT-aware network monitoring tool (Dragos, Claroty, Nozomi)</li><li><strong>OT endpoint telemetry:</strong> Windows Event Logs from HMI systems and OT engineering workstations — enable audit process creation (4688) with command-line logging</li><li><strong>OT historian/SCADA audit logs:</strong> Configuration change audit trail for PLC parameter modifications and logic uploads outside approved windows</li>' if is_ot else '<li><strong>Windows Security Events:</strong> ID 4688 (process creation with full command-line logging), 4698 (scheduled task creation), 4624/4625 (auth success/failure), 4672 (special privileges assigned)</li><li><strong>EDR/XDR Telemetry:</strong> Process tree with parent-child relationships, file system events, registry modifications (Sysmon Event ID 13), network connection events</li><li><strong>Network telemetry:</strong> DNS query logs (all query types), proxy/web gateway logs, NetFlow/PCAP from network choke points</li>'
    _ics_ref = '<li>MITRE ATT&CK for ICS — <a href="https://attack.mitre.org/matrices/ics/" target="_blank" rel="noopener">https://attack.mitre.org/matrices/ics/</a></li>' if is_ot else ''
    _ai_ref = '<li>OWASP LLM Top 10 — <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" target="_blank" rel="noopener">https://owasp.org/www-project-top-10-for-large-language-model-applications/</a></li>' if is_ai else ''
    _nvd_refs = ''.join(f'<li>NVD — {cve} — <a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" rel="noopener">https://nvd.nist.gov/vuln/detail/{cve}</a></li>' for cve in cves) if cves else '<li>NIST National Vulnerability Database — <a href="https://nvd.nist.gov" target="_blank" rel="noopener">https://nvd.nist.gov</a></li>'
    _cvss_plain = cvss if cvss else "pending — see NVD entry"
    _cve_analysis = ('<ul>' + '\n'.join(f'<li><strong>{cve}</strong> — {category} vulnerability. CVSS: {_cvss_plain}. Monitor NVD entry at https://nvd.nist.gov/vuln/detail/{cve} and vendor security advisory for authoritative CVSS vector string, affected version range, and patch availability.</li>' for cve in cves) + '</ul>') if cves else ''
    # RX-PR0 follow-up (CodeRabbit): distinguish "confirmed not in KEV" from
    # "KEV status unknown" instead of collapsing both into the same
    # unconditional "requires immediate defensive action" framing.
    _cisa_sentence = (
        'CISA has added this to the Known Exploited Vulnerabilities catalog, imposing mandatory patching deadlines for U.S. federal agencies.' if article.kev_listed is True else
        'This item is not present in the verified CISA KEV catalog snapshot; absence does not rule out exploitation. CYBERDUDEBIVASH® SENTINEL APEX has classified this as a priority intelligence item warranting evaluation.' if article.kev_listed is False else
        'CISA KEV status is unknown or unavailable at time of publication. CYBERDUDEBIVASH® SENTINEL APEX has classified this as a priority intelligence item warranting evaluation.'
    )
    _cve_facts = (f'<li>CVE identifiers: {", ".join(cves)} — extracted from article content</li>' + '\n') if cves else ''
    _cvss_fact = (f'<li>CVSS score: {cvss} — extracted from article or vendor advisory</li>' + '\n') if cvss else ''
    _cvss_severity = f'based on CVSS score {cvss}' if cvss else 'based on threat category, exploitation status, and operational impact assessment'
    _patch_fact = '<li>Patch availability confirmed: vendor or CISA advisory references patch or required action</li>' if is_patch else '<li>Patch availability: unconfirmed at time of report generation — monitor vendor advisory channel</li>'
    _cvss_header = f'  |  CVSS {cvss}' if cvss else ''
    _exploit_confidence = 'Actively exploited in the wild — CISA KEV catalog inclusion confirmed (HIGH CONFIDENCE)' if article.kev_listed is True else 'Active exploitation not confirmed in CISA KEV at time of publication — technical severity assessed independently of exploitation status (MEDIUM CONFIDENCE)'
    _impact_text = 'Operational disruption, data encryption, ransom demand, potential double-extortion data leak' if is_ransomware else ('Production system disruption, perishable goods spoilage, supply chain continuity impact' if is_ot else ('Unauthorized account access, financial fraud, identity theft, regulatory breach notification obligation' if is_ato else 'Unauthorized access, privilege escalation, potential data exfiltration'))
    _prevalence_text = 'Widespread ransomware campaign with multiple victims across sector' if is_ransomware else ('Targeted exploitation — organizations matching the threat actor known targeting profile' if is_apt else 'Broad exposure — all organizations running the affected software or exposed services')
    _patch_status_text = 'Emergency patch available — deploy immediately' if is_patch else 'Monitor vendor advisory channel; implement compensating controls immediately pending patch availability'
    _ot_classification = 'Operational technology and industrial control system targeting with direct production impact risk.' if is_ot else 'Enterprise IT environment threat with potential for data loss, operational disruption, or financial impact.'
    _exploit_status = (
        f'{context.exploitation_label} (HIGH CONFIDENCE).'
        if context.exploitation_status == "confirmed" else
        f'{context.exploitation_label} — not confirmed is not the same as ruled out (MEDIUM CONFIDENCE).'
        if context.exploitation_status in {"not_confirmed", "unknown"} else
        f'{context.exploitation_label}.'
    )
    _attribution_note = 'Threat actor category identified based on TTPs and campaign characteristics described in source material.' if (is_ransomware or is_apt) else 'Attribution to specific threat actors has not been confirmed in the source material — analyst assessment and sector context are the basis for any attribution statements in this report (LOW CONFIDENCE).'
    _business_impact = (
        'Ransomware encryption of production systems carries average recovery costs exceeding $1.85M (Sophos State of Ransomware 2024) excluding reputational damage and regulatory penalty exposure. GDPR Article 33 requires breach notification within 72 hours; NIS2 Directive extends mandatory reporting to a broader set of critical sectors.' if is_ransomware else
        'Nation-state APT intrusions carry costs averaging $4.4M per breach (IBM Cost of a Data Breach Report) in addition to strategic IP loss, regulatory penalties under GDPR (up to 4% global annual revenue), NIS2, DORA, and sector-specific regulations. Government notification obligations under CISA binding operational directives and sector ISAC frameworks may apply depending on sector classification.' if is_apt else
        'OT disruption to industrial production carries operational downtime costs averaging $500K per hour in manufacturing sectors, food safety liability, supply chain continuity failure, and mandatory CISA ICS-CERT and sector regulator notification obligations. FDA, USDA, and EU NIS2 critical infrastructure requirements impose specific incident reporting timelines.' if is_ot else
        'Credential stuffing ATO incidents carry average costs of $290K per incident (Ponemon Institute) including fraud remediation, breach notification, and regulatory fines. GDPR Article 83 fines up to €20M or 4% of global annual revenue apply if personal data is accessed. PCI-DSS 4.0 Section 8 requires MFA for all account access — non-compliance creates direct audit liability.' if is_ato else
        f'Organizations with unpatched exposure to {cve_str} face unauthorized access, data exfiltration, and regulatory enforcement under GDPR (up to 4% global annual revenue), NIS2, DORA, or SOC 2 audit findings.'
    )
    _ot_para = '<p>Operational technology environments face elevated risk due to the combination of legacy systems with extended patching cycles, limited network segmentation between IT and OT networks, and the operational sensitivity of production disruption that may incentivize ransom payment or prevent proper incident containment.</p>' if is_ot else ''
    _ato_para = '<p>Credential stuffing operations rely on the reuse of username/password pairs from prior data breaches — victims are compromised through no fault of their current security posture. The attack succeeds entirely because of credential reuse across services, making MFA enforcement the single highest-efficacy defensive control available.</p>' if is_ato else ''

    # ── IOC behavioral styled cards ──────────────────────────────────────────
    _ioc_parts = [p.replace("<li>", "").strip() for p in ioc_behavioral.split("</li>") if p.replace("<li>", "").strip()]
    ioc_styled = "\n".join(
        f'<div style="margin:6px 0;padding:10px 14px;background:#120a00;border-left:3px solid #f59e0b;border-radius:0 4px 4px 0;font-size:13px;color:#cbd5e1;line-height:1.7">{item}</div>'
        for item in _ioc_parts
    )

    # ── Severity alert banner ────────────────────────────────────────────────
    _sev_bg = "#1a0000" if severity == "CRITICAL" else "#120a00" if severity == "HIGH" else "#001020"
    _sev_banner = (
        f'<div style="margin:0 0 24px;padding:14px 20px;background:{_sev_bg};border:1px solid {severity_color};border-radius:6px">'
        f'<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">'
        f'<span style="background:{severity_color};color:#fff;padding:4px 12px;border-radius:4px;font-weight:900;font-size:12px;font-family:monospace;letter-spacing:1.5px">{severity}</span>'
        f'<span style="color:{severity_color};font-size:13px;font-weight:700;font-family:monospace;letter-spacing:1px">SENTINEL APEX THREAT ADVISORY</span>'
        f'<span style="color:#475569;font-size:11px;font-family:monospace;margin-left:auto">{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</span>'
        f'</div></div>'
    )

    # ── Section header helper ────────────────────────────────────────────────
    def _sh(title: str, color: str = "#00d4ff") -> str:
        return (
            f'<div style="margin:32px 0 14px;padding:10px 18px;'
            f'background:linear-gradient(90deg,#0a1628,#050d1a);'
            f'border-left:3px solid {color};font-size:11px;font-weight:700;'
            f'color:{color};letter-spacing:2.5px;text-transform:uppercase;'
            f'font-family:monospace">&#9658; {title}</div>'
        )

    ai_section = (
        f'{_sh("AI Security Impact", "#a855f7")}\n'
        f'<div style="background:#0d0014;border:1px solid #a855f733;border-radius:6px;padding:16px 20px;'
        f'font-size:13px;color:#c4b5fd;line-height:1.8">\n{_ai_section_body}\n</div>'
    ) if _ai_section_body else ""

    # ── Terminal-style Sigma block ───────────────────────────────────────────
    _sigma_date = datetime.now(timezone.utc).strftime("%Y%m%d")
    _sigma_date_fmt = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    _sigma_terminal = (
        f'<div style="margin:16px 0;border-radius:8px;overflow:hidden;border:1px solid #1e3a5f">'
        f'<div style="background:#161b22;padding:8px 14px;display:flex;align-items:center;gap:6px;border-bottom:1px solid #0d2137">'
        f'<span style="width:10px;height:10px;border-radius:50%;background:#ef4444;display:inline-block"></span>'
        f'<span style="width:10px;height:10px;border-radius:50%;background:#f59e0b;display:inline-block"></span>'
        f'<span style="width:10px;height:10px;border-radius:50%;background:#22c55e;display:inline-block"></span>'
        f'<span style="color:#64748b;font-size:11px;font-family:monospace;margin-left:8px">sigma-detection-rule.yml &mdash; SENTINEL APEX Detection Engineering</span>'
        f'</div>'
        f'<pre style="margin:0;padding:16px;background:#0a0f0a;color:#22c55e;font-family:\'Courier New\',monospace;font-size:12px;line-height:1.6;overflow-x:auto;white-space:pre-wrap"><code>'
        f'title: {sigma_title}\n'
        f'id: cdb-sentinel-apex-{_sigma_date}-001\n'
        f'status: experimental\n'
        f'description: &gt;\n'
        f'  Detects {sigma_title.lower()}.\n'
        f'  CYBERDUDEBIVASH&#174; SENTINEL APEX Detection Engineering.\n'
        f'references:\n'
        f'    - {article.url}\n'
        f'    - https://blog.cyberdudebivash.in\n'
        f'    - https://intel.cyberdudebivash.com\n'
        f'author: CYBERDUDEBIVASH&#174; SENTINEL APEX Detection Engineering\n'
        f'date: {_sigma_date_fmt}\n'
        f'tags:\n'
        f'{sigma_tags}\n'
        f'logsource:\n'
        f'    {sigma_logsource}\n'
        f'{sigma_detection}\n'
        f'falsepositives:\n'
        f'    - Legitimate administrative activity\n'
        f'    - Security testing or red team exercises\n'
        f'level: high'
        f'</code></pre></div>'
    )

    # ── Multi-SIEM query pack — same detection logic as the Sigma rule
    # above, translated to each platform's native query syntax. ─────────────
    def _siem_block(queries: dict) -> str:
        if not queries:
            return ""
        panes = []
        for key, label in SIEM_PLATFORM_LABELS.items():
            query = queries.get(key)
            if not query:
                continue
            panes.append(
                f'<div style="margin:12px 0;border-radius:8px;overflow:hidden;border:1px solid #1e3a5f">'
                f'<div style="background:#161b22;padding:6px 14px;border-bottom:1px solid #0d2137;'
                f'color:#67e8f9;font-size:11px;font-weight:700;font-family:monospace;letter-spacing:0.5px">{label}</div>'
                f'<pre style="margin:0;padding:14px 16px;background:#0a0f0a;color:#67e8f9;'
                f'font-family:\'Courier New\',monospace;font-size:11.5px;line-height:1.6;'
                f'overflow-x:auto;white-space:pre-wrap"><code>{query}</code></pre></div>'
            )
        return "\n".join(panes)

    # ── CVE cards ────────────────────────────────────────────────────────────
    _cve_cards = "\n".join(
        (
            f'<div style="margin:6px 0;padding:10px 14px;background:#1a0005;border-left:3px solid #ef4444;border-radius:0 4px 4px 0">'
            f'<span style="color:#ef4444;font-family:monospace;font-size:11px;font-weight:700">{cve}</span>'
            f'<span style="color:#94a3b8;font-size:12px;margin-left:10px">{category} &middot; CVSS: {_cvss_plain} &middot; </span>'
            f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" rel="noopener" style="color:#60a5fa;font-size:12px;text-decoration:none">NVD &#8599;</a>'
            f'</div>'
        )
        for cve in cves
    ) if cves else ""

    # ── Styled references ────────────────────────────────────────────────────
    _ref_style = 'style="margin:4px 0;padding:8px 14px;background:#050d1a;border-radius:4px;font-size:12px"'
    _ref_arrow = '<span style="color:#334155;font-family:monospace;margin-right:8px">&#8594;</span>'
    _ref_link = 'style="color:#60a5fa;text-decoration:none"'
    _refs_items = [
        f'<div {_ref_style}>{_ref_arrow}<a href="{article.url}" target="_blank" rel="noopener" {_ref_link}>Source Article</a></div>',
        f'<div {_ref_style}>{_ref_arrow}<a href="https://attack.mitre.org" target="_blank" rel="noopener" {_ref_link}>MITRE ATT&amp;CK Enterprise Matrix</a></div>',
        f'<div {_ref_style}>{_ref_arrow}<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener" {_ref_link}>CISA Known Exploited Vulnerabilities Catalog</a></div>',
    ]
    if is_ot:
        _refs_items.append(f'<div {_ref_style}>{_ref_arrow}<a href="https://attack.mitre.org/matrices/ics/" target="_blank" rel="noopener" {_ref_link}>MITRE ATT&amp;CK for ICS</a></div>')
    if is_ai:
        _refs_items.append(f'<div {_ref_style}>{_ref_arrow}<a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" target="_blank" rel="noopener" {_ref_link}>OWASP LLM Top 10</a></div>')
    for _rc in cves:
        _refs_items.append(f'<div {_ref_style}>{_ref_arrow}<a href="https://nvd.nist.gov/vuln/detail/{_rc}" target="_blank" rel="noopener" {_ref_link}>NVD &mdash; {_rc}</a></div>')
    _refs_styled = "\n".join(_refs_items)

    # Executive decision matrix
    exec_matrix_rows = ""
    if is_ransomware:
        exec_matrix_rows = """<tr><td>P0</td><td>Authorize emergency host isolation for confirmed/suspected infected systems</td><td>CISO / SOC Lead</td><td>Immediate</td></tr>
<tr><td>P0</td><td>Verify immutable backup availability and authorize test restoration</td><td>IT Operations / CISO</td><td>Within 2 hours</td></tr>
<tr><td>P1</td><td>Activate incident response retainer and engage external IR firm</td><td>CISO / General Counsel</td><td>Within 4 hours</td></tr>
<tr><td>P1</td><td>Assess regulatory breach notification obligations and prepare notification draft</td><td>Legal / Privacy Officer</td><td>Within 24 hours</td></tr>
<tr><td>P2</td><td>Board notification: assess cyber insurance claim initiation</td><td>CEO / CFO / CISO</td><td>Within 48 hours</td></tr>"""
    elif is_apt:
        exec_matrix_rows = """<tr><td>P0</td><td>Authorize 90-day retroactive threat hunt across all EDR-enrolled endpoints</td><td>CISO / Threat Intel Lead</td><td>Immediate</td></tr>
<tr><td>P1</td><td>Assess whether affected systems host regulated data requiring government notification</td><td>Legal / Compliance</td><td>Within 24 hours</td></tr>
<tr><td>P1</td><td>Evaluate whether sector ISAC notification is appropriate for intelligence sharing</td><td>CISO</td><td>Within 48 hours</td></tr>
<tr><td>P2</td><td>Authorize engagement of external attribution/forensics specialist if compromise confirmed</td><td>CISO / CEO</td><td>Within 72 hours</td></tr>"""
    elif is_cve:
        exec_matrix_rows = f"""<tr><td>P0</td><td>Authorize emergency patching of {cve_str} — override change management freeze if required</td><td>CISO / IT Operations</td><td>Immediate</td></tr>
<tr><td>P0</td><td>Authorize WAF virtual patching deployment if patch is not available within 4 hours</td><td>CISO / Security Architect</td><td>Within 4 hours</td></tr>
<tr><td>P1</td><td>Authorize retroactive log review to determine if pre-patch exploitation occurred</td><td>CISO / SOC Lead</td><td>Within 24 hours</td></tr>
<tr><td>P2</td><td>Assess whether asset inventory process needs improvement to accelerate future CVE exposure identification</td><td>CISO / VP Engineering</td><td>Within 30 days</td></tr>"""
    elif is_ot:
        exec_matrix_rows = """<tr><td>P0</td><td>Confirm production system status — assess if emergency production shutdown is required</td><td>Operations Director / CISO</td><td>Immediate</td></tr>
<tr><td>P0</td><td>Verify IT/OT network boundary controls are intact — validate firewall rules between IT and OT VLANs</td><td>IT Security / OT Engineering</td><td>Within 2 hours</td></tr>
<tr><td>P1</td><td>Engage ICS security specialist for OT forensic assessment if intrusion indicators found</td><td>CISO</td><td>Within 24 hours</td></tr>
<tr><td>P1</td><td>Assess CISA ICS-CERT and sector regulator notification obligations for OT security incidents</td><td>Legal / CISO</td><td>Within 48 hours</td></tr>
<tr><td>P2</td><td>Authorize ICS security assessment program and network monitoring tool deployment in OT environment</td><td>CISO / COO</td><td>Within 90 days</td></tr>"""
    else:
        exec_matrix_rows = """<tr><td>P0</td><td>Authorize SOC activation and threat detection rule deployment for this threat type</td><td>CISO / SOC Lead</td><td>Immediate</td></tr>
<tr><td>P1</td><td>Assess user population exposure to this threat vector and authorize targeted user communication</td><td>CISO / Communications</td><td>Within 24 hours</td></tr>
<tr><td>P1</td><td>Evaluate regulatory notification obligations if user data may be at risk</td><td>Legal / Privacy Officer</td><td>Within 48 hours</td></tr>
<tr><td>P2</td><td>Authorize detection engineering investment to close identified SIEM coverage gaps</td><td>CISO / Security Engineering</td><td>Within 30 days</td></tr>"""

    # Predictive intelligence — confidence-labeled
    if is_ransomware:
        predictive = "<p><strong>Campaign continuation (HIGH CONFIDENCE):</strong> Ransomware groups maintain active operations between public disclosures — affected organizations not yet encrypted remain at elevated risk for 30-60 days following initial campaign reporting.</p><p><strong>Sector expansion (MEDIUM CONFIDENCE):</strong> If initial targeting yields successful outcomes, ransomware operators historically expand targeting to adjacent sector verticals within 60-90 days of initial campaign success.</p><p><strong>Affiliate TTPs evolution (MEDIUM CONFIDENCE):</strong> RaaS affiliate programs rapidly incorporate newly published vulnerability exploits as initial access vectors — monitor CISA KEV for vulnerabilities relevant to your attack surface immediately following any ransomware campaign disclosure.</p>"
    elif is_apt:
        predictive = "<p><strong>Ongoing access maintenance (HIGH CONFIDENCE):</strong> Nation-state actors with established footholds rotate infrastructure and implants on 30-60 day cycles to survive IOC-based defenses — confirmed IOC blocks provide limited protection without behavioral detection capability.</p><p><strong>Campaign scope expansion (MEDIUM CONFIDENCE):</strong> APT campaigns typically expand to additional targets in the same sector or supply chain after initial success — organizations in the same sector should treat this as direct targeting risk regardless of confirmed victim identity.</p><p><strong>Attribution stability (LOW CONFIDENCE):</strong> Technical attribution to specific nation-state actors based on public reporting carries inherent uncertainty — false flag operations and shared tooling between groups are documented phenomena that limit high-confidence attribution.</p>"
    elif is_cve:
        # KEV-aware: never forecast a KEV addition for a CVE the report already
        # states is in the KEV catalog — that contradiction destroys analyst credibility.
        # RX-PR0 follow-up (CodeRabbit): a "confirmed exploitation" KEV-addition
        # forecast must not fire for kev_listed=False (positively confirmed NOT
        # listed) or kev_listed=None (unknown) with no other exploitation
        # evidence — only when context.exploitation_status is actually
        # "confirmed" (KEV-true or a confirmed-exploitation text match).
        _kev_listed = article.kev_listed is True
        if _kev_listed:
            _kev_paragraph = "<p><strong>KEV remediation deadline pressure (HIGH CONFIDENCE):</strong> With this vulnerability already listed in the CISA Known Exploited Vulnerabilities catalog, U.S. federal agencies face a mandatory remediation deadline — expect intensified adversary scanning for unpatched instances as the deadline approaches and public attention peaks.</p>"
        elif context.exploitation_status == "confirmed":
            _kev_paragraph = "<p><strong>CISA KEV addition (MEDIUM CONFIDENCE):</strong> Vulnerabilities with confirmed exploitation and public PoC availability are typically added to CISA KEV within 7-14 days of that confirmation — monitor KEV for mandatory patching deadline implications.</p>"
        else:
            _kev_paragraph = "<p><strong>KEV status (LOW CONFIDENCE):</strong> No confirmed exploitation evidence is available at time of publication to support a KEV-addition timeline forecast — monitor the CISA KEV catalog for status changes.</p>"
        predictive = f"<p><strong>Active exploitation escalation (HIGH CONFIDENCE):</strong> Based on historical patterns for vulnerabilities in this class, {cve_str} will be incorporated into exploit kits and automated scanning tools within 72 hours of PoC publication, dramatically expanding the threat actor population able to exploit it.</p>{_kev_paragraph}<p><strong>RaaS initial access broker adoption (MEDIUM CONFIDENCE):</strong> High-CVSS network-exploitable vulnerabilities are routinely adopted by ransomware initial access brokers within 30 days of public exploit availability.</p>"
    else:
        predictive = "<p><strong>Threat vector persistence (MEDIUM CONFIDENCE):</strong> Based on the attack methodology described, this threat vector is likely to remain active for the next 60-90 days as threat actors exhaust the target population or shift to alternative delivery mechanisms.</p><p><strong>Detection evasion evolution (MEDIUM CONFIDENCE):</strong> Threat actors actively monitor public detection rule releases and typically modify malware signatures within 24-48 hours of public Sigma/YARA rule publication to evade new detections.</p><p><strong>Targeting scope (LOW CONFIDENCE):</strong> Without confirmed attribution or explicit campaign scope disclosure in the source material, targeting scope projection carries significant uncertainty — maintain standard monitoring posture while avoiding over-scoping defensive response.</p>"

    # ── Style exec matrix + parse predictive (must be after both are assigned) ─
    _emr = exec_matrix_rows
    for _mp, _mc in [("P0", "#ef4444"), ("P1", "#f59e0b"), ("P2", "#3b82f6")]:
        _emr = _emr.replace(
            f"<td>{_mp}</td>",
            f'<td style="padding:10px 14px;vertical-align:top;white-space:nowrap"><span style="background:{_mc};color:#fff;padding:3px 8px;border-radius:3px;font-size:10px;font-weight:900;font-family:monospace">{_mp}</span></td>',
        )
    _emr = _emr.replace("<td>", '<td style="padding:10px 14px;color:#cbd5e1;font-size:13px;vertical-align:top;line-height:1.5">')
    _emr = _emr.replace("<tr>", '<tr style="border-bottom:1px solid #0d2137">')

    _pred_parts = re.findall(r"<p>(.*?)</p>", predictive, re.DOTALL)
    _pred_cards = []
    for _pp in _pred_parts:
        if "HIGH CONFIDENCE" in _pp:
            _pc, _pl = "#22c55e", "&#9679; HIGH CONFIDENCE"
        elif "MEDIUM CONFIDENCE" in _pp:
            _pc, _pl = "#f59e0b", "&#9679; MEDIUM CONFIDENCE"
        else:
            _pc, _pl = "#64748b", "&#9679; LOW CONFIDENCE"
        _pred_cards.append(
            f'<div style="margin:8px 0;padding:12px 16px;background:#050d1a;border-left:3px solid {_pc};border-radius:0 4px 4px 0">'
            f'<div style="color:{_pc};font-size:10px;font-weight:900;font-family:monospace;letter-spacing:1.5px;margin-bottom:6px">{_pl}</div>'
            f'<div style="color:#94a3b8;font-size:13px;line-height:1.6">{_pp}</div></div>'
        )
    _pred_styled = "\n".join(_pred_cards) if _pred_cards else f'<div style="color:#94a3b8;font-size:13px;line-height:1.7">{predictive}</div>'

    # Intelligence/news families carry no threat-specific telemetry or
    # observables (mirrors report_renderer.py's _detection_package()
    # not-applicable set). Rendering process-execution/Sigma/ATT&CK content
    # for them is exactly the schema contamination validate_publication()
    # rejects — a governance-focused analysis replaces it instead of an
    # invented technical detection surface.
    if context.family in {"ai_security", "breach_notice", "general_intelligence"} and not article.cve_id:
        _detection_block = _family_analysis(article, context)
    else:
        # Detection/Sigma/ATT&CK content is sourced from report_renderer.py's
        # vulnerability-class-aware, evidence-gated generator rather than the
        # is_ransomware/is_ot/... heuristics below (which predate the KEV/
        # exploitation-evidence model and, per RX-STABILIZATION-1 forensics,
        # can assert unearned technical precision — e.g. branded ransomware
        # Sigma rules with no actor-specific IOCs). mitre_techniques/sigma_*/
        # siem_queries/hunt_queries/soc_actions above stay in place as
        # reference material for a future richer, evidence-bound rebuild of
        # the SIEM-query/hunting/SOC-playbook sections; they are intentionally
        # not rendered here.
        _package = _detection_package(article, context)
        _detection_block = _attack_section(_package) + _detection_section(_package)

    return f"""{_sev_banner}

{_sh("Executive Summary")}
<div style="background:#050d1a;border:1px solid #1e3a5f44;border-radius:6px;padding:16px 20px;font-size:14px;color:#cbd5e1;line-height:1.8">
<p style="margin:0 0 10px">{article.summary[:350].rstrip('.')}. This represents a <strong style="color:{severity_color}">{severity}</strong>-severity threat ({cvss_str} risk profile) requiring immediate evaluation by SOC and vulnerability management teams.</p>
<p style="margin:0;color:#94a3b8;font-size:13px">{_cisa_sentence}</p>
</div>

{_sh("Verified Facts", "#22c55e")}
<div style="background:#001a10;border:1px solid #22c55e33;border-radius:6px;padding:14px 20px">
<div style="margin:4px 0;padding:6px 0;border-bottom:1px solid #0d2137;font-size:13px;color:#86efac"><span style="color:#22c55e;font-family:monospace;font-size:11px;font-weight:700;margin-right:10px">TYPE</span>{category} &mdash; derived from article classification and content analysis</div>
{f'<div style="margin:4px 0;padding:6px 0;border-bottom:1px solid #0d2137;font-size:13px;color:#86efac"><span style="color:#22c55e;font-family:monospace;font-size:11px;font-weight:700;margin-right:10px">CVE</span>{", ".join(cves)} &mdash; extracted from article content</div>' if cves else ''}
{f'<div style="margin:4px 0;padding:6px 0;border-bottom:1px solid #0d2137;font-size:13px;color:#86efac"><span style="color:#22c55e;font-family:monospace;font-size:11px;font-weight:700;margin-right:10px">CVSS</span>{cvss} &mdash; extracted from article or vendor advisory</div>' if cvss else ''}
<div style="margin:4px 0;padding:6px 0;border-bottom:1px solid #0d2137;font-size:13px;color:#86efac"><span style="color:#22c55e;font-family:monospace;font-size:11px;font-weight:700;margin-right:10px">SEVERITY</span><span style="color:{severity_color};font-weight:700">{severity}</span> &mdash; {_cvss_severity}</div>
<div style="margin:4px 0;padding:6px 0;font-size:13px;color:#86efac"><span style="color:#22c55e;font-family:monospace;font-size:11px;font-weight:700;margin-right:10px">PATCH</span>{'Confirmed available &mdash; deploy immediately' if is_patch else 'Unconfirmed at time of report &mdash; monitor vendor advisory'}</div>
</div>

{_sh("Threat Classification & Severity", "#ef4444")}
<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px">
<div style="flex:1;min-width:200px;background:#1a0005;border:1px solid #ef444433;border-radius:6px;padding:14px 16px">
<div style="color:#ef4444;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1.5px;margin-bottom:8px">THREAT TYPE</div>
<div style="color:#fca5a5;font-size:14px;font-weight:700">{category}</div>
<div style="color:#64748b;font-size:11px;margin-top:4px">{_ot_classification}</div>
</div>
<div style="flex:1;min-width:200px;background:#120a00;border:1px solid {severity_color}44;border-radius:6px;padding:14px 16px">
<div style="color:{severity_color};font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1.5px;margin-bottom:8px">SEVERITY</div>
<div style="color:{severity_color};font-size:24px;font-weight:900;font-family:monospace">{severity}{f" &nbsp;CVSS {cvss}" if cvss else ""}</div>
</div>
<div style="flex:1;min-width:200px;background:#050d1a;border:1px solid #1e3a5f;border-radius:6px;padding:14px 16px">
<div style="color:#00d4ff;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1.5px;margin-bottom:8px">EXPLOIT STATUS</div>
<div style="color:#cbd5e1;font-size:12px;line-height:1.6">{_exploit_status}</div>
</div>
</div>
<div style="background:#050d1a;border:1px solid #1e3a5f44;border-radius:6px;padding:14px 20px;font-size:13px;color:#94a3b8;line-height:1.7">
<strong style="color:#cbd5e1">Exploitability:</strong> {_exploit_confidence}<br>
<strong style="color:#cbd5e1">Impact scope:</strong> {_impact_text}<br>
<strong style="color:#cbd5e1">Prevalence:</strong> {_prevalence_text}<br>
<strong style="color:#cbd5e1">Attribution:</strong> {_attribution_note}
</div>

{_sh("Business Impact", "#f97316")}
<div style="background:#120800;border:1px solid #f9731633;border-radius:6px;padding:16px 20px;font-size:13px;color:#fed7aa;line-height:1.8">
<p style="margin:0 0 10px">{_business_impact}</p>
<p style="margin:0;color:#78350f;font-size:12px;border-top:1px solid #f9731622;padding-top:10px">Risk quantification requires correlation against your specific asset inventory, data classification, and regulatory obligations. CVSS scores reflect technical severity, not business impact to your environment.</p>
</div>

{_sh("Technical Analysis")}
<div style="background:#050d1a;border:1px solid #1e3a5f44;border-radius:6px;padding:16px 20px;font-size:13px;color:#cbd5e1;line-height:1.8">
<p style="margin:0 0 10px">{article.summary[:800]}</p>
{_ot_para}
{_ato_para}
</div>

{f'{_sh("CVE Analysis", "#ef4444")}<div style="background:#0d0014;border:1px solid #ef444433;border-radius:6px;padding:14px 16px">{_cve_cards}</div>' if cves else ''}

{_detection_block}

{_sh("Executive Decision Matrix", "#ef4444")}
<div style="overflow-x:auto">
<table style="width:100%;border-collapse:collapse;font-size:13px;background:#050d1a;border-radius:6px;overflow:hidden">
<tr style="background:#0d2137;border-bottom:2px solid #ef444433">
<th style="padding:10px 14px;text-align:left;color:#ef4444;font-family:monospace;font-size:10px;letter-spacing:1.5px;white-space:nowrap">PRIORITY</th>
<th style="padding:10px 14px;text-align:left;color:#ef4444;font-family:monospace;font-size:10px;letter-spacing:1.5px">DECISION REQUIRED</th>
<th style="padding:10px 14px;text-align:left;color:#ef4444;font-family:monospace;font-size:10px;letter-spacing:1.5px;white-space:nowrap">OWNER</th>
<th style="padding:10px 14px;text-align:left;color:#ef4444;font-family:monospace;font-size:10px;letter-spacing:1.5px;white-space:nowrap">TIMELINE</th>
</tr>
{_emr}
</table>
</div>

{_sh("Executive Recommendations", "#06b6d4")}
<div style="background:#001a1a;border:1px solid #06b6d433;border-radius:6px;padding:14px 16px">
{ent_html}
</div>

{_sh("Predictive Intelligence", "#3b82f6")}
<div style="background:#00081a;border:1px solid #3b82f633;border-radius:6px;padding:14px 16px">
<div style="color:#1d4ed8;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1.5px;margin-bottom:10px">&#9670; CONFIDENCE-LABELED ANALYST FORECASTS</div>
{_pred_styled}
</div>

{_sh("MSSP Partner Advisory", "#ec4899")}
<div style="background:#1a001a;border:1px solid #ec489933;border-radius:6px;padding:16px 20px;font-size:13px;color:#f9a8d4;line-height:1.8">
{mssp_block}
</div>

{_sh("SENTINEL APEX Intelligence Correlation")}
<div style="background:#050d1a;border:1px solid #00d4ff22;border-radius:6px;padding:16px 20px">
<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px">
<div style="flex:1;min-width:180px;background:#001220;border:1px solid #00d4ff22;border-radius:6px;padding:12px 14px">
<div style="color:#00d4ff;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1px;margin-bottom:6px">&#9670; LIVE CVE &amp; KEV</div>
<div style="color:#94a3b8;font-size:12px">Real-time NVD, CISA KEV, vendor advisory monitoring with CVSS-weighted client exposure scoring</div>
</div>
<div style="flex:1;min-width:180px;background:#001220;border:1px solid #00d4ff22;border-radius:6px;padding:12px 14px">
<div style="color:#00d4ff;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1px;margin-bottom:6px">&#9670; MITRE CORRELATION</div>
<div style="color:#94a3b8;font-size:12px">Automated technique mapping with detection gap analysis vs. your SIEM coverage and ATT&amp;CK Navigator heatmap</div>
</div>
<div style="flex:1;min-width:180px;background:#001220;border:1px solid #00d4ff22;border-radius:6px;padding:12px 14px">
<div style="color:#00d4ff;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1px;margin-bottom:6px">&#9670; SIGMA &amp; YARA LIBRARY</div>
<div style="color:#94a3b8;font-size:12px">Production detection rules for Splunk, Elastic, Sentinel, Chronicle, QRadar</div>
</div>
<div style="flex:1;min-width:180px;background:#001220;border:1px solid #00d4ff22;border-radius:6px;padding:12px 14px">
<div style="color:#00d4ff;font-size:10px;font-weight:700;font-family:monospace;letter-spacing:1px;margin-bottom:6px">&#9670; IOC INTELLIGENCE FEED</div>
<div style="color:#94a3b8;font-size:12px">Real-time enrichment from commercial feeds, ISAC sharing, and dark web monitoring</div>
</div>
</div>
<div style="text-align:center;padding-top:10px;border-top:1px solid #1e3a5f33">
<a href="https://intel.cyberdudebivash.com" target="_blank" rel="noopener" style="display:inline-block;background:linear-gradient(90deg,#0284c7,#00d4ff);color:#fff;padding:10px 24px;border-radius:6px;font-weight:700;font-size:13px;text-decoration:none;letter-spacing:0.5px">&#9658; Launch SENTINEL APEX</a>
</div>
</div>

{ai_section}

{_sh("Long-Term Strategic Risk", "#64748b")}
<div style="background:#050d1a;border:1px solid #33415566;border-radius:6px;padding:16px 20px;font-size:13px;color:#94a3b8;line-height:1.8">
{long_term_risk}
</div>

{_sh("References", "#475569")}
<div style="background:#030912;border:1px solid #1e3a5f33;border-radius:6px;padding:14px 16px">
{_refs_styled}
</div>
""".strip()


# ─────────────────────────────────────────────────────────────────────────────
# PRODUCTION EVIDENCE-FIRST TEMPLATE
# ─────────────────────────────────────────────────────────────────────────────

def _template_enhance(article: DiscoveredArticle, config: Config) -> str:
    """Render the minimal evidence-only template (RX-STABILIZATION-1, deprecated).

    Between commit 0a4b2df and RX-PR0 this was the sole production renderer;
    it produced provenance-safe but commercially thin reports. `transform()`
    now uses `_legacy_template_enhance()` (LLM-fallback deterministic
    template, restored) so every report gets full commercial depth while
    still passing through the same `validate_publication()` evidence gate.
    `render_evidence_report()` is kept — not deleted — as a reviewable
    reference renderer and a candidate input for the RX-PR2 canonical
    contract; nothing in the production pipeline currently calls it.
    """
    return render_evidence_report(article, config).html


@dataclass(frozen=True)
class _ComposerOutcome:
    """``achieved_tier`` distinguishes WHY ``html`` may be unusable, because
    the two cases must be handled differently by ``transform()``:

    - ``""`` -- ``compose_report()`` itself raised. An unproven-in-production
      path must not be able to break publication, so this is a software-fault
      safety net: the legacy template still supplies body content and the
      article still publishes, exactly as before this change.
    - ``"PUBLIC_REFERENCE_DRAFT"`` -- ``compose_report()`` succeeded and its
      own fail-closed tier ladder found the EVIDENCE unreliable, not merely
      the code broken. That must hard-block publication rather than quietly
      substitute a legacy template and publish anyway (P0-COMMERCIAL-QUALITY-2026-08-18:
      "no silent downgrade to public-reference or legacy output") -- see the
      ``validate_publication()`` gate this feeds in ``report_integrity.py``.
    - anything else -- a real, evidence-graph-certified tier.
    """
    html: Optional[str]
    achieved_tier: str
    failed_controls: tuple = ()
    # COMMERCIAL-QUALITY-2026-08-18: the 20-dimension commercial-readiness
    # scorecard (Intelligence Validation Framework, PR #90) -- real,
    # already-computed observability data, not (yet) a hard gate. None only
    # on the composer-exception path, where no scorecard was ever computed.
    quality_score: Optional[int] = None
    quality_score_eligible: Optional[bool] = None
    # RX-P1C-WIRE: the real, per-article claim/evidence/source graph
    # (sentinel_engine.reportx.claim_model.EvidenceGraph.to_dict()) --
    # already built by compose_report() for every article via
    # discovery_bridge.build_evidence_graph(), already claim-level
    # (claim_id/claim_type/status/evidence_refs/source_refs/
    # corroboration_state/contradictions per Sections 3-4), but previously
    # discarded at this exact boundary: only the derived tier/scorecard
    # crossed into _ComposerOutcome, never the graph itself. Exposed here as
    # real, observable data first -- same discipline as quality_score above
    # -- not yet rendered into the HTML body or used by any gate. None only
    # on the composer-exception path, where no graph was ever built.
    evidence_graph: Optional[dict] = None
    # RX-P1E-WIRE: compose_report()'s own intelligence_gaps list (currently
    # always exactly one real, honest gap -- "whether an independent second
    # source corroborates this record has not been assessed"; not yet a
    # rich, per-article gap analysis -- see analytic_scaffolding.IntelligenceGap)
    # was likewise computed unconditionally and then discarded at this same
    # boundary. Exposed for the same reason as evidence_graph above.
    intelligence_gaps: tuple = ()
    # RX-P1D-WIRE: compose_report()'s own contradiction_engine.py findings
    # (cross-claim same-dimension EpistemicState conflicts + rendered-text
    # pattern conflicts) -- computed unconditionally, discarded at this same
    # boundary before this change. Unlike the two fields above, this one
    # also feeds a hard publication gate below (every Contradiction this
    # engine can currently produce carries severity=="block" by
    # construction -- see contradiction_engine.py's own module docstring:
    # "Gate: unresolved_contradictions == 0").
    contradictions: tuple = ()
    # RX-P1E-WIRE: compose_report()'s own structured 3-axis confidence
    # model (source reliability grade / information credibility number+
    # label / corroboration state / overall confidence), computed
    # unconditionally, discarded at this same boundary before this change.
    # Empty dict only on the composer-exception path.
    analytical_confidence: dict = field(default_factory=dict)
    # RX-P1G-WIRE: compose_report()'s own canonical_entities (Phase 1G --
    # CVE/ransomware_actor/sector/country from this article's structured
    # fields, plus curated-lexicon malware/tool/vendor/product mentions from
    # its own text -- see entity_resolution.py), computed unconditionally,
    # discarded at this same boundary before this change. Empty tuple on
    # the composer-exception path, same as the fields above.
    canonical_entities: tuple = ()
    # RX-P1I-WIRE: compose_report()'s own hunt_hypotheses (real,
    # evidence-grounded, cve_advisory only today -- see pipeline_composer.
    # _cve_hunt_hypotheses()), same discard-at-this-boundary situation
    # canonical_entities was in before Phase 1G wired it through.
    hunt_hypotheses: tuple = ()
    # RX-P1I-WIRE (structured ATT&CK): compose_report()'s own
    # attack_mappings (real, evidence-gated, every family) -- same
    # discard-at-this-boundary situation hunt_hypotheses was in until this
    # exact change.
    attack_mappings: tuple = ()
    # RX-P1J-WIRE: compose_report()'s own role_decisions (real,
    # family-conditioned, gate-passed -- see pipeline_composer.
    # _lean_role_decisions()/_validate_role_decisions()). Same
    # discard-at-this-boundary situation hunt_hypotheses/attack_mappings
    # were in until wired: previously computed by the composer, counted by
    # report_contract.py's Section 19 via analytical_depth_gate.py, but
    # never reaching this function's own output at all -- the identical
    # defect class the hunt_hypotheses fix above was written to prevent
    # from recurring, found here because it recurred anyway.
    role_decisions: tuple = ()
    # RX-P1K-WIRE: compose_report()'s own reliability_html (Section 6,
    # Evidence & Source Assessment -- real two-axis Admiralty grading and
    # corroboration state, always non-empty once the composer succeeds).
    # Same discard-at-this-boundary situation as the three fields above --
    # previously baked into composer_outcome.html for the reportx_composer
    # path only, silently absent from every other path even though Section
    # 6 has claimed unconditional COMPLETE since report_contract.py was
    # first written. Already a complete HTML string (unlike the three
    # fields above): exactly one place ever builds it, so it is passed
    # through directly rather than re-derived from structured data.
    reliability_html: str = ""
    # RX-P1K-WIRE: compose_report()'s own forecasts (real, evidence-grounded
    # Forecast/WithheldForecast entries -- cve_advisory/cisa_kev/
    # cisa_advisory only today, see pipeline_composer._cve_forecast()).
    # forecast.py's dataclasses existed, were tested, and certified, but
    # were never imported by this live pipeline before this round --
    # Section 22 (Forecast/Outlook) was permanently WITHHELD for every
    # article regardless of family. Same discard-at-this-boundary
    # situation hunt_hypotheses/attack_mappings/role_decisions were in.
    forecasts: tuple = ()


def _composer_enhance(article: DiscoveredArticle, config: Config) -> _ComposerOutcome:
    """Runs the Intelligence Factory composer
    (``Sentinel-APEX/engine/sentinel_engine/reportx/pipeline_composer.py``,
    RX-PR2) unconditionally for every article -- not merely as a fallback
    after the LLM path fails. Evidence-graph correctness is a property of
    the article's own evidence, not of which renderer happens to write the
    prose, so the certification/publication gate below must see this
    result regardless of whether the LLM, the composer, or (on a composer
    exception) the legacy template ends up supplying ``transform()``'s
    actual body content (P0-COMMERCIAL-QUALITY-2026-08-18 finding: before
    this change, an LLM-authored article -- the first-choice path --
    published with zero evidence-based certification at all, because this
    function was only ever called after the LLM path had already failed).
    """
    try:
        import sys
        from pathlib import Path

        engine_path = str(Path(__file__).resolve().parents[1] / "Sentinel-APEX" / "engine")
        if engine_path not in sys.path:
            sys.path.insert(0, engine_path)

        from sentinel_engine.reportx.human_review import CertificationState
        from sentinel_engine.reportx.pipeline_composer import compose_report

        result = compose_report(
            article, config, requested_tier=CertificationState.FLASH_READY, include_provenance=False,
        )
        tier = result.downgrade.achieved_tier
        logger.info(
            "ReportX commercial-readiness scorecard",
            extra={
                "overall_score": result.scorecard.overall_score,
                "publication_eligible": result.scorecard.publication_eligible,
                "coverage": round(result.scorecard.coverage, 3),
            },
        )
        evidence_graph = result.bundle.graph.to_dict()
        intelligence_gaps = tuple(g.to_dict() for g in result.bundle.intelligence_gaps)
        contradictions = tuple(c.to_dict() for c in result.contradictions)
        analytical_confidence = dict(result.analytical_confidence)
        canonical_entities = tuple(e.to_dict() for e in result.canonical_entities)
        hunt_hypotheses = tuple(h.to_dict() for h in result.hunt_hypotheses)
        attack_mappings = tuple(m.to_dict() for m in result.attack_mappings)
        role_decisions = tuple(d.to_dict() for d in result.role_decisions)
        reliability_html = result.reliability_html
        forecasts = tuple(f.to_dict() for f in result.forecasts)
        if contradictions:
            logger.warning(
                "ReportX composer found unresolved contradiction(s) -- publication will be blocked",
                extra={"contradictions": list(contradictions)},
            )
        if tier == CertificationState.PUBLIC_REFERENCE_DRAFT:
            logger.info(
                "ReportX composer evidence graph failed correctness controls -- publication will be blocked",
                extra={"failed_controls": list(result.downgrade.failed_controls)},
            )
            return _ComposerOutcome(
                html=None, achieved_tier=tier.value, failed_controls=result.downgrade.failed_controls,
                quality_score=result.scorecard.overall_score, quality_score_eligible=result.scorecard.publication_eligible,
                evidence_graph=evidence_graph, intelligence_gaps=intelligence_gaps, contradictions=contradictions,
                analytical_confidence=analytical_confidence, canonical_entities=canonical_entities,
                hunt_hypotheses=hunt_hypotheses, attack_mappings=attack_mappings, role_decisions=role_decisions,
                reliability_html=reliability_html, forecasts=forecasts,
            )
        return _ComposerOutcome(
            html=result.html, achieved_tier=tier.value,
            quality_score=result.scorecard.overall_score, quality_score_eligible=result.scorecard.publication_eligible,
            evidence_graph=evidence_graph, intelligence_gaps=intelligence_gaps, contradictions=contradictions,
            analytical_confidence=analytical_confidence, canonical_entities=canonical_entities,
            hunt_hypotheses=hunt_hypotheses, attack_mappings=attack_mappings, role_decisions=role_decisions,
            reliability_html=reliability_html, forecasts=forecasts,
        )
    except Exception as e:
        logger.warning("ReportX composer failed, using legacy template", extra={"error": str(e)[:200]})
        return _ComposerOutcome(html=None, achieved_tier="")


# ─────────────────────────────────────────────────────────────────────────────
# AUTHORITY TRANSFORMER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class AuthorityTransformer:
    """Transforms source articles into enterprise-grade Blogger-ready HTML."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.monetization = MonetizationInjector(config)
        self.linker = InternalLinker(config)
        self.seo = SEOOptimizer(config)

    def transform(self, article: DiscoveredArticle) -> dict:
        """Return full transformed post ready for Blogger publication."""
        logger.info("Transforming article", extra={"title": article.title[:80], "url": article.url})

        # Strip internal scoring artifacts before any content generation or SEO use
        article.summary = _sanitize_summary(article.summary)

        # RX-STABILIZATION-1 (RX-PR0): try LLM-authored content first, fall
        # back to the deterministic enterprise template on failure. Richness
        # is never achieved by skipping the evidence gate below, and honesty
        # is never achieved by skipping richness — both paths pass through
        # the same build_report_context()/validate_publication() gate.
        llm_attempts: list = []
        llm_result = call_llm(self.config, _build_analyst_prompt(article), attempts=llm_attempts)
        # Evidence-graph correctness is a property of the article's own
        # evidence, not of which renderer writes the prose -- run the
        # composer's certification check unconditionally, even when the LLM
        # path below succeeds and supplies the actual body content. Without
        # this, LLM-authored articles (the first-choice path) published with
        # zero evidence-based certification at all.
        composer_outcome = _composer_enhance(article, self.config)
        if llm_result:
            raw_llm_content, content_source = llm_result
            body_content = _sanitize_llm_html(raw_llm_content)
        elif composer_outcome.html is not None:
            body_content = composer_outcome.html
            content_source = "reportx_composer"
        else:
            body_content = _legacy_template_enhance(article, self.config)
            content_source = "template"

        context = build_report_context(article, achieved_tier=composer_outcome.achieved_tier)
        detection_status = _detection_package(article, context).status

        # RX-P1F: Key Judgements -- structured analytical synthesis
        # (key_judgements.py), not free-form prose. Only attempted when
        # this article's narrative is genuinely LLM-authored: analytical_
        # depth_gate.py's own PREMIUM_LONG_FORM gate already requires
        # llm_authored regardless of Key Judgements, so attempting this
        # second LLM call when the first one already failed would be a
        # wasted call against an already-capped article. Every judgement
        # is independently re-verified against the real evidence graph
        # before acceptance -- see key_judgements.validate_key_judgements().
        key_judgements: tuple = ()
        key_judgement_rejections: tuple = ()
        if content_source in LLM_AUTHORED_SOURCES and composer_outcome.evidence_graph:
            key_judgements, key_judgement_rejections = generate_key_judgements(
                article, self.config, composer_outcome.evidence_graph,
                composer_outcome.contradictions, composer_outcome.analytical_confidence, context,
            )
            if key_judgements:
                body_content = body_content + _render_key_judgements_html(key_judgements)

        # RX-P1I fix: composer_outcome.hunt_hypotheses is computed
        # unconditionally by _composer_enhance() above (real for cve_advisory
        # articles), but was only ever reaching the published page when
        # content_source == "reportx_composer" -- composer_outcome.html
        # already has hunt_html baked in for that path (pipeline_composer.
        # compose_report()'s own html = base.html + role_html +
        # reliability_html + hunt_html), so appending here again would
        # duplicate it. Every other path (LLM-authored, template fallback)
        # never included it at all despite hunt_hypothesis_count still being
        # passed to evaluate_product_tier() below -- Section 14 could show
        # COMPLETE while the actually-published page had no hunt content.
        if content_source != "reportx_composer" and composer_outcome.hunt_hypotheses:
            body_content = body_content + _render_hunt_hypotheses_html(composer_outcome.hunt_hypotheses)

        # RX-P1I (structured ATT&CK): identical duplication guard as the
        # hunt-hypotheses fix immediately above -- composer_outcome.html
        # already has attack_html baked in for the reportx_composer path
        # (pipeline_composer.compose_report()'s own html assembly), so
        # every other path renders it here instead.
        if content_source != "reportx_composer" and composer_outcome.attack_mappings:
            body_content = body_content + _render_attack_mappings_html(composer_outcome.attack_mappings)

        # RX-P1J fix: identical duplication guard as the two fixes
        # immediately above -- composer_outcome.html already has role_html
        # baked in for the reportx_composer path (pipeline_composer.
        # compose_report()'s own html assembly), so every other path
        # (LLM-authored, template fallback) renders it here instead. Before
        # this fix, role_decisions was computed and counted toward Section
        # 19 (see evaluate_product_tier() below) but never appended to
        # body_content on any of those paths at all.
        if content_source != "reportx_composer" and composer_outcome.role_decisions:
            body_content = body_content + _render_role_decisions_html(composer_outcome.role_decisions)

        # RX-P1K fix: identical duplication guard as the three fixes above --
        # composer_outcome.html already has reliability_html baked in for
        # the reportx_composer path (pipeline_composer.compose_report()'s
        # own html assembly), so every other path appends the pre-built
        # string here instead. Before this fix, Section 6 (Evidence &
        # Source Assessment) claimed unconditional COMPLETE for every
        # article regardless of content_source, while the actual two-axis
        # reliability/corroboration content only ever reached the published
        # page on the composer path -- 2 of 3 real content paths silently
        # omitted it.
        if content_source != "reportx_composer" and composer_outcome.reliability_html:
            body_content = body_content + composer_outcome.reliability_html

        # RX-P1K fix: identical duplication guard as the fixes above --
        # composer_outcome.html now has intelligence_gaps rendered in for
        # the reportx_composer path (see pipeline_composer.py's matching
        # RX-P1K change), so every other path appends it here instead.
        # Before this round, Section 21 (Intelligence Gaps) resolved
        # PARTIAL_EVIDENCE for every article on the strength of a real,
        # family-conditioned gap list that had never once been rendered
        # into a published page on ANY content path.
        if content_source != "reportx_composer" and composer_outcome.intelligence_gaps:
            body_content = body_content + _render_intelligence_gaps_html(composer_outcome.intelligence_gaps)

        # RX-P1K fix: identical duplication guard as the fixes above --
        # composer_outcome.html already has forecast_html baked in for the
        # reportx_composer path (pipeline_composer.compose_report()'s own
        # html assembly), so every other path renders it here instead.
        # Section 22 (Forecast/Outlook) was permanently WITHHELD for every
        # article before this round -- see pipeline_composer._cve_forecast().
        if content_source != "reportx_composer" and composer_outcome.forecasts:
            body_content = body_content + _render_forecast_html(composer_outcome.forecasts)

        # A WithheldForecast is a real, explained outcome, not a failure --
        # only an adequately-supported Forecast counts toward Section 22's
        # completeness, mirroring _render_forecast_html()'s own filter.
        forecast_count = sum(
            1 for f in composer_outcome.forecasts
            if not f.get("withheld") and f.get("supporting_observation_claim_ids") and f.get("confidence_rationale")
        )

        # RX-P1K-16: Section 16 (Indicators/Observables) -- see
        # _extract_article_iocs()'s own docstring for why this needs no
        # reportx_composer duplication guard (nothing else in this
        # pipeline renders IOCs today, unlike the composer-derived
        # sections above). Computed and appended unconditionally, once,
        # regardless of content_source.
        article_iocs = _extract_article_iocs(article)
        if article_iocs:
            body_content = body_content + _render_iocs_html(article_iocs)

        # RX-P1B-WIRE: analytical_depth_gate.py + report_contract.py (the
        # founder-mandate 24-section contract + FLASH/TACTICAL/PREMIUM_LONG_FORM
        # tier gate) were built and certified
        # (docs/audits/REPORTX-24-SECTION-LONG-FORM-RELEASE-CERTIFICATION.md)
        # but never actually invoked by the live pipeline -- a certified-but-
        # dormant module. This runs it unconditionally, the same discipline
        # already applied to the composer's own tier ladder above: a real
        # verdict for every article, not merely a capability that exists.
        product_tier_verdict = evaluate_product_tier(
            article, context, content_source, detection_status=detection_status,
            state_file=self.config.state_file, key_judgement_count=len(key_judgements),
            hunt_hypothesis_count=len(composer_outcome.hunt_hypotheses),
            attack_mapping_count=len(composer_outcome.attack_mappings),
            role_decision_count=len(composer_outcome.role_decisions),
            forecast_count=forecast_count, ioc_count=len(article_iocs),
        )

        # Dynamic per-article social card (ESPMP v1). Computed independently
        # from _assemble_html()'s own cves/cvss extraction (same pattern
        # already used elsewhere in this file — see seo_data below, which
        # also re-derives cves/cvss on the same text) because this value
        # needs to reach main.py's publish_post() call directly, not just
        # the embedded HTML body. Computed before seo_data (moved ahead of
        # it) so the same URL can be threaded into the JSON-LD Article.image
        # too — otherwise the page's structured data claims a different
        # image than the one actually shown, which is exactly the kind of
        # conflicting same-entity metadata a crawler should never see.
        _cves_for_image = _extract_cve_ids(article.title + " " + article.summary)
        _cvss_for_image = _extract_cvss(article.title + " " + article.summary)
        _severity_for_image, _ = _derive_severity(article, _cvss_for_image)
        image_url = _build_dynamic_og_image_url(
            self.config, title=article.title, severity=_severity_for_image,
            cve_id=_cves_for_image[0] if _cves_for_image else "", cvss=_cvss_for_image,
            type_label=primary_category(article.labels) or "THREAT INTEL",
            report_id=context.report_id, published_at=article.published_at,
            ransomware_group=article.ransomware_group, ransomware_sector=article.ransomware_sector,
            kev_listed=article.kev_listed,
            epss_pct=(article.epss_score * 100 if article.epss_score is not None else None),
        )

        # Generate SEO metadata
        seo_data = self.seo.generate(
            title=article.title,
            summary=article.summary,
            url=article.url,
            labels=article.labels,
            published_at=article.published_at,
            image_url=image_url,
        )

        # Social-preview certification -- OBSERVE stage (see
        # social_preview_certifier.py's module docstring for the full staged
        # rollout: observe -> warn -> shadow -> blocking). Logged and carried
        # in this method's return value for the run report; never blocks
        # publication at this stage. canonical_url/expected_domain are
        # omitted deliberately -- Blogger doesn't assign a post's real URL
        # until after publish_post() returns, so there is nothing genuine to
        # certify that against yet (a live fetch-back check belongs in
        # social_preview_certifier.certify_live_html(), run post-publish).
        preview_certification = certify_metadata(
            image_url=image_url, title=seo_data["meta_title"], description=seo_data["meta_description"],
        ).to_dict()
        if preview_certification["verdict"] != "CERTIFIED":
            logger.warning(
                "Social preview certification BLOCKED (observe mode — publication proceeds)",
                extra={"title": article.title[:60], "reasons": preview_certification["reasons"]},
            )

        # Build full HTML
        html = self._assemble_html(
            article,
            body_content,
            seo_data,
            context,
            image_url=image_url,
            detection_status=detection_status,
            product_tier=product_tier_verdict.tier,
            content_source=content_source,
        )

        # RX-P1M fix: composer_outcome.contradictions was computed inside
        # pipeline_composer.compose_report() against ITS OWN internally-
        # built html -- on the reportx_composer path that's a close
        # approximation of the final page, but on the LLM-authored or
        # legacy-template paths body_content becomes different prose
        # entirely, and _assemble_html() adds further wrapping (SEO data,
        # monetization CTAs) on every path. The text-pattern contradiction
        # layer (unlike the dimension layer, which reads the evidence
        # graph directly and is unaffected by which prose won) has
        # therefore never once been evaluated against the actual,
        # published page. Re-run it here, against the real final html,
        # every time -- the dimension-level findings from composer_outcome
        # still apply unchanged (the graph itself doesn't depend on
        # content_source).
        from sentinel_engine.reportx.contradiction_engine import find_text_contradictions
        final_text_contradictions = tuple(c.to_dict() for c in find_text_contradictions(html))
        all_contradictions = tuple(composer_outcome.contradictions) + final_text_contradictions

        validate_publication(
            article, context, html, product_tier=product_tier_verdict.tier,
            contradictions=all_contradictions, body_content=body_content,
        )
        # RX-P1-ARTIFACT-BINDING (mandate Section 17/34): computed on the
        # EXACT `html` that just passed every fail-closed gate above, not
        # re-derived later -- the publisher (main.py) recomputes this same
        # hash over the exact bytes it is about to send Blogger and blocks
        # if they differ, closing "premium report certified -> legacy
        # renderer replaces content -> short article published" outright,
        # not just in the cases this session could enumerate in advance.
        certified_artifact_hash = compute_artifact_hash(html)

        blogger_labels = article.labels[:20]

        logger.info(
            "Transformation complete",
            extra={
                "title": article.title[:60],
                "content_source": content_source,
                "labels": blogger_labels,
                "product_tier": product_tier_verdict.tier,
                "claim_count": len(composer_outcome.evidence_graph["claims"]) if composer_outcome.evidence_graph else 0,
            },
        )

        return {
            "title": self._build_blogger_title(article),
            "content": html,
            "labels": blogger_labels,
            "image_url": image_url,
            "preview_certification": preview_certification,
            # meta_title/meta_description/keywords below have no Blogger API
            # home: verified against the real Posts v3 schema (the
            # blogger.googleapis.com discovery document) that no
            # searchDescription/metaTitle/keywords field exists on that
            # resource, so unlike image_url above these cannot reach Blogger
            # through publish_post(). Left computed (not removed) for a
            # future non-Blogger publishing target — do not "fix" this by
            # inventing a Blogger field that doesn't exist.
            "meta_title": seo_data["meta_title"],
            "meta_description": seo_data["meta_description"],
            "keywords": seo_data["keywords"],
            "source_url": article.url,
            "content_hash": article.content_hash,
            "content_source": content_source,
            "llm_attempts": llm_attempts,
            "report_id": context.report_id,
            "source_record_hash": context.source_record_hash,
            "report_family": context.family,
            "review_status": context.review_status,
            "certification_status": context.certification_status,
            "achieved_tier": context.achieved_tier,
            "quality_score": composer_outcome.quality_score,
            "quality_score_eligible": composer_outcome.quality_score_eligible,
            # RX-P1B-WIRE: the founder-mandate 24-section-contract tier
            # verdict (FLASH/TACTICAL/PREMIUM_LONG_FORM) -- a distinct
            # signal from achieved_tier above, see validate_publication()'s
            # docstring in report_integrity.py for why these are kept separate.
            "product_tier": product_tier_verdict.tier,
            "product_tier_reason": product_tier_verdict.reason,
            "product_tier_mandatory_withheld": list(product_tier_verdict.mandatory_withheld),
            # RX-P1C-WIRE: the real claim/evidence/source graph -- see
            # _ComposerOutcome.evidence_graph's docstring above. None only
            # on the rare composer-exception path.
            "evidence_graph": composer_outcome.evidence_graph,
            # RX-P1E-WIRE: see _ComposerOutcome.intelligence_gaps' docstring above.
            "intelligence_gaps": list(composer_outcome.intelligence_gaps),
            # RX-P1D-WIRE: see _ComposerOutcome.contradictions' docstring above.
            # RX-P1M: includes the text-pattern contradictions found by
            # re-scanning the actual final page above, not only the ones
            # composer_outcome carried in from compose_report()'s own html.
            "contradictions": list(all_contradictions),
            # RX-P1E-WIRE: see _ComposerOutcome.analytical_confidence's docstring above.
            "analytical_confidence": composer_outcome.analytical_confidence,
            # RX-P1G-WIRE: see _ComposerOutcome.canonical_entities' docstring above.
            "canonical_entities": list(composer_outcome.canonical_entities),
            # RX-P1I-WIRE: see _ComposerOutcome.hunt_hypotheses' docstring above.
            "hunt_hypotheses": list(composer_outcome.hunt_hypotheses),
            # RX-P1I-WIRE (structured ATT&CK): see _ComposerOutcome.attack_mappings' docstring above.
            "attack_mappings": list(composer_outcome.attack_mappings),
            # RX-P1J-WIRE: see _ComposerOutcome.role_decisions' docstring above.
            "role_decisions": list(composer_outcome.role_decisions),
            # RX-P1K-WIRE: see _ComposerOutcome.forecasts' docstring above.
            "forecasts": list(composer_outcome.forecasts),
            # RX-P1K-16: see _extract_article_iocs()' own docstring above.
            "iocs": article_iocs,
            "detection_status": detection_status,
            "generated_at": context.generated_at,
            # RX-P1-ARTIFACT-BINDING: see the comment at this hash's
            # computation site above. main.py's publish step must recompute
            # this same hash over the exact bytes sent to Blogger and block
            # on any mismatch -- see main.py::run_pipeline().
            "certified_artifact_hash": certified_artifact_hash,
            # RX-P1F: validated Key Judgements (never raw LLM output --
            # every entry already passed key_judgements.validate_key_judgements()).
            "key_judgements": [kj.to_dict() for kj in key_judgements],
            "key_judgement_rejections": list(key_judgement_rejections),
        }

    def _build_blogger_title(self, article: DiscoveredArticle) -> str:
        """Optimise title for Blogger/SEO — max 85 chars."""
        title = article.title.strip()
        cves = _extract_cve_ids(title)
        if cves and cves[0].upper() not in title.upper():
            title = f"{cves[0]} — {title}"
        if len(title) > 85:
            title = title[:82].rsplit(" ", 1)[0] + "..."
        return title

    def _assemble_html(
        self, article: DiscoveredArticle, body_content: str, seo_data: dict, context: ReportContext,
        image_url: Optional[str] = None,
        *,
        detection_status: str = "",
        product_tier: str = "",
        content_source: str = "",
    ) -> str:
        """Assemble the complete Blogger-compatible HTML article."""
        safe_source_url = _html_escape.escape(article.url, quote=True)
        json_ld = seo_data.get("json_ld", {})
        json_ld_str = (
            json.dumps(json_ld, indent=2, ensure_ascii=False)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            if json_ld else ""
        )

        # Legacy FAQ/HowTo generators inferred exploitation, patch presence,
        # ATT&CK mappings, and response steps from keywords. Those schemas are
        # disabled until they consume the same structured ReportContext as the
        # visible report. Main Article JSON-LD remains source-backed.
        faq_str = ""
        howto_str = ""
        glossary_str = ""

        cves = _extract_cve_ids(article.title + " " + article.summary)
        cvss = _extract_cvss(article.title + " " + article.summary)
        category = primary_category(article.labels)
        pub_date = datetime.now(timezone.utc).strftime("%B %d, %Y")

        # Lead image — FIRST element so Blogger uses it as firstImageUrl.
        # Pass image_url through so this becomes a real fetchable HTTPS URL
        # (see _generate_svg_thumbnail's docstring) instead of a data URI.
        svg_thumbnail = _generate_svg_thumbnail(article.title, article.labels, cvss, image_url=image_url)

        # Customer-facing presentation layer. This is intentionally applied
        # after all analytical content has been produced and before the final
        # fail-closed publication validation. It changes presentation only:
        # report text, evidence objects, ReportX/Dossier state, and quality
        # thresholds remain untouched.
        visual_style = premium_report_style_block()
        accent, accent_soft = family_accent(context)
        report_hero = build_report_hero(
            article,
            context,
            detection_status=detection_status,
            product_tier=product_tier,
            content_source=content_source,
        )
        premium_body = wrap_premium_report(
            body_content,
            accent=accent,
            accent_soft=accent_soft,
        )

        # Executive Risk Command Center — real CVSS/EPSS/KEV data only,
        # rendered once here so both the LLM and template content paths
        # get an identical, un-duplicated dashboard above the article body.
        risk_command_center = _build_risk_command_center(article, cves, cvss)

        # Publication-volume counters and inferred detection counts are not
        # report evidence. Keep them out of automated customer-facing output.
        trust_stats_block = ""

        # Recommended Services — data-driven, see product_recommendations.py
        recommended_services_block = _build_recommended_services_block(article.labels, self.config)

        # Industry profiles are generic reference material and can overstate a
        # source record's actual sector impact. The evidence-first renderer
        # includes sector content only where the source itself supplies it.
        industry_block = ""

        # The family-specific report body already contains decision guidance.
        # Do not append a second generic decision center that may recommend a
        # Sigma deployment or vulnerability response for non-technical news.
        exec_decision_center = ""

        # Metadata bar
        meta_items = [
            f"📅 {_html_escape.escape(str(pub_date))}",
            f"📂 {_html_escape.escape(str(category))}",
            "🛡 CYBERDUDEBIVASH®",
        ]
        if cves:
            meta_items.insert(0, f"🔍 {', '.join(cves[:2])}")
        if cvss:
            meta_items.insert(1 if cves else 0, f"⚠ CVSS {cvss}")
        meta_bar = " &nbsp;|&nbsp; ".join(meta_items)

        # Keep the report focused: generic platform-link blocks duplicate the
        # header CTA and dilute source provenance.
        related_block = ""
        correlation_block = self.linker.build_correlation_block(
            article.labels, cves, exclude_hash=article.content_hash,
            article_ransomware_group=article.ransomware_group or "",
            article_ransomware_sector=article.ransomware_sector or "",
            article_ransomware_country=article.ransomware_country or "",
        )
        mitre_navigator_download = ""
        ext_refs = ""
        hashtags = self.linker.build_hashtag_block(article.labels)

        # Secondary closing CTA — mutually exclusive by design, not stacked
        # with the urgency CTA above or with each other. inject_mssp_cta
        # (highest-ticket, enterprise lead gen) only fires for the same
        # highest-urgency categories the urgency CTA already targets
        # (KEV-listed or ransomware); showing it immediately alongside that
        # CTA would be two "book a call" asks back to back, so it runs down
        # here instead, after the reader has seen the full technical
        # content. inject_api_cta (self-serve, lower-friction) only fires
        # when a real CVE is present — its own content ("live CVE data, KEV
        # alerts") has nothing to offer an article with no CVE. Checks both
        # `cves` (regex-extracted from title+summary) and article.cve_id
        # (structured, populated independently by source enrichment --
        # e.g. nvd_source.py/cisa_kev_source.py's own API response) since
        # an editorial/LLM-rewritten title+summary can omit the literal
        # "CVE-YYYY-NNNNN" string even when the structured field carries a
        # real one. Never both CTAs: two competing conversion asks in the
        # same slot is worse than one well-chosen ask, and KEV/ransomware
        # already wins the higher-value MSSP ask over the API one when
        # both conditions are true.
        label_set = {str(label).lower() for label in (article.labels or [])}
        if article.kev_listed is True or "ransomware" in label_set:
            closing_cta = self.monetization.inject_mssp_cta()
        elif article.cve_id or cves:
            closing_cta = self.monetization.inject_api_cta()
        else:
            closing_cta = ""

        schema_blocks = ""
        if json_ld_str:
            schema_blocks += f'<script type="application/ld+json">\n{json_ld_str}\n</script>\n'
        if faq_str:
            schema_blocks += f'<script type="application/ld+json">\n{faq_str}\n</script>\n'
        if howto_str:
            schema_blocks += f'<script type="application/ld+json">\n{howto_str}\n</script>\n'
        if glossary_str:
            schema_blocks += f'<script type="application/ld+json">\n{glossary_str}\n</script>\n'

        html = f"""{self.monetization.get_style_block()}
{visual_style}
{schema_blocks}
<!-- CYBERDUDEBIVASH® SENTINEL APEX — Enterprise Threat Intelligence Report -->
<!-- Generated: {datetime.now(timezone.utc).isoformat()} -->

{svg_thumbnail}

{report_hero}

{risk_command_center}

{self.monetization.inject_header_cta()}

{self.monetization.inject_urgency_cta(article.labels, kev_listed=article.kev_listed)}

<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e2e8f0;margin:20px 0;padding:14px 18px;background:#050d1a;border-radius:6px;font-size:12px;color:#64748b">
  {meta_bar}
</div>

<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#e2e8f0;line-height:1.8;font-size:15px">

{premium_body}

</div>

{trust_stats_block}

{recommended_services_block}

{industry_block}

{exec_decision_center}

{related_block}

{correlation_block}

{mitre_navigator_download}

{ext_refs}

{closing_cta}

{self.monetization.inject_newsletter_cta()}

{self.monetization.inject_read_more_cta(article.url)}

{hashtags}

{self.monetization.inject_about_block()}

<div style="margin-top:20px;padding:12px 16px;background:#050d1a;border-top:1px solid #1e3a5f22;font-size:11px;color:#334155;font-family:monospace">
  Intelligence source: <a href="{safe_source_url}" target="_blank" rel="noopener noreferrer" style="color:#64748b">{safe_source_url}</a> · CYBERDUDEBIVASH® SENTINEL APEX Evidence Engine v3.0
</div>

{_provenance(article, context)}
"""
        return html
