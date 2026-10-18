"""Evidence-bounded CTI Dossier v11: SOC first-response and ecosystem discovery.

Additive presentation after v10, before commercial and final integrity guards.
No change to event facts, source provenance, severity, confidence or checkout.
"""
from __future__ import annotations

import html
import re
from typing import Any, Optional
from urllib.parse import urlencode
from bs4 import BeautifulSoup

MARKER = "CDB-CTI-DOSSIER-V11"
_INSTALL_ATTR = "__cdb_cti_dossier_v11__"
_INNER_ASSEMBLE = None

_ECOSYSTEM = {
    "intelligence": ("Threat Intelligence Platform", "https://intel.cyberdudebivash.com/"),
    "ai": ("AI Security Hub", "https://www.cyberdudebivash.in/"),
    "academy": ("Enterprise Academy", "https://academy.cyberdudebivash.com/"),
    "labs": ("Security Labs", "https://labs.cyberdudebivash.in/"),
    "tools": ("Security Tools", "https://tools.cyberdudebivash.com/"),
    "trust": ("TRUSTX Identity Security (Private Preview)", "https://trustx.cyberdudebivash.com/"),
    "corporate": ("Enterprise Services", "https://www.cyberdudebivash.com/"),
}
# Validation instructions, not assertions that these activities occurred.
_GUIDES = {
    "m365_identity": (
        "Microsoft 365 identity and SaaS compromise validation",
        "Confirm the named application, integration or delegated identity exists in the tenant; identify its owners and privileges.",
        "Review Microsoft Entra sign-in and audit records and Microsoft 365 unified audit events for relevant identities, consent grants, access changes and abnormal activity in the source-supported window.",
        "Preserve original logs and timestamps; scope anomalous sessions and revoke or rotate credentials only under the organization’s incident-response procedure after evidence review.",
    ),
    "identity": (
        "Identity and SaaS compromise validation",
        "Confirm the named integration, service account or delegated identity exists in the relevant environment; document its effective permissions and owner.",
        "Review the affected identity provider's sign-in and audit logs and related SaaS activity for source-supported indicators; do not assume a particular cloud or identity platform.",
        "Preserve original logs and timestamps; review suspicious sessions and follow approved incident-response procedures for access restrictions or credential rotation.",
    ),
    "cve": (
        "Vulnerability exposure and remediation validation",
        "Match the named vendor, component, exact affected version and reachable surface against authoritative inventory and the cited vendor advisory.",
        "Check CISA KEV, vendor remediation and available relevant telemetry; do not equate a public CVE record with confirmed exploitation.",
        "Prioritize a change-controlled fix or vendor-supported mitigation where applicability is confirmed; validate the deployed version afterward.",
    ),
    "ransomware_claim": (
        "Third-party ransomware claim triage",
        "Identify any direct supplier, subsidiary or customer relationship with the named organization before treating the claim as operationally relevant.",
        "Seek independently attributable disclosures or corroboration; a leak-site listing alone does not confirm intrusion, encryption or stolen data.",
        "If internally relevant, preserve scoped identity, endpoint, backup and data-access logs and escalate only on supported incident evidence.",
    ),
    "ai": (
        "AI system trust-boundary validation",
        "Inventory affected models, agents, extensions or dependencies in approved and shadow deployments; record exact versions and permissions.",
        "Review externally supplied prompts/data, tool access, delegated secrets and audit traces only for the behavior actually described in the cited evidence.",
        "Test mitigations in a controlled environment and require verifiable telemetry before enabling any production detection or automatic containment.",
    ),
    "editorial": (
        "Editorial intelligence collection triage",
        "Treat this newsletter or roundup as a discovery index, not as proof of a single attack or enterprise exposure.",
        "Open each relevant underlying primary article and validate the original source, dates, affected technology and any observable evidence independently.",
        "Create separate incident- or vulnerability-specific work items only when an individual claim has a defensible evidence basis.",
    ),
    "general": (
        "General threat-intelligence validation",
        "Confirm the event, technology and sector in the cited primary record and determine whether they intersect organizational inventory.",
        "Collect relevant identity, endpoint, application, network or cloud telemetry guided by supported facts; document evidence gaps explicitly.",
        "Escalate to remediation or incident response only after confirming the actual exposure or observed malicious activity.",
    ),
}

def _guide_key(article: Any, context: Any) -> str:
    family = str(getattr(context, "family", "") or "").strip().lower()
    title = str(getattr(article, "title", "") or "")
    if re.search(r"\b(?:newsletter|round[ -]?up|weekly digest|daily digest|top stories)\b", title, re.I):
        return "editorial"
    if family in {"cve_advisory", "cisa_kev", "cisa_advisory"}:
        return "cve"
    if family in {"ransomware_claim", "ransomware_reporting"}:
        return "ransomware_claim"
    if family == "ai_security":
        return "ai"
    if re.search(r"\b(?:microsoft 365|m365|entra)\b", title, re.I):
        return "m365_identity"
    if re.search(r"\b(?:oauth|connectwise|credential|identity|service principal)\b", title, re.I):
        return "identity"
    return "general"

def _recommended_links(key: str) -> tuple[str, str, str]:
    return {
        "ai": ("ai", "labs", "academy"),
        "cve": ("intelligence", "tools", "corporate"),
        "ransomware_claim": ("intelligence", "corporate", "trust"),
        "m365_identity": ("intelligence", "trust", "corporate"),
        "identity": ("intelligence", "trust", "corporate"),
        "editorial": ("intelligence", "academy", "ai"),
    }.get(key, ("intelligence", "ai", "corporate"))

def _link(slug: str, family: str, role: str) -> str:
    label, base_url = _ECOSYSTEM[slug]
    query = urlencode({
        "utm_source": "sentinel_apex_cti",
        "utm_medium": "intelligence_report",
        "utm_campaign": "contextual_ecosystem_v11",
        "utm_content": f"{family}_{role}_{slug}",
    })
    return (f'<a href="{html.escape(base_url + "?" + query, quote=True)}" '
            f'target="_blank" rel="noopener noreferrer" data-cdb-v11-destination="{slug}">'
            f'{html.escape(label)} →</a>')

def build_panel(article: Any, context: Any) -> str:
    key = _guide_key(article, context)
    family = str(getattr(context, "family", "general_intelligence") or "general_intelligence")
    heading, *steps = _GUIDES[key]
    items = "".join(f"<li>{html.escape(step)}</li>" for step in steps)
    primary = _recommended_links(key)
    links = "".join(_link(slug, family, "recommended") for slug in primary)
    other = "".join(_link(slug, family, "directory") for slug in _ECOSYSTEM if slug not in primary)
    return f'''<section class="cdbv11-intel-actions" data-cdb-dossier-v11="true" data-cdb-guide="{key}" aria-label="SOC validation and related security services">
  <div class="cdbv11-title"><span>SENTINEL APEX™ | SOC FIRST-RESPONSE WORKFLOW</span><strong>{html.escape(heading)}</strong></div>
  <p class="cdbv11-disclaimer">Analyst validation checklist — recommended actions, not observed attack evidence. Source facts and customer telemetry must be evaluated separately.</p>
  <ol>{items}</ol>
  <div class="cdbv11-related"><strong>Extend your investigation with the CYBERDUDEBIVASH® ecosystem</strong><p>Explore relevant platforms, labs, training and enterprise services. Product access does not change the confidence of this intelligence.</p><nav aria-label="Relevant CYBERDUDEBIVASH platforms">{links}</nav></div>
  <details class="cdbv11-more"><summary>Explore more official platforms and portals</summary><nav aria-label="Other CYBERDUDEBIVASH platforms">{other}</nav></details>
</section>'''

_STYLES = r'''<style id="cdb-dossier-v11-css">
.cdbv11-intel-actions{margin:20px 0;padding:clamp(14px,2vw,24px);border:1px solid rgba(56,189,248,.25);border-radius:14px;background:linear-gradient(140deg,#091928,#07111c);color:#dbeafe;font:normal 14px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}
.cdbv11-title{display:flex;flex-direction:column;gap:6px}.cdbv11-title span{color:#7dd3fc;font-size:11px;font-weight:800;letter-spacing:.08em}.cdbv11-title strong{color:#f8fafc;font-size:clamp(17px,2.2vw,21px);line-height:1.3}.cdbv11-disclaimer{color:#bfdbfe!important;font-size:12px!important;margin:12px 0!important}.cdbv11-intel-actions ol{margin:12px 0 20px!important;padding-left:24px!important}.cdbv11-intel-actions li{margin:0 0 10px!important;color:#e2e8f0!important}.cdbv11-related{border-top:1px solid rgba(125,211,252,.2);padding-top:16px}.cdbv11-related strong{color:#f8fafc}.cdbv11-related p{color:#b6c8dd!important;font-size:12px!important;margin:6px 0 10px!important}.cdbv11-intel-actions nav{display:flex;flex-wrap:wrap;gap:9px}.cdbv11-intel-actions nav a{display:inline-flex;align-items:center;min-height:36px;padding:7px 12px;border:1px solid rgba(56,189,248,.3);border-radius:8px;color:#7dd3fc!important;font-size:12px;font-weight:700;text-decoration:none!important;overflow-wrap:anywhere}.cdbv11-intel-actions nav a:hover,.cdbv11-intel-actions nav a:focus-visible{background:rgba(56,189,248,.12);outline-offset:2px}.cdbv11-more{margin-top:12px}.cdbv11-more summary{cursor:pointer;color:#a5b4fc;font-size:12px;padding:7px 0}.cdbv11-more nav{padding:10px 0}@media print{.cdbv11-intel-actions{background:#fff!important;color:#111!important;break-inside:avoid}.cdbv11-title strong,.cdbv11-intel-actions li,.cdbv11-related strong{color:#111!important}}
</style>'''

def enhance_dossier(rendered_html: str, article: Any, context: Any) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    soup = BeautifulSoup(rendered_html, "html.parser")
    if soup.select_one('[data-cdb-dossier-v11="true"]'):
        return rendered_html
    anchor = soup.select_one(".cdbv10-capabilities") or soup.select_one(".cdbv9-framework") or soup.select_one(".cdbd-command")
    if anchor is None:
        return rendered_html
    panel = BeautifulSoup(build_panel(article, context), "html.parser")
    for node in reversed(list(panel.contents)):
        anchor.insert_after(node)
    if not soup.select_one("#cdb-dossier-v11-css"):
        soup.insert(0, BeautifulSoup(_STYLES, "html.parser"))
    return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"

def _wrapped_assemble(self: Any, article: Any, body_content: str, seo_data: dict, context: Any, image_url: Optional[str] = None) -> str:
    if _INNER_ASSEMBLE is None:
        raise RuntimeError("CTI v11 presentation not installed")
    rendered = _INNER_ASSEMBLE(self, article, body_content, seo_data, context, image_url)
    try:
        return enhance_dossier(rendered, article, context)
    except Exception:
        return rendered  # Do not alter prior v8 fail-closed integrity controls.

setattr(_wrapped_assemble, _INSTALL_ATTR, True)

def install_cti_dossier_v11(main_module: Any) -> None:
    global _INNER_ASSEMBLE
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return
    _INNER_ASSEMBLE = current
    transformer._assemble_html = _wrapped_assemble
