"""CTI dossier v13 — typography/accessibility polish for existing evidence.

Presentation only, scoped to cdb-cti-dossier. Never edits semantic report
content, citations, timestamps, scores, TLP, detections or checkout links.
"""
from __future__ import annotations

from typing import Any, Optional
from bs4 import BeautifulSoup

MARKER = "CDB-CTI-READABILITY-V13"
_INSTALL_ATTR = "__cdb_cti_readability_v13__"
_ORIGINAL = None

_CSS = r"""<style id="cdb-cti-readability-v13-css">
.cdb-cti-dossier{--read-body:#e5f1fc;--read-muted:#bfd3e4;--read-link:#9de7ff;overflow-wrap:break-word;text-rendering:optimizeLegibility}
.cdb-cti-dossier :is(a,button,input,summary):focus-visible{outline:3px solid #ffda80!important;outline-offset:3px!important}
.cdb-cti-dossier .cdbd-body{max-width:86ch;margin:0 auto;min-width:0}
.cdb-cti-dossier .cdbd-body :is(p,li){font-size:clamp(15px,1.08vw,17px)!important;line-height:1.82!important;color:var(--read-body)!important;letter-spacing:normal}
.cdb-cti-dossier .cdbd-section-title{font-size:clamp(20px,2.1vw,27px)!important;line-height:1.35!important;margin-top:38px!important;margin-bottom:17px!important;scroll-margin-top:108px!important;letter-spacing:-.015em!important}
.cdb-cti-dossier .cdbd-nav{padding:12px!important}
.cdb-cti-dossier .cdbd-nav>a,.cdb-cti-dossier .cdbd-nav a{font-size:12px!important;line-height:1.4!important;display:inline-flex;align-items:center;min-height:44px!important;padding:8px 12px!important}
.cdb-cti-dossier .cdbd-nav>b{font-size:11px!important;line-height:1.5!important}
.cdb-cti-dossier .cdbd-kpi span{font-size:10.5px!important;line-height:1.4!important;letter-spacing:.06em!important;color:#bed4e8!important}
.cdb-cti-dossier .cdbd-kpi strong{font-size:13px!important;line-height:1.45!important}
.cdb-cti-dossier .cdbv12-grid small{font-size:11px!important;line-height:1.5!important;color:#b6d0e4!important}
.cdb-cti-dossier .cdbv12-grid strong{font-size:13px!important;line-height:1.55!important}
.cdb-cti-dossier .cdbv12-nav a{font-size:12px!important;min-height:44px!important;display:inline-flex;align-items:center;line-height:1.5!important}
.cdb-cti-dossier .cdbv12-brief h3{font-size:19px!important}
.cdb-cti-dossier .cdbv12-brief p{font-size:14px!important;line-height:1.75!important}
.cdb-cti-dossier .cdbv12-boundary{font-size:12px!important;line-height:1.75!important}
.cdb-cti-dossier .cdbv11-intel-actions{font-size:15px!important;line-height:1.75!important}
.cdb-cti-dossier .cdbv11-intel-actions li{font-size:14px!important;line-height:1.7!important}
.cdb-cti-dossier .cdbv11-intel-actions nav a{min-height:44px!important;font-size:13px!important}
.cdb-cti-dossier :is(.cdbv9-state span,.cdbv9-decision span,.cdbv9-head,.cdbv9-framework-label){font-size:10.5px!important;line-height:1.5!important}
.cdb-cti-dossier :is(.cdbv9-state strong,.cdbv9-decision strong){font-size:12px!important;line-height:1.6!important}
.cdb-cti-dossier th{font-size:11px!important;line-height:1.5!important;letter-spacing:.04em!important;overflow-wrap:anywhere}
.cdb-cti-dossier td{font-size:14px!important;line-height:1.7!important;overflow-wrap:anywhere}
.cdb-cti-dossier :is(pre,code){font-size:13px!important;line-height:1.6!important;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}
.cdb-cti-dossier pre{max-width:100%!important;overflow:auto!important;tab-size:2}
.cdb-cti-dossier a{color:var(--read-link)!important;text-underline-offset:3px!important}
.cdb-cti-dossier .cdbv12-cover{max-width:100%!important}
@media(max-width:760px){.cdb-cti-dossier{padding-inline:clamp(12px,3vw,19px)!important}.cdb-cti-dossier .cdbd-nav{top:0!important}.cdb-cti-dossier .cdbd-nav>div{overscroll-behavior-x:contain}.cdb-cti-dossier :is(.cdbv12-nav,.cdbv11-intel-actions nav){gap:8px!important}.cdb-cti-dossier .cdb-cti-dossier table{display:block!important;overflow-x:auto!important}}
@media(prefers-reduced-motion:reduce){.cdb-cti-dossier *{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
@media print{.cdb-cti-dossier{background:#fff!important;color:#111!important;box-shadow:none!important}.cdb-cti-dossier :is(p,li,td,th){color:#111!important}.cdb-cti-dossier :is(.cdbd-command,.cdbv12-cover,.cdbv11-intel-actions){box-shadow:none!important;break-inside:avoid}.cdb-cti-dossier :is(.cdbd-nav,.cdbv12-nav){display:none!important}}
</style>"""


def enhance_cti_readability_v13(rendered_html: str) -> str:
    if not rendered_html or MARKER in rendered_html:
        return rendered_html
    soup = BeautifulSoup(rendered_html, "html.parser")
    if soup.select_one("#cdb-cti-readability-v13-css"):
        return rendered_html
    root = soup.select_one(".cdb-cti-dossier")
    if root is None:
        return rendered_html
    root.insert_before(BeautifulSoup(_CSS, "html.parser"))
    return f"<!-- {MARKER} -->{soup}<!-- /{MARKER} -->"


def _patched_assemble(self: Any, article: Any, body_content: str, seo_data: dict,
                      context: Any, image_url: Optional[str] = None) -> str:
    if _ORIGINAL is None:
        raise RuntimeError("CTI readability v13 was not installed")
    existing = _ORIGINAL(self, article, body_content, seo_data, context, image_url)
    try:
        return enhance_cti_readability_v13(existing)
    except Exception:
        return existing  # Rendering polish cannot relax prior evidence gates.


setattr(_patched_assemble, _INSTALL_ATTR, True)


def install_cti_readability_v13(main_module: Any) -> None:
    global _ORIGINAL
    transformer = getattr(main_module, "AuthorityTransformer", None)
    if transformer is None:
        from .authority_transformer import AuthorityTransformer as transformer
    current = transformer._assemble_html
    if getattr(current, _INSTALL_ATTR, False):
        return
    _ORIGINAL = current
    transformer._assemble_html = _patched_assemble
