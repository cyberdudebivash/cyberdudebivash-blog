"""Proof that v13 only changes enterprise dossier presentation."""
from bs4 import BeautifulSoup

from automation.cti_readability_v13 import (
    MARKER, enhance_cti_readability_v13,
)

BODY = (
    '<article class="cdb-cti-dossier">'
    '<div class="cdbd-command">Original severity: MEDIUM</div>'
    '<div class="cdbd-body"><h2 id="technical-analysis">Technical Analysis</h2>'
    '<p>Primary claim from cited source only.</p><table>'
    '<tr><th>Claim</th><td>Source not independently verified</td></tr></table>'
    '<a href="https://vendor.example/advisory">Vendor record</a></div>'
    '</article>'
)


def test_css_is_inserted_once_and_source_record_is_preserved():
    out = enhance_cti_readability_v13(BODY)
    soup = BeautifulSoup(out, "html.parser")
    assert MARKER in out
    assert len(soup.select("#cdb-cti-readability-v13-css")) == 1
    assert len(soup.select(".cdb-cti-dossier")) == 1
    assert "Primary claim from cited source only." in out
    assert 'href="https://vendor.example/advisory"' in out
    assert enhance_cti_readability_v13(out) == out
    source = BeautifulSoup(BODY, "html.parser")
    assert soup.select_one(".cdb-cti-dossier").get_text(" ", strip=True) == source.get_text(" ", strip=True)


def test_unknown_html_layout_unchanged_and_fail_open():
    unknown = '<main><h2>Unrecognized</h2><p>Keep content</p></main>'
    assert enhance_cti_readability_v13(unknown) == unknown
    assert enhance_cti_readability_v13("") == ""


def test_included_css_is_responsive_accessible_and_print_friendly():
    text = enhance_cti_readability_v13(BODY)
    assert "prefers-reduced-motion" in text
    assert ":focus-visible" in text
    assert "min-height:44px" in text
    assert "@media print" in text
    assert "max-width:86ch" in text
    assert "@import" not in text



def test_print_export_contrast_contract_preserves_source_content():
    """Print/PDF exports must never put dark text on the original dark cards."""
    output = enhance_cti_readability_v13(BODY)
    soup = BeautifulSoup(output, "html.parser")
    style = soup.select_one("#cdb-cti-readability-v13-css")
    assert style is not None
    css = style.get_text()
    print_css = css.split("@media print{", 1)[1]
    assert ".cdb-cti-dossier :is(.cdbd-command,.cdbd-kpi,.cdbd-matrix,.cdbv12-cover" in print_css
    assert ".cdbv12-grid>div" in print_css
    assert "background:#fff!important" in print_css
    assert "color:#182635!important" in print_css
    assert "color:#064a70!important;text-decoration:underline!important" in print_css
    assert "break-inside:auto!important" in print_css
    assert "white-space:pre-wrap!important" in print_css
    assert "display:table!important" in print_css
    assert ".cdbd-command:after{display:none!important}" in print_css
    assert "Primary claim from cited source only." in output
    assert soup.select_one(".cdb-cti-dossier").get_text(" ", strip=True) == BeautifulSoup(BODY, "html.parser").get_text(" ", strip=True)


def test_print_export_keeps_live_screen_style_and_unknown_layout_untouched():
    css = BeautifulSoup(enhance_cti_readability_v13(BODY), "html.parser").select_one("#cdb-cti-readability-v13-css").get_text()
    screen_css, print_css = css.split("@media print{", 1)
    assert "background:#fff!important" not in screen_css
    assert ".cdb-cti-dossier .cdbv12-cover{max-width:100%!important}" in screen_css
    assert "a,a:visited" in print_css
    unknown = '<article><p>Unrecognized, immutable evidence.</p></article>'
    assert enhance_cti_readability_v13(unknown) == unknown

def test_report_evidence_is_untouched_even_with_untrusted_text():
    raw = BODY.replace("Primary claim", "Source text: &lt;script&gt;Primary claim")
    out = enhance_cti_readability_v13(raw)
    soup = BeautifulSoup(out, "html.parser")
    assert soup.select_one("script") is None
    assert "&lt;script&gt;" in out
    assert "source not independently verified" in out.lower()
