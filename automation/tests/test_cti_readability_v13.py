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


def test_print_dark_screen_surfaces_are_reset_for_ciso_evidence_exports():
    """Print-only white surfaces protect analytical text from dark-background bleed."""
    source = (
        '<article class="cdb-cti-dossier">'
        '<h2 class="cdbd-section-title">Verified facts</h2>'
        '<table><thead><tr><th>Source</th></tr></thead>'
        '<tbody><tr><td>TLP:CLEAR confirmed provenance</td></tr></tbody></table>'
        '<ul><li>No customer exposure established</li></ul>'
        '<pre><code>indicator=source_qualified</code></pre>'
        '<a href="https://vendor.example/advisory">Vendor citation</a>'
        '</article>'
    )
    output = enhance_cti_readability_v13(source)
    soup = BeautifulSoup(output, "html.parser")
    css = soup.select_one("#cdb-cti-readability-v13-css").get_text()
    screen, paper = css.split("@media print{", 1)
    # The normal dark-mode customer interface is unchanged.
    assert ".cdb-cti-dossier .cdbd-section-title{background:#fff!important" not in screen
    assert ".cdb-cti-dossier .cdbd-section-title{background:#fff!important" in paper
    for selector in (
        ":is(table,thead,tbody,tfoot,tr,th,td,ul,ol,blockquote,pre,code)",
        ":is(table,pre,blockquote,ul,ol)",
    ):
        assert ".cdb-cti-dossier " + selector in paper
    assert "background:#fff!important;color:#182635!important;box-shadow:none!important" in paper
    assert ".cdb-cti-dossier thead{display:table-header-group!important}" in paper
    assert ".cdb-cti-dossier tfoot{display:table-footer-group!important}" in paper
    assert ".cdb-cti-dossier :is(h2,h3,h4){break-after:avoid-page!important}" in paper
    # Content, evidence classification, citation and report identity are untouched.
    assert soup.select_one(".cdb-cti-dossier").get_text(" ", strip=True) == (
        BeautifulSoup(source, "html.parser").get_text(" ", strip=True)
    )
    assert soup.select_one('a[href="https://vendor.example/advisory"]') is not None
    assert enhance_cti_readability_v13(output) == output


def test_print_theme_never_changes_unrecognized_or_entitlement_layout():
    untouched = '<main><p>TLP:AMBER customer-only source. Not an authorized public report.</p></main>'
    assert enhance_cti_readability_v13(untouched) == untouched
    assert "window.location" not in enhance_cti_readability_v13(
        '<article class="cdb-cti-dossier"><p>Evidence-only</p></article>'
    )
