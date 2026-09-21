import inspect
import re

from automation.authority_transformer import AuthorityTransformer
from automation.content_discovery import DiscoveredArticle
from automation.premium_report_visuals import (
    build_report_hero,
    family_accent,
    premium_report_style_block,
    wrap_premium_report,
)
from automation.report_integrity import build_report_context
from automation.report_renderer import _bullets, _panel, _section


def _article(**overrides):
    data = {
        "url": "https://example.test/source",
        "title": "Example ransomware activity report",
        "summary": "A source-backed intelligence summary.",
        "published_at": "2026-09-21T12:00:00Z",
        "content_hash": "visual-test-1",
        "labels": ["Ransomware", "Threat Intelligence"],
        "source": "ransomware_intel",
        "source_publisher": "Example Publisher",
        "full_content": "Example Publisher reports a ransomware leak-site claim.",
        "ransomware_group": "ExampleGroup",
    }
    data.update(overrides)
    return DiscoveredArticle(**data)


def test_premium_style_is_static_blogger_safe_and_has_mobile_contract():
    css = premium_report_style_block()
    assert '<style id="cdb-premium-report-v1">' in css
    assert ".cdb-report-hero" in css
    assert ".cdb-meta-grid" in css
    assert ".cdb-section-card" in css
    assert ".cdb-premium-report table" in css
    assert ".cdb-premium-report pre" in css
    assert "@media(max-width:760px)" in css
    assert "<script" not in css.lower()


def test_hero_maps_only_existing_report_state_and_escapes_untrusted_text():
    article = _article(title='Bad <img src=x onerror=alert(1)> title')
    context = build_report_context(article)
    hero = build_report_hero(
        article,
        context,
        detection_status="withheld_insufficient_evidence",
        product_tier="TACTICAL",
        content_source="reportx_composer",
    )

    assert "cdb-report-hero" in hero
    assert "Quick Situation Snapshot" in hero
    assert "SOURCE-BACKED" in hero
    assert "EVIDENCE-GRAPH CONTROLLED" in hero
    assert "WITHHELD INSUFFICIENT EVIDENCE" in hero
    assert context.review_status in hero
    assert context.exploitation_label in hero
    assert context.patch_label in hero
    assert "<img src=x" not in hero
    assert "&lt;img src=x onerror=alert(1)&gt;" in hero


def test_ransomware_family_gets_stable_family_specific_accent():
    context = build_report_context(_article())
    accent, soft = family_accent(context)
    assert context.family == "ransomware_claim"
    assert accent == "#e11d48"
    assert soft == "#fecdd3"


def test_unknown_cvss_does_not_invent_severity():
    article = _article(cvss_score=None, full_content="No CVSS score is provided.")
    context = build_report_context(article)
    hero = build_report_hero(
        article,
        context,
        detection_status="not_applicable",
        product_tier="FLASH_READY",
        content_source="reportx_composer",
    )
    assert "UNRATED" in hero
    assert "CRITICAL" not in hero


def test_wrapper_preserves_body_bytes_inside_visual_container():
    body = '<h3>Verified Facts</h3><p>Exact evidence text 123.</p>'
    wrapped = wrap_premium_report(body, accent="#2563eb", accent_soft="#bfdbfe")
    assert body in wrapped
    assert "cdb-premium-report" in wrapped


def test_report_renderer_primitives_expose_stable_visual_classes():
    assert 'class="cdb-section-card"' in _section("Executive Summary", "<p>x</p>")
    assert 'class="cdb-panel"' in _panel("x")
    assert 'class="cdb-bullet"' in _bullets(["x"])


def test_hero_does_not_duplicate_raw_summary_paragraph():
    article = _article(summary="UNIQUE SOURCE SUMMARY SENTENCE")
    context = build_report_context(article)
    hero = build_report_hero(
        article,
        context,
        detection_status="not_applicable",
        product_tier="TACTICAL",
        content_source="reportx_composer",
    )
    assert "UNIQUE SOURCE SUMMARY SENTENCE" not in hero


def test_visual_status_labels_are_not_fake_certification_claims():
    article = _article()
    context = build_report_context(article)
    hero = build_report_hero(
        article,
        context,
        detection_status="not_applicable",
        product_tier="TACTICAL",
        content_source="reportx_composer",
    )
    assert "PREMIUM CERTIFIED" not in hero
    assert "HUMAN REVIEWED" not in hero
    assert "CERTIFIED CUSTOMER DELIVERABLE" not in hero
    assert "SOURCE-BACKED" in hero


def test_no_dynamic_or_unsafe_html_behaviors_are_introduced():
    article = _article()
    context = build_report_context(article)
    combined = premium_report_style_block() + build_report_hero(
        article,
        context,
        detection_status="not_applicable",
        product_tier="TACTICAL",
        content_source="reportx_composer",
    )
    lowered = combined.lower()
    assert "<script" not in lowered
    assert "javascript:" not in lowered
    assert "onerror=" not in lowered
    assert "onclick=" not in lowered


def test_assemble_html_preserves_legacy_wrapper_abi():
    signature = inspect.signature(AuthorityTransformer._assemble_html)
    assert list(signature.parameters) == [
        "self",
        "article",
        "body_content",
        "seo_data",
        "context",
        "image_url",
    ]
    assert "detection_status" not in signature.parameters
    assert "product_tier" not in signature.parameters
    assert "content_source" not in signature.parameters


def test_actual_rapid_intelligence_label_gets_rapid_route_badge():
    article = _article(labels=["Threat Intelligence", "Rapid Intelligence"])
    context = build_report_context(article)
    hero = build_report_hero(
        article,
        context,
        detection_status="not_applicable",
        product_tier="FLASH_READY",
        content_source="evidence_compiled",
    )
    assert "RAPID INTELLIGENCE" in hero
    assert "EVIDENCE COMPILED" not in hero


def test_style_has_fallbacks_before_color_mix_enhancement():
    css = premium_report_style_block()
    assert "border:1px solid #31506a;" in css
    assert "background:linear-gradient(145deg,#0d1a25,#08131d 72%);" in css
