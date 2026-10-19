"""Blogger live-theme OG image edit regression; does not touch real Blogger."""
from __future__ import annotations

import pytest
from scripts.prepare_cti_og_theme import DEFAULT_URL, prepare_current_theme


def current_theme() -> str:
    return ("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html><html xmlns:b="http://www.google.com/2005/gml/b">
<head>
<meta name='description' content='Unrelated preserved SEO description'/>
<b:if cond='data:blog.pageType == &quot;item&quot;'>
  <b:if cond='data:blog.postImageUrl'>
    <meta expr:content='data:blog.postImageUrl' property='og:image'/>
  <b:else/>
    <meta content='https://example.com/old-card.png' property='og:image'/>
  </b:if>
<b:else/>
  <meta content='https://example.com/old-card.png' property='og:image'/>
</b:if>
<b:if cond='data:blog.postImageUrl'>
  <meta expr:content='data:blog.postImageUrl' name='twitter:image'/>
<b:else/>
  <meta content='https://example.com/old-card.png' name='twitter:image'/>
</b:if>
<b:include data='blog' name='all-head-content'/>
</head>
<body><main><img src='https://example.com/report-cover.png'/><h1>Do not change this report</h1>
""" + "<p>Existing audience source records remain unchanged.</p>" * 50 + "</main></body></html>")


def test_replace_only_live_head_social_image_values_and_preserve_body():
    raw = current_theme()
    altered, report = prepare_current_theme(raw)
    assert altered.count("property='og:image' content='" + DEFAULT_URL + "'") == 3
    assert altered.count("name='twitter:image' content='" + DEFAULT_URL + "'") == 2
    assert "expr:content='data:blog.postImageUrl' property='og:image'" not in altered
    assert "content='https://example.com/old-card.png' property='og:image'" not in altered
    assert "property='og:image:secure_url' content='" + DEFAULT_URL + "'" in altered
    assert "property='og:image:width' content='1200'" in altered
    assert "property='og:image:height' content='630'" in altered
    assert "property='og:image:type' content='image/jpeg'" in altered
    assert "<img src='https://example.com/report-cover.png'/>" in altered
    assert "<h1>Do not change this report</h1>" in altered
    assert "name='description' content='Unrelated preserved SEO description'" in altered
    assert report["replaced"]["og:image"] == 3


def test_rejects_partial_and_unknown_theme_forms():
    with pytest.raises(ValueError, match="complete exported"):
        prepare_current_theme("<html><head></head></html>")
    unknown = current_theme().replace("property='og:image'", "property='irrelevant:image'")
    with pytest.raises(ValueError, match="unfamiliar"):
        prepare_current_theme(unknown)


def test_rejects_offsite_or_insecure_asset():
    for value in ("http://blog.cyberdudebivash.in/card.jpg", "https://attacker.example/card.jpg", "javascript:alert(1)"):
        with pytest.raises(ValueError, match="exact HTTPS"):
            prepare_current_theme(current_theme(), value)
