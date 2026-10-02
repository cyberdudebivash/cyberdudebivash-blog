from types import SimpleNamespace
from unittest.mock import Mock

from automation import astra_revenue_intelligence_v18 as astra
from automation import premium_publication as premium
from automation import premium_yield_contract_guard as yield_guard
from automation import publication_scheduler as scheduler


def _article(**overrides):
    values = dict(
        title="Enterprise threat intelligence research",
        summary="Source-backed technical research with detection guidance.",
        full_content="source evidence " * 500,
        labels=["Threat Intelligence"],
        source="rss",
        source_publisher="Example Research",
        published_at="2026-09-07T00:00:00+00:00",
        content_hash="abc123",
        url="https://publisher.example/research",
        cve_id=None,
        cvss_score=None,
        cvss_vector=None,
        cwe_ids=None,
        affected_vendor=None,
        affected_product=None,
        epss_score=None,
        epss_percentile=None,
        kev_listed=None,
        kev_date_added=None,
        kev_due_date=None,
        kev_required_action=None,
        ransomware_group=None,
        ransomware_sector=None,
        ransomware_country=None,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def _near_complete_contract() -> str:
    # All canonical sections + paragraph/list density are present; only the
    # authoritative word floor remains short so v18 can demonstrate bounded
    # continuation without manufacturing a missing structural section.
    headings = "".join(f"<h3>{heading}</h3>" for heading in yield_guard._MANDATORY_HEADINGS)
    paragraph = " ".join(["evidence"] * 108)
    paragraphs = "".join(f"<p>{paragraph} {idx}</p>" for idx in range(18))
    items = "".join(
        f"<li>validated telemetry collection requirement {idx}</li>" for idx in range(18)
    )
    return headings + paragraphs + f"<ul>{items}</ul>"


def test_authoritative_public_quality_floor_is_unchanged():
    assert premium.MIN_VISIBLE_WORDS == 2200
    assert premium.MIN_DISTINCT_HEADINGS == 18
    assert premium.MIN_PARAGRAPHS == 18
    assert premium.MIN_LIST_ITEMS == 18


def test_commercial_priority_is_bounded_and_explicitly_not_risk_score(monkeypatch):
    monkeypatch.setattr(astra, "_published_age_hours", lambda _a: 6.0)
    rich = _article(
        source="cisa_kev",
        cve_id="CVE-2026-99999",
        cvss_score=9.8,
        epss_score=0.75,
        kev_listed=True,
        affected_vendor="Vendor",
        affected_product="Product",
        full_content=("CVE-2026-99999 indicator detection sigma evidence " * 500),
    )
    result = astra.commercial_priority(rich)

    assert 0 <= result.score <= 100
    assert result.band in {"P0", "P1", "P2", "P3"}
    assert result.to_dict()["semantics"] == "commercial_delivery_priority_not_threat_risk"
    assert "kev:confirmed" in result.reasons


def test_commercial_priority_prefers_productizable_evidence(monkeypatch):
    monkeypatch.setattr(astra, "_published_age_hours", lambda _a: 12.0)
    low = astra.commercial_priority(_article(full_content="brief commentary " * 40))
    high = astra.commercial_priority(
        _article(
            source="ransomware_intel",
            ransomware_group="ExampleGroup",
            full_content="malware indicator ioc sha256 detection sigma yara campaign evidence " * 250,
        )
    )
    assert high.score > low.score


def test_generation_readiness_prefers_source_rich_evidence_without_granting_publication(monkeypatch):
    thin = _article(full_content="brief source note " * 30)
    rich = _article(full_content="source-backed technical evidence " * 700)

    thin_band, thin_words, _ = astra.generation_readiness(thin)
    rich_band, rich_words, _ = astra.generation_readiness(rich)

    assert rich_words > thin_words
    assert rich_band > thin_band
    assert premium.MIN_VISIBLE_WORDS == 2200
    assert premium.MIN_PARAGRAPHS == 18
    assert premium.MIN_LIST_ITEMS == 18


def test_scheduler_prefers_generation_readiness_before_commercial_score_inside_same_trust_lane(monkeypatch):
    monkeypatch.setattr(astra, "_INNER_PRIORITY_KEY", lambda a: (0, 10.0, a.content_hash))
    thin = _article(content_hash="thin", full_content="brief note " * 30)
    rich = _article(content_hash="rich", full_content="source evidence " * 1800)

    monkeypatch.setattr(astra, "commercial_priority", lambda a: astra.CommercialPriority(
        100 if a.content_hash == "thin" else 10,
        "P0" if a.content_hash == "thin" else "P3",
        (),
        "threat_analysis",
    ))

    assert astra._astra_priority_key(rich) > astra._astra_priority_key(thin)

def test_scheduler_priority_preserves_canonical_first(monkeypatch):
    monkeypatch.setattr(astra, "_INNER_PRIORITY_KEY", lambda a: (
        1 if scheduler.is_canonical_report(a) else 0,
        10.0,
        a.content_hash,
    ))
    monkeypatch.setattr(astra, "commercial_priority", lambda a: astra.CommercialPriority(
        5 if scheduler.is_canonical_report(a) else 100,
        "P3" if scheduler.is_canonical_report(a) else "P0",
        (),
        "threat_analysis",
    ))
    canonical = _article(url="https://blog.cyberdudebivash.in/posts/test.html", content_hash="c")
    external = _article(url="https://publisher.example/test", content_hash="e")

    assert astra._astra_priority_key(canonical)[0] == 1
    assert astra._astra_priority_key(external)[0] == 0
    assert astra._astra_priority_key(canonical) > astra._astra_priority_key(external)


def test_selection_wrapper_preserves_inner_selection_and_adds_commercial_metrics(monkeypatch):
    chosen = [_article(content_hash="a"), _article(content_hash="b", source="ransomware_intel", ransomware_group="R")]
    inner = Mock(return_value=scheduler.PublicationSelection(chosen, {"candidate_count": 10}))
    monkeypatch.setattr(astra, "_INNER_SELECT", inner)
    monkeypatch.setattr(astra, "commercial_priority", lambda a: astra.CommercialPriority(
        80 if a.content_hash == "b" else 55,
        "P0" if a.content_hash == "b" else "P2",
        ("test",),
        "ransomware" if a.content_hash == "b" else "threat_analysis",
    ))

    result = astra._astra_select_publication_batch([], chosen, 5)

    assert result.articles == chosen
    assert result.metrics["candidate_count"] == 10
    assert result.metrics["astra_revenue_v18"] is True
    assert result.metrics["commercial_priority_semantics"] == "delivery_value_not_threat_risk"
    assert result.metrics["commercial_selected_average"] == 67.5
    assert result.metrics["commercial_selected_max"] == 80
    assert result.metrics["commercial_priority_bands"] == {"P0": 1, "P2": 1}


def test_targeted_continuation_is_not_called_when_initial_contract_is_complete(monkeypatch):
    monkeypatch.setattr(astra, "_INNER_AUTHORITY_CALL", Mock(return_value=("complete", "gemini")))
    continuation = Mock(side_effect=AssertionError("continuation must not run"))
    monkeypatch.setattr(astra, "_CONTINUATION_CALL", continuation)
    monkeypatch.setattr(yield_guard, "strict_yield_contract_complete", lambda content: content == "complete")

    result = astra.astra_quality_aware_authority_llm(SimpleNamespace(), "prompt", attempts=[], sleep_fn=lambda _s: None)

    assert result == ("complete", "gemini")
    continuation.assert_not_called()


def test_targeted_continuation_requires_active_source_evidence(monkeypatch):
    monkeypatch.setattr(astra, "_INNER_AUTHORITY_CALL", Mock(return_value=("thin", "gemini")))
    continuation = Mock(side_effect=AssertionError("continuation must not run"))
    monkeypatch.setattr(astra, "_CONTINUATION_CALL", continuation)
    monkeypatch.setattr(yield_guard, "strict_yield_contract_complete", lambda _content: False)
    monkeypatch.setattr(astra, "_active_article", lambda: None)

    result = astra.astra_quality_aware_authority_llm(SimpleNamespace(), "prompt", attempts=[], sleep_fn=lambda _s: None)

    assert result == ("thin", "gemini")
    continuation.assert_not_called()


def test_targeted_continuation_can_cross_existing_gate_without_lowering_it(monkeypatch):
    existing = _near_complete_contract()
    assert yield_guard.strict_yield_contract_complete(existing) is False

    fragment = "<p>" + ("source bounded validation evidence " * 70) + "</p>"
    inner = Mock(return_value=(existing, "gemini"))
    continuation = Mock(return_value=(fragment, "nvidia_nim"))
    monkeypatch.setattr(astra, "_INNER_AUTHORITY_CALL", inner)
    monkeypatch.setattr(astra, "_CONTINUATION_CALL", continuation)
    monkeypatch.setattr(astra, "_active_article", lambda: _article(full_content="trusted source evidence " * 500))

    result = astra.astra_quality_aware_authority_llm(
        SimpleNamespace(),
        "SOURCE DATA: trusted source evidence",
        attempts=[],
        sleep_fn=lambda _s: None,
    )

    assert result is not None
    content, provider = result
    assert provider == "gemini"
    assert "source bounded validation evidence" in content
    assert yield_guard.strict_yield_contract_complete(content) is True
    assert continuation.call_count == 1
    assert continuation.call_args.kwargs["max_tokens"] == astra.CONTINUATION_MAX_TOKENS


def test_continuation_rejects_duplicate_existing_canonical_heading():
    existing = "<h3>Executive Summary</h3><p>Existing source-bounded analysis remains authoritative.</p>"
    raw = "<h3>Executive Summary</h3><p>Repeated content that should never be appended to the report body.</p>"
    assert astra._safe_continuation_fragment(raw, existing) is None


def test_continuation_rejects_model_meta_leak():
    raw = "<p>The user wants me to produce a longer report and I need to meet the token budget.</p>"
    assert astra._safe_continuation_fragment(raw, "<p>Existing evidence.</p>") is None


def test_commercial_panel_uses_existing_entitlements_and_utm_attribution(monkeypatch):
    article = _article(source="ransomware_intel", ransomware_group="ExampleGroup")
    context = SimpleNamespace(family="ransomware_claim", report_id="CDB-CTI-2026-TEST")
    html = astra._commercial_panel_html(article, context)

    assert "API STARTER" in html
    assert "5,000 API calls/day" in html
    assert "SOC PRO" in html
    assert "25,000 API calls/day" in html
    assert "STIX 2.1 export" in html
    assert "utm_campaign=astra_revenue_v18" in html.replace("&amp;", "&")
    assert "Customer exposure or compromise is never inferred" in html
    assert "SOC 2 certified" not in html
    assert "guaranteed" not in html.lower()


def test_presentation_is_idempotent_and_reduced_motion_safe():
    article = _article()
    context = SimpleNamespace(family="general_intelligence", report_id="CDB-CTI-TEST")
    base = '<div class="cdbv10-capabilities">INTELLIGENCE OUTPUTS</div>'
    once = astra.enhance_astra_revenue_presentation(base, article, context)
    twice = astra.enhance_astra_revenue_presentation(once, article, context)

    assert once == twice
    assert once.count(astra.PRESENTATION_MARKER) == 2  # opening + closing comment
    assert "prefers-reduced-motion:reduce" in once
    assert "data-astra-revenue-v18=\"true\"" in once


def test_telemetry_is_aggregate_and_never_claims_server_side_conversions():
    telemetry = astra.telemetry_snapshot()
    serialized = str(telemetry).lower()

    assert telemetry["server_side_clicks_claimed"] is False
    assert telemetry["telemetry_contains_prompts"] is False
    assert telemetry["telemetry_contains_response_content"] is False
    assert telemetry["telemetry_contains_credentials"] is False
    assert "api_key" not in serialized
    assert "auth_token" not in serialized
    assert telemetry["public_quality_floor"] == {
        "visible_words": 2200,
        "distinct_headings": 18,
        "substantive_paragraphs": 18,
        "substantive_list_items": 18,
    }


def test_v18_does_not_mutate_paid_provider_policy():
    # The module owns no ALLOW_PAID_LLM flag and has no provider credentials.
    source = open(astra.__file__, "r", encoding="utf-8").read()
    assert "ALLOW_PAID_LLM =" not in source
    assert "GEMINI_API_KEY" not in source
    assert "NVIDIA_NIM_API_KEY" not in source
    assert "PUTER_AUTH_TOKEN =" not in source
