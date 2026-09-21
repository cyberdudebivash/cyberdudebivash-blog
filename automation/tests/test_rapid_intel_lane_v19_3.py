"""Regression tests for the P0 Rapid Intelligence lane v19.3."""
from __future__ import annotations

from bs4 import BeautifulSoup

from automation.content_discovery import DiscoveredArticle
from automation import rapid_intel_lane_v19_3 as v19_3
from automation import authority_transformer as authority
from automation import premium_publication as premium


def _article(**overrides) -> DiscoveredArticle:
    values = {
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-99999",
        "title": "CVE-2026-99999 test vulnerability",
        "summary": " ".join(["source-backed"] * 80),
        "published_at": "2026-09-07T08:00:00+00:00",
        "content_hash": "abc123",
        "labels": ["Threat Intelligence", "Vulnerabilities"],
        "source": "nvd",
        "full_content": " ".join(["authoritative evidence"] * 100),
        "source_publisher": "NIST NVD",
        "cve_id": "CVE-2026-99999",
    }
    values.update(overrides)
    return DiscoveredArticle(**values)


def _rapid_html(words: int = 900, headings: int = 8) -> str:
    sections = []
    per = max(1, words // headings)
    for idx in range(headings):
        sections.append(f"<h3>Section {idx}</h3><p>" + " ".join(["evidence"] * per) + "</p>")
    return (
        '<div class="cdb-cti-dossier" data-report-id="CDB-CTI-2026-ABC123">'
        "<p>CDB_SOURCE_URL: https://nvd.nist.gov/vuln/detail/CVE-2026-99999</p>"
        + "".join(sections)
        + "</div>"
    )


def test_authoritative_connector_is_rapid_eligible(monkeypatch):
    monkeypatch.delenv("CDB_RAPID_INTEL_ENABLED", raising=False)
    eligible, reason = v19_3.rapid_lane_eligibility(_article())
    assert eligible is True
    assert reason == "authoritative_connector:nvd"


def test_first_party_canonical_is_rapid_eligible(monkeypatch):
    monkeypatch.delenv("CDB_RAPID_INTEL_ENABLED", raising=False)
    article = _article(
        source="rss",
        url="https://blog.cyberdudebivash.in/posts/fresh-intel.html",
        cve_id=None,
    )
    eligible, reason = v19_3.rapid_lane_eligibility(article)
    assert eligible is True
    assert reason.startswith("first_party_canonical:")


def test_external_global_rss_defaults_to_premium(monkeypatch):
    monkeypatch.delenv("CDB_RAPID_INTEL_ENABLED", raising=False)
    article = _article(
        source="global_rss",
        url="https://example.com/security/research",
        cve_id=None,
        source_publisher="Example Security Research",
    )
    eligible, reason = v19_3.rapid_lane_eligibility(article)
    assert eligible is False
    assert reason == "premium_default"


def test_configured_source_rich_rss_publisher_is_rapid_eligible(monkeypatch):
    monkeypatch.delenv("CDB_RAPID_INTEL_ENABLED", raising=False)
    article = _article(
        source="global_rss",
        url="https://www.bleepingcomputer.com/news/security/example-malware-campaign/",
        title="New malware loader campaign targets enterprise endpoints",
        cve_id=None,
        source_publisher="BleepingComputer",
        full_content=" ".join(["source-backed malware campaign evidence"] * 100),
    )
    eligible, reason = v19_3.rapid_lane_eligibility(article)
    assert eligible is True
    assert reason == "curated_rss:BleepingComputer"


def test_thin_source_cannot_use_rapid_lane(monkeypatch):
    monkeypatch.delenv("CDB_RAPID_INTEL_ENABLED", raising=False)
    article = _article(summary="tiny source", full_content="tiny source")
    eligible, reason = v19_3.rapid_lane_eligibility(article)
    assert eligible is False
    assert reason == "source_too_thin"


def test_operator_kill_switch_disables_rapid_lane(monkeypatch):
    monkeypatch.setenv("CDB_RAPID_INTEL_ENABLED", "false")
    eligible, reason = v19_3.rapid_lane_eligibility(_article())
    assert eligible is False
    assert reason == "disabled"


def test_rapid_provider_wrapper_returns_none_without_calling_provider(monkeypatch):
    called = []

    def provider(*args, **kwargs):
        called.append(True)
        return ("<p>generated</p>", "provider")

    monkeypatch.setattr(v19_3, "_ORIGINAL_AUTHORITY_LLM", provider)
    token = v19_3._RAPID_ACTIVE.set(True)
    try:
        assert v19_3._lane_aware_call_llm(object(), "prompt") is None
    finally:
        v19_3._RAPID_ACTIVE.reset(token)
    assert called == []


def test_premium_provider_wrapper_delegates_unchanged(monkeypatch):
    def provider(*args, **kwargs):
        return ("<p>generated</p>", "provider")

    monkeypatch.setattr(v19_3, "_ORIGINAL_AUTHORITY_LLM", provider)
    assert v19_3._lane_aware_call_llm(object(), "prompt") == ("<p>generated</p>", "provider")


def test_cross_node_and_code_prompt_leakage_is_repaired():
    soup = BeautifulSoup(
        """
        <div class="cdb-cti-dossier">
          <p><strong>Let me</strong> write a customer-facing report now.</p>
          <pre>CDB_EXPLOITATION_STATUS</pre>
          <p>Researchers observed a source-backed condition.</p>
        </div>
        """,
        "html.parser",
    )
    changed = v19_3._repair_cross_node_prompt_leakage(soup)
    visible = " ".join(soup.stripped_strings)
    assert changed >= 2
    assert "Let me write" not in visible
    assert "CDB_EXPLOITATION_STATUS" not in visible
    assert "Researchers observed a source-backed condition." in visible


def test_rapid_live_assessment_passes_distinct_rapid_floor():
    content = _rapid_html(words=900, headings=8)
    labels = ["Threat Intelligence", v19_3.RAPID_LABEL]
    live = {"title": "Rapid report", "content": content, "labels": labels}
    result = v19_3._rapid_live_assessment(live, "Rapid report", content, labels)
    assert result.verified is True
    assert result.live_words >= v19_3.RAPID_MIN_VISIBLE_WORDS


def test_rapid_live_assessment_blocks_thin_live_copy():
    content = _rapid_html(words=900, headings=8)
    thin = _rapid_html(words=200, headings=8)
    labels = ["Threat Intelligence", v19_3.RAPID_LABEL]
    live = {"title": "Rapid report", "content": thin, "labels": labels}
    result = v19_3._rapid_live_assessment(live, "Rapid report", content, labels)
    assert result.verified is False
    assert "live_copy_below_rapid_word_floor" in result.defects


def test_rapid_transform_calls_base_integrity_transform_not_premium_gate(monkeypatch):
    article = _article()
    calls = []

    def base_transform(self, current):
        calls.append("base")
        # This stands in for AuthorityTransformer's already-certified return.
        return {
            "title": current.title,
            "content": _rapid_html(),
            "labels": list(current.labels),
            "content_source": "reportx_composer",
            "product_tier": "TACTICAL",
            "achieved_tier": "TACTICAL",
            "certified_artifact_hash": "certified",
        }

    def premium_transform(self, current):
        calls.append("premium")
        raise AssertionError("premium structural gate must not run for rapid-eligible source")

    monkeypatch.setattr(authority.AuthorityTransformer, "transform", base_transform)
    monkeypatch.setattr(premium.PremiumAuthorityTransformer, "transform", premium_transform)
    transformer = object.__new__(v19_3.RapidAwareAuthorityTransformer)
    result = transformer.transform(article)

    assert calls == ["base"]
    assert result["publication_lane"] == "RAPID_INTELLIGENCE"
    assert result["public_quality_band"] == v19_3.RAPID_QUALITY_BAND
    assert v19_3.RAPID_LABEL in result["labels"]
    assert article.labels == ["Threat Intelligence", "Vulnerabilities"]
    assert v19_3._RAPID_ACTIVE.get() is False


def test_non_rapid_transform_stays_on_premium_path(monkeypatch):
    article = _article(
        source="global_rss",
        url="https://example.com/security/research",
        cve_id=None,
        source_publisher="Example Security Research",
    )
    calls = []

    def premium_transform(self, current):
        calls.append("premium")
        return {"title": current.title, "content": "premium"}

    monkeypatch.setattr(premium.PremiumAuthorityTransformer, "transform", premium_transform)
    transformer = object.__new__(v19_3.RapidAwareAuthorityTransformer)
    result = transformer.transform(article)
    assert calls == ["premium"]
    assert result["content"] == "premium"


def test_telemetry_proves_hard_gates_and_premium_floors_are_unchanged():
    snapshot = v19_3.telemetry_snapshot()
    assert snapshot["premium_quality_floors_changed"] is False
    assert snapshot["reportx_integrity_gates_changed"] is False
    assert snapshot["v8_fail_closed_gate_preserved"] is True
    assert snapshot["paid_provider_policy_changed"] is False
    assert snapshot["pricing_changed"] is False
    assert snapshot["billing_changed"] is False
