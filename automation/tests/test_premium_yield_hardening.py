from unittest.mock import Mock

import requests

from automation import premium_incident_recovery as recovery
from automation import premium_provider_budget as budget
from automation import premium_publication as premium
from automation import premium_yield_hardening as hardening
from automation import premium_yield_contract_guard as guard
from automation.config import Config
from automation.content_discovery import DiscoveredArticle


_SUBSTANTIVE_PARAGRAPH = (
    "Evidence-backed analysis explains telemetry validation and enterprise response decisions."
)
_SUBSTANTIVE_LIST_ITEM = (
    "Validate authoritative telemetry before operational escalation or containment decisions."
)


def _article(**overrides):
    values = dict(
        url="https://example.test/advisory/CVE-2026-99999",
        title="CVE-2026-99999 Example Product remote security advisory",
        summary="Example Vendor reports a security issue affecting Example Product.",
        published_at="2026-09-03T00:00:00Z",
        content_hash="yield-hardening-abc123",
        labels=["Threat Intelligence", "Vulnerabilities", "CVE Analysis"],
        source="nvd",
        full_content=("Example Vendor Example Product CVE-2026-99999 evidence remediation telemetry. " * 180),
        source_publisher="Example Vendor",
        cve_id="CVE-2026-99999",
        cvss_score=8.1,
        cwe_ids=["CWE-20"],
        affected_vendor="Example Vendor",
        affected_product="Example Product",
        kev_listed=False,
    )
    values.update(overrides)
    return DiscoveredArticle(**values)


def _report_without_tail(words=2300):
    # The strict runtime contract is 25 sections.  A legitimate terminal
    # recovery fixture therefore contains every non-tail mandatory section,
    # not merely the smaller public-core subset used by the pre-P0.1 tests.
    headings = [
        heading for heading in guard._MANDATORY_HEADINGS
        if heading not in {"Executive Recommendations", "References"}
    ]
    sections = "".join(
        f"<h3>{heading}</h3>"
        f"<p>{_SUBSTANTIVE_PARAGRAPH}</p>"
        f"<ul><li>{_SUBSTANTIVE_LIST_ITEM}</li></ul>"
        for heading in headings
    )
    filler = " ".join("evidence" for _ in range(words))
    return f"{sections}<p>{filler}</p>"


def test_prompt_adds_authoritative_evidence_boundary_and_stays_provider_safe(monkeypatch):
    monkeypatch.setattr(recovery, "_ORIGINAL_PROMPT_BUILDER", budget.build_budgeted_premium_prompt)
    monkeypatch.setattr(hardening, "_ORIGINAL_PROMPT_BUILDER", recovery.build_completion_safe_prompt)

    prompt = hardening.build_evidence_explicit_prompt(_article())

    assert "CDB_EVIDENCE_FAMILY: cve_advisory" in prompt
    assert "CDB_EXPLOITATION_STATUS: not_confirmed" in prompt
    assert "CDB_SOURCE_CLAIM_ONLY: false" in prompt
    assert "do not assert that exploitation is active" in prompt
    assert len(prompt) <= budget.PREMIUM_PROMPT_CHAR_CEILING


def test_authoritative_structural_preflight_accepts_numbered_mandatory_headings():
    # Preserve the original numbered-heading regression but make the fixture a
    # real publication-shaped report.  P0 semantic alignment intentionally no
    # longer treats ten public-core headings plus arbitrary auxiliary headings
    # as a complete 25-section contract.
    numbered = [
        f"{idx}. {heading}"
        for idx, heading in enumerate(guard._MANDATORY_HEADINGS, 1)
    ]
    sections = "".join(
        f"<h3>{heading}</h3>"
        f"<p>{_SUBSTANTIVE_PARAGRAPH}</p>"
        f"<ul><li>{_SUBSTANTIVE_LIST_ITEM}</li></ul>"
        for heading in numbered
    )
    content = sections + "<p>" + ("evidence " * 2300) + "</p>"

    words, heading_count, coverage = hardening.authoritative_raw_contract_metrics(content)

    assert words >= premium.MIN_VISIBLE_WORDS
    assert heading_count >= premium.MIN_DISTINCT_HEADINGS
    # Depending on whether the production contract guard has already been
    # installed in this pytest process, compatibility metric #3 is either
    # public-core coverage (10) or strict mandatory coverage (25).  Both must
    # at least cover every public-core heading; completeness is asserted below.
    assert coverage >= len(premium._CORE_HEADINGS)
    assert hardening.yield_contract_complete(content) is True


def test_tail_repair_only_completes_terminal_sections_on_otherwise_publishable_report():
    content = _report_without_tail()
    prompt = """SOURCE TITLE: Example advisory
SOURCE URL: https://example.test/advisory
CDB_EVIDENCE_FAMILY: cve_advisory
CDB_EXPLOITATION_STATUS: not_confirmed
"""

    assert hardening.yield_contract_complete(content) is True
    repaired, sections_added = hardening._tail_sections(content, prompt)

    assert sections_added == 2
    assert "<h3>Executive Recommendations</h3>" in repaired
    assert "<h3>References</h3>" in repaired
    assert "https://example.test/advisory" in repaired
    assert hardening._missing_core_headings(repaired) == set()


def test_tail_repair_refuses_short_or_broadly_incomplete_content():
    short = "<h3>Executive Summary</h3><p>" + ("evidence " * 500) + "</p>"
    prompt = "SOURCE URL: https://example.test/advisory\nSOURCE TITLE: Example\n"

    repaired, sections_added = hardening._tail_sections(short, prompt)

    assert repaired == short
    assert sections_added == 0


def test_baseline_tail_repair_rejects_unsafe_reference_url():
    content = _report_without_tail()
    prompt = """SOURCE TITLE: Adversarial feed item
SOURCE URL: javascript:alert(document.domain)
CDB_EVIDENCE_FAMILY: cve_advisory
CDB_EXPLOITATION_STATUS: not_confirmed
"""

    repaired, sections_added = hardening._tail_sections(content, prompt)

    assert repaired == content
    assert sections_added == 0
    assert "javascript:" not in repaired
    assert "<h3>References</h3>" not in repaired


def test_baseline_reference_url_validator_rejects_non_http_and_credential_urls():
    assert hardening._validated_http_url("https://example.test/source") == "https://example.test/source"
    assert hardening._validated_http_url("http://example.test/source") == "http://example.test/source"
    assert hardening._validated_http_url("javascript:alert(1)") is None
    assert hardening._validated_http_url("data:text/html,boom") is None
    assert hardening._validated_http_url("//example.test/source") is None
    assert hardening._validated_http_url("https://user:pass@example.test/source") is None
    assert hardening._validated_http_url("https://example.test:99999/source") is None


def test_unconfirmed_exploitation_language_is_conservatively_downgraded():
    content = (
        "<h3>Verified Facts</h3><p>The vulnerability is actively exploited and "
        "exploitation has been observed across exposed systems.</p>"
    )
    prompt = "CDB_EVIDENCE_FAMILY: cve_advisory\nCDB_EXPLOITATION_STATUS: not_confirmed\n"

    repaired, changes = hardening._repair_evidence_language(content, prompt)

    assert changes == 2
    assert "is not established as actively exploited in cited evidence" in repaired
    assert "exploitation has not been observed in cited evidence" in repaired
    for pattern in hardening._integrity._CONFIRMED_EXPLOITATION_PATTERNS:
        for match in hardening.re.finditer(pattern, repaired, hardening.re.IGNORECASE):
            assert hardening._integrity._is_negated_immediately_before(repaired, match.start())


def test_ransomware_claim_language_remains_claim_not_confirmed_breach():
    content = (
        "<p>The actor confirms a breach. The breach is confirmed. "
        "Data was stolen and the victim's network was compromised.</p>"
    )
    prompt = "CDB_EVIDENCE_FAMILY: ransomware_claim\nCDB_EXPLOITATION_STATUS: third_party_claim\n"

    repaired, changes = hardening._repair_evidence_language(content, prompt)

    assert changes == 4
    assert "reports a claimed breach or compromise" in repaired
    assert "not independently confirmed" in repaired
    assert "not independently verified" in repaired
    for pattern in hardening._integrity._RANSOMWARE_CLAIM_CONFIRMED_BREACH_PATTERNS:
        assert hardening.re.search(pattern, repaired, hardening.re.IGNORECASE) is None


def test_provider_declared_long_reset_activates_process_local_model_cooldown(monkeypatch):
    url = "https://api.groq.com/openai/v1/chat/completions"
    model = "openai/gpt-oss-120b"
    response = Mock(status_code=429, headers={"Retry-After": "300"})
    error = requests.exceptions.HTTPError("429", response=response)

    monkeypatch.setattr(hardening, "_ORIGINAL_OPENAI_CALL", Mock(side_effect=error))
    hardening._MODEL_COOLDOWNS.clear()

    try:
        hardening.quota_aware_openai_call(
            url=url,
            api_key="k",
            model=model,
            prompt="p",
            max_tokens=100,
            extra_headers={},
            sleep_fn=lambda _seconds: None,
        )
        assert False, "expected HTTPError"
    except requests.exceptions.HTTPError:
        pass

    assert hardening._cooldown_remaining(url, model) > 250


def test_cooldown_skips_repeat_model_without_network_call(monkeypatch):
    url = "https://api.groq.com/openai/v1/chat/completions"
    model = "openai/gpt-oss-120b"
    original_try = Mock(side_effect=AssertionError("network path must not run during cooldown"))
    monkeypatch.setattr(hardening, "_ORIGINAL_TRY_PROVIDER", original_try)
    hardening._MODEL_COOLDOWNS.clear()
    hardening._activate_model_cooldown(url, model, 120)
    attempts = []

    result = hardening.quota_aware_try_provider(
        name="groq",
        url=url,
        api_key="k",
        model=model,
        prompt="p",
        max_tokens=100,
        extra_headers={},
        sleep_fn=lambda _seconds: None,
        attempts=attempts,
    )

    assert result is None
    original_try.assert_not_called()
    assert attempts[0]["error"] == "provider_cooldown_active"
    assert attempts[0]["retry_after_seconds"] > 0


def test_key_judgements_spend_fallback_model_quota_before_primary(monkeypatch):
    config = Config(
        groq_api_key="k",
        llm_model_groq="primary-120b",
        llm_model_groq_fallbacks=("small-20b", "qwen-a", "qwen-b"),
    )
    captured = {}

    def fake_call(routed, prompt, max_tokens=2000, attempts=None, sleep_fn=None):
        captured["primary"] = routed.llm_model_groq
        captured["fallbacks"] = routed.llm_model_groq_fallbacks
        return "[]", "groq"

    monkeypatch.setattr(hardening._budget, "_pace_premium_request", lambda _sleep: None)
    monkeypatch.setattr(hardening._budget, "_ORIGINAL_KEY_JUDGEMENTS_LLM_CALL", fake_call)

    result = hardening.call_quota_efficient_key_judgements(
        config,
        "prompt",
        attempts=[],
        sleep_fn=lambda _seconds: None,
    )

    assert result == ("[]", "groq")
    assert captured["primary"] == "small-20b"
    assert captured["fallbacks"] == ("qwen-a", "qwen-b", "primary-120b")



def test_groq_http_404_only_quarantines_exact_model_for_current_run(monkeypatch):
    """Repeated 404s are skipped without suppressing other Groq models."""
    url = "https://api.groq.com/openai/v1/chat/completions"
    model = "qwen/qwen3.6-27b"
    response = Mock(status_code=404, headers={})
    error = requests.exceptions.HTTPError("404", response=response)
    network = Mock(side_effect=error)
    fallback = Mock(return_value="verified-other-model-content")
    monkeypatch.setattr(hardening, "_ORIGINAL_OPENAI_CALL", network)
    monkeypatch.setattr(hardening, "_ORIGINAL_TRY_PROVIDER", fallback)
    hardening._GROQ_404_THIS_RUN.clear()
    try:
        with __import__("pytest").raises(requests.exceptions.HTTPError):
            hardening.quota_aware_openai_call(
                url=url, api_key="safe-test", model=model, prompt="p",
                max_tokens=80, extra_headers={}, sleep_fn=lambda _: None,
            )
        assert network.call_count == 1
        ledger = []
        assert hardening.quota_aware_try_provider(
            name="groq", url=url, api_key="safe-test", model=model,
            prompt="p", max_tokens=80, extra_headers={},
            sleep_fn=lambda _: None, attempts=ledger,
        ) is None
        assert ledger == [{"provider": "groq", "model": model,
                           "ok": False, "error": "groq_http_404_quarantined_this_run"}]
        fallback.assert_not_called()
        assert hardening.quota_aware_try_provider(
            name="groq", url=url, api_key="safe-test", model="openai/gpt-oss-20b",
            prompt="p", max_tokens=80, extra_headers={},
            sleep_fn=lambda _: None, attempts=[],
        ) == "verified-other-model-content"
    finally:
        hardening._GROQ_404_THIS_RUN.clear()


def test_non_groq_404_never_quarantines_model(monkeypatch):
    """An unrelated provider endpoint must not inherit Groq's circuit breaker."""
    url = "https://openrouter.ai/api/v1/chat/completions"
    response = Mock(status_code=404, headers={})
    error = requests.exceptions.HTTPError("404", response=response)
    monkeypatch.setattr(hardening, "_ORIGINAL_OPENAI_CALL", Mock(side_effect=error))
    monkeypatch.setattr(hardening, "_ORIGINAL_TRY_PROVIDER", Mock(return_value="fallback"))
    hardening._GROQ_404_THIS_RUN.clear()
    try:
        with __import__("pytest").raises(requests.exceptions.HTTPError):
            hardening.quota_aware_openai_call(
                url=url, api_key="safe-test", model="model-xyz",
                prompt="p", max_tokens=80, extra_headers={},
                sleep_fn=lambda _: None,
            )
        assert hardening._GROQ_404_THIS_RUN == set()
        assert hardening.quota_aware_try_provider(
            name="openrouter", url=url, api_key="safe-test", model="model-xyz",
            prompt="p", max_tokens=80, extra_headers={},
            sleep_fn=lambda _: None, attempts=[],
        ) == "fallback"
    finally:
        hardening._GROQ_404_THIS_RUN.clear()


def test_groq_non_404_failure_does_not_suppress_future_attempts(monkeypatch):
    url = "https://api.groq.com/openai/v1/chat/completions"
    response = Mock(status_code=503, headers={})
    monkeypatch.setattr(hardening, "_ORIGINAL_OPENAI_CALL",
                        Mock(side_effect=requests.exceptions.HTTPError("503", response=response)))
    hardening._GROQ_404_THIS_RUN.clear()
    try:
        with __import__("pytest").raises(requests.exceptions.HTTPError):
            hardening.quota_aware_openai_call(
                url=url, api_key="safe-test", model="temporary-unavailable",
                prompt="p", max_tokens=80, extra_headers={}, sleep_fn=lambda _: None,
            )
        assert hardening._GROQ_404_THIS_RUN == set()
    finally:
        hardening._GROQ_404_THIS_RUN.clear()
