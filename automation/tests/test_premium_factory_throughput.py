from dataclasses import replace

from automation import premium_factory_throughput as factory
from automation import premium_yield_contract_guard as guard
from automation.config import Config
from automation.content_discovery import DiscoveredArticle, PublicationState


def _article(index: int, *, title: str, source: str = "global_rss", cve_id=None):
    return DiscoveredArticle(
        url=f"https://example.test/report/{index}",
        title=title,
        summary=f"Evidence summary for {title}",
        published_at=f"2026-09-03T10:{index % 60:02d}:00Z",
        content_hash=f"factory-{index:04d}",
        labels=["Threat Intelligence"],
        source=source,
        full_content=f"Source evidence for {title}",
        source_publisher="Example Publisher",
        cve_id=cve_id,
    )


def _semantic_report_with_h2_reference():
    chunks = []
    for index, heading in enumerate(guard._MANDATORY_HEADINGS, 1):
        tag = "h2" if heading == "References" else "h3"
        chunks.append(f"<{tag}>{index}. {heading}</{tag}>")
        chunks.append(
            "<p>Evidence-specific analytical paragraph with decision relevance, telemetry, validation, and operational context for enterprise defenders.</p>"
        )
        chunks.append(
            "<ul><li>Evidence-specific action with validation criteria and a clearly stated operational decision boundary.</li></ul>"
        )
    chunks.append("<p>" + ("evidence decision validation telemetry " * 600) + "</p>")
    return "".join(chunks)


def test_h3_preflight_matches_sanitizer_and_repairs_h2_reference_to_real_h3(monkeypatch):
    content = _semantic_report_with_h2_reference()
    monkeypatch.setattr(guard, "_normalized_heading_set", factory.h3_only_heading_set)

    assert "references" not in factory.h3_only_heading_set(content)
    assert guard._missing_mandatory(content) == {"references"}
    assert guard.strict_yield_contract_complete(content) is True

    repaired, added = guard.strict_tail_sections(
        content,
        "SOURCE URL: https://example.test/source\nSOURCE TITLE: Example source\n",
    )

    assert added == 1
    assert "<h3>References</h3>" in repaired
    assert guard._missing_mandatory(repaired) == set()


def test_model_pacing_is_per_groq_model_not_global(monkeypatch):
    calls = []
    sleeps = []
    monkeypatch.setattr(factory, "_ORIGINAL_TRY_PROVIDER", lambda **kwargs: calls.append(kwargs["model"]) or "ok")
    monkeypatch.setattr(factory.time, "monotonic", lambda: 100.0)
    factory._MODEL_LAST_STARTED.clear()

    common = dict(
        name="groq",
        url=factory._llm._GROQ_URL,
        api_key="k",
        prompt="p",
        max_tokens=100,
        extra_headers={},
        sleep_fn=lambda seconds: sleeps.append(seconds),
        attempts=[],
    )

    assert factory.model_aware_try_provider(model="model-a", **common) == "ok"
    assert factory.model_aware_try_provider(model="model-b", **common) == "ok"
    assert sleeps == []

    assert factory.model_aware_try_provider(model="model-a", **common) == "ok"
    assert sleeps == [factory._budget.PREMIUM_RATE_LIMIT_WAIT_CEILING_SECONDS]
    assert calls == ["model-a", "model-b", "model-a"]


def test_balanced_primary_preserves_every_configured_groq_model(monkeypatch):
    config = Config(
        groq_api_key="k",
        llm_model_groq="primary",
        llm_model_groq_fallbacks=("small-a", "small-b", "small-c"),
    )
    captured = {}

    def fake_call(routed, prompt, max_tokens=3000, attempts=None, sleep_fn=None):
        captured["models"] = [routed.llm_model_groq, *routed.llm_model_groq_fallbacks]
        return "<h3>Executive Summary</h3>", "groq"

    monkeypatch.setattr(factory, "_ORIGINAL_PREMIUM_CALL", fake_call)
    result = factory.balanced_premium_llm(
        config,
        "SOURCE URL: https://example.test/a\n",
        attempts=[],
        sleep_fn=lambda _seconds: None,
    )

    assert result[1] == "groq"
    assert set(captured["models"]) == {"primary", "small-a", "small-b", "small-c"}
    assert len(captured["models"]) == 4


def test_key_judgements_use_secondary_models_first_and_bounded_tokens(monkeypatch):
    config = Config(
        groq_api_key="k",
        llm_model_groq="primary-120b",
        llm_model_groq_fallbacks=("small-20b", "qwen-a", "qwen-b"),
    )
    captured = {}

    def fake_call(routed, prompt, max_tokens=2000, attempts=None, sleep_fn=None):
        captured["primary"] = routed.llm_model_groq
        captured["models"] = [routed.llm_model_groq, *routed.llm_model_groq_fallbacks]
        captured["max_tokens"] = max_tokens
        return "[]", "groq"

    monkeypatch.setattr(factory._budget, "_ORIGINAL_KEY_JUDGEMENTS_LLM_CALL", fake_call)
    result = factory.balanced_key_judgements_llm(
        config,
        "SOURCE URL: https://example.test/key-judgements\n",
        max_tokens=2000,
        attempts=[],
        sleep_fn=lambda _seconds: None,
    )

    assert result == ("[]", "groq")
    assert captured["primary"] in {"small-20b", "qwen-a", "qwen-b"}
    assert captured["models"][-1] == "primary-120b"
    assert captured["max_tokens"] == factory.FACTORY_KEY_JUDGEMENT_TOKENS


def test_factory_scheduler_drains_cve_supply_without_starving_strategic_intel(monkeypatch):
    # Fix rotation only so the assertion is deterministic; the production
    # implementation intentionally rotates it every 15-minute UTC slot.
    monkeypatch.setattr(factory.time, "time", lambda: 0.0)
    vulnerabilities = [
        _article(i, title=f"CVE-2026-{10000 + i} critical vulnerability", source="nvd", cve_id=f"CVE-2026-{10000 + i}")
        for i in range(10)
    ]
    malware = _article(100, title="New malware loader campaign targets enterprises")

    selection = factory.select_factory_publication_batch([], vulnerabilities + [malware], 5)

    assert len(selection.articles) == 5
    assert selection.metrics["vulnerability_selected"] == 4
    assert selection.metrics["strategic_selected"] == 1
    assert selection.metrics["selected_families"]["malware"] == 1


def test_factory_classifier_exposes_major_global_cti_report_families():
    cases = [
        ("CVE-2026-12345 remote code execution vulnerability", "nvd", "CVE-2026-12345", "vulnerability"),
        ("Vendor confirms zero-day security advisory", "global_rss", None, "zero_day"),
        ("New infostealer malware campaign observed", "global_rss", None, "malware"),
        ("Ransomware group posts extortion claim", "ransomware_intel", None, "ransomware"),
        ("Company publishes data breach notice", "breach_intel", None, "breach"),
        ("Security incident affects production systems", "global_rss", None, "incident"),
        ("APT29 threat actor campaign update", "threat_actor_intel", None, "campaign"),
        ("Phishing campaign targets cloud identities", "global_rss", None, "phishing"),
        ("Supply-chain dependency compromise affects npm package", "global_rss", None, "supply_chain"),
        ("LLM prompt injection vulnerability in AI agent", "global_rss", None, "ai_security"),
    ]
    for index, (title, source, cve_id, expected) in enumerate(cases):
        assert factory.classify_factory_family(
            _article(index, title=title, source=source, cve_id=cve_id)
        ) == expected


def test_factory_nvd_window_keeps_up_to_forty_recent_critical_and_high(monkeypatch):
    source = factory._nvd.NVDCVESource(Config())
    critical = [_article(i, title=f"critical-{i}", source="nvd") for i in range(20)]
    high = [_article(100 + i, title=f"high-{i}", source="nvd") for i in range(20)]

    monkeypatch.setattr(
        source,
        "_fetch_by_severity",
        lambda severity, _state: critical if severity == "CRITICAL" else high,
    )

    result = factory.factory_nvd_discover(source, object())
    assert len(result) == 40
    assert result[:20] == critical
    assert result[20:] == high


def test_factory_retry_store_scales_without_changing_fail_closed_state(tmp_path, monkeypatch):
    state = PublicationState(str(tmp_path / "state.json"))
    monkeypatch.setenv("CDB_FACTORY_RETRY_QUEUE_LIMIT", "500")
    monkeypatch.setenv("CDB_FACTORY_RETRY_ATTEMPTS", "5")

    for index in range(25):
        factory.factory_add_to_retry_queue(
            state,
            _article(index, title=f"Evidence-blocked report {index}"),
            "premium gate blocked",
        )

    assert len(state._state["retry_queue"]) == 25
    assert len(factory.factory_get_retry_queue(state)) == 25

    target = _article(0, title="Evidence-blocked report 0")
    for _ in range(5):
        factory.factory_add_to_retry_queue(state, target, "still blocked")
    queued = next(item for item in state._state["retry_queue"] if item["content_hash"] == target.content_hash)
    assert queued["attempts"] == 6
    assert target.content_hash not in {item["content_hash"] for item in factory.factory_get_retry_queue(state)}


def test_factory_discovery_window_is_broad_but_bounded():
    assert factory.factory_candidate_discovery_limit(5) == 200
    assert factory.factory_candidate_discovery_limit(50) == 300
    assert factory.factory_candidate_discovery_limit(1000) == 300


def test_daily_delivery_classifier_maps_customer_report_classes():
    cases = [
        (
            _article(201, title="Akira ransomware claim against Example Corp", source="ransomware_intel"),
            "ransomware",
        ),
        (
            _article(202, title="New infostealer malware campaign targets enterprise identities"),
            "malware_campaign",
        ),
        (
            _article(203, title="Backdoor malware attack compromises enterprise endpoints"),
            "malware_attack",
        ),
        (
            _article(204, title="Deep malware research on newly observed backdoor"),
            "malware",
        ),
        (
            _article(205, title="Company publishes data breach notice", source="breach_intel"),
            "breach",
        ),
        (
            _article(206, title="APT29 threat actor campaign update"),
            "threat_analysis",
        ),
        (
            _article(
                207,
                title="CVE-2026-55555 remote code execution vulnerability",
                source="nvd",
                cve_id="CVE-2026-55555",
            ),
            None,
        ),
    ]

    for article, expected in cases:
        assert factory.classify_delivery_class(article) == expected


def test_daily_delivery_sla_prioritizes_missing_ransomware_without_disabling_cves(monkeypatch):
    monkeypatch.setattr(factory, "_DAILY_DELIVERY_SLA_ACTIVE", True)
    monkeypatch.setattr(
        factory,
        "_ACTIVE_DAILY_DELIVERED",
        frozenset({
            "malware",
            "malware_campaign",
            "malware_attack",
            "breach",
            "threat_analysis",
        }),
    )
    monkeypatch.setattr(factory.time, "time", lambda: 0.0)

    vulnerabilities = [
        _article(
            i,
            title=f"CVE-2026-{20000 + i} critical vulnerability",
            source="nvd",
            cve_id=f"CVE-2026-{20000 + i}",
        )
        for i in range(10)
    ]
    ransomware = _article(
        299,
        title="ExampleGroup ransomware claims Example Corp",
        source="ransomware_intel",
    )

    selection = factory.select_factory_publication_batch(
        [],
        vulnerabilities + [ransomware],
        5,
    )

    assert len(selection.articles) == 5
    assert ransomware in selection.articles
    assert selection.metrics["selected_delivery_classes"]["ransomware"] == 1
    assert "ransomware" not in selection.metrics["delivery_sla_missing_after_selection"]
    assert selection.metrics["vulnerability_selected"] == 4


def test_daily_delivery_sla_never_holds_empty_slots_or_fabricates_supply(monkeypatch):
    monkeypatch.setattr(factory, "_DAILY_DELIVERY_SLA_ACTIVE", True)
    monkeypatch.setattr(factory, "_ACTIVE_DAILY_DELIVERED", frozenset())
    monkeypatch.setattr(factory.time, "time", lambda: 0.0)

    vulnerabilities = [
        _article(
            i,
            title=f"CVE-2026-{30000 + i} critical vulnerability",
            source="nvd",
            cve_id=f"CVE-2026-{30000 + i}",
        )
        for i in range(10)
    ]

    selection = factory.select_factory_publication_batch([], vulnerabilities, 5)

    assert len(selection.articles) == 5
    assert selection.metrics["vulnerability_selected"] == 5
    assert selection.metrics["selected_delivery_classes"] == {}
    assert set(selection.metrics["delivery_sla_missing_after_selection"]) == set(
        factory.FACTORY_DAILY_DELIVERY_CLASSES
    )


def test_daily_delivery_ledger_counts_only_successful_publications_from_current_utc_day(tmp_path):
    import json
    from datetime import timedelta

    now = factory.datetime.now(factory.timezone.utc)
    yesterday = now - timedelta(days=1)
    state_file = tmp_path / "published.json"
    state_file.write_text(
        json.dumps({
            "posts": {
                "ransom": {
                    "published_at": now.isoformat(),
                    "source_title": "Akira ransomware claim against Example Corp",
                    "source": "ransomware_intel",
                    "labels": ["Threat Intelligence", "Ransomware"],
                    "report_family": "ransomware_claim",
                    "cves": [],
                },
                "malware_campaign": {
                    "published_at": now.isoformat(),
                    "source_title": "New infostealer malware campaign targets enterprises",
                    "source": "global_rss",
                    "labels": ["Threat Intelligence", "Malware Research"],
                    "report_family": "general_intelligence",
                    "cves": [],
                },
                "vulnerability": {
                    "published_at": now.isoformat(),
                    "source_title": "CVE-2026-55555 vulnerability",
                    "source": "nvd",
                    "labels": ["Threat Intelligence", "Vulnerabilities"],
                    "report_family": "cve_advisory",
                    "cves": ["CVE-2026-55555"],
                },
                "old_breach": {
                    "published_at": yesterday.isoformat(),
                    "source_title": "Company publishes data breach notice",
                    "source": "breach_intel",
                    "labels": ["Threat Intelligence", "Data Breach"],
                    "report_family": "breach_notice",
                    "cves": [],
                },
            }
        }),
        encoding="utf-8",
    )

    assert factory._published_delivery_classes_today(str(state_file)) == {
        "ransomware",
        "malware_campaign",
    }


def test_factory_excludes_jobs_roundup_from_family_and_daily_delivery_sla(monkeypatch):
    monkeypatch.setattr(factory, "_DAILY_DELIVERY_SLA_ACTIVE", True)
    monkeypatch.setattr(factory, "_ACTIVE_DAILY_DELIVERED", frozenset())
    monkeypatch.setattr(factory.time, "time", lambda: 0.0)

    jobs = _article(
        801,
        title="Cybersecurity jobs available right now: September 22, 2026",
        source="global_rss",
    )
    jobs.full_content = (
        "Malware Reverse Engineer: analyze malware. "
        "Threat Hunter: incident response, threat intelligence, detection engineering."
    )
    real_malware = _article(802, title="Backdoor malware attack compromises enterprise endpoints")
    ransomware = _article(803, title="Akira ransomware claim", source="ransomware_intel")
    breach = _article(804, title="Company publishes data breach notice", source="breach_intel")
    cve = _article(805, title="CVE-2026-88888 remote code execution vulnerability", source="nvd", cve_id="CVE-2026-88888")
    apt = _article(806, title="APT29 threat actor campaign update")

    assert factory.classify_factory_family(jobs) == "non_intelligence"
    assert factory.classify_delivery_class(jobs) is None

    selection = factory.select_factory_publication_batch(
        [],
        [jobs, real_malware, ransomware, breach, cve, apt],
        5,
    )

    assert jobs not in selection.articles
    assert selection.metrics["non_intelligence_filtered"] == 1
    assert "non_intelligence" not in selection.metrics["selected_families"]
    assert len(selection.articles) == 5
