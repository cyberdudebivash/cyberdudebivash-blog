from datetime import datetime, timezone, timedelta

from automation.content_discovery import DiscoveredArticle
from automation.publication_scheduler import (
    candidate_discovery_limit,
    classify_publication_family,
    is_cti_relevant,
    select_publication_batch,
)


def article(idx: int, *, source: str, title: str, labels=None, url_host="example.test", summary=None, full_content=None):
    published = (datetime.now(timezone.utc) - timedelta(minutes=idx)).isoformat()
    return DiscoveredArticle(
        url=f"https://{url_host}/reports/{idx}.html",
        title=title,
        summary=title if summary is None else summary,
        published_at=published,
        content_hash=f"hash-{source}-{idx}",
        labels=list(labels or ["Threat Intelligence"]),
        source=source,
        full_content=full_content,
    )


def test_candidate_budget_is_wider_than_blogger_write_budget_but_bounded():
    assert candidate_discovery_limit(5) == 50
    assert candidate_discovery_limit(20) == 100
    assert candidate_discovery_limit(500) == 100


def test_nvd_burst_cannot_starve_strategic_intelligence():
    fresh = [
        article(i, source="nvd", title=f"CVE-2026-{10000 + i} critical vulnerability")
        for i in range(10)
    ]
    fresh += [
        article(100 + i, source="ransomware_intel", title=f"Ransomware campaign {i}")
        for i in range(5)
    ]
    fresh += [
        article(200 + i, source="breach_intel", title=f"Data breach notice {i}")
        for i in range(5)
    ]

    result = select_publication_batch([], fresh, 5)

    assert len(result.articles) == 5
    assert result.metrics["strategic_selected"] >= 3
    assert result.metrics["vulnerability_selected"] <= 2
    assert any(a.source == "ransomware_intel" for a in result.articles)
    assert any(a.source == "breach_intel" for a in result.articles)


def test_vulnerability_only_run_preserves_full_throughput():
    fresh = [
        article(i, source="nvd", title=f"CVE-2026-{20000 + i} high vulnerability")
        for i in range(8)
    ]
    result = select_publication_batch([], fresh, 5)
    assert len(result.articles) == 5
    assert result.metrics["vulnerability_selected"] == 5
    assert result.metrics["strategic_selected"] == 0


def test_retry_backlog_cannot_monopolise_when_fresh_work_exists():
    retry = [
        article(i, source="nvd", title=f"CVE-2026-{30000 + i} retry vulnerability")
        for i in range(10)
    ]
    fresh = [
        article(100 + i, source="ransomware_intel", title=f"Fresh ransomware report {i}")
        for i in range(5)
    ]

    result = select_publication_batch(retry, fresh, 5)

    assert len(result.articles) == 5
    assert result.metrics["fresh_selected"] >= 3
    assert result.metrics["retry_selected"] <= 2
    assert result.metrics["strategic_selected"] >= 3


def test_global_strategic_reserve_survives_mixed_fresh_and_retry_allocation():
    retry = [
        article(i, source="nvd", title=f"CVE-2026-{35000 + i} retry vulnerability")
        for i in range(6)
    ]
    fresh = [
        article(100, source="ransomware_intel", title="Fresh ransomware campaign"),
        article(101, source="breach_intel", title="Fresh public data breach notice"),
        article(102, source="global_rss", title="Fresh malware loader campaign"),
        article(103, source="nvd", title="CVE-2026-35999 fresh vulnerability"),
    ]

    result = select_publication_batch(retry, fresh, 5)

    assert len(result.articles) == 5
    assert result.metrics["strategic_selected"] >= 3
    assert result.metrics["vulnerability_selected"] <= 2
    assert result.metrics["fresh_selected"] >= 3
    assert result.metrics["retry_selected"] <= 2


def test_retry_can_use_spare_capacity_when_fresh_supply_is_thin():
    retry = [
        article(i, source="nvd", title=f"CVE-2026-{40000 + i} retry vulnerability")
        for i in range(10)
    ]
    fresh = [article(100, source="ransomware_intel", title="Only fresh ransomware report")]

    result = select_publication_batch(retry, fresh, 5)

    assert len(result.articles) == 5
    assert result.metrics["fresh_selected"] == 1
    assert result.metrics["retry_selected"] == 4


def test_canonical_report_is_preferred_within_same_title():
    external = article(
        1,
        source="global_rss",
        title="New malware campaign targets enterprise VPNs",
        url_host="news.example",
    )
    canonical = article(
        2,
        source="rss",
        title="New malware campaign targets enterprise VPNs",
        url_host="blog.cyberdudebivash.in",
    )

    result = select_publication_batch([], [external, canonical], 1)

    assert len(result.articles) == 1
    assert result.articles[0].url.startswith("https://blog.cyberdudebivash.in/")
    assert result.metrics["canonical_selected"] == 1


def test_strategic_round_robin_represents_distinct_report_families():
    fresh = [
        article(1, source="global_rss", title="Zero-day exploitation observed", labels=["Zero-Day"]),
        article(2, source="global_rss", title="New malware loader campaign"),
        article(3, source="ransomware_intel", title="Ransomware victim claim"),
        article(4, source="breach_intel", title="Public data breach notice"),
        article(5, source="threat_actor_intel", title="APT campaign activity"),
    ]

    result = select_publication_batch([], fresh, 5)
    families = {classify_publication_family(item) for item in result.articles}

    assert {"zero_day", "malware", "ransomware", "breach", "campaign"}.issubset(families)


def test_jobs_roundup_is_blocked_even_when_role_descriptions_mention_malware_and_soc():
    jobs = article(
        900,
        source="global_rss",
        title="Cybersecurity jobs available right now: September 22, 2026",
        summary="Open security roles across engineering, analysis, and leadership.",
        full_content=(
            "Malware Reverse Engineer: analyze malware campaigns. "
            "Threat Hunter: investigate intrusions. SOC Analyst: incident response."
        ),
    )

    assert is_cti_relevant(jobs) is False

    result = select_publication_batch([], [jobs], 5)
    assert result.articles == []
    assert result.metrics["relevance_blocked"] == 1
    assert result.metrics["fresh_relevance_blocked"] == 1


def test_primary_subject_classifier_ignores_incidental_body_keywords():
    jobs = article(
        901,
        source="global_rss",
        title="Cybersecurity jobs available right now",
        summary="A roundup of current cybersecurity employment opportunities.",
        full_content="Malware campaign analysis, ransomware response, and threat hunting are job duties.",
    )
    assert classify_publication_family(jobs) == "threat_analysis"

    real_malware = article(
        902,
        source="global_rss",
        title="New infostealer malware campaign targets enterprise browsers",
        summary="Researchers observed a new infostealer distribution campaign.",
        full_content="The article also advertises a webinar at the end.",
    )
    assert is_cti_relevant(real_malware) is True
    assert classify_publication_family(real_malware) == "malware"


def test_non_threat_term_does_not_override_real_incident_subject():
    incident = article(
        903,
        source="global_rss",
        title="Security conference website breached after credential compromise",
        summary="Organizers disclosed a breach affecting the event website.",
    )
    assert is_cti_relevant(incident) is True
    assert classify_publication_family(incident) == "breach"
