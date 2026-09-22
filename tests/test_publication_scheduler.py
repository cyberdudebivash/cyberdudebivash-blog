from datetime import datetime, timezone, timedelta

from automation.content_discovery import DiscoveredArticle
from automation.publication_scheduler import (
    candidate_discovery_limit,
    classify_publication_family,
    is_non_threat_editorial,
    select_publication_batch,
)


def article(idx: int, *, source: str, title: str, labels=None, url_host="example.test"):
    published = (datetime.now(timezone.utc) - timedelta(minutes=idx)).isoformat()
    return DiscoveredArticle(
        url=f"https://{url_host}/reports/{idx}.html",
        title=title,
        summary=title,
        published_at=published,
        content_hash=f"hash-{source}-{idx}",
        labels=list(labels or ["Threat Intelligence"]),
        source=source,
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


def test_cybersecurity_jobs_roundup_is_not_threat_intelligence_even_with_threat_keywords():
    jobs = article(
        900,
        source="global_rss",
        title="Cybersecurity jobs available right now: September 22, 2026",
        labels=["Threat Intelligence", "Malware Research", "Incident Response"],
    )
    jobs.full_content = (
        "Malware Reverse Engineer role analyzes malware campaigns. "
        "Threat Hunter role supports incident response and threat intelligence."
    )

    assert is_non_threat_editorial(jobs) is True
    assert classify_publication_family(jobs) == "non_intelligence"

    malware = article(
        901,
        source="global_rss",
        title="Malware campaign targets enterprise CI/CD jobs",
    )
    assert is_non_threat_editorial(malware) is False
    assert classify_publication_family(malware) == "malware"


def test_non_threat_editorial_is_removed_before_cti_publication_slot_allocation():
    jobs = article(
        910,
        source="global_rss",
        title="Cybersecurity jobs available right now: September 22, 2026",
    )
    jobs.full_content = "Malware reverse engineering and incident response jobs are listed."
    threats = [
        article(911, source="ransomware_intel", title="Akira ransomware victim claim"),
        article(912, source="breach_intel", title="Company publishes data breach notice"),
        article(913, source="global_rss", title="New infostealer malware campaign"),
        article(914, source="nvd", title="CVE-2026-99114 critical vulnerability"),
        article(915, source="global_rss", title="APT29 threat actor campaign activity"),
    ]

    result = select_publication_batch([], [jobs, *threats], 5)

    assert jobs not in result.articles
    assert len(result.articles) == 5
    assert result.metrics["non_intelligence_filtered"] == 1
    assert "non_intelligence" not in result.metrics["selected_families"]
