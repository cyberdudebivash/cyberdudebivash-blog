#!/usr/bin/env python3
"""P0 commercial intelligence surface integrity gate."""
from pathlib import Path

SURFACES = [
    Path("malware/index.html"),
    Path("ai-security/index.html"),
    Path("intel/index.html"),
]
FORBIDDEN = {
    "malware/index.html": [
        "67+ victims this month",
        "50,000+ indicators",
        "185.220.101.47",
        "c2.lockbit4[.]onion",
    ],
    "ai-security/index.html": [
        "73% of enterprise AI deployments vulnerable",
    ],
    "intel/index.html": [
        "48h pre-disclosure CVE reports",
    ],
}

ENGINE = Path("auto-intel-engine.js")

def main():
    failures=[]
    for surface in SURFACES:
        text=surface.read_text(encoding="utf-8-sig")
        for claim in FORBIDDEN.get(surface.as_posix(), []):
            if claim.lower() in text.lower():
                failures.append(f"{surface}: unsupported commercial claim remains: {claim}")
    engine=ENGINE.read_text(encoding="utf-8-sig")
    for state in ["UNAVAILABLE", "DEGRADED", "LIVE", "STALE"]:
        single = f"setRuntimeState('{state}'"
        double = f'setRuntimeState("{state}"'
        if single not in engine and double not in engine:
            failures.append(f"{ENGINE}: missing runtime trust state: {state}")
    if "cveCount || '50+'" in engine:
        failures.append(f"{ENGINE}: synthetic CVE fallback count is forbidden")
    for forbidden in ["4,800+ analysts", "1,200+ CVEs tracked", "48H pre-disclosure", "typical weaponization window", "tracks emerging threats before NVD publication"]:
        if forbidden.lower() in engine.lower():
            failures.append(f"{ENGINE}: unsupported synthetic intelligence claim remains: {forbidden}")
    for forbidden_pattern in ["if (!filtered.length) filtered = items", "i.riskScore >= 50", "b.riskScore - a.riskScore"]:
        if forbidden_pattern in engine:
            failures.append(f"{ENGINE}: fail-closed triage regression: {forbidden_pattern}")
    if "No evidence-matched intelligence is currently available for this workspace" not in engine:
        failures.append(f"{ENGINE}: category-specific empty state must fail closed")
    for forbidden_engine_claim in ["Unlock with SOC Pro — $18/mo", "48 hours before NVD", "800+ YARA rules", r'data-risk="${item.riskScore}"']:
        if forbidden_engine_claim.lower() in engine.lower():
            failures.append(f"{ENGINE}: legacy commercial/inference claim remains: {forbidden_engine_claim}")
    for required_guard in ["ATT&CK mappings require canonical behavioral evidence from ReportX", "Attribution requires source-bound canonical claims", "safeExternalUrl", 'rel="noopener noreferrer"']:
        if required_guard not in engine:
            failures.append(f"{ENGINE}: missing evidence/security guard: {required_guard}")
    if "riskScore:   null" not in engine:
        failures.append(f"{ENGINE}: heuristic numeric risk scoring must remain disabled")
    for required in ["soc-runtime-state", "soc-critical", "soc-exploited", "soc-reports"]:
        if required not in engine:
            failures.append(f"{ENGINE}: SOC console is not runtime-bound: {required}")
    for surface in SURFACES:
        page=surface.read_text(encoding="utf-8-sig")
        if "SOC and CTI operations console" not in page:
            failures.append(f"{surface}: hybrid SOC/CTI console missing")
        if "no certification claim" not in page.lower():
            failures.append(f"{surface}: SOC 2 non-certification disclosure missing")
    if failures:
        raise SystemExit("\n".join(failures))
    print("commercial-intel-surface-integrity: PASS")

if __name__ == "__main__":
    main()

def test_enterprise_soc_command_center_contract():
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        assert 'class="soc-workspace"' in html
        assert 'aria-label="Selected intelligence actions"' in html
        assert 'SOC 2-aligned evidence; no certification claim' in html
        assert 'updated every 10 minutes from global threat feeds' not in html.lower()
        assert 'Unlock SOC Pro — $18/mo' not in html

def test_evidence_inspector_governance_contract():
    drawer = Path("soc-evidence-drawer.js").read_text(encoding="utf-8")
    for required in [
        "Not human reviewed",
        "Test-only review fixture — not production review",
        "Human review: APPROVE",
        "Human review: REJECT",
        "Human review: REQUEST_CHANGES",
        "u.protocol !== 'https:'",
        "u.username || u.password",
        "noopener noreferrer",
    ]:
        assert required in drawer
    assert "review.decision || review.status || 'Recorded'" not in drawer

def test_priority_intelligence_triage_workspace_contract():
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        assert 'class="soc-triage"' in html
        assert 'data-triage-search' in html
        assert 'data-triage-severity' in html
        assert 'Filters operate only on rendered source records.' in html
        assert '/soc-triage-workspace.js' in html


def test_browser_intel_engine_fails_closed_without_canonical_claim_evidence():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    assert "pubDate:     item.pubDate || null" in engine
    assert "severity:    'not_assessed'" in engine
    assert "cvssScore:   null" in engine
    assert "isExploited: false" in engine
    assert "isCritical:  false" in engine
    assert "isBreaking:  false" in engine
    assert "SEVERITY_KEYWORDS" not in engine
    assert "function detectSeverity" not in engine
    assert "function extractCVSS" not in engine
    assert "48 hours of NVD publication" not in engine
    assert "current dark web signals" not in engine


def test_browser_intel_external_links_require_absolute_credential_free_https():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    assert "new URL(String(value || '').trim())" in engine
    assert "u.protocol !== 'https:' || u.username || u.password" in engine
    assert "new URL(String(value || ''), window.location.origin)" not in engine


def test_browser_intel_missing_or_invalid_time_is_not_presented_as_fresh():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    assert "if (!dateStr) return 'Timestamp unavailable'" in engine
    assert "Number.isNaN(d.getTime())" in engine
    assert "return 'Recent'" not in engine


def test_browser_intel_source_label_is_html_escaped():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    assert 'source-chip\">${escHTML(item.source)}' in engine
    assert 'source-chip\">${item.source}' not in engine


def test_priority_triage_is_feed_scoped_async_aware_and_accessible():
    triage = Path("soc-triage-workspace.js").read_text(encoding="utf-8")
    assert "feed.querySelectorAll('.intel-post')" in triage
    assert "document.querySelectorAll('.intel-post')" not in triage
    assert "new MutationObserver" in triage
    assert ".observe(feed,{childList:true,subtree:true})" in triage
    assert "x.severity===sev" in triage
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        assert 'data-triage-feed="#intel-feed"' in html
        assert 'aria-live="polite"' in html
        assert '>All severities</option>' in html
        assert '>All evidence states</option>' not in html


def test_soc_commandbar_has_no_dead_root_routes():
    dead = ["/investigations.html", "/hunts.html", "/detections.html", "/watchlists.html"]
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        for route in dead:
            assert route not in html
        assert 'href="/api-dashboard.html" data-soc-action="investigate"' in html
        assert 'href="/api-dashboard.html" data-soc-action="hunt"' in html
        assert 'href="/api-dashboard.html" data-soc-action="detect"' in html
        assert 'href="/api-dashboard.html" data-soc-action="watch"' in html
        assert 'href="/api.html" data-soc-action="export"' in html


def test_evidence_inspector_source_links_are_absolute_https_only():
    drawer = Path("soc-evidence-drawer.js").read_text(encoding="utf-8")
    assert "new URL(String(raw || '').trim())" in drawer
    assert "new URL(String(raw || ''), window.location.origin)" not in drawer
    assert "u.protocol !== 'https:' || u.username || u.password" in drawer
    assert "noopener noreferrer" in drawer


def test_hybrid_soc_cti_workspace_v2_is_runtime_and_evidence_bound():
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    css = Path("soc-cti-console.css").read_text(encoding="utf-8")
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        assert 'class="soc-workspace"' in html
        assert 'data-workspace-feed="#intel-feed"' in html
        assert 'Runtime-derived · no synthetic telemetry' in html
        assert 'ReportX-bound only' in html
        assert '/soc-hybrid-workspace.js' in html
        assert 'data-requires-selection' in html
    for required in ["data-ws-runtime","data-ws-visible","data-ws-critical","data-ws-exploited","data-ws-evidence","data-ws-claims","data-ws-confirmed","cdb:soc-record-selected"]:
        assert required in controller
    assert "soc-selected-record" in css

def test_ai_security_static_taxonomy_is_not_asserted_as_live_risk_telemetry():
    html = Path("ai-security/index.html").read_text(encoding="utf-8-sig")
    assert "AI Security Analysis Taxonomy" in html
    assert "ANALYSIS CATEGORY" in html
    assert "⚠ Active AI Risks" not in html
    assert '<span class="risk-level risk-critical">CRITICAL</span>' not in html


def test_hybrid_workspace_fails_closed_without_canonical_report_id():
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    assert "data-report-id" in controller
    assert "data-requires-report-id" in controller
    assert "Browser-derived record · canonical evidence ID unavailable" in controller
    assert "title" not in controller.split("function reportId(card)",1)[1].split("}",1)[0].lower()
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        assert "data-requires-report-id" in html
        assert "Canonical evidence requires a ReportX report ID." in html


def test_hybrid_console_has_single_nonduplicated_operational_command_surface():
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        assert 'soc-ops-commandbar' not in html
        assert html.count('class="soc-commandbar"') == 1
        assert html.count('class="soc-workspace"') == 1

def test_malware_actor_taxonomy_does_not_assert_unbound_live_activity():
    html = Path("malware/index.html").read_text(encoding="utf-8-sig")
    assert "ANALYSIS CATEGORY" in html
    assert "Activity state requires current evidence" in html
    assert '<div class="threat-status status-active">● ACTIVE</div>' not in html
    assert '<div class="threat-status status-high">⚠ HIGH ACTIVITY</div>' not in html


def test_hybrid_workspace_clears_hidden_selection_and_exposes_state_accessibly():
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    assert "selected.hidden || selected.style.display==='none'" in controller
    assert "No visible intelligence record selected." in controller
    assert "Runtime state " in controller
    assert "Evidence contract state " in controller
