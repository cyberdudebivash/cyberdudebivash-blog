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
    dead = ["/investigations.html", "/detections.html", "/watchlists.html"]
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        for route in dead:
            assert route not in html
        assert 'href="/dossier.html" data-soc-action="investigate"' in html
        assert 'href="/hunts.html" data-soc-action="hunt"' in html
        assert 'href="/dossier.html" data-soc-action="detect"' in html
        assert 'href="/dossier.html" data-soc-action="watch"' in html
        assert 'href="/dossier.html" data-soc-action="export"' in html


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

def test_ai_security_taxonomy_is_live_feed_bound_not_placeholder_telemetry():
    html = Path("ai-security/index.html").read_text(encoding="utf-8-sig")
    assert "AI Security Analysis Taxonomy" in html
    assert "data-intel-pivot" in html
    assert "data-pivot-state" in html
    assert "LIVE FEED PIVOT" in html
    assert "ANALYSIS CATEGORY" not in html
    assert "⚠ Active AI Risks" not in html
    assert '<span class="risk-level risk-critical">CRITICAL</span>' not in html
    assert "/soc-taxonomy-pivots.js" in html


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

def test_malware_taxonomy_is_live_feed_bound_not_placeholder_activity():
    html = Path("malware/index.html").read_text(encoding="utf-8-sig")
    assert "data-intel-pivot" in html
    assert "data-pivot-state" in html
    assert "LIVE FEED PIVOT" in html
    assert "ANALYSIS CATEGORY" not in html
    assert "Activity state requires current evidence" not in html
    assert "Sample IOCs (Free)" not in html
    assert 'id="selected-record-preview"' in html
    assert "/soc-taxonomy-pivots.js" in html
    assert '<div class="threat-status status-active">● ACTIVE</div>' not in html
    assert '<div class="threat-status status-high">⚠ HIGH ACTIVITY</div>' not in html


def test_hybrid_workspace_clears_hidden_selection_and_exposes_state_accessibly():
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    assert "selected.hidden || selected.style.display==='none'" in controller
    assert "No visible intelligence record selected." in controller
    assert "Runtime state " in controller
    assert "Evidence contract state " in controller
    assert "aria-pressed" in controller


def test_pro_console_exposes_evidence_safe_analyst_context():
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    for token in ["data-case-record","data-case-position","data-case-runtime","data-case-evidence"]:
        assert token in controller
    for path in SURFACES:
        html = path.read_text(encoding="utf-8-sig")
        assert 'class="soc-pro-rail"' in html
        assert "Selection persistence" in html
        assert ">SESSION</dd>" in html
        assert "SOC 2-aligned evidence model" in html
        assert "SOC 2 certified" not in html
        assert "SOC 2 Type II certified" not in html
    css = Path("soc-cti-console.css").read_text(encoding="utf-8")
    assert ".soc-ops-commandbar" not in css
    assert ".soc-ops-actions" not in css


def test_soc_dashboard_uses_first_party_runtime_data_plane():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    api = Path("api/v1/intel.js").read_text(encoding="utf-8")
    assert "fetchDashboardFeed(section" in engine
    load = engine.split("function loadSection(section)", 1)[1].split("// Boot on DOMContentLoaded", 1)[0]
    assert "fetchDashboardFeed(section" in load
    assert "aggregateFeeds(section" not in load
    assert "First-party dashboard feed unavailable; no synthetic fallback substituted" in load
    assert "updateRuntimeState(enriched, payload.generated_at)" in load
    assert "action === 'dashboard'" in api
    assert "contract: 'cdb.dashboard-feed.v1'" in api
    assert "getIntel('live', 'enterprise'" in api
    for secret_field in ["iocs:", "explanation:", "scoring:", "actor_attribution:"]:
        dashboard_block = api.split("function publicDashboardItems", 1)[1].split("/* ─── Main Router", 1)[0]
        assert secret_field not in dashboard_block


def test_soc_dashboard_canonical_identity_and_session_selection_are_real():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    drawer = Path("soc-evidence-drawer.js").read_text(encoding="utf-8")
    assert "data-record-id" in engine
    assert "data-report-id" in engine
    assert "SESSION_KEY='cdb_soc_selected_record_v1'" in controller
    assert "sessionStorage.setItem" in controller
    assert "sessionStorage.getItem" in controller
    assert "AUTH_REQUIRED" in drawer
    assert "Canonical evidence requires authentication" in drawer
    assert "Open authenticated API dashboard" in drawer
    assert "cdb:soc-record-selected" in drawer


def test_commercial_runtime_has_no_synthetic_customer_activity_toasts():
    monetization = Path("monetization.js").read_text(encoding="utf-8")
    for forbidden in [
        "SOC Analyst, Fortune 500",
        "Subscribed to SOC Pro",
        "CISO, Healthcare Org",
        "Threat Hunter, Gov Agency",
        "3,800+ SOC analysts",
        "before public disclosure",
        "security professionals</strong> are viewing this report right now",
        "Math.floor(Math.random() * 65) + 24",
    ]:
        assert forbidden not in monetization
    assert "Synthetic purchase/subscription activity is intentionally disabled." in monetization
    assert "synthetic viewer counts and blanket exploitation assertions" in monetization


def test_analyst_context_rail_tracks_runtime_and_selection_outside_workspace_root():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    assert "cdb:soc-runtime-state" in engine
    for token in [
        "all(document,'[data-case-record]'",
        "all(document,'[data-case-position]'",
        "all(document,'[data-case-runtime]'",
        "all(document,'[data-case-evidence]'",
    ]:
        assert token in controller


def test_dashboard_api_normalizes_multi_reference_urls_and_malware_scope():
    api = Path("api/v1/intel.js").read_text(encoding="utf-8")
    dashboard = api.split("function publicDashboardItems", 1)[1].split("/* ─── Main Router", 1)[0]
    assert ".flatMap(ref => String(ref || '').split(/\\s*;\\s*/))" in dashboard
    assert "explicitRansomwareRecord" in dashboard
    assert "cveLinkedRansomware" in dashboard
    assert "return explicitMalware || explicitRansomwareRecord || cveLinkedRansomware" in dashboard


def test_selected_record_actions_are_contextual_customer_workflows():
    controller = Path("soc-hybrid-workspace.js").read_text(encoding="utf-8")
    for token in [
        "entityContext(card)",
        "focus=overview",
        "/hunts.html?entity_type=",
        "focus=detections",
        "focus=watch",
        "focus=export",
    ]:
        assert token in controller
    assert "syncActionTargets(root,card)" in controller
    assert "selected-record-preview" in controller


def test_dossier_completes_investigate_hunt_detect_watch_and_export_flows():
    html = Path("dossier.html").read_text(encoding="utf-8-sig")
    for anchor in [
        'id="dossier-overview"',
        'id="dossier-evidence"',
        'id="dossier-attack"',
        'id="dossier-detections"',
        'id="watch-btn-container"',
        'id="dossier-export"',
    ]:
        assert anchor in html
    for fn in [
        "downloadCurrentDossier",
        "downloadCurrentDetectionPack",
        "copyCurrentApiCommand",
        "applyWorkflowFocus",
    ]:
        assert fn in html
    assert "action=detection-pack" in html
    assert "No placeholder or synthetic artifact is produced." in html


def test_taxonomy_pivot_runtime_filters_rendered_intelligence_only():
    pivots = Path("soc-taxonomy-pivots.js").read_text(encoding="utf-8")
    assert "feed.querySelectorAll('.intel-post')" in pivots
    assert "data-filter-query" in pivots
    assert "data-triage-search" in pivots
    assert "0 matches in the current first-party feed" in pivots
    assert "this does not assert absence in your environment" in pivots
    assert "new MutationObserver(refresh)" in pivots
    assert "group.split(/\\s+/)" in pivots
    assert "group.split(/s+/)" not in pivots


def test_revenue_sample_funnel_is_real_first_party_and_published():
    html = Path("leads.html").read_text(encoding="utf-8")
    build = Path("scripts/build-cloudflare-assets.js").read_text(encoding="utf-8")
    for required in [
        "/api/v1/newsletter",
        "free_sample_report",
        "SA-2026-0001",
        "SA-2026-0002",
        "SA-2026-0003",
        "/privacy.html",
        "/terms.html",
    ]:
        assert required in html
    assert "'leads.html'" in build
    assert "formsubmit.co" not in html.lower()


def test_legacy_product_checkout_stays_fail_closed_and_routes_to_sellable_offers():
    html = Path("products.html").read_text(encoding="utf-8")
    assert "create-product-checkout" not in html
    assert "/intelligence-store.html" in html
    assert "/pricing.html" in html
    assert "legacy_product_interest" in html
    assert "exact artifact is verified deliverable" in html
    assert "Register SKU Interest" in html


def test_commercial_ctas_preserve_selected_intelligence_context():
    engine = Path("auto-intel-engine.js").read_text(encoding="utf-8")
    for required in [
        "function contextualUrl(base, item, intent)",
        "u.searchParams.set('entity_type'",
        "u.searchParams.set('entity_id'",
        "u.searchParams.set('title'",
        "u.searchParams.set('intent'",
        "contextualUrl(cp.primary.url,item,'detection-pack')",
        "contextualUrl(cp.secondary.url,item,'api')",
    ]:
        assert required in engine


def test_api_onboarding_is_explicit_and_terms_are_not_circular():
    html = Path("api-dashboard.html").read_text(encoding="utf-8")
    assert 'href="/terms.html"' in html
    assert 'href="/privacy.html"' in html
    assert "your key is issued immediately on this page" in html
    assert "function unlockWatchlists()" in html
    assert "Authentication required: enter your API key" in html
    assert 'id="watchlist-private" class="hidden"' in html


def test_dashboard_severity_uses_cvss_semantics_separate_from_priority():
    api = Path("api/v1/intel.js").read_text(encoding="utf-8")
    assert "function cvssSeverity(cvss, fallback)" in api
    assert "if (n >= 9) return 'CRITICAL'" in api
    assert "if (n >= 7) return 'HIGH'" in api
    assert "severity: cvssSeverity(i.cvss, i.threat_level)" in api
    assert "priority: String(i.threat_level || 'NOT_ASSESSED').toUpperCase()" in api


def test_priority_queue_is_first_party_and_worker_routable():
    api = Path("api/v1/intel.js").read_text(encoding="utf-8")
    routes = Path("workers/lib/route-table.js").read_text(encoding="utf-8")
    assert "'breaking'" in api
    assert "i.exploited === true" in api
    assert "sev === 'CRITICAL'" in api
    assert "/breaking/index.html" in routes


def test_primary_commercial_surfaces_do_not_promise_unimplemented_timed_trial():
    for path in [
        Path("api.html"),
        Path("revenue-cta-block.js"),
        Path("conversion-engine.js"),
        Path("ai-monetization-engine.js"),
        Path("ux-controller.js"),
        Path("intelligence.html"),
        Path("enterprise.html"),
    ]:
        text = path.read_text(encoding="utf-8-sig")
        assert "Start 7-Day Free Trial" not in text
        assert "48hr pre-disclosure" not in text.lower()


def test_commercial_truth_engines_do_not_emit_synthetic_counters_or_scarcity():
    conversion = Path("conversion-engine.js").read_text(encoding="utf-8")
    revenue = Path("revenue-cta-block.js").read_text(encoding="utf-8")
    aim = Path("ai-monetization-engine.js").read_text(encoding="utf-8")
    products = Path("products.html").read_text(encoding="utf-8")
    api = Path("api.html").read_text(encoding="utf-8")

    for text in [conversion, revenue]:
        for forbidden in [
            "4,800+",
            "1,200+ CVEs tracked",
            "80+ countries",
            "23 spots left this month",
            "Offer valid this week only",
        ]:
            assert forbidden not in text

    boot = aim.split("function boot()", 1)[1].split("// Public API", 1)[0]
    assert "DYNPRICE.injectPricingBadges()" not in boot
    assert "COUNTDOWN.startAll()" not in boot
    assert "SCARCITY.refreshAll()" not in boot
    assert "SOCIAL_PROOF.init()" not in boot
    assert "BUNDLE_ENGINE.injectBundlePrompt()" not in boot

    for forbidden in ["MOST POPULAR", "BEST SELLER", "Save $742", "60% OFF", "47+"]:
        assert forbidden not in products
    assert "Browse Certified Intelligence" in products
    assert "Compare Subscription Plans" in products
    assert "Unverified standalone bundles have been withdrawn from direct sale" in products

    assert "1,230+" not in api
    assert "Real-time (10 min)" not in api
    assert "Real-time CVE feed (0-delay)" not in api
    assert "Zero manual triage" not in api
    assert "under 30 minutes" not in api


def test_cloudflare_release_certifies_revenue_critical_customer_journeys():
    workflow = Path(".github/workflows/cloudflare-production-deploy.yml").read_text(encoding="utf-8")
    for required in [
        'Certify revenue-critical customer journeys',
        'fetch_page "/breaking/"',
        'fetch_page "/leads.html"',
        'Get Free Intelligence Sample',
        '/api/v1/newsletter',
        'fetch_page "/api-dashboard.html"',
        'your key is issued immediately on this page',
        'Authentication required: enter your API key',
        'fetch_page "/products.html"',
        'Unverified standalone bundles have been withdrawn from direct sale',
        'function contextualUrl(base, item, intent)',
        "u.searchParams.set('entity_id'",
    ]:
        assert required in workflow

def test_soc2_cti_customer_assurance_is_truthful_public_and_machine_readable():
    html = Path("customer-assurance.html").read_text(encoding="utf-8")
    machine = Path("api/intel/customer-assurance.json").read_text(encoding="utf-8")
    build = Path("scripts/build-cloudflare-assets.js").read_text(encoding="utf-8")
    enterprise = Path("enterprise.html").read_text(encoding="utf-8-sig")
    intelligence = Path("intelligence.html").read_text(encoding="utf-8-sig")

    assert "SOC 2-aligned operational evidence; not SOC 2 certified." in html
    assert "does not represent this service as SOC 2 certified" in html
    assert "source-bound evidence" in html.lower()
    assert "No synthetic SOC telemetry" in html
    assert "/security-disclosure.html" in html
    assert "/.well-known/security.txt" in html
    assert "/privacy.html" in html
    assert "/terms.html" in html
    assert "/api/intel/customer-assurance.json" in html
    assert '"soc2_certified": false' in machine
    assert '"soc2_attestation_published": false' in machine
    assert "SOC_2_ALIGNED_OPERATIONAL_EVIDENCE_NOT_CERTIFIED" in machine
    assert "customer-assurance.html" in build
    assert "/customer-assurance.html" in enterprise
    assert "/customer-assurance.html" in intelligence
    for forbidden in [
        "SOC 2 certified platform",
        "SOC 2 Type II certified",
        "SOC2 certified",
        "auditor attestation available",
    ]:
        assert forbidden.lower() not in html.lower()


def test_cloudflare_release_fail_closes_on_soc2_cti_customer_assurance():
    workflow = Path(".github/workflows/cloudflare-production-deploy.yml").read_text(encoding="utf-8")
    for required in [
        "Certify SOC 2 + CTI customer assurance",
        'fetch_page "/customer-assurance.html"',
        "SOC 2-aligned operational evidence; not SOC 2 certified.",
        'fetch_page "/api/intel/customer-assurance.json"',
        ".soc2_certified == false",
        "CTI customer assurance certified",
    ]:
        assert required in workflow

def test_homepage_is_soc2_cti_customer_command_center_and_not_static_incident_marketing():
    html = Path("index.html").read_text(encoding="utf-8-sig")
    for required in [
        "Hybrid SOC + CTI · Customer Control Plane",
        "Operational trust before analyst action.",
        "/customer-assurance.html",
        "ALIGNED · NOT CERTIFIED",
        "SOURCE-BOUND",
        "Synthetic Telemetry",
        "DISABLED",
        "Search intelligence",
        "CISA KEV",
        "<b>Priority</b> = analyst workflow ordering",
        'id="homepage-feed-state">VERIFYING',
        'id="homepage-priority-runtime">VERIFYING',
        "Open Hybrid SOC + CTI operational workspace",
        "PRIORITY INTELLIGENCE",
        "Review customer control and evidence posture",
        "Evidence-Bound Analyst Queues",
        "No synthetic victim counters",
        "Source and freshness bound",
        "Evidence-Bound · Runtime Verified",
    ]:
        assert required in html

    for forbidden in [
        "Qilin/LockBit 4.0 Active — 67 Victims April",
        "Nation-State APT Tracking in Real Time",
        "Ransomware Group Activity — Live Updates",
        "FEED STATUS: <strong>SHOWN BELOW</strong>",
        "Most Exploited CVEs This Week",
        "67 Victims",
        "$4.2B Demanded",
        "3B Users at Risk",
        "2 Unpatched",
        "PoC in Wild",
        "73% of production enterprise AI deployments vulnerable",
        "67% of successful attacks go undetected for 72+ hours",
        "150GB exfiltrated",
    ]:
        assert forbidden not in html


def test_cloudflare_release_certifies_homepage_soc2_cti_command_center():
    workflow = Path(".github/workflows/cloudflare-production-deploy.yml").read_text(encoding="utf-8")
    for required in [
        "'index.html'",
        'fetch_page "/"',
        "Hybrid SOC + CTI · Customer Control Plane",
        "Operational trust before analyst action.",
        "ALIGNED · NOT CERTIFIED",
        "SOURCE-BOUND",
        "Synthetic Telemetry",
        "customer-assurance.html",
    ]:
        assert required in workflow


def test_homepage_exposes_runtime_derived_cti_metrics_and_control_evidence():
    html = Path("index.html").read_text(encoding="utf-8-sig")
    for required in [
        "Live CTI operational metrics",
        "Production Control Evidence",
        "Exact Git SHA → Cloudflare deployment",
        "Allowlisted production asset bundle",
        "API-key boundary for protected operations",
        'id="soc2-total-published"',
        'id="soc2-critical-count"',
        'id="soc2-kev-count"',
        'id="soc2-exploited-count"',
        'id="soc2-source-count"',
        'id="soc2-pipeline-age"',
        "intel.totalPublished",
        "stats.cisaKev",
        "stats.exploited",
        "stats.sources",
        "SOC 2-aligned controls support due diligence but do not replace an independent auditor attestation.",
    ]:
        assert required in html

def test_homepage_release_gate_waits_for_current_release_markers_not_just_http_200():
    workflow = Path(".github/workflows/cloudflare-production-deploy.yml").read_text(encoding="utf-8")
    homepage_gate = workflow.split('name: "Certify SOC 2 + CTI homepage command center"', 1)[1].split('name: "Certify SOC 2 + CTI customer assurance"', 1)[0]
    assert 'local ready=0' in homepage_gate
    assert "grep -Fq 'Live CTI operational metrics' \"$file\"" in homepage_gate
    assert 'grep -Fq \'id="soc2-kev-count"\' "$file"' in homepage_gate
    assert 'grep -Fq \'id="soc2-pipeline-age"\' "$file"' in homepage_gate
    assert 'ready=1' in homepage_gate
    assert 'test "$ready" -eq 1' in homepage_gate
    assert 'if [ "$code" = "200" ]; then break; fi' not in homepage_gate

