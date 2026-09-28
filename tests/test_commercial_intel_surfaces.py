#!/usr/bin/env python3
"""P0 commercial intelligence surface integrity gate."""
from pathlib import Path
import json

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
    # P0 full SOC 2 / CTI customer-release package: these checks execute in
    # the production workflow's direct python invocation, not only under pytest.
    required_release_files = [
        Path("customer-assurance.html"),
        Path("service-status.html"),
        Path("enterprise-onboarding.html"),
        Path("cti-delivery-acceptance.html"),
        Path("api/intel/customer-assurance.json"),
        Path("api/intel/service-assurance.json"),
        Path("api/intel/cti-delivery-acceptance.json"),
        Path("api/v1/customer/assurance.js"),
    ]
    for release_file in required_release_files:
        if not release_file.exists():
            failures.append(f"{release_file}: required customer-release artifact missing")

    enterprise = Path("enterprise.html").read_text(encoding="utf-8-sig")
    for forbidden in [
        "99.9% SLA UPTIME", "99.9% uptime SLA", "Sub-100ms latency",
        "Low FP guarantee", "4-hour emergency response SLA",
        "24–72 hours before public disclosure", "Pre-disclosure CVE access",
        "Early CVE disclosure access", "4-hour emergency SLA",
        "FORTUNE 500 READY", "SLA-backed CVE data", "SLA guarantees",
    ]:
        if forbidden.lower() in enterprise.lower():
            failures.append(f"enterprise.html: unsupported assurance/commercial claim remains: {forbidden}")

    service = json.loads(Path("api/intel/service-assurance.json").read_text(encoding="utf-8"))
    acceptance = json.loads(Path("api/intel/cti-delivery-acceptance.json").read_text(encoding="utf-8"))
    if service.get("historical_uptime_percentage") is not None or service.get("historical_uptime_claimed") is not False:
        failures.append("api/intel/service-assurance.json: historical uptime must fail closed without measured history")
    if acceptance.get("automatic_acceptance") is not False or len(acceptance.get("criteria", [])) != 10:
        failures.append("api/intel/cti-delivery-acceptance.json: acceptance contract must require 10 explicit customer criteria")

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

def test_homepage_has_single_authoritative_header_and_control_strip():
    html = Path("index.html").read_text(encoding="utf-8-sig")
    assert html.count('<header id="main-header">') == 1
    assert html.count('id="live-critical-alert-bar"') == 1
    assert html.count('class="apex-status-bar"') == 1
    assert html.count('id="cdb-live-command-center"') == 1
    assert html.count('class="mobile-nav-drawer"') == 1


def test_homepage_is_soc2_cti_customer_command_center_and_not_static_incident_marketing():
    html = Path("index.html").read_text(encoding="utf-8-sig")
    css = Path("apex-command-center.css").read_text(encoding="utf-8")
    runtime = Path("apex-command-center.js").read_text(encoding="utf-8")
    for required in [
        "LIVE HYBRID SOC 2 + CTI OPERATIONS",
        "Enterprise Security Intelligence Command Center",
        "/customer-assurance.html",
        "ALIGNED · NOT CERTIFIED",
        'id="cdb-integrity-state"',
        "Synthetic Customer Telemetry",
        "Search cyber threat intelligence",
        "CISA KEV",
        'id="cdb-live-command-center"',
        'id="cdbSignalCanvas"',
        "No synthetic incident queue is displayed.",
        "Abstract topology generated from the current priority feed.",
        "ASSURANCE BOUNDARY",
        "SOC 2 Type I or Type II certification",
    ]:
        assert required in html
    for required in [
        "fetchJson('/live-intel.json')",
        "fetchJson('/api/intel/customer-assurance.json')",
        "a.cti_controls.source_bound_evidence?'SOURCE-BOUND':'VERIFY'",
        "fetchJson('/api/intel/service-assurance.json')",
        "fetchJson('/api/intel/cti-delivery-acceptance.json')",
        "stats.cisaKev",
        "stats.exploited",
        "stats.ransomware",
        "stats.sources",
    ]:
        assert required in runtime
    assert ".cdb-grid" in css
    assert ".cdb-fabric" in css

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
        "LIVE HYBRID SOC 2 + CTI OPERATIONS",
        "Security Intelligence Command Center",
        "ALIGNED · NOT CERTIFIED",
        'id="cdb-integrity-state"',
        "Synthetic Customer Telemetry",
        "customer-assurance.html",
        "apex-command-center.js",
        "apex-command-center.css",
    ]:
        assert required in workflow


def test_homepage_exposes_runtime_derived_cti_metrics_and_control_evidence():
    html = Path("index.html").read_text(encoding="utf-8-sig")
    runtime = Path("apex-command-center.js").read_text(encoding="utf-8")
    for required in [
        'id="cdb-total"',
        'id="cdb-critical"',
        'id="cdb-kev"',
        'id="cdb-exploited"',
        'id="cdb-ransomware"',
        'id="cdb-sources"',
        'id="cdb-freshness"',
        "API-key boundary: protected operations",
        "Production assets: allowlisted",
        "No synthetic incident queue is displayed.",
        "SOC 2 Type I or Type II certification",
    ]:
        assert required in html
    for required in [
        "feed.totalPublished",
        "stats.critical",
        "stats.cisaKev",
        "stats.exploited",
        "stats.ransomware",
        "stats.sources",
        "feedStamp(feed)",
    ]:
        assert required in runtime

def test_homepage_release_certifies_major_customer_routes():
    workflow = Path(".github/workflows/cloudflare-production-deploy.yml").read_text(encoding="utf-8")
    for required in [
        'customer_route_check() {',
        'customer_route_check "/intel/" "Live Threat Intelligence Feed"',
        'customer_route_check "/hunts.html" "Threat Hunting Workspace"',
        'customer_route_check "/detections/" "Traceable Detection Pack"',
        'customer_route_check "/customer-assurance.html" "Operational assurance for enterprise CTI customers."',
        'customer_route_check "/api-dashboard.html" "API Dashboard — CYBERDUDEBIVASH SENTINEL APEX"',
        'customer_route_check "/service-status.html" "Availability without invented percentages."',
        'customer_route_check "/enterprise-onboarding.html" "From security review to accepted CTI delivery."',
        'customer_route_check "/customer-incident-response.html" "Customer Incident"',
        'customer_route_check "/cti-delivery-acceptance.html" "Acceptance is evidence, not assumption."',
        'customer_route_check "/products.html" "Premium Intelligence Reports"',
        'customer_route_check "/pricing.html" "Pricing — CYBERDUDEBIVASH SENTINEL APEX Threat Intelligence Plans"',
        'customer_route_check "/enterprise.html" "Enterprise Threat Intelligence Platform — CYBERDUDEBIVASH SENTINEL APEX"',
        'customer_route_check "/search.html" "cybersecurity reports"',
    ]:
        assert required in workflow


def test_homepage_exposes_premium_soc2_cti_brand_and_live_hero():
    html = Path("index.html").read_text(encoding="utf-8-sig")
    css = Path("apex-command-center.css").read_text(encoding="utf-8")
    runtime = Path("apex-command-center.js").read_text(encoding="utf-8")
    for required in [
        "CYBERDUDEBIVASH SENTINEL APEX SOC 2 & CTI PLATFORM",
        "SENTINEL APEX SOC 2 &amp; CTI PLATFORM",
        "Enterprise Security Intelligence",
        "SOC 2 Assurance",
        "CTI Operations",
        'id="cdb-edge-state"',
        'class="cdb-hero"',
        'class="cdb-hero-visual"',
        'id="cdb-hero-total"',
        'id="cdb-hero-kev"',
        'id="cdb-hero-sources"',
        'id="cdb-hero-freshness"',
        'id="cdb-hero-assurance"',
        "SOC 2-ALIGNED",
        "Not certified",
    ]:
        assert required in html
    for required in [
        ".cdb-brand-lockup",
        ".cdb-platform-name",
        ".cdb-trust-strip",
        ".cdb-hero-brand",
        ".cdb-hero-company",
        ".cdb-hero-platform",
        ".cdb-hero-visual",
        ".cdb-orbit",
        ".cdb-hero-metric",
    ]:
        assert required in css
    for required in [
        "setText('cdb-hero-total'",
        "setText('cdb-hero-kev'",
        "setText('cdb-hero-sources'",
        "setText('cdb-hero-freshness'",
        "setText('cdb-hero-assurance'",
        "PRODUCTION EDGE · VERIFIED",
    ]:
        assert required in runtime


def test_homepage_command_center_meets_enterprise_visibility_floor():
    html = Path("index.html").read_text(encoding="utf-8-sig")
    css = Path("apex-command-center.css").read_text(encoding="utf-8")
    assert "CYBERDUDEBIVASH SENTINEL APEX SOC 2 & CTI PLATFORM" in html
    assert "/apex-command-center.css?v=20260928-brandhero1" in html
    assert "/apex-command-center.js?v=20260928-brandhero1" in html
    for required in [
        "#main-header nav a{",
        "font-size:13px!important",
        "min-height:48px",
        ".cdb-panel-title{font-size:13.5px",
        ".cdb-kpi-value{margin:11px 0 8px;font-size:32px",
        ".cdb-feed-title{font-size:13px",
        ".cdb-assurance-desc{font-size:11.8px",
        ".cdb-search input{",
        "height:50px",
        ".cdb-quick a{",
        "min-height:46px",
        "a:focus-visible,button:focus-visible,input:focus-visible",
    ]:
        assert required in css


def test_homepage_release_gate_waits_for_current_release_markers_not_just_http_200():
    workflow = Path(".github/workflows/cloudflare-production-deploy.yml").read_text(encoding="utf-8")
    homepage_gate = workflow.split('name: "Certify SOC 2 + CTI homepage command center"', 1)[1].split('name: "Certify SOC 2 + CTI customer assurance"', 1)[0]
    assert 'local ready=0' in homepage_gate
    assert "grep -Fq 'LIVE HYBRID SOC 2 + CTI OPERATIONS' \"$file\"" in homepage_gate
    assert 'grep -Fq \'id="cdb-kev"\' "$file"' in homepage_gate
    assert 'grep -Fq \'id="cdb-freshness"\' "$file"' in homepage_gate
    assert 'ready=1' in homepage_gate
    assert 'test "$ready" -eq 1' in homepage_gate
    assert 'if [ "$code" = "200" ]; then break; fi' not in homepage_gate
    assert 'fetch_asset() {' in homepage_gate
    assert 'fetch_asset "/apex-command-center.css"' in homepage_gate
    assert 'fetch_asset "/apex-command-center.js"' in homepage_gate
    assert 'fetch_page "/apex-command-center.css"' not in homepage_gate
    assert 'fetch_page "/apex-command-center.js"' not in homepage_gate

def test_full_soc2_cti_customer_release_package_contract():
    assurance = Path("customer-assurance.html").read_text(encoding="utf-8-sig")
    service = Path("service-status.html").read_text(encoding="utf-8-sig")
    onboarding = Path("enterprise-onboarding.html").read_text(encoding="utf-8-sig")
    acceptance = Path("cti-delivery-acceptance.html").read_text(encoding="utf-8-sig")
    dashboard = Path("api-dashboard.html").read_text(encoding="utf-8-sig")
    enterprise = Path("enterprise.html").read_text(encoding="utf-8-sig")

    for required in [
        "/service-status.html",
        "/enterprise-onboarding.html",
        "/cti-delivery-acceptance.html",
        "GET /api/v1/customer/assurance?download=1",
    ]:
        assert required in assurance

    for required in [
        "Availability without invented percentages.",
        "Historical uptime percentages are not fabricated",
        "Marketing copy is not an SLA.",
        "security@cyberdudebivash.in",
        "contact@cyberdudebivash.in",
        "ALIGNED · NOT CERTIFIED",
    ]:
        assert required in service

    for required in [
        "From security review to accepted CTI delivery.",
        "Security & vendor-risk review",
        "Access provisioning",
        "CTI integration validation",
        "Delivery acceptance",
        "GET /api/v1/customer/assurance",
    ]:
        assert required in onboarding

    for criterion in [f"A{i}" for i in range(1, 11)]:
        assert criterion in acceptance
    assert "No silent acceptance." in acceptance
    assert "CUSTOMER VERIFY" in acceptance

    assert "Download Assurance JSON" in dashboard
    assert "/api/v1/customer/assurance?download=1" in dashboard
    assert "sessionKey" in dashboard
    assert "localStorage.setItem" not in dashboard
    assert "sessionStorage.setItem" not in dashboard

    for forbidden in [
        "99.9% SLA UPTIME",
        "99.9% uptime SLA",
        "Sub-100ms latency",
        "Low FP guarantee",
        "4-hour emergency response SLA",
        "24–72 hours before public disclosure",
        "Pre-disclosure CVE access",
        "Early CVE disclosure access",
        "4-hour emergency SLA",
        "FORTUNE 500 READY",
        "SLA-backed CVE data",
        "SLA guarantees",
        "Major Bank Reduces MTTD",
        "Hospital Network Deploys",
        "MSSP White-Labels CYBERDUDEBIVASH",
        "Email support (24h SLA)",
        "Custom rule development SLA",
    ]:
        assert forbidden.lower() not in enterprise.lower()


def test_machine_readable_service_and_acceptance_truth_boundaries():
    service = json.loads(Path("api/intel/service-assurance.json").read_text(encoding="utf-8"))
    acceptance = json.loads(Path("api/intel/cti-delivery-acceptance.json").read_text(encoding="utf-8"))
    assurance = json.loads(Path("api/intel/customer-assurance.json").read_text(encoding="utf-8"))

    assert service["historical_uptime_percentage"] is None
    assert service["historical_uptime_claimed"] is False
    assert service["contractual_sla"]["status"] == "CUSTOMER_SPECIFIC_IF_EXECUTED"
    assert acceptance["automatic_acceptance"] is False
    assert len(acceptance["criteria"]) == 10
    assert {c["id"] for c in acceptance["criteria"]} == {f"A{i}" for i in range(1, 11)}
    assert assurance["soc2_certified"] is False
    assert assurance["soc2_attestation_published"] is False
    assert assurance["customer_resources"]["authenticated_customer_evidence"] == "/api/v1/customer/assurance"
    assert assurance["customer_resources"]["service_assurance"] == "/service-status.html"
    assert assurance["customer_resources"]["enterprise_onboarding"] == "/enterprise-onboarding.html"
    assert assurance["customer_resources"]["cti_delivery_acceptance"] == "/cti-delivery-acceptance.html"


def test_authenticated_customer_assurance_export_is_scoped_and_fail_closed():
    handler = Path("api/v1/customer/assurance.js").read_text(encoding="utf-8")
    route_table = Path("workers/lib/route-table.js").read_text(encoding="utf-8")
    router = Path("workers/lib/router.js").read_text(encoding="utf-8")

    for required in [
        "authenticate(req, res)",
        "globalIpRateLimit",
        "Cache-Control",
        "no-store",
        "soc2_certified: false",
        "soc2_attestation_published: false",
        "historical_uptime_percentage: null",
        "Content-Disposition",
        "customer_scope",
    ]:
        assert required in handler
    assert "user.keyHash" not in handler
    assert "api_key" not in handler.lower()
    assert "'api/v1/customer/assurance'" in route_table
    assert "'api/v1/customer/assurance': () => require('../../api/v1/customer/assurance')" in router


def test_cloudflare_release_certifies_complete_customer_release_package():
    workflow = Path(".github/workflows/cloudflare-production-deploy.yml").read_text(encoding="utf-8")
    for required in [
        "dist-public/service-status.html",
        "dist-public/enterprise-onboarding.html",
        "dist-public/cti-delivery-acceptance.html",
        "dist-public/api/intel/service-assurance.json",
        "dist-public/api/intel/cti-delivery-acceptance.json",
        'fetch_page "/service-status.html"',
        'fetch_page "/enterprise-onboarding.html"',
        'fetch_page "/cti-delivery-acceptance.html"',
        'test "$code" = "401"',
        "Download Assurance JSON",
        "CUSTOMER_SPECIFIC_IF_EXECUTED",
        ".automatic_acceptance == false",
        "CUSTOM SLA BY CONTRACT",
        "Operational patterns without invented customer outcomes",
        'test "$enterprise_ready" -eq 1',
    ]:
        assert required in workflow

def test_api_dashboard_contract_and_freshness_copy_is_truth_bound():
    dashboard = Path("api-dashboard.html").read_text(encoding="utf-8-sig")
    for required in [
        "Operational intelligence feed with runtime timestamps",
        "Contract-defined SLA where explicitly executed",
        "Dedicated analyst option / contract-defined SLA",
    ]:
        assert required in dashboard
    for forbidden in [
        "Real-time intel feed",
        "SLA guarantee",
        "Dedicated analyst / custom SLA",
    ]:
        assert forbidden not in dashboard

