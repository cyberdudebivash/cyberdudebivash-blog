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
        assert 'soc-ops-commandbar' in html
        assert 'Validate → Investigate → Hunt → Detect → Watch → Export' in html
        assert 'SOC 2-aligned evidence; no certification claim' in html
        assert 'updated every 10 minutes from global threat feeds' not in html.lower()
        assert 'Unlock SOC Pro — $18/mo' not in html
