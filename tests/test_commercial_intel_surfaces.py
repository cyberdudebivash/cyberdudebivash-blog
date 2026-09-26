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
    for required in ["setRuntimeState('UNAVAILABLE'", "setRuntimeState('DEGRADED'", "setRuntimeState('LIVE'", "setRuntimeState('STALE'"]:
        if required not in engine:
            failures.append(f"{ENGINE}: missing runtime trust state: {required}")
    if "cveCount || '50+'" in engine:
        failures.append(f"{ENGINE}: synthetic CVE fallback count is forbidden")
    if failures:
        raise SystemExit("\n".join(failures))
    print("commercial-intel-surface-integrity: PASS")

if __name__ == "__main__":
    main()
