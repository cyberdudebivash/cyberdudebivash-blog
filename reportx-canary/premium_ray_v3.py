"""Export the CVE-2025-62593 (Ray) v3.0 premium edition for human review.

    cd Sentinel-APEX/engine && python3 ../../reportx-canary/premium_ray_v3.py

Builds the bundle from cve_2025_62593_ray_v3.py and runs the 23-control
commercial-readiness gate as of the evidence cut-off (must be 23/23). It
validates every Sigma rule with the pySigma reference parser when available
(set PYTHONPATH to include pySigma), then writes:

  exports/v3/<report_id>-export.json        the artifact (review=None)
  exports/v3/<report_id>-REVIEWER-PACK.md   reviewer pack, diffed against v1
  exports/v3/RELEASE-MANIFEST.json          hash, size, gate result

Nothing here auto-approves anything: the authorized CYBERDUDEBIVASH internal
review authority records the artifact-bound decision with `cli.py reportx-review
approve` after completing the review checklist (docs/quality/PREMIUM-REPORT-HUMAN-REVIEW.md).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Sentinel-APEX" / "engine"))

from sentinel_engine.reportx.bundle_io import export_report_json  # noqa: E402
from sentinel_engine.reportx.reviewer_pack import render_reviewer_pack_markdown  # noqa: E402

CANARY = ROOT / "reportx-canary"
OUT = CANARY / "exports" / "v3"
GATE_AS_OF = date(2026, 10, 1)
PREVIOUS = CANARY / "exports" / "cve-2025-62593-ray-canary-export.json"


def _module():
    spec = importlib.util.spec_from_file_location("ray_v3", CANARY / "cve_2025_62593_ray_v3.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pysigma_check(rules) -> tuple[list[str], str]:
    """Parse every rule AND its condition with pySigma, and run the engine's
    own validator. Returns (problems, pysigma_version)."""
    from sentinel_engine.quality import validate_sigma
    try:
        import importlib.metadata as md
        from sigma.rule import SigmaRule  # type: ignore
        version = md.version("pysigma")
    except Exception:  # noqa: BLE001
        return ["pySigma not importable: SYNTAX_VALIDATED rules cannot be re-validated"], ""
    problems = []
    for r in rules:
        problems += [f"{r.rule_id}: {p}" for p in validate_sigma(r.body)]
        try:
            parsed = SigmaRule.from_yaml(r.body)
            for cond in parsed.detection.parsed_condition:
                cond.parsed  # forces condition parsing and selection resolution
            problems += [f"{r.rule_id}: {e}" for e in getattr(parsed, "errors", [])]
        except Exception as e:  # noqa: BLE001 - report every parser failure verbatim
            problems.append(f"{r.rule_id}: {type(e).__name__}: {e}")
    return problems, version


def main() -> int:
    mod = _module()
    bundle = mod.build_bundle()
    sigma_problems, pysigma_version = _pysigma_check(bundle.detection_rules)
    if sigma_problems:
        raise SystemExit("Sigma validation failed:\n  " + "\n  ".join(sigma_problems))
    export = export_report_json(bundle, as_of=GATE_AS_OF)
    cr = export["commercial_readiness"]
    if cr["verdict"] != "COMMERCIAL-READY":
        failed = [(c["control_id"], c["failures"][:3]) for c in cr["controls"] if c["status"] != "PASS"]
        raise SystemExit(f"23-control gate {cr['pass_count']}/{cr['total_count']}: {failed}")
    OUT.mkdir(parents=True, exist_ok=True)
    rid = bundle.report_id
    (OUT / f"{rid}-export.json").write_text(json.dumps(export, indent=2) + "\n", encoding="utf-8")
    previous = json.loads(PREVIOUS.read_text(encoding="utf-8"))
    (OUT / f"{rid}-REVIEWER-PACK.md").write_text(render_reviewer_pack_markdown(export, previous_export=previous), encoding="utf-8")
    text = export["bundle"]["rendered_text"]
    manifest = {
        "report_id": rid, "version": mod.VERSION, "supersedes": "cve-2025-62593-ray-canary",
        "evidence_cutoff": mod.EVIDENCE_CUTOFF,
        "artifact_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "bytes": len(text.encode("utf-8")), "words": len(text.split()),
        "gate": f"{cr['pass_count']}/{cr['total_count']}",
        "sigma": f"pySigma {pysigma_version}: rule and condition parse OK for all {len(bundle.detection_rules)} rules",
    }
    (OUT / "RELEASE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())