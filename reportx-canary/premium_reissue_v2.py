"""Premium report reissue v2: customer-facing editions of the four sellable reports.

The v1 artifacts on sale were the ReportX canary renders: their titles read
"Premium Intelligence Canary" and the text carried internal production
language ("this session", "this canary set", "checked-in raw files",
"reportx-canary-*" rule ids, a GENERIC_DEFENSIVE_READINESS tag). This module
rebuilds each report from its own canary module (the same evidence graph,
claims, sources, metrics and detection logic -- nothing is re-researched or
invented) and applies ONE explicit, reviewable rewrite table:

  * customer-facing title + a product header (brand, version, evidence
    cut-off derived from the sources' own retrieval times, detection maturity);
  * internal process wording replaced by customer wording with the same
    meaning (e.g. "this session" -> "for this assessment");
  * report and Sigma rule ids renamed (sentinel-apex-*); the DetectionRule
    objects are updated together with the rendered text.

Every rewrite is fail-closed: if an expected source phrase is missing (the
canary text drifted), the reissue stops instead of shipping a half-edited
report. The 23-control commercial-readiness gate is re-run on each v2 bundle
and must return 23/23 PASS. A copy-gate scan must find no internal terms.

Nothing here approves anything. Outputs carry review=None
(PREMIUM_READY_PENDING_HUMAN); a named human approves each v2 artifact with
`python3 Sentinel-APEX/engine/cli.py reportx-review approve ...` after reading
the reviewer pack (docs/quality/PREMIUM-REPORT-HUMAN-REVIEW.md).

    cd Sentinel-APEX/engine && python3 ../../reportx-canary/premium_reissue_v2.py
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "Sentinel-APEX" / "engine"
sys.path.insert(0, str(ENGINE))

from sentinel_engine.reportx.bundle_io import export_report_json  # noqa: E402
from sentinel_engine.reportx.reviewer_pack import render_reviewer_pack_markdown  # noqa: E402

CANARY_DIR = ROOT / "reportx-canary"
OUT_DIR = CANARY_DIR / "exports" / "v2"
VERSION = "2.0"
GATE_AS_OF = date(2026, 8, 17)  # the as-of date the v1 gate certified against

BRAND = "CYBERDUDEBIVASH SENTINEL APEX INTEL FACTORY"
DETECTION_LEGEND = ("Detection maturity: SYNTAX_VALIDATED (rule syntax checked; "
                    "not lab-tested or deployment-validated -- validate in your environment before production use)")

# Terms that must never reach a paying customer. Scoped so that legitimate
# intelligence vocabulary ("proof sample", "Mimikatz module", "browser
# session") is not blocked; mirrored by the JS gate in
# tests-js/premium-copy-gate.test.js.
INTERNAL_COPY = re.compile(
    r"premium intelligence canary|\bcanar(?:y|ies)\b|this session|checked-in raw files|hand-typed|"
    r"reportx|GENERIC_DEFENSIVE_READINESS|content_sha256|internal pipeline|test artifact|"
    r"test-only|fixture|\bstaging\b|demo-only",
    re.IGNORECASE,
)

COMMON = [
    ("SYNTAX_VALIDATED maturity only -- neither lab testing nor any deployment validation has been performed this session --",
     "SYNTAX_VALIDATED maturity only -- neither lab testing nor any deployment validation has been performed for this assessment --"),
]
GDR = ("## Generic Defensive Readiness (GENERIC_DEFENSIVE_READINESS)", "## Generic Defensive Readiness")
LEDGER_HASH_LABEL = ("- content_sha256: `", "- SHA-256 of retrieved content: `")

REPORTS = [
    {
        "module": "qilin_spoonful_of_comfort_canary.py",
        "old_report_id": "qilin-spoonful-of-comfort-premium-canary",
        "report_id": "sentinel-apex-ransomware-qilin-spoonful-of-comfort",
        "title": "Sentinel APEX Ransomware Intelligence Report -- Qilin Claim Against 'Spoonful of Comfort'",
        "old_title": "# Qilin / 'Spoonful of Comfort' — Premium Intelligence Canary",
        "rule_ids": [("reportx-canary-qilin-vssadmin-tvinstallrestore", "sentinel-apex-qilin-vssadmin-tvinstallrestore")],
        "rewrites": [
            GDR,
            ("all fetched as raw bytes via direct HTTP fetch with content_sha256 computed programmatically from the checked-in raw files, never hand-typed:",
             "each archived at retrieval and identified in Appendix A by the SHA-256 of its retrieved content:"),
            ("was not independently retrieved this session,", "was not independently retrieved for this assessment,"),
        ],
    },
    {
        "module": "dragonforce_vermont_xcenter_canary.py",
        "old_report_id": "dragonforce-vermont-xcenter-premium-canary",
        "report_id": "sentinel-apex-ransomware-dragonforce-vermont-xcenter",
        "title": "Sentinel APEX Ransomware Intelligence Report -- DragonForce Claim Against 'Vermont XCenter'",
        "old_title": "# DragonForce / 'Vermont XCenter' — Premium Intelligence Canary",
        "rule_ids": [("reportx-canary-dragonforce-simplehelp-persistence", "sentinel-apex-dragonforce-simplehelp-persistence")],
        "rewrites": [
            GDR,
            ("all fetched as raw bytes via direct HTTP fetch with content_sha256 computed programmatically from the checked-in raw files:",
             "each archived at retrieval and identified in Appendix A by the SHA-256 of its retrieved content:"),
            ("verified directly against the raw page this session.", "verified directly against the archived page during this assessment."),
            ("than other victims in this canary set", "than the other victims assessed in this report series"),
            ("than this canary set's other victims", "than the other victims assessed in this report series"),
        ],
    },
    {
        "module": "medusalocker_bija_industrie_canary.py",
        "old_report_id": "medusalocker-bija-industrie-premium-canary",
        "report_id": "sentinel-apex-ransomware-medusalocker-bija-industrie",
        "title": "Sentinel APEX Ransomware Intelligence Report -- MedusaLocker Claim Against 'Bija Industrie'",
        "old_title": "# MedusaLocker / 'Bija Industrie' — Premium Intelligence Canary",
        "rule_ids": [("reportx-canary-medusalocker-svhost-persistence", "sentinel-apex-medusalocker-svhost-persistence")],
        "rewrites": [
            GDR,
            ("all fetched as raw bytes via direct HTTP fetch with content_sha256 computed programmatically from the checked-in raw files, never hand-typed:",
             "each archived at retrieval and identified in Appendix A by the SHA-256 of its retrieved content:"),
            ("consistent with the blocking behavior documented elsewhere in this canary set)",
             "consistent with the blocking behavior observed for other government sources in this report series)"),
        ],
    },
    {
        "module": "cve_2025_62593_ray_canary.py",
        "old_report_id": "cve-2025-62593-ray-canary",
        "report_id": "sentinel-apex-vuln-cve-2025-62593-ray",
        "title": "Sentinel APEX Vulnerability Intelligence Assessment -- CVE-2025-62593 (Ray)",
        "old_title": "# CVE-2025-62593 (Ray) — Premium Intelligence Canary",
        "rule_ids": [("reportx-canary-cve-2025-62593-ray-jobs-api", "sentinel-apex-cve-2025-62593-ray-jobs-api")],
        "rewrites": [
            ("Six of the seven were retrieved as raw bytes via direct HTTP fetch and their content_sha256 is computed programmatically from the checked-in raw files, never hand-typed.",
             "Six of the seven were archived at retrieval and are identified in Appendix A by the SHA-256 of their retrieved content."),
            ("this session; full content_sha256 could not be captured.", "during this assessment; a full-content SHA-256 could not be captured."),
        ],
    },
]


def _load(module_file: str):
    path = CANARY_DIR / module_file
    name = path.stem
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _replace_exactly(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"[{label}] expected phrase not found (canary text drifted): {old[:90]!r}")
    return text.replace(old, new)


def _evidence_cutoff(bundle) -> str:
    stamps = [str(s.retrieved_at)[:10] for s in bundle.graph.sources.values() if getattr(s, "retrieved_at", None)]
    if not stamps:
        raise SystemExit(f"[{bundle.report_id}] no source retrieval timestamps")
    return max(stamps)


def reissue(spec: dict) -> dict:
    bundle = _load(spec["module"]).build_bundle()
    label = spec["report_id"]
    if bundle.report_id != spec["old_report_id"]:
        raise SystemExit(f"[{label}] unexpected source report id {bundle.report_id}")

    text = bundle.rendered_text
    header = (f"# {spec['title']}\n\n"
              f"**{BRAND}** · Premium Intelligence Report · Version {VERSION}\n\n"
              f"Evidence cut-off: {_evidence_cutoff(bundle)} · {DETECTION_LEGEND}")
    text = _replace_exactly(text, spec["old_title"], header, label)
    for old, new in COMMON + spec["rewrites"]:
        text = _replace_exactly(text, old, new, label)
    text = text.replace(*LEDGER_HASH_LABEL)

    rules = list(bundle.detection_rules)
    for old_id, new_id in spec["rule_ids"]:
        text = _replace_exactly(text, f"id: {old_id}", f"id: {new_id}", label)
        rules = [dataclasses.replace(r, rule_id=new_id if r.rule_id == old_id else r.rule_id,
                                     body=r.body.replace(f"id: {old_id}", f"id: {new_id}")) for r in rules]

    leftovers = sorted(set(m.group(0) for m in INTERNAL_COPY.finditer(text)))
    if leftovers:
        raise SystemExit(f"[{label}] internal terminology remains: {leftovers}")

    depth = dataclasses.replace(bundle.depth_assessment, rendered_word_count=len(text.split()),
                                distinct_evidence_backed_sections=bundle.depth_assessment.distinct_evidence_backed_sections)
    v2 = dataclasses.replace(bundle, report_id=spec["report_id"], rendered_text=text,
                             detection_rules=rules, depth_assessment=depth, review=None)
    export = export_report_json(v2, as_of=GATE_AS_OF)
    cr = export["commercial_readiness"]
    if cr["verdict"] != "COMMERCIAL-READY":
        failed = [c["control_id"] for c in cr["controls"] if c["status"] != "PASS"]
        raise SystemExit(f"[{label}] 23-control gate: {cr['pass_count']}/{cr['total_count']} -- failing {failed}")
    return export


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    summary = []
    for spec in REPORTS:
        export = reissue(spec)
        rid = spec["report_id"]
        previous_path = CANARY_DIR / "exports" / f"{spec['old_report_id']}-export.json"
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
        (OUT_DIR / f"{rid}-export.json").write_text(json.dumps(export, indent=2) + "\n", encoding="utf-8")
        pack = render_reviewer_pack_markdown(export, previous_export=previous)
        (OUT_DIR / f"{rid}-REVIEWER-PACK.md").write_text(pack, encoding="utf-8")
        text = export["bundle"]["rendered_text"]
        sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        old_sha = hashlib.sha256(previous["bundle"]["rendered_text"].encode("utf-8")).hexdigest()
        summary.append({"report_id": rid, "previous_report_id": spec["old_report_id"], "version": VERSION,
                        "artifact_sha256": sha, "previous_artifact_sha256": old_sha,
                        "bytes": len(text.encode("utf-8")), "words": len(text.split()),
                        "gate": f"{export['commercial_readiness']['pass_count']}/{export['commercial_readiness']['total_count']}"})
        print(f"{rid}: v{VERSION} sha256={sha[:16]} bytes={summary[-1]['bytes']} gate={summary[-1]['gate']} (pending human review)")
    (OUT_DIR / "REISSUE-MANIFEST.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
