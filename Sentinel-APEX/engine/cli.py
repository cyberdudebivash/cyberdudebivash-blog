#!/usr/bin/env python3
"""SENTINEL APEX Intelligence Engine CLI.

Usage (from Sentinel-APEX/engine/):

  python3 cli.py normalize <source.txt> [--url URL]
      Normalize a raw source article; print extracted evidence as JSON.

  python3 cli.py gate <report.txt> [more reports...]
      Run publication quality gates on published report dump(s).
      With 2+ reports, corpus-level duplication gates also run.
      Exit code 1 if any report fails a blocking gate.

  python3 cli.py run <source.txt> --id RPT-ID [--url URL] [--graph kg.json] [--enrich]
      Full pipeline: normalize -> (enrich) -> correlate -> detect -> draft.
      Prints the gated draft markdown; persists the knowledge graph if given.

  python3 cli.py enrich <CVE-ID>
      Live NVD/EPSS/KEV enrichment for one CVE (network required).

  python3 cli.py detect <source.txt> [--url URL]
      Compile multi-platform detections (Sigma/KQL/Splunk/OSQuery + Suricata)
      from a raw source's evidence. Prints each format.

  python3 cli.py score <source.txt> --id RPT-ID [--url URL] [--graph kg.json]
                       [--enrich] [--threshold N]
      Run the full pipeline and print the intelligence score (10 dimensions,
      overall publication score, tier, eligibility) as JSON. Exit 0 if
      publish-eligible, 2 if held below threshold.

  python3 cli.py certify <report.md> [--html published.html] [--sitemap sitemap.xml]
                         [--index index.html] [--node node]
      Enterprise Intelligence Certification Framework (EICF v1): runs the
      quality gate, the canonical renderer, and (if --html is given) the
      shipped publication artifacts through all five certification domains
      and prints a Release Governance Markdown record. Exit 0 if CERTIFIED
      or CERTIFIED WITH CONDITIONS, 1 if NOT CERTIFIED.

  python3 cli.py graph <report.md> --id REPORT-ID [--graph kg.json]
      GIKEP v1: ingest one already-published, quality-gated report
      (Sentinel-APEX/reports/published/) into the knowledge graph.
      `run`/`score` already do this for the pre-publication pipeline's own
      NormalizedDoc; this is the equivalent for a final, hand-authored
      report file, which had no path into the graph before. Prints any
      prior context the graph already had, then the graph's stats as JSON.

  python3 cli.py reportx-gate <bundle.json> [--as-of YYYY-MM-DD] [--json]
                              [--export out.json]
      ReportX commercial-readiness validator (docs/reportx/). Loads a
      ReportBundle from JSON (sentinel_engine.reportx.bundle_io schema),
      evaluates all 23 commercial-readiness controls, and prints the
      COMMERCIAL READINESS matrix. Add --json for the machine-readable
      form. Exit 0 only on a true 23/23 PASS; exit 1 otherwise (any FAIL
      or BLOCKED row) -- never exits 0 on a partial result. Add --export
      to additionally write the full validated bundle + precomputed gate
      results to out.json -- the single self-contained artifact System 5
      (api/_lib/reportx-adapter.js) reads; it never recomputes anything
      this command already validated.

  python3 cli.py reportx-review inspect <export.json> [--out pack.md]
                                [--previous prior-export.json]
      Renders the human-readable reviewer pack (sentinel_engine.reportx.
      reviewer_pack) from a `reportx-gate --export` artifact -- the 23-
      control matrix, sources, claims, statistics, regulatory
      determinations, detections, forecasts, hypotheses, gaps, and any
      existing review record. Prints to stdout, or writes to --out.

  python3 cli.py reportx-review (approve|reject|request-changes) <export.json>
                                [--reviewer cyberdudebivash]
                                [--reviewer-type cdb_internal]
                                [--role CDB_INTERNAL]
                                [--comments "..."] [--version N] --out review.json
      Writes an artifact-bound CYBERDUDEBIVASH internal ReviewRecord with
      the exact SHA-256 and gate-snapshot hash. Production governance uses
      reviewer_type=cdb_internal and reviewer=cyberdudebivash by default.
      Test fixtures remain explicitly separate and must not be represented
      as production approvals.

  python3 cli.py reportx-release certify --release-id ID
                --canary export1.json [--canary export2.json ...]
                --test-result "suite:passed:failed" [...]
                --render-qa {pass|fail} --system5-tests {pass|fail}
                --anti-padding {pass|fail} --npm-audit {pass|fail}
                --reviewer "Full Name" --out manifest.json
      ReportX RELEASE-level certification (docs/reportx/REPORTX-RELEASE-
      CERTIFICATION.md). Section 5's invariant: this certifies that THE
      RELEASE has demonstrated correct behaviour on the required canaries
      -- it never certifies any individual future report. Reads each
      --canary export (a reportx-gate --export artifact), auto-discovers
      a sibling `<report-id>-REVIEW-RECORD.json` if one exists next to
      it, and recomputes every canary's artifact hash from its own
      rendered_text rather than trusting a stored value. Real,
      artifact-bound PREMIUM_CERTIFIED review records are REQUIRED for
      every canary -- this command never constructs one itself. Exit 0
      only if REPORTX_RELEASE_CERTIFIED; 1 otherwise.

  python3 cli.py reportx-release (inspect|status|verify) manifest.json
      inspect: print the manifest exactly as stored, no drift check.
      status: print the manifest PLUS a live component-drift check
              against the current working tree (read-only, does not
              rewrite the file).
      verify: same drift check as status, but persists the result --
              a certified release whose tracked components have since
              changed is rewritten to REPORTX_RELEASE_REVIEW_REQUIRED
              on disk (Section 8). Exit 0 only if still certified.

  python3 cli.py reportx-release invalidate manifest.json --reason "..."
      Force a certified release to REPORTX_RELEASE_REVIEW_REQUIRED for
      an operator-supplied reason (e.g. a release-health degradation
      alert). Never used to force the opposite direction -- there is no
      "certify" action in this command, only "certify" the top-level
      subcommand above, which requires the real inputs.

  python3 cli.py reportx-certify <export.json> --release-manifest manifest.json
                [--audit-log log.jsonl]
  python3 cli.py reportx-certify batch <directory> --release-manifest manifest.json
                [--audit-log log.jsonl]
      Per-report AUTOMATED premium certification (docs/reportx/REPORTX-
      AUTOMATED-CERTIFICATION.md) -- Sections 3/5/6. Requires an already
      REPORTX_RELEASE_CERTIFIED manifest; refuses (falls back to
      PREMIUM_READY_PENDING_HUMAN or a fail-closed downgraded tier) if
      the release isn't certified, has since drifted, the report isn't
      23/23, or a derivable escalation signal fires. NEVER constructs a
      ReviewRecord and NEVER prints "human reviewed" -- see the rendered
      certification block conventions in REPORTX-AUTOMATED-
      CERTIFICATION.md. `batch` runs every `*-export.json` in a
      directory and, with --audit-log, appends one AuditLogRecord per
      report (append-only; see sentinel_engine.reportx.audit_log).

  python3 cli.py reportx-validate <export.json> [--json]
                [--overall-minimum N] [--minimum-coverage F]
      Intelligence Validation Framework (docs/reportx/REPORTX-INTELLIGENCE-
      VALIDATION-FRAMEWORK.md) -- scores a `reportx-gate --export` artifact
      across the 20 Phase-3 dimensions (Evidence Traceability, Source
      Reliability, Information Credibility, ..., Production Readiness) and
      prints the scorecard. Every dimension is computed from the same
      already-validated bundle/control results this command loads; it
      recomputes nothing evidence-related. Exit 0 only when
      publication_eligible is true (every gated dimension clears its
      mandatory threshold, overall score and coverage both clear their
      floors); exit 1 otherwise.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel_engine import certification, pipeline, quality, report_parser  # noqa: E402
from sentinel_engine.detection_builder import build_all  # noqa: E402
from sentinel_engine.enrichment import Enricher  # noqa: E402
from sentinel_engine.ioc_extractor import IOCType  # noqa: E402
from sentinel_engine.knowledge_graph import KnowledgeGraph  # noqa: E402
from sentinel_engine.models import SourceDocument  # noqa: E402
from sentinel_engine.normalizer import normalize  # noqa: E402
from sentinel_engine.report_ingest import normalize_report  # noqa: E402


def cmd_normalize(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    doc = normalize(SourceDocument(raw_text=text, source_url=args.url or ""))
    print(json.dumps(doc.to_dict(), indent=2))
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    reports = {
        Path(p).name: report_parser.parse_report(
            Path(p).read_text(errors="replace")
        )
        for p in args.reports
    }
    failed = False
    for name, parsed in sorted(reports.items()):
        result = quality.gate_report(parsed)
        status = "PASS" if result.passed else "FAIL"
        failed |= not result.passed
        print(f"[{status}] {name} — {parsed.title[:70]}")
        for f in result.findings:
            print(f"    {f.severity.upper():5s} [{f.gate}] {f.message}")
    if len(reports) > 1:
        print("\n== corpus gates ==")
        corpus = quality.gate_corpus(reports)
        failed |= not corpus.passed
        if not corpus.findings:
            print("    no corpus-level findings")
        for f in corpus.findings:
            print(f"    {f.severity.upper():5s} [{f.gate}] {f.message}")
    return 1 if failed else 0


def cmd_run(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    source = SourceDocument(raw_text=text, source_url=args.url or "")
    graph = KnowledgeGraph.load(args.graph) if args.graph else None
    enricher = Enricher() if args.enrich else None
    result = pipeline.run(source, args.id, enricher=enricher, graph=graph)
    if graph is not None and args.graph:
        graph.save(args.graph)
    print(result.draft_markdown)
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    record = Enricher().enrich_cve(args.cve_id)
    print(json.dumps(dataclasses.asdict(record), indent=2))
    return 0 if record.status == "enriched" else 1


def cmd_detect(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    doc = normalize(SourceDocument(raw_text=text, source_url=args.url or ""))
    iocs = [i for i in doc.iocs if i.type != IOCType.CVE]
    refs = [args.url] if args.url else []
    artifacts, suricata = build_all(doc.techniques, iocs=iocs, references=refs)
    if not artifacts and not suricata:
        print("No detections: source yielded no mapped techniques or network IOCs.")
        return 0
    for art in artifacts:
        print(f"\n===== {art.technique_id} — {art.title} =====")
        for fmt, body in art.formats().items():
            print(f"\n--- {fmt} ---\n{body}")
    if suricata:
        print("\n===== Suricata (network) =====")
        for rule in suricata:
            print(rule)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    text = Path(args.source).read_text(errors="replace")
    source = SourceDocument(raw_text=text, source_url=args.url or "")
    graph = KnowledgeGraph.load(args.graph) if args.graph else None
    enricher = Enricher() if args.enrich else None
    result = pipeline.run(
        source, args.id, enricher=enricher, graph=graph, threshold=args.threshold
    )
    if graph is not None and args.graph:
        graph.save(args.graph)
    print(json.dumps(result.score.to_dict(), indent=2))
    return 0 if result.score.eligible else 2


def cmd_graph(args: argparse.Namespace) -> int:
    report = report_parser.parse_report(Path(args.report).read_text(errors="replace"))
    doc = normalize_report(report)
    graph = KnowledgeGraph.load(args.graph) if args.graph else KnowledgeGraph()
    prior = graph.prior_context(doc)
    graph.ingest(doc, args.id)
    if args.graph:
        graph.save(args.graph)
    if prior:
        print("== prior context ==")
        for note in prior:
            print(f"  - {note}")
    print(json.dumps(graph.stats(), indent=2))
    return 0


def cmd_certify(args: argparse.Namespace) -> int:
    cert = certification.certify(
        args.report, html_path=args.html or None,
        sitemap_path=args.sitemap or None, index_path=args.index or None,
        node_bin=args.node,
    )
    print(certification.render_release_governance_markdown(cert))
    return 1 if cert.decision == "NOT CERTIFIED" else 0


def cmd_reportx_gate(args: argparse.Namespace) -> int:
    from datetime import date as date_cls

    from sentinel_engine.reportx.bundle_io import run_gate_on_file

    as_of = date_cls.fromisoformat(args.as_of) if args.as_of else None
    markdown, as_json = run_gate_on_file(args.bundle, as_of=as_of)
    print(as_json if args.json else markdown)

    if args.export:
        from sentinel_engine.reportx.bundle_io import bundle_from_dict, export_report_json

        with open(args.bundle, encoding="utf-8") as fh:
            bundle = bundle_from_dict(json.load(fh))
        with open(args.export, "w", encoding="utf-8") as fh:
            json.dump(export_report_json(bundle, as_of=as_of), fh, indent=2)
        print(f"Exported System-3-validated bundle + gate results to {args.export}", file=sys.stderr)

    return 0 if "FINAL VERDICT: COMMERCIAL-READY (23/23 PASS)" in markdown else 1


def cmd_reportx_review(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from sentinel_engine.reportx.human_review import (
        CDB_REVIEWER_IDENTITY,
        CDB_REVIEWER_TYPE,
        ReviewDecision,
        ReviewRecord,
        compute_artifact_hash,
        compute_gate_snapshot_hash,
    )
    from sentinel_engine.reportx.reviewer_pack import render_reviewer_pack_markdown

    with open(args.export, encoding="utf-8") as fh:
        export = json.load(fh)

    if args.action == "inspect":
        previous = None
        if args.previous:
            with open(args.previous, encoding="utf-8") as fh:
                previous = json.load(fh)
        pack = render_reviewer_pack_markdown(export, render_preview_path=args.render_preview, previous_export=previous)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(pack)
            print(f"Wrote reviewer pack to {args.out}", file=sys.stderr)
        else:
            print(pack)
        return 0

    decision_by_action = {
        "approve": ReviewDecision.APPROVE,
        "reject": ReviewDecision.REJECT,
        "request-changes": ReviewDecision.REQUEST_CHANGES,
    }
    decision = decision_by_action[args.action]

    artifact_sha256 = compute_artifact_hash(export["bundle"]["rendered_text"])
    controls_json = json.dumps(export["commercial_readiness"]["controls"], sort_keys=True)
    gate_snapshot_sha256 = compute_gate_snapshot_hash(controls_json)

    review = ReviewRecord(
        report_id=export["bundle"]["report_id"],
        artifact_sha256=artifact_sha256,
        reviewer_identity=args.reviewer or CDB_REVIEWER_IDENTITY,
        reviewer_type=args.reviewer_type or CDB_REVIEWER_TYPE,
        reviewer_role=args.role or "CDB_INTERNAL",
        review_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        decision=decision,
        review_version=args.version,
        notes=args.comments or "",
        gate_snapshot_sha256=gate_snapshot_sha256,
        is_test_only_fixture=False,
    )

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(review.to_dict(), fh, indent=2)

    print(f"Recorded {decision.value} under {review.reviewer_type}:{review.reviewer_identity} bound to artifact {artifact_sha256[:16]}... "
          f"-> {args.out}", file=sys.stderr)
    return 0


def cmd_reportx_release(args: argparse.Namespace) -> int:
    from sentinel_engine.reportx.human_review import ReviewDecision, ReviewRecord, compute_artifact_hash
    from sentinel_engine.reportx.release_certification import (
        CanaryCertificationInput,
        ReleaseState,
        SuiteResult,
        apply_drift_check,
        certify_release,
        manifest_from_dict,
        render_release_report,
    )

    if args.action == "certify":
        canaries = []
        for export_path in args.canary:
            with open(export_path, encoding="utf-8") as fh:
                export = json.load(fh)
            bundle = export["bundle"]
            cr = export["commercial_readiness"]
            rendered_text = bundle.get("rendered_text", "")

            review = None
            review_path = Path(export_path).with_name(f"{bundle['report_id']}-REVIEW-RECORD.json")
            if review_path.exists():
                with open(review_path, encoding="utf-8") as fh:
                    r = json.load(fh)
                review = ReviewRecord(
                    report_id=r["report_id"], artifact_sha256=r["artifact_sha256"],
                    reviewer_identity=r["reviewer_identity"], review_timestamp=r["review_timestamp"],
                    decision=ReviewDecision(r["decision"]), review_version=r.get("review_version", 1),
                    reviewer_type=r.get("reviewer_type", "cdb_internal"),
                    notes=r.get("notes", ""), is_test_only_fixture=r.get("is_test_only_fixture", False),
                    reviewer_role=r.get("reviewer_role", ""), gate_snapshot_sha256=r.get("gate_snapshot_sha256", ""),
                )

            canaries.append(CanaryCertificationInput(
                canary_id=bundle["report_id"],
                artifact_sha256=compute_artifact_hash(rendered_text),
                rendered_text=rendered_text,
                commercial_readiness_pass_count=cr["pass_count"],
                commercial_readiness_total_count=cr["total_count"],
                review=review,
            ))

        test_results = []
        for spec in args.test_result:
            name, passed, failed = spec.rsplit(":", 2)
            test_results.append(SuiteResult(name, int(passed), int(failed)))

        manifest = certify_release(
            release_id=args.release_id, canaries=canaries, test_results=test_results,
            render_qa_passed=(args.render_qa == "pass"), system5_tests_passed=(args.system5_tests == "pass"),
            anti_padding_passed=(args.anti_padding == "pass"), npm_audit_passed=(args.npm_audit == "pass"),
            reviewer_identity=args.reviewer,
        )
        print(render_release_report(manifest))
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(manifest.to_dict(), fh, indent=2)
        print(f"Wrote release manifest to {args.out}", file=sys.stderr)
        return 0 if manifest.is_certified else 1

    if args.action == "inspect":
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = manifest_from_dict(json.load(fh))
        print(render_release_report(manifest))
        return 0 if manifest.is_certified else 1

    if args.action == "status":
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = manifest_from_dict(json.load(fh))
        checked = apply_drift_check(manifest)
        print(render_release_report(checked))
        if checked.release_decision != manifest.release_decision:
            print(f"NOTE: live state differs from what's on disk ({manifest.release_decision.value} -> "
                  f"{checked.release_decision.value}). Run 'reportx-release verify' to persist this.", file=sys.stderr)
        return 0 if checked.is_certified else 1

    if args.action == "verify":
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = manifest_from_dict(json.load(fh))
        checked = apply_drift_check(manifest)
        print(render_release_report(checked))
        if checked.release_decision != manifest.release_decision:
            with open(args.manifest, "w", encoding="utf-8") as fh:
                json.dump(checked.to_dict(), fh, indent=2)
            print(f"Release state changed ({manifest.release_decision.value} -> "
                  f"{checked.release_decision.value}); rewrote {args.manifest}", file=sys.stderr)
        return 0 if checked.is_certified else 1

    if args.action == "invalidate":
        with open(args.manifest, encoding="utf-8") as fh:
            manifest = manifest_from_dict(json.load(fh))
        invalidated = dataclasses.replace(
            manifest, release_decision=ReleaseState.REPORTX_RELEASE_REVIEW_REQUIRED,
            failed_requirements=manifest.failed_requirements + (args.reason,),
        )
        with open(args.manifest, "w", encoding="utf-8") as fh:
            json.dump(invalidated.to_dict(), fh, indent=2)
        print(f"Invalidated {args.manifest}: {args.reason}", file=sys.stderr)
        return 0

    raise ValueError(f"unknown reportx-release action {args.action!r}")


def cmd_reportx_certify(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone

    from sentinel_engine.reportx.audit_log import AuditLogRecord, append_record
    from sentinel_engine.reportx.automated_certification import certify_report_automated, collect_derivable_escalations
    from sentinel_engine.reportx.bundle_io import bundle_from_dict
    from sentinel_engine.reportx.commercial_readiness import ControlResult
    from sentinel_engine.reportx.human_review import CertificationState, compute_artifact_hash
    from sentinel_engine.reportx.release_certification import manifest_from_dict

    with open(args.release_manifest, encoding="utf-8") as fh:
        manifest = manifest_from_dict(json.load(fh))

    if args.target == "batch":
        if not args.directory:
            print("reportx-certify batch requires a directory argument", file=sys.stderr)
            return 2
        targets = sorted(str(p) for p in Path(args.directory).glob("*-export.json"))
        if not targets:
            print(f"No *-export.json artifacts found in {args.directory}", file=sys.stderr)
    else:
        targets = [args.target]

    any_not_certified = False
    for target in targets:
        with open(target, encoding="utf-8") as fh:
            export = json.load(fh)
        control_results = [
            ControlResult(c["control_id"], c["name"], c["status"], c["evidence"],
                          c.get("failures", []), c.get("warnings", []))
            for c in export["commercial_readiness"]["controls"]
        ]
        bundle = bundle_from_dict(export["bundle"])
        escalations = collect_derivable_escalations(
            report_id=bundle.report_id, detection_rules=bundle.detection_rules,
            rendered_text=bundle.rendered_text, sources=list(bundle.graph.sources.values()),
        )
        result = certify_report_automated(bundle.report_id, manifest, control_results, escalation_reasons=escalations)

        print(f"{target}: {result.certification_state.value} "
              f"({result.commercial_readiness_pass_count}/{result.commercial_readiness_total_count})")
        for reason in result.refusal_reasons:
            print(f"  - {reason}")
        if result.certification_state != CertificationState.PREMIUM_AUTOMATED_CERTIFIED:
            any_not_certified = True

        if args.audit_log:
            record = AuditLogRecord(
                report_id=bundle.report_id, artifact_sha256=compute_artifact_hash(bundle.rendered_text),
                release_id=manifest.release_id, timestamp=result.decided_at,
                automated_controls=f"{result.commercial_readiness_pass_count}/{result.commercial_readiness_total_count}",
                certification_state=result.certification_state.value,
                escalation_reason="; ".join(r.value for r in result.escalation_reasons),
                downgrade_reason="; ".join(result.refusal_reasons),
                human_review_required=(result.certification_state == CertificationState.PREMIUM_READY_PENDING_HUMAN),
            )
            append_record(Path(args.audit_log), record)

    if args.target == "batch":
        return 0
    return 1 if any_not_certified else 0


def cmd_reportx_validate(args: argparse.Namespace) -> int:
    from sentinel_engine.reportx.intelligence_validation import (
        ValidationThresholds,
        evaluate_from_export,
        render_scorecard_markdown,
    )

    with open(args.export, encoding="utf-8") as fh:
        export = json.load(fh)

    thresholds = ValidationThresholds(overall_minimum=args.overall_minimum, minimum_coverage=args.minimum_coverage)
    scorecard = evaluate_from_export(export, thresholds=thresholds)

    print(json.dumps(scorecard.to_dict(), indent=2) if args.json else render_scorecard_markdown(scorecard))
    return 0 if scorecard.publication_eligible else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("normalize", help="normalize a raw source article")
    p.add_argument("source")
    p.add_argument("--url", default="")
    p.set_defaults(func=cmd_normalize)

    p = sub.add_parser("gate", help="quality-gate published report dumps")
    p.add_argument("reports", nargs="+")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("run", help="full pipeline on a raw source")
    p.add_argument("source")
    p.add_argument("--id", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--graph", default="")
    p.add_argument("--enrich", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("enrich", help="live CVE enrichment (NVD/EPSS/KEV)")
    p.add_argument("cve_id")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("detect", help="compile multi-platform detections")
    p.add_argument("source")
    p.add_argument("--url", default="")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("score", help="intelligence scoring + publication decision")
    p.add_argument("source")
    p.add_argument("--id", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--graph", default="")
    p.add_argument("--enrich", action="store_true")
    p.add_argument("--threshold", type=int, default=60)
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("graph", help="ingest a published report into the knowledge graph")
    p.add_argument("report")
    p.add_argument("--id", required=True)
    p.add_argument("--graph", default="")
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("certify", help="run the EICF v1 certification framework on one report")
    p.add_argument("report")
    p.add_argument("--html", default="", help="path to the already-published HTML page, if any")
    p.add_argument("--sitemap", default="", help="path to sitemap.xml, for the Publication Quality domain")
    p.add_argument("--index", default="", help="path to index.html, for the Publication Quality domain")
    p.add_argument("--node", default="node", help="node binary to invoke for the Rendering Quality domain")
    p.set_defaults(func=cmd_certify)

    p = sub.add_parser("reportx-gate", help="ReportX commercial-readiness validator (23-control matrix)")
    p.add_argument("bundle", help="path to a ReportBundle JSON file")
    p.add_argument("--as-of", default="", help="ISO date to evaluate statistics freshness against (default: today)")
    p.add_argument("--json", action="store_true", help="print the machine-readable JSON form instead of Markdown")
    p.add_argument("--export", default="", help="also write the full validated bundle + gate results to this path (for System 5 / JS consumers)")
    p.set_defaults(func=cmd_reportx_gate)

    p = sub.add_parser("reportx-review", help="ReportX CDB-internal review workflow: inspect a reviewer pack, or record an artifact-bound approve/reject/request-changes decision")
    review_sub = p.add_subparsers(dest="action", required=True)

    p_inspect = review_sub.add_parser("inspect", help="render the reviewer pack for an exported artifact")
    p_inspect.add_argument("export", help="path to a reportx-gate --export artifact")
    p_inspect.add_argument("--out", default="", help="write the pack here instead of stdout")
    p_inspect.add_argument("--render-preview", default="", help="path to a rendered preview file, if one exists, to note in the pack")
    p_inspect.add_argument("--previous", default="", help="a prior --export artifact, to show what changed since the last review")

    for action in ("approve", "reject", "request-changes"):
        p_action = review_sub.add_parser(action, help=f"record a real {action} decision, bound to the artifact's exact SHA-256")
        p_action.add_argument("export", help="path to a reportx-gate --export artifact")
        p_action.add_argument("--reviewer", default="cyberdudebivash", help="CDB internal reviewer identity (default: cyberdudebivash)")
        p_action.add_argument("--reviewer-type", choices=["cdb_internal"], default="cdb_internal", help="review governance type; production value is cdb_internal")
        p_action.add_argument("--role", default="CDB_INTERNAL", help="internal review role (default: CDB_INTERNAL)")
        p_action.add_argument("--comments", default="", help="review comments/notes")
        p_action.add_argument("--version", type=int, default=1, help="review_version, if this artifact has been reviewed before")
        p_action.add_argument("--out", required=True, help="path to write the resulting ReviewRecord JSON")

    p.set_defaults(func=cmd_reportx_review)

    p = sub.add_parser("reportx-release", help="ReportX release-level certification: certify/inspect/status/verify/invalidate a release manifest")
    release_sub = p.add_subparsers(dest="action", required=True)

    p_rcertify = release_sub.add_parser("certify", help="certify a release from real canary exports + regression results")
    p_rcertify.add_argument("--release-id", required=True)
    p_rcertify.add_argument("--canary", action="append", required=True, default=[],
                             help="path to a reportx-gate --export artifact for one required canary (repeatable)")
    p_rcertify.add_argument("--test-result", action="append", default=[],
                             help="'suite_name:passed:failed', repeatable")
    p_rcertify.add_argument("--render-qa", choices=["pass", "fail"], required=True)
    p_rcertify.add_argument("--system5-tests", choices=["pass", "fail"], required=True)
    p_rcertify.add_argument("--anti-padding", choices=["pass", "fail"], required=True)
    p_rcertify.add_argument("--npm-audit", choices=["pass", "fail"], required=True)
    p_rcertify.add_argument("--reviewer", required=True,
                             help="identity of the operator running this release certification (recorded on the manifest; not a gate)")
    p_rcertify.add_argument("--out", required=True)

    for action in ("inspect", "status", "verify"):
        p_raction = release_sub.add_parser(action, help=f"{action} an existing release manifest")
        p_raction.add_argument("manifest")

    p_rinvalidate = release_sub.add_parser("invalidate", help="force a certified release to REPORTX_RELEASE_REVIEW_REQUIRED")
    p_rinvalidate.add_argument("manifest")
    p_rinvalidate.add_argument("--reason", required=True)

    p.set_defaults(func=cmd_reportx_release)

    p = sub.add_parser("reportx-certify", help="ReportX per-report automated premium certification against a certified release")
    p.add_argument("target", help="path to a reportx-gate --export artifact, or the literal 'batch'")
    p.add_argument("directory", nargs="?", default="", help="directory of *-export.json artifacts, when target is 'batch'")
    p.add_argument("--release-manifest", required=True, help="path to a reportx-release certify --out manifest")
    p.add_argument("--audit-log", default="", help="append each decision to this JSONL audit log (sentinel_engine.reportx.audit_log)")
    p.set_defaults(func=cmd_reportx_certify)

    p = sub.add_parser("reportx-validate", help="Intelligence Validation Framework: 20-dimension scorecard + mandatory publication thresholds")
    p.add_argument("export", help="path to a reportx-gate --export artifact")
    p.add_argument("--json", action="store_true", help="print the machine-readable JSON form instead of Markdown")
    p.add_argument("--overall-minimum", type=int, default=75, help="mandatory minimum overall score (default: 75)")
    p.add_argument("--minimum-coverage", type=float, default=0.5,
                    help="mandatory minimum fraction of the 20 dimensions that must be scoreable, not BLOCKED (default: 0.5)")
    p.set_defaults(func=cmd_reportx_validate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())