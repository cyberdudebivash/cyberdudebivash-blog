"""Tests for `cli.py reportx-review` (inspect/approve/reject/request-changes).

Exercises the actual CLI entry point (cli.main()) against a real exported
artifact, not a mocked one -- these are load-bearing tests since this
subcommand is the canonical artifact-bound internal review path. Production
defaults to CYBERDUDEBIVASH internal governance; tests may still override the
reviewer identity explicitly so fixtures cannot be confused with production.
"""

import json
from pathlib import Path

import cli

FIXTURES_DIR = Path(__file__).resolve().parents[3].parent / "tests" / "fixtures" / "reportx-commercial-readiness"
EXPORT_PATH = str(FIXTURES_DIR / "qilin-spoonful-of-comfort-exported-bundle.json")


class TestInspect:
    def test_inspect_writes_a_reviewer_pack_to_out(self, tmp_path, capsys):
        out = tmp_path / "pack.md"
        rc = cli.main(["reportx-review", "inspect", EXPORT_PATH, "--out", str(out)])
        assert rc == 0
        text = out.read_text()
        assert "Reviewer Pack" in text
        assert "23-Control Commercial Readiness Matrix" in text

    def test_inspect_without_out_prints_to_stdout(self, capsys):
        rc = cli.main(["reportx-review", "inspect", EXPORT_PATH])
        assert rc == 0
        captured = capsys.readouterr()
        assert "Reviewer Pack" in captured.out

    def test_inspect_accepts_a_previous_artifact_for_diffing(self, tmp_path, capsys):
        # Reuse the same export as its own "previous" -- just exercising
        # the wiring, not asserting on real historical content.
        rc = cli.main(["reportx-review", "inspect", EXPORT_PATH, "--previous", EXPORT_PATH])
        assert rc == 0
        captured = capsys.readouterr()
        assert "No change" in captured.out


class TestReject:
    def test_reject_defaults_to_cdb_internal_governance(self, tmp_path):
        out = tmp_path / "review.json"
        rc = cli.main(["reportx-review", "reject", EXPORT_PATH, "--out", str(out)])
        assert rc == 0
        review = json.loads(out.read_text())
        assert review["reviewer_type"] == "cdb_internal"
        assert review["reviewer_identity"] == "cyberdudebivash"
        assert review["reviewer_role"] == "CDB_INTERNAL"

    def test_reject_writes_a_review_record_bound_to_the_real_artifact_hash(self, tmp_path):
        import hashlib
        out = tmp_path / "review.json"
        rc = cli.main([
            "reportx-review", "reject", EXPORT_PATH,
            "--reviewer", "TEST-ONLY CI Reviewer", "--role", "QA",
            "--comments", "Automated test run, not a real decision.",
            "--out", str(out),
        ])
        assert rc == 0
        review = json.loads(out.read_text())
        assert review["decision"] == "REJECT"
        assert review["reviewer_type"] == "cdb_internal"
        assert review["reviewer_identity"] == "TEST-ONLY CI Reviewer"
        assert review["reviewer_role"] == "QA"
        assert review["is_test_only_fixture"] is False  # the CLI never sets this -- it's a Python-construction-only escape hatch

        export = json.loads(Path(EXPORT_PATH).read_text())
        expected_hash = hashlib.sha256(export["bundle"]["rendered_text"].encode("utf-8")).hexdigest()
        assert review["artifact_sha256"] == expected_hash

    def test_reject_records_a_gate_snapshot_hash(self, tmp_path):
        out = tmp_path / "review.json"
        cli.main([
            "reportx-review", "reject", EXPORT_PATH,
            "--reviewer", "TEST-ONLY CI Reviewer", "--out", str(out),
        ])
        review = json.loads(out.read_text())
        assert review["gate_snapshot_sha256"]
        assert len(review["gate_snapshot_sha256"]) == 64  # a real SHA-256 hex digest


class TestRequestChanges:
    def test_request_changes_writes_the_correct_decision(self, tmp_path):
        out = tmp_path / "review.json"
        rc = cli.main([
            "reportx-review", "request-changes", EXPORT_PATH,
            "--reviewer", "TEST-ONLY CI Reviewer", "--comments", "Needs more sources.",
            "--out", str(out),
        ])
        assert rc == 0
        review = json.loads(out.read_text())
        assert review["decision"] == "REQUEST_CHANGES"
        assert review["notes"] == "Needs more sources."


class TestApprove:
    def test_approve_writes_the_correct_decision(self, tmp_path):
        # Proves the CLI mechanism works -- this is NOT a real operator
        # approval and is explicitly labeled as a test fixture in the
        # reviewer identity, exactly like every other test in this file.
        out = tmp_path / "review.json"
        rc = cli.main([
            "reportx-review", "approve", EXPORT_PATH,
            "--reviewer", "TEST-ONLY CI Reviewer", "--role", "Automated Test",
            "--version", "2",
            "--out", str(out),
        ])
        assert rc == 0
        review = json.loads(out.read_text())
        assert review["decision"] == "APPROVE"
        assert review["review_version"] == 2

    def test_approved_review_from_cli_is_valid_against_the_real_artifact_text(self, tmp_path):
        from sentinel_engine.reportx.human_review import ReviewDecision, ReviewRecord, is_review_valid_for_artifact

        out = tmp_path / "review.json"
        cli.main([
            "reportx-review", "approve", EXPORT_PATH,
            "--reviewer", "TEST-ONLY CI Reviewer", "--out", str(out),
        ])
        review_dict = json.loads(out.read_text())
        review = ReviewRecord(
            report_id=review_dict["report_id"], artifact_sha256=review_dict["artifact_sha256"],
            reviewer_identity=review_dict["reviewer_identity"], review_timestamp=review_dict["review_timestamp"],
            decision=ReviewDecision(review_dict["decision"]), review_version=review_dict["review_version"],
            is_test_only_fixture=True,  # re-hydrated for this test's own validity check only
        )
        export = json.loads(Path(EXPORT_PATH).read_text())
        assert is_review_valid_for_artifact(review, export["bundle"]["rendered_text"])