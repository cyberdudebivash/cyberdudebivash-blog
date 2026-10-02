"""Regression guarantee for the CVE-2025-62593 (Ray) v3.0 premium edition.

Module: reportx-canary/cve_2025_62593_ray_v3.py. The committed export
(reportx-canary/exports/v3/...-export.json) is what a human reviews and what
the manifest pins; this test proves the module still rebuilds exactly those
bytes from the archived raw sources, and that the 2026-10-01 review defects
cannot come back.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

from sentinel_engine.quality import validate_sigma
from sentinel_engine.reportx.commercial_readiness import evaluate_commercial_readiness
from sentinel_engine.reportx.evidence_integrity import compute_content_sha256

REPO = Path(__file__).resolve().parents[3].parent
MODULE = REPO / "reportx-canary" / "cve_2025_62593_ray_v3.py"
EXPORT = REPO / "reportx-canary" / "exports" / "v3" / "sentinel-apex-vuln-cve-2025-62593-ray-v3-export.json"
MANIFEST = REPO / "config" / "premium-catalog.json"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("cve_2025_62593_ray_v3", MODULE)
    m = importlib.util.module_from_spec(spec)
    sys.modules["cve_2025_62593_ray_v3"] = m
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def bundle(mod):
    return mod.build_bundle()


def test_rebuilds_exactly_the_committed_reviewed_artifact(bundle):
    committed = json.loads(EXPORT.read_text(encoding="utf-8"))["bundle"]["rendered_text"]
    assert bundle.rendered_text == committed
    pinned = next(p for p in json.loads(MANIFEST.read_text(encoding="utf-8"))["products"]
                  if p["report_id"] == bundle.report_id)
    assert hashlib.sha256(committed.encode("utf-8")).hexdigest() == pinned["artifact_sha256"]


def test_23_of_23_as_of_evidence_cutoff(bundle):
    results = evaluate_commercial_readiness(bundle, as_of=date(2026, 10, 1))
    failing = [(r.control_id, r.failures[:2]) for r in results if r.status != "PASS"]
    assert failing == []
    assert bundle.review is None  # pending a named human; never self-approved


def test_every_archived_source_hash_matches_its_raw_file(bundle):
    raw = REPO / "reportx-canary" / "raw-sources"
    by_hash = {compute_content_sha256(f.read_bytes()) for f in raw.iterdir() if f.is_file()}
    for s in bundle.graph.sources.values():
        if s.content_sha256:
            assert s.content_sha256 in by_hash, s.source_id
        else:
            assert s.excerpt_fingerprint_sha256 and s.fingerprint_fallback_reason, s.source_id


def test_review_defects_cannot_return(bundle):
    text = bundle.rendered_text
    # Outdated EPSS judgement is gone; current value and its date are present.
    assert "notably low" not in text
    assert "0.62459 (99.17th percentile)" in text
    assert "automatable yes" in text and "forensic triage" in text.lower()
    # No rule filters out loopback: the browser path arrives from 127.0.0.1.
    for rule in bundle.detection_rules:
        assert "127.0.0.1/32" not in rule.body
        assert "src_ip" not in rule.body
        assert validate_sigma(rule.body) == []
        parsed = yaml.safe_load(rule.body)
        assert len(parsed["id"]) == 36  # UUID, as pySigma requires
    # The browser-path rule keys on what the vendor fix rejects.
    assert "sec-fetch" in bundle.detection_rules[0].body.lower()


def test_indicator_counts_match_the_text(mod, bundle):
    rondo = len(mod.RONDODOX_EXPLOIT_IPS) + len(mod.RONDODOX_HOSTING_IPS) + len(mod.RONDODOX_C2_IPS)
    assert (rondo, len(mod.SHADOWRAY_IOCS)) == (36, 20)
    assert "36 RondoDox addresses and one User-Agent string, plus 20 ShadowRay 2.0 indicators" in bundle.rendered_text
    # every address published defanged
    assert all("[.]" in ip for ip, _ in mod.RONDODOX_EXPLOIT_IPS + mod.RONDODOX_HOSTING_IPS + mod.RONDODOX_C2_IPS)
