"""SOC and CTI dossier v12 — evidence, compliance and rendering regression."""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from bs4 import BeautifulSoup

from automation.cti_dossier_v12 import MARKER, enhance_cti_dossier_v12


def article(**overrides):
    data = dict(
        title="Example CVE-2026-11001 advisory",
        url="https://vendor.example/advisory",
        source="vendor_security_bulletin",
        published_at="2026-10-18T08:00:00Z",
    )
    data.update(overrides)
    return SimpleNamespace(**data)


def context(**overrides):
    data = dict(
        family="cve_advisory",
        family_label="CVE Vulnerability Advisory",
        report_id="CTI-EXAMPLE-11001",
        source_record_hash="a" * 64,
        generated_at="2026-10-19T04:00:00Z",
        exploitation_label="Exploitation not established",
    )
    data.update(overrides)
    return SimpleNamespace(**data)


BASE = (
    '<main><div class="cdbd-command">Original command dashboard</div>'
    '<h2>Executive Summary</h2><p>Canonical evidence, unchanged.</p>'
    '<h2>Verified Facts</h2><p>Source factual content.</p>'
    '<h2>Technical Analysis</h2><p>Original analysis.</p>'
    '<h2>References</h2><p>Official citations remain.</p>'
    '</main>'
)


class TestSociDossier(unittest.TestCase):
    def test_premium_cover_injected_once_without_changes_to_evidence(self):
        output = enhance_cti_dossier_v12(BASE, article(), context())
        soup = BeautifulSoup(output, "html.parser")
        self.assertIn(MARKER, output)
        self.assertEqual(len(soup.select("[data-cdb-cti-v12]")), 1)
        self.assertIn("Canonical evidence, unchanged.", output)
        self.assertIn("Official citations remain.", output)
        self.assertEqual(enhance_cti_dossier_v12(output, article(), context()), output)

    def test_jumps_target_actual_existing_sections_only(self):
        soup = BeautifulSoup(enhance_cti_dossier_v12(BASE, article(), context()), "html.parser")
        jumps = soup.select(".cdbv12-nav a")
        self.assertGreaterEqual(len(jumps), 3)
        for jump in jumps:
            self.assertIsNotNone(soup.select_one(jump["href"]))
        self.assertNotIn("Detection", [a.text for a in jumps])

    def test_source_and_compilation_dates_and_hash_are_distinguished(self):
        output = enhance_cti_dossier_v12(BASE, article(), context())
        self.assertIn("2026-10-18T08:00:00Z", output)
        self.assertIn("2026-10-19T04:00:00Z", output)
        self.assertIn("aaaaaaaaaaaa", output)
        self.assertNotIn("a" * 64, output)

    def test_no_soc2_certification_or_customer_incident_assertion(self):
        output = enhance_cti_dossier_v12(BASE, article(), context())
        self.assertIn("not an AICPA SOC 2 report", output)
        self.assertIn("Customer exposure: NOT ASSESSED", output)
        self.assertIn("Incident determination: NOT MADE", output)
        self.assertNotIn("SOC 2 Type II CERTIFIED", output)

    def test_ransomware_claim_does_not_become_verified_breach(self):
        output = enhance_cti_dossier_v12(
            BASE, article(title="Claimed ransomware victim"),
            context(family="ransomware_claim", family_label="Ransomware Claim Intelligence",
                    exploitation_label="Third-party actor claim — independently unverified"),
        )
        self.assertIn("Do not elevate a public leak-site claim", output)
        self.assertIn("independently unverified", output)

    def test_untrusted_html_and_url_scheme_not_rendered_as_markup(self):
        output = enhance_cti_dossier_v12(
            BASE, article(title='Report <script>alert(1)</script>', url="javascript:alert(1)"),
            context(report_id='TEST"><img src=x onerror=alert(1)>'),
        )
        soup = BeautifulSoup(output, "html.parser")
        self.assertIsNone(soup.select_one("script"))
        self.assertIsNone(soup.select_one("img"))
        self.assertIsNone(soup.select_one(".cdbv12-brief a"))
        self.assertIn("&lt;script&gt;", output)

    def test_unknown_layout_is_not_transformed(self):
        self.assertEqual(
            enhance_cti_dossier_v12("<main>Unrecognized</main>", article(), context()),
            "<main>Unrecognized</main>",
        )

    def test_missing_metadata_is_clearly_unknown(self):
        output = enhance_cti_dossier_v12(
            BASE, article(source=None, published_at=None),
            context(source_record_hash="not-a-sha256", report_id=None, generated_at=None),
        )
        self.assertIn("NOT AVAILABLE", output)
        self.assertIn("NOT IDENTIFIED", output)
        self.assertIn("NOT RECORDED", output)


if __name__ == "__main__":
    unittest.main()
