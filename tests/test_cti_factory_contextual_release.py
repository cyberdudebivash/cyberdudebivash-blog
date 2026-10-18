"""CTI Intel Factory source-relevance, actions and commercial safety regression tests."""
from __future__ import annotations
import unittest
from types import SimpleNamespace
from bs4 import BeautifulSoup

from automation.content_discovery import DiscoveredArticle, _compute_hash
from automation.report_integrity import build_report_context
from automation.cti_dossier_v11 import build_panel, enhance_dossier


def _article(title, **kw):
    defaults = dict(
        title=title,
        summary="",
        url="https://example.test/report",
        published_at="2026-10-18T00:00:00Z",
        source="global_rss",
        labels=[],
        content_hash=_compute_hash("https://example.test/report", title),
    )
    defaults.update(kw)
    return DiscoveredArticle(**defaults)


class TestEvidenceFirstFamilyRouting(unittest.TestCase):
    def test_identity_compromise_incidental_ai_in_syndication_body(self):
        item = _article(
            "Hackers Use Compromised ConnectWise Credential to Sign In to 173 Microsoft 365 Tenants",
            summary="Threat actors abused a compromised backup provider credential.",
            full_content="The main story concerns M365 tenants. Related reading: AI security, LLM and model safety.",
            labels=["Cybersecurity"],
        )
        self.assertEqual(build_report_context(item).family, "general_intelligence")

    def test_cve_in_related_story_does_not_reclassify_news(self):
        item = _article(
            "Security incident affecting cloud backup authentication",
            full_content="Related reading: CVE-2026-12345 is a separate vulnerability.",
        )
        self.assertEqual(build_report_context(item).family, "general_intelligence")

    def test_ai_newsletter_is_not_an_individual_incident(self):
        item = _article(
            "SECURITY AFFAIRS AI-CYBERSECURITY NEWSLETTER ROUND 4",
            summary="A weekly summary of AI security articles and CVE-2026-12345.",
            labels=["AI Security"],
        )
        self.assertEqual(build_report_context(item).family, "general_intelligence")

    def test_explicit_ai_report_keeps_ai_family(self):
        item = _article(
            "Prompt injection in an LLM coding agent",
            summary="Researchers identify an untrusted instruction boundary in an agent.",
        )
        self.assertEqual(build_report_context(item).family, "ai_security")

    def test_explicit_cve_keeps_cve_family(self):
        item = _article("CVE-2026-112008 libmng overflow")
        self.assertEqual(build_report_context(item).family, "cve_advisory")

    def test_structured_cve_overrides_editorial_title(self):
        item = _article("Daily Digest of Security", cve_id="CVE-2026-112008")
        self.assertEqual(build_report_context(item).family, "cve_advisory")

    def test_ransomware_claim_connector_keeps_uncertain_status(self):
        item = _article("N0n Claims a New Victim", source="ransomware_intel")
        result = build_report_context(item)
        self.assertEqual(result.family, "ransomware_claim")
        self.assertEqual(result.exploitation_status, "third_party_claim")


class TestContextualCustomerExperience(unittest.TestCase):
    def test_identity_investigation_uses_identity_specific_telemetry(self):
        panel = build_panel(
            SimpleNamespace(title="Compromised ConnectWise credential in Microsoft 365"),
            SimpleNamespace(family="general_intelligence"),
        )
        self.assertIn("Microsoft Entra sign-in", panel)
        self.assertNotIn("AI system trust-boundary validation", panel)

    def test_generic_identity_guidance_does_not_assume_microsoft(self):
        panel = build_panel(
            SimpleNamespace(title="Cloud API credential theft in unrelated service"),
            SimpleNamespace(family="general_intelligence"),
        )
        self.assertIn("identity provider", panel)
        self.assertNotIn("Microsoft Entra", panel)

    def test_incidental_ransomware_in_related_story_does_not_reclassify(self):
        item = _article(
            "Cloud identity access incident",
            summary="Unauthorized login through a SaaS integration.",
            full_content="Related story: ransomware in another organization.",
        )
        self.assertEqual(build_report_context(item).family, "general_intelligence")

    def test_ransomware_panel_does_not_claim_confirmed_breach(self):
        panel = build_panel(SimpleNamespace(title="Leak site claim"), SimpleNamespace(family="ransomware_claim"))
        self.assertIn("does not confirm intrusion", panel)

    def test_advisory_panel_has_no_unsupported_exploit_claim(self):
        panel = build_panel(SimpleNamespace(title="CVE-2026-112008"), SimpleNamespace(family="cve_advisory"))
        self.assertIn("do not equate a public CVE", panel)

    def test_editorial_panel_disallows_incident_assumption(self):
        panel = build_panel(SimpleNamespace(title="AI Security Newsletter Round 4"), SimpleNamespace(family="general_intelligence"))
        self.assertIn("discovery index, not as proof", panel)

    def test_links_are_safe_and_not_hardcoded_checkout(self):
        panel = build_panel(SimpleNamespace(title="CVE-2026-112008"), SimpleNamespace(family="cve_advisory"))
        soup = BeautifulSoup(panel, "html.parser")
        links = soup.select("nav a")
        self.assertEqual(len(links), 7)
        self.assertTrue(all(link["href"].startswith("https://") for link in links))
        self.assertTrue(all("noopener" in link.get("rel", []) for link in links))
        self.assertTrue(all("utm_campaign=contextual_ecosystem_v11" in link["href"] for link in links))
        self.assertNotIn("₹", panel)
        self.assertNotIn("checkout", panel.lower())

    def test_dossier_injects_exactly_once_without_destroying_source(self):
        base = '<main><div class="cdbv10-capabilities">SOURCE-LINKED</div><p>Unchanged source record</p></main>'
        item = SimpleNamespace(title="CVE-2026-112008")
        ctx = SimpleNamespace(family="cve_advisory")
        output = enhance_dossier(base, item, ctx)
        self.assertEqual(output.count('data-cdb-dossier-v11="true"'), 1)
        self.assertIn("Unchanged source record", output)
        self.assertEqual(enhance_dossier(output, item, ctx), output)
        self.assertEqual(enhance_dossier("<main>Unrecognized report</main>", item, ctx), "<main>Unrecognized report</main>")


if __name__ == "__main__":
    unittest.main()
