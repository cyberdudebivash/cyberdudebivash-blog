"""
CYBERDUDEBIVASH® SENTINEL APEX — Monetization Injection Module
Injects product/service CTAs, ecosystem links, and conversion blocks into articles.
"""

import html

from .config import Config

# Inline CSS for Blogger compatibility (no external stylesheets available)
_INLINE_CSS = """
<style>
.apex-cta-block{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:28px 0;padding:20px 24px;background:linear-gradient(135deg,#0a0f1e 0%,#0d1525 100%);border:1px solid #1e3a5f;border-left:4px solid #00d4ff;border-radius:8px;color:#e2e8f0}
.apex-cta-block h4{margin:0 0 8px;font-size:14px;font-weight:700;color:#00d4ff;text-transform:uppercase;letter-spacing:1px}
.apex-cta-block p{margin:0 0 14px;font-size:14px;line-height:1.6;color:#a0b3cc}
.apex-cta-grid{display:flex;flex-wrap:wrap;gap:10px}
.apex-btn{display:inline-block;padding:9px 18px;border-radius:5px;font-size:13px;font-weight:700;text-decoration:none;letter-spacing:.5px}
.apex-btn-primary{background:#00d4ff;color:#000}
.apex-btn-secondary{background:transparent;border:1px solid #00d4ff;color:#00d4ff}
.apex-btn-upgrade{background:linear-gradient(90deg,#f59e0b,#ef4444);color:#fff}
.apex-banner{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:32px 0;padding:28px;background:linear-gradient(135deg,#050d1a 0%,#0a1628 100%);border:2px solid #00d4ff22;border-radius:10px;text-align:center;color:#e2e8f0}
.apex-banner h3{margin:0 0 6px;font-size:22px;font-weight:800;color:#00d4ff}
.apex-banner p{margin:0 0 18px;font-size:15px;color:#94a3b8;line-height:1.6}
.apex-ecosystem{display:flex;flex-wrap:wrap;gap:10px;justify-content:center;margin-top:14px}
.apex-eco-item{padding:7px 14px;background:#0d1a2e;border:1px solid #1e3a5f;border-radius:5px;font-size:12px;color:#94a3b8;text-decoration:none}
.apex-services{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:28px 0;padding:20px 24px;background:#0a0f1e;border:1px solid #1e3a5f;border-radius:8px;color:#e2e8f0}
.apex-services h4{margin:0 0 12px;font-size:13px;font-weight:700;color:#f59e0b;text-transform:uppercase;letter-spacing:1px}
.apex-services-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px}
.apex-svc-item{padding:10px 12px;background:#0d1525;border:1px solid #1e3a5f22;border-radius:5px}
.apex-svc-item strong{display:block;font-size:12px;color:#00d4ff;margin-bottom:3px}
.apex-svc-item span{font-size:11px;color:#64748b}
.apex-about{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:32px 0;padding:20px 24px;background:#050d1a;border-top:2px solid #00d4ff33;color:#94a3b8;font-size:13px;line-height:1.7}
.apex-about strong{color:#00d4ff}
.apex-read-more{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:24px 0;text-align:center}
.apex-read-more a{display:inline-block;padding:12px 28px;background:linear-gradient(90deg,#00d4ff,#0099cc);color:#000;font-weight:800;font-size:15px;border-radius:6px;text-decoration:none;letter-spacing:.5px}
</style>
"""


class MonetizationInjector:
    """Injects conversion-optimised CTAs into syndicated article HTML."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def inject_header_cta(self) -> str:
        """Top-of-article brand banner + primary CTA."""
        return f"""
<div class="apex-banner">
  <h3>⚡ CYBERDUDEBIVASH® SENTINEL APEX</h3>
  <p>Source-linked automated security intelligence with explicit evidence status and provenance.</p>
  <div class="apex-ecosystem">
    <a class="apex-btn apex-btn-primary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">Explore Sentinel APEX</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.api_url}/docs" target="_blank" rel="noopener">API Documentation</a>
    <a class="apex-btn apex-btn-upgrade" href="mailto:{self.config.contact_email}">Contact Enterprise Team</a>
  </div>
</div>
""".strip()

    def inject_mid_products_cta(self) -> str:
        """Mid-article products promotion block."""
        return f"""
<div class="apex-cta-block">
  <h4>🛡 SENTINEL APEX ECOSYSTEM</h4>
  <p>Access source-linked threat intelligence, CVE analysis, detection engineering resources, and SOC decision support with explicit evidence boundaries.</p>
  <div class="apex-cta-grid">
    <a class="apex-btn apex-btn-primary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">🛡 Sentinel APEX Platform</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.api_url}" target="_blank" rel="noopener">⎋ Threat Intelligence API</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.tools_url}" target="_blank" rel="noopener">🔧 Security Tools Hub</a>
    <a class="apex-btn apex-btn-upgrade" href="{self.config.sentinel_apex_url}/upgrade" target="_blank" rel="noopener">▲ Enterprise Upgrade</a>
  </div>
</div>
""".strip()

    def inject_services_block(self) -> str:
        """Mid-article services CTA grid."""
        return f"""
<div class="apex-services">
  <h4>🏢 CYBERDUDEBIVASH® Enterprise Services</h4>
  <div class="apex-services-grid">
    <div class="apex-svc-item"><strong>Threat Intelligence</strong><span>CTI Advisory &amp; Premium Intel Briefs</span></div>
    <div class="apex-svc-item"><strong>AI Security Assessment</strong><span>LLM · Prompt Injection · Agent Security</span></div>
    <div class="apex-svc-item"><strong>Vulnerability Assessment</strong><span>API · SaaS · Cloud · Web Security</span></div>
    <div class="apex-svc-item"><strong>SOC &amp; MSSP Services</strong><span>Co-Managed SOC · Threat Hunting</span></div>
    <div class="apex-svc-item"><strong>AI Governance Consulting</strong><span>NIST AI RMF · ISO 42001 · OWASP LLM</span></div>
    <div class="apex-svc-item"><strong>DevSecOps Optimization</strong><span>CI/CD Security · Pipeline Hardening</span></div>
    <div class="apex-svc-item"><strong>Incident Response</strong><span>Digital Forensics · IR Retainer</span></div>
    <div class="apex-svc-item"><strong>Detection Engineering</strong><span>Versioned Sigma · YARA · SIEM Content</span></div>
  </div>
  <div style="margin-top:14px">
    <a class="apex-btn apex-btn-primary" href="{self.config.corporate_url}" target="_blank" rel="noopener">View All Services →</a>
    <a class="apex-btn apex-btn-secondary" style="margin-left:8px" href="mailto:{self.config.contact_email}">Book Enterprise Call</a>
  </div>
</div>
""".strip()

    def inject_detection_packs_cta(self) -> str:
        """Detection Engineering promotion without report-specific claims."""
        return f"""
<div class="apex-cta-block">
  <h4>🎯 Detection Engineering Resources</h4>
  <p>Versioned Sigma rules, YARA signatures, and incident-response playbooks mapped to MITRE ATT&amp;CK. Validate field mappings, telemetry coverage, and false positives in a non-production environment before deployment.</p>
  <div class="apex-cta-grid">
    <a class="apex-btn apex-btn-primary" href="{self.config.sentinel_apex_url}/detections" target="_blank" rel="noopener">Review Detection Resources →</a>
    <a class="apex-btn apex-btn-secondary" href="mailto:{self.config.contact_email}">Discuss Validation Support</a>
  </div>
</div>
""".strip()

    def inject_newsletter_cta(self) -> str:
        """Email newsletter signup — highest-value repeat visitor capture."""
        return f"""
<div class="apex-cta-block" style="border-left-color:#a855f7;background:linear-gradient(135deg,#0d0a1e 0%,#0a0f1e 100%)">
  <h4 style="color:#a855f7">📩 WEEKLY THREAT INTELLIGENCE BRIEFING</h4>
  <p>Receive source-linked weekly intelligence briefings covering CVE alerts, threat activity, AI security, detection engineering, and SOC operational decisions.</p>
  <p style="font-size:12px;color:#64748b;margin:-6px 0 12px">Free tier · No spam · Unsubscribe anytime · Enterprise tier available</p>
  <div class="apex-cta-grid">
    <a class="apex-btn" style="background:#a855f7;color:#fff" href="{self.config.newsletter_signup_url}" target="_blank" rel="noopener">Subscribe Free →</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">Explore Platform</a>
  </div>
</div>
""".strip()

    def inject_api_cta(self) -> str:
        """Dedicated Threat Intelligence API conversion block — free→paid funnel."""
        return f"""
<div class="apex-cta-block" style="border-left-color:#f59e0b;background:linear-gradient(135deg,#0d0a00 0%,#0d0f1e 100%)">
  <h4 style="color:#f59e0b">⎋ THREAT INTELLIGENCE API — FREE TIER AVAILABLE</h4>
  <p>Integrate live CVE data, KEV alerts, malware intelligence, and AI threat summaries directly into your security stack — Splunk, Elastic, Microsoft Sentinel, SOAR, or custom tooling. RESTful JSON API. No vendor lock-in.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:6px;margin:8px 0 12px;font-size:11px">
    <div style="padding:6px 8px;background:#0a0f1e;border:1px solid #f59e0b22;border-radius:4px;color:#94a3b8">✓ Live CVE feed</div>
    <div style="padding:6px 8px;background:#0a0f1e;border:1px solid #f59e0b22;border-radius:4px;color:#94a3b8">✓ CISA KEV stream</div>
    <div style="padding:6px 8px;background:#0a0f1e;border:1px solid #f59e0b22;border-radius:4px;color:#94a3b8">✓ AI summaries</div>
    <div style="padding:6px 8px;background:#0a0f1e;border:1px solid #f59e0b22;border-radius:4px;color:#94a3b8">✓ APT tracking</div>
  </div>
  <div class="apex-cta-grid">
    <a class="apex-btn" style="background:#f59e0b;color:#000" href="{self.config.api_url}" target="_blank" rel="noopener">⎋ Get Free API Key</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.api_url}/docs" target="_blank" rel="noopener">📄 View API Docs</a>
    <a class="apex-btn apex-btn-upgrade" href="{self.config.sentinel_apex_url}/upgrade" target="_blank" rel="noopener">▲ Enterprise API</a>
  </div>
</div>
""".strip()

    def inject_read_more_cta(self, source_url: str) -> str:
        """Bottom CTA directing readers to the full original report."""
        safe_source_url = html.escape(source_url, quote=True)
        return f"""
<div class="apex-read-more">
  <a href="{safe_source_url}" target="_blank" rel="noopener noreferrer">📄 Open Cited Source Record →</a>
</div>
""".strip()

    def inject_about_block(self) -> str:
        """CYBERDUDEBIVASH® About section with ecosystem links."""
        return f"""
<div class="apex-about">
  <strong>About CYBERDUDEBIVASH®</strong><br>
  CYBERDUDEBIVASH® is an AI-native cybersecurity ecosystem specializing in Threat Intelligence, AI Security, SOC Operations, Managed Security Services, Incident Response, Threat Hunting, Security Automation, DevSecOps, and Enterprise Cyber Defense.<br><br>
  <strong>Flagship Platforms:</strong>
  <a href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">Sentinel APEX™ Intelligence Platform</a> ·
  <a href="{self.config.api_url}" target="_blank" rel="noopener">Threat Intelligence API</a> ·
  <a href="{self.config.tools_url}" target="_blank" rel="noopener">Security Tools Hub</a> ·
  <a href="{self.config.corporate_url}" target="_blank" rel="noopener">Enterprise Portal</a><br><br>
  <em>Defending the Future with AI-Powered Cybersecurity.</em><br>
  Contact: <a href="mailto:{self.config.contact_email}">{self.config.contact_email}</a> ·
  Website: <a href="{self.config.brand_url}" target="_blank" rel="noopener">{self.config.brand_url}</a>
</div>
""".strip()

    def inject_urgency_cta(self, labels: list, kev_listed: bool | None = None) -> str:
        """Return a category-specific high-conversion CTA block."""
        label_set = set(l.lower() for l in labels)

        # A label alone is not evidence of KEV inclusion. The urgent KEV CTA
        # is rendered only from the structured catalog result.
        if kev_listed is True:
            return f"""
<div class="apex-cta-block" style="border-left-color:#ef4444;background:linear-gradient(135deg,#1a0505 0%,#0d0505 100%)">
  <h4 style="color:#ef4444">🚨 CISA FEDERAL MANDATE — ACTIVE EXPLOITATION CONFIRMED</h4>
  <p>This vulnerability is actively exploited in the wild. Federal agencies face a legal remediation deadline. Enterprise organizations should treat this with equivalent urgency. CYBERDUDEBIVASH® provides rapid vulnerability assessment and remediation guidance.</p>
  <div class="apex-cta-grid">
    <a class="apex-btn" style="background:#ef4444;color:#fff" href="mailto:{self.config.contact_email}">🚨 Emergency Assessment Request</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">Monitor All KEV Entries →</a>
  </div>
</div>""".strip()

        if "ransomware" in label_set:
            return f"""
<div class="apex-cta-block" style="border-left-color:#f59e0b">
  <h4 style="color:#f59e0b">🔒 RANSOMWARE PROTECTION ASSESSMENT</h4>
  <p>A public ransomware claim does not establish customer-specific exposure. CYBERDUDEBIVASH® provides ransomware readiness assessments covering backup integrity, network segmentation, identity controls, detection coverage, and incident-response playbooks.</p>
  <div class="apex-cta-grid">
    <a class="apex-btn apex-btn-upgrade" href="mailto:{self.config.contact_email}">Get Ransomware Assessment →</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">Monitor Ransomware Threats</a>
  </div>
</div>""".strip()

        if "apt" in label_set or "nation-state" in label_set:
            return f"""
<div class="apex-cta-block" style="border-left-color:#8b5cf6">
  <h4 style="color:#8b5cf6">🎯 NATION-STATE THREAT HUNTING</h4>
  <p>Advanced Persistent Threat actors use long-dwell techniques invisible to standard defenses. CYBERDUDEBIVASH® threat hunting services identify APT presence using MITRE ATT&CK TTPs, memory forensics, and behavioral analytics.</p>
  <div class="apex-cta-grid">
    <a class="apex-btn" style="background:#8b5cf6;color:#fff" href="mailto:{self.config.contact_email}">Request Threat Hunt →</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">APT Tracking Dashboard</a>
  </div>
</div>""".strip()

        if "ai security" in label_set:
            return f"""
<div class="apex-cta-block" style="border-left-color:#10b981">
  <h4 style="color:#10b981">🤖 AI SECURITY ASSESSMENT</h4>
  <p>AI systems, LLMs, and agentic applications introduce novel attack surfaces. CYBERDUDEBIVASH® AI Security assessments cover OWASP LLM Top 10, prompt injection, data leakage, model manipulation, and supply chain attacks against AI systems.</p>
  <div class="apex-cta-grid">
    <a class="apex-btn" style="background:#10b981;color:#000" href="mailto:{self.config.contact_email}">Book AI Security Assessment →</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">AI Threat Intelligence →</a>
  </div>
</div>""".strip()

        if "vulnerabilities" in label_set or "zero-day" in label_set or "critical cve" in label_set:
            return f"""
<div class="apex-cta-block">
  <h4>🔍 VULNERABILITY EXPOSURE ASSESSMENT</h4>
  <p>Are your systems exposed to this vulnerability? CYBERDUDEBIVASH® provides rapid vulnerability assessments covering API attack surfaces, cloud infrastructure, web applications, and network perimeter — with remediation-ready reports.</p>
  <div class="apex-cta-grid">
    <a class="apex-btn apex-btn-primary" href="mailto:{self.config.contact_email}">Request Vulnerability Scan →</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.sentinel_apex_url}" target="_blank" rel="noopener">Track Live CVEs →</a>
  </div>
</div>""".strip()

        # Default
        return self.inject_mid_products_cta()

    def inject_strategic_intel_cta(self, report_family: str, labels: list[str] | None = None) -> str:
        """One closing conversion path for non-CVE strategic intelligence.

        This block is intentionally factual and capability-oriented: it does
        not imply that the reader is affected, compromised, or already a
        customer. The primary conversion destination is the existing Sentinel
        APEX upgrade flow (Razorpay-backed for automated platform checkout);
        standalone digital products remain on the existing Tools/Gumroad path.
        No new backend, analytics store, or paid infrastructure is required.
        """
        family = str(report_family or "general_intelligence").strip().lower()
        label_set = {str(label or "").strip().lower() for label in (labels or [])}

        theme = "Strategic Threat Intelligence"
        accent = "#22d3ee"
        lead = (
            "Turn this source-linked report into continuous monitoring, higher-volume API access, "
            "IOC delivery, detection resources, and operational intelligence workflows."
        )

        if family.startswith("ransomware") or "ransomware" in label_set:
            theme = "Operationalize Ransomware Intelligence"
            accent = "#fb7185"
            lead = (
                "Move from a public ransomware report to continuous ransomware monitoring, API delivery, "
                "IOC tracking, and evidence-bounded SOC decision support."
            )
        elif family == "breach_notice" or any("breach" in label for label in label_set):
            theme = "Operationalize Breach Intelligence"
            accent = "#38bdf8"
            lead = (
                "Continuously monitor breach and exposure reporting, correlate source-backed indicators, "
                "and deliver intelligence into analyst and automation workflows."
            )
        elif any(token in " ".join(label_set) for token in ("malware", "campaign", "supply chain")):
            theme = "Operationalize Campaign & Malware Intelligence"
            accent = "#f59e0b"
            lead = (
                "Extend this report into continuous campaign, malware, and supply-chain monitoring with "
                "API access, IOC feeds, and detection-oriented intelligence workflows."
            )
        elif family == "threat_actor" or any(token in " ".join(label_set) for token in ("apt", "threat actor", "nation-state")):
            theme = "Operationalize Threat-Actor Intelligence"
            accent = "#a78bfa"
            lead = (
                "Track actor reporting over time, correlate source-backed activity, and integrate intelligence "
                "into hunting, SOC, and case-management workflows."
            )
        elif family == "ai_security" or "ai security" in label_set:
            theme = "Operationalize AI Security Intelligence"
            accent = "#34d399"
            lead = (
                "Convert public AI-security reporting into continuous monitoring, API access, and evidence-bounded "
                "security workflows for AI and agentic systems."
            )

        return f"""
<div class="apex-cta-block" data-cdb-conversion="strategic-intel" style="border-left-color:{accent};background:linear-gradient(135deg,#071018 0%,#0b1420 100%)">
  <h4 style="color:{accent}">▲ {theme.upper()}</h4>
  <p>{lead}</p>
  <p style="font-size:12px;color:#64748b;margin:-4px 0 12px">
    Customer-specific exposure or compromise must be validated from internal telemetry before action.
  </p>
  <div class="apex-cta-grid">
    <a class="apex-btn apex-btn-upgrade" href="{self.config.sentinel_apex_url}/upgrade" target="_blank" rel="noopener">View Paid Sentinel APEX Plans →</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.api_url}/docs" target="_blank" rel="noopener">Review API Capabilities</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.tools_url}" target="_blank" rel="noopener">Standalone Security Tools</a>
  </div>
</div>
""".strip()

    def inject_mssp_cta(self) -> str:
        """MSSP-specific conversion block — highest-value enterprise lead generation CTA."""
        return f"""
<div class="apex-cta-block" style="border-left-color:#10b981;background:linear-gradient(135deg,#050d0d 0%,#0a0f1e 100%)">
  <h4 style="color:#10b981">🏢 MANAGED SECURITY SERVICES — CYBERDUDEBIVASH® MSSP</h4>
  <p>Stop reacting to threats. Start preventing them. CYBERDUDEBIVASH® offers co-managed SOC services, threat hunting retainers, AI security assessments, detection engineering, incident-response support, and white-label intelligence packages for enterprise security workflows.</p>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:6px;margin:10px 0 14px;font-size:11px">
    <div style="padding:8px 10px;background:#0a1a0a;border:1px solid #10b98133;border-radius:4px;color:#94a3b8">✓ 24/7 Co-Managed SOC</div>
    <div style="padding:8px 10px;background:#0a1a0a;border:1px solid #10b98133;border-radius:4px;color:#94a3b8">✓ Threat Hunting Retainer</div>
    <div style="padding:8px 10px;background:#0a1a0a;border:1px solid #10b98133;border-radius:4px;color:#94a3b8">✓ AI Security Assessments</div>
    <div style="padding:8px 10px;background:#0a1a0a;border:1px solid #10b98133;border-radius:4px;color:#94a3b8">✓ White-Label Intelligence</div>
    <div style="padding:8px 10px;background:#0a1a0a;border:1px solid #10b98133;border-radius:4px;color:#94a3b8">✓ Detection Engineering</div>
    <div style="padding:8px 10px;background:#0a1a0a;border:1px solid #10b98133;border-radius:4px;color:#94a3b8">✓ IR Retainer Services</div>
  </div>
  <div class="apex-cta-grid">
    <a class="apex-btn" style="background:#10b981;color:#000" href="mailto:{self.config.contact_email}">Book MSSP Discovery Call →</a>
    <a class="apex-btn apex-btn-secondary" href="{self.config.corporate_url}" target="_blank" rel="noopener">View MSSP Services</a>
    <a class="apex-btn apex-btn-upgrade" href="{self.config.sentinel_apex_url}/upgrade" target="_blank" rel="noopener">▲ Enterprise Plans</a>
  </div>
</div>
""".strip()

    def get_style_block(self) -> str:
        return _INLINE_CSS
