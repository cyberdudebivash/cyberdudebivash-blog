"""Deterministic, evidence-first renderer for public CTI reports.

All report families share one visual system, while their analytical modules are
selected by source schema.  Unsupported fields are omitted or explicitly
marked unknown; completeness never outranks evidence integrity.
"""

from __future__ import annotations

import html
import re
import uuid
from dataclasses import dataclass
from typing import Optional

import yaml

from .config import Config
from .content_discovery import DiscoveredArticle
from .report_integrity import ReportContext, build_report_context
from .seo_optimizer import _truncate


@dataclass(frozen=True)
class RenderedReport:
    html: str
    context: ReportContext
    detection_status: str


@dataclass(frozen=True)
class DetectionPackage:
    status: str
    rationale: str
    telemetry: tuple[str, ...]
    sigma_yaml: Optional[str] = None
    kql: Optional[str] = None
    attack_mappings: tuple[str, ...] = ()


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _section(title: str, body: str, color: str = "#00d4ff") -> str:
    return (
        f'<section class="cdb-section-card" style="margin:30px 0" data-section="{_esc(title.lower().replace(" ", "-"))}">'
        f'<div style="margin-bottom:12px;padding:10px 16px;background:linear-gradient(90deg,#0a1628,#050d1a);'
        f'border-left:3px solid {color};color:{color};font-family:monospace;font-size:11px;'
        f'font-weight:800;letter-spacing:2px;text-transform:uppercase">{_esc(title)}</div>'
        f'{body}</section>'
    )


def _panel(body: str, color: str = "#1e3a5f", background: str = "#050d1a") -> str:
    return (
        f'<div class="cdb-panel" style="background:{background};border:1px solid {color}66;border-radius:8px;'
        f'padding:16px 20px;color:#cbd5e1;font-size:13px;line-height:1.75">{body}</div>'
    )


def _bullets(items: list[str], color: str = "#00d4ff") -> str:
    return "".join(
        f'<div class="cdb-bullet" style="margin:7px 0;padding:10px 14px;background:#050d1a;border-left:3px solid {color};'
        f'border-radius:0 5px 5px 0;color:#cbd5e1;font-size:13px;line-height:1.65">{item}</div>'
        for item in items
    )


def _label(value: str) -> str:
    return value.replace("_", " ").title()


_CVSS_ACCESS = {"N": "over the network", "A": "from an adjacent network", "L": "with local access", "P": "with physical access"}
_CVSS_PRIVILEGE = {"N": "no privileges", "L": "low-privileged access", "H": "high-privileged access"}
_CVSS_INTERACTION = {"N": "no user interaction", "R": "user interaction"}


def _exploit_prerequisites_clause(cvss_vector: Optional[str]) -> str:
    """Turns the report's own already-verified CVSS vector (Attack Vector,
    Privileges Required, User Interaction) into a per-CVE exploitation
    sentence, instead of a single "Prioritization must combine..." sentence
    repeated identically across every non-KEV-confirmed CVE report
    regardless of how different their real exploit prerequisites are
    (COMMERCIAL-QUALITY-2026-08-19: independently verified live -- e.g.
    CVE-2026-75914's AV:N/PR:N/UI:N and CVE-2026-75912's AV:N/PR:N/UI:R
    rendered the exact same Assessment text). Every clause is a direct,
    deterministic reading of the CVSS metric values already displayed
    verbatim in this same report's "Verified Facts" section -- nothing is
    inferred or fabricated beyond the standard CVSS metric definitions."""
    if not cvss_vector:
        return ""
    metrics = dict(part.split(":", 1) for part in cvss_vector.split("/") if ":" in part)
    access = _CVSS_ACCESS.get(metrics.get("AV", ""))
    privilege = _CVSS_PRIVILEGE.get(metrics.get("PR", ""))
    interaction = _CVSS_INTERACTION.get(metrics.get("UI", ""))
    if not (access and privilege and interaction):
        return ""
    return f" This vulnerability is exploitable {access}, requiring {privilege} and {interaction}."


# RX-P1K-16: known-publisher domains this pipeline already curates and
# trusts (rss_aggregator.py's own feed list) -- real source article text
# routinely self-cites its own publisher ("as first reported by
# SecurityWeek...") or a peer outlet, which ioc_extractor.py's own
# DEFAULT_ALLOWLIST (MITRE/NVD/CISA/social-media/reference infrastructure
# only) has no way to know about; confirmed as a real false positive during
# this round's own real-data validation (securityweek.com misclassified as
# a domain indicator from ordinary citation prose). Derived once from data
# this pipeline already maintains for feed ingestion, not a second,
# separately hand-maintained list that could drift out of sync (Single
# Source of Truth) -- excludes multi-tenant platforms a real indicator
# could still legitimately be hosted on (medium.com; feeds.feedburner.com
# is Google's shared syndication proxy, not a citable publisher domain in
# article prose either way) so this never masks a genuine indicator. Lives
# here (not authority_transformer.py, its only caller until this round)
# because _defang_text() below -- also called from this module -- needs it
# too, and authority_transformer.py already imports from report_renderer.py,
# never the reverse, so this is this pipeline's one safe, non-circular home
# for it.
def _known_publisher_domains() -> frozenset:
    from urllib.parse import urlparse

    from .rss_aggregator import _GLOBAL_FEEDS

    exclude = {"medium.com", "feeds.feedburner.com"}
    domains = set()
    for feed in _GLOBAL_FEEDS:
        host = urlparse(feed.url).netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        if host and host not in exclude:
            domains.add(host)
    return frozenset(domains)


_KNOWN_PUBLISHER_DOMAINS = _known_publisher_domains()


def _defang_text(text: str) -> str:
    """RX-P1K-16-ADJACENT: found during this round's own real-data
    validation of Section 16 (Indicators/Observables) -- _source_lines()
    below has always quoted the article's raw source text verbatim (only
    HTML-escaped, never defanged) into the published "Source Evidence
    Extract" section, so any live indicator present in the article's own
    source text (an active C2 URL, for example) was published exactly as
    written: a real, clickable link to attacker infrastructure. Confirmed
    reachable on the pipeline's own primary content path, not a rare
    edge case: pipeline_composer.compose_report() (Sentinel-APEX/engine)
    reuses render_evidence_report() -- and therefore this function -- as
    its own base HTML for every article, not merely the legacy-template
    fallback. Pre-existing and unrelated to Section 16's own wiring, but
    found while proving Section 16's own defanging guarantee end-to-end
    and directly adjacent to it (both concern the same underlying hazard),
    so fixed in the same round rather than deferred -- small, surgical,
    and reuses this round's own extract_iocs()/defang() integration rather
    than a second, separate mechanism. Returns ``text`` unchanged (never
    raises) if the engine package can't be imported, matching
    authority_transformer.py's own established fail-safe convention for
    this exact import."""
    try:
        import sys
        from pathlib import Path

        engine_path = str(Path(__file__).resolve().parents[1] / "Sentinel-APEX" / "engine")
        if engine_path not in sys.path:
            sys.path.insert(0, engine_path)

        from sentinel_engine.ioc_extractor import DEFAULT_ALLOWLIST, defang, extract_iocs
    except Exception:
        return text

    allowlist = DEFAULT_ALLOWLIST | _KNOWN_PUBLISHER_DOMAINS
    out = text
    for ioc in extract_iocs(text, allowlist=allowlist, include_context=False):
        if ioc.value in out:
            out = out.replace(ioc.value, defang(ioc.value, ioc.type))
    return out


def _source_lines(article: DiscoveredArticle) -> list[str]:
    source = _defang_text(str(article.full_content or article.summary))
    lines = [line.strip() for line in source.splitlines() if line.strip()]
    return lines[:18] if lines else [article.summary]


def _severity(article: DiscoveredArticle) -> tuple[str, str]:
    score = article.cvss_score
    if score is None:
        match = re.search(r"\bCVSS(?:\s+(?:v?3(?:\.1)?))?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b", _source_text(article), re.IGNORECASE)
        if match:
            try:
                score = float(match.group(1))
            except ValueError:
                score = None
    if score is None:
        return "UNRATED", "#64748b"
    if score >= 9.0:
        return "CRITICAL", "#ef4444"
    if score >= 7.0:
        return "HIGH", "#f59e0b"
    if score >= 4.0:
        return "MEDIUM", "#22c55e"
    return "LOW", "#3b82f6"


def _source_text(article: DiscoveredArticle) -> str:
    return " ".join((article.title, article.summary, article.full_content or ""))


def _validated_sigma(report_id: str, rule: dict) -> str:
    """Return stable YAML only after syntax and minimum-contract validation."""
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://cti.cyberdudebivash.in/{report_id}"))
    document = {
        "title": rule["title"],
        "id": rule_id,
        "status": "experimental",
        "description": rule["description"],
        "references": rule["references"],
        "author": "CYBERDUDEBIVASH Sentinel APEX Detection Engineering",
        "date": rule["date"],
        "logsource": rule["logsource"],
        "detection": rule["detection"],
        "falsepositives": rule["falsepositives"],
        "level": rule["level"],
        "tags": rule["tags"],
    }
    rendered = yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=110)
    parsed = yaml.safe_load(rendered)
    mandatory = {"title", "id", "status", "description", "logsource", "detection", "falsepositives", "level"}
    if not isinstance(parsed, dict) or not mandatory.issubset(parsed):
        raise ValueError("generated Sigma rule failed minimum contract validation")
    if "condition" not in parsed.get("detection", {}):
        raise ValueError("generated Sigma rule has no detection condition")
    return rendered


_KQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KQL_ALLOWED_OPERATORS = ("has_any", "has", "contains", "==", "!=", "startswith", "endswith")
# Matches one well-formed, correctly-escaped KQL double-quoted string
# literal (an indicator token like "SLEEP(" is valid KQL despite containing
# an unbalanced paren *inside the literal* -- that paren is data, not
# structure). Stripping every well-formed literal first, so structural
# balance checks below run only on code, is what makes those checks
# meaningful instead of false-positiving on legitimate literal content.
_KQL_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def _kql_string_list(tokens: list[str]) -> str:
    """Render a comma-separated list of KQL double-quoted string literals
    with real backslash/quote escaping for that language -- not Python's
    own repr() quote-style-picking, which mixes single- and double-quoted
    output depending on a token's content and has no obligation to match
    KQL's escape conventions."""
    literals = []
    for token in tokens:
        escaped = token.replace("\\", "\\\\").replace('"', '\\"')
        literals.append(f'"{escaped}"')
    return ", ".join(literals)


def _validated_kql(report_id: str, rule: dict) -> str:
    """Return stable Sentinel KQL text only after structural syntax and
    minimum-contract validation -- the same rigor level ``_validated_sigma``
    applies via PyYAML's real parser: neither is a full grammar/semantic
    validator for its language, both refuse to return text that fails
    their language's minimum structural contract (balanced quoting and
    parens, a bare-identifier table line followed only by pipe stages, a
    real non-empty ``where`` filter using a recognized operator) rather
    than trusting hand-assembled string interpolation.
    """
    mandatory = {"title", "table", "where", "project"}
    if not mandatory.issubset(rule):
        raise ValueError("KQL rule is missing a mandatory field")
    if not rule["where"]:
        raise ValueError("generated KQL rule has no where clause")
    if not _KQL_IDENTIFIER_RE.match(rule["table"]):
        raise ValueError(f"invalid KQL table identifier: {rule['table']!r}")

    comment_lines = [f"// {rule['title']}", f"// report: {report_id}"]
    if rule.get("table_note"):
        comment_lines.append(f"// {rule['table_note']}")
    code_lines = [rule["table"]] + [f"| where {clause}" for clause in rule["where"]]
    if rule["project"]:
        code_lines.append(f"| project {', '.join(rule['project'])}")
    rendered = "\n".join(comment_lines + code_lines)

    if not _KQL_IDENTIFIER_RE.match(code_lines[0]):
        raise ValueError("generated KQL does not open with a bare table identifier")
    for stage in code_lines[1:]:
        if not stage.startswith("| "):
            raise ValueError(f"generated KQL stage does not start with a pipe operator: {stage!r}")
    # Strip every well-formed string literal before checking structural
    # balance -- a literal like "SLEEP(" legitimately contains an
    # unbalanced paren as data; only code-level parens/quotes must balance.
    structural_text = _KQL_STRING_LITERAL_RE.sub("", rendered)
    if '"' in structural_text:
        raise ValueError("generated KQL has an unterminated or malformed string literal")
    if structural_text.count("(") != structural_text.count(")"):
        raise ValueError("generated KQL has unbalanced parentheses")
    where_stages = [ln for ln in code_lines if ln.startswith("| where ")]
    if not where_stages:
        raise ValueError("generated KQL has no where stage")
    for stage in where_stages:
        if not any(op in stage for op in _KQL_ALLOWED_OPERATORS):
            raise ValueError(f"generated KQL where stage uses no recognized operator: {stage!r}")
    return rendered


def _detection_package(article: DiscoveredArticle, context: ReportContext) -> DetectionPackage:
    source = _source_text(article).lower()
    source_ref = article.url
    date = context.generated_at[:10]

    if context.family == "ransomware_claim":
        return DetectionPackage(
            status="withheld_insufficient_evidence",
            rationale=(
                "The source establishes a leak-site claim but provides no validated actor-specific IOCs or TTPs. "
                "Publishing a branded rule would create false precision."
            ),
            telemetry=(
                "Validate EDR coverage for mass file modification and recovery-inhibition activity as a general ransomware readiness control.",
                "Monitor identity, remote-access, and backup-administration logs; do not attribute activity to the named group without matching evidence.",
            ),
        )

    # RX-P1H: threat_actor and ransomware_reporting used to miss this set
    # entirely and fall through to the vulnerability-class branches below --
    # those are all CVE-shaped (context.vulnerability_class is never set for
    # either family), so in practice they always landed on the final
    # withheld_insufficient_evidence return anyway, but for the wrong,
    # generic "no product-specific telemetry" rationale rather than the
    # honest, family-appropriate one this branch already gives ai_security/
    # breach_notice/general_intelligence -- both are equally intelligence/
    # news records with no threat-specific telemetry of their own.
    if context.family in {"ai_security", "breach_notice", "general_intelligence", "threat_actor", "ransomware_reporting"}:
        return DetectionPackage(
            status="not_applicable",
            rationale="The source is an intelligence/news record without threat-specific telemetry or observables.",
            telemetry=(
                "Track the cited development through the relevant risk, governance, or incident-management process.",
                "Create detection content only after a concrete attack behavior, log source, and testable observable are confirmed.",
            ),
        )

    if context.vulnerability_class == "denial_of_service":
        return DetectionPackage(
            status="telemetry_specification_only",
            rationale="Availability-impact evidence does not justify a process-execution or web-shell rule.",
            telemetry=(
                "Alert on affected-service crash/restart loops, saturation, latency, and request-rate anomalies against a measured baseline.",
                "Correlate load-balancer, application, operating-system, and infrastructure metrics around the reported failure window.",
            ),
            attack_mappings=("Impact → Endpoint Denial of Service (T1499), only where service exhaustion is observed.",),
        )

    if context.vulnerability_class in {"spoofing", "authentication_failure", "authorization_failure"}:
        return DetectionPackage(
            status="telemetry_specification_only",
            rationale="The source describes an identity/control-boundary weakness but provides no stable exploit signature.",
            telemetry=(
                "Correlate successful sessions with a preceding authentication event, expected identity context, device identity, and authorization decision.",
                "Alert on identity/session changes that violate normal trust-boundary or policy sequencing for the affected component.",
            ),
            attack_mappings=("Defense Evasion → Valid Accounts (T1078), only if authentication/session abuse is observed.",),
        )

    if context.vulnerability_class == "privilege_escalation":
        return DetectionPackage(
            status="telemetry_specification_only",
            rationale="Privilege-escalation behavior requires product- and platform-specific event semantics not present in the source record.",
            telemetry=(
                "Monitor privilege/token changes, setuid or service-account transitions, and privileged child processes tied to the affected product.",
                "Correlate elevation events with the exact vulnerable process and version after exposure is confirmed.",
            ),
            attack_mappings=("Privilege Escalation → Exploitation for Privilege Escalation (T1068), conditional on observed elevation.",),
        )

    if context.vulnerability_class == "sql_injection":
        rule = {
            "title": f"Potential SQL Injection Probing Related to {article.cve_id or context.report_id}",
            "description": "Detects common SQL injection metacharacter sequences in web request targets. Validate against application routes and WAF telemetry.",
            "references": [source_ref],
            "date": date,
            "logsource": {"category": "webserver"},
            "detection": {
                "selection": {"cs-uri-query|contains": ["' OR ", "UNION SELECT", "SLEEP(", "WAITFOR DELAY"]},
                "condition": "selection",
            },
            "falsepositives": ["Security testing", "Encoded legitimate query values"],
            "level": "medium",
            "tags": ["attack.initial-access", "attack.t1190"],
        }
        sqli_tokens = rule["detection"]["selection"]["cs-uri-query|contains"]
        kql_rule = {
            "title": rule["title"],
            "table": "WebRequestLogs",
            "table_note": "Placeholder table name -- bind to your ingested web/WAF request-log table "
                           "(e.g. AzureDiagnostics with Category == 'ApplicationGatewayAccessLog', W3CIISLog, "
                           "or a custom table) and confirm the request-URI column name before deployment.",
            "where": [f"RequestUri has_any ({_kql_string_list(sqli_tokens)})"],
            "project": ["TimeGenerated", "RequestUri", "ClientIP"],
        }
        return DetectionPackage(
            status="syntax_validated_experimental",
            rationale="The source explicitly identifies SQL injection; the rule detects class-level probes, not successful exploitation.",
            telemetry=(
                "Collect full reverse-proxy/WAF request targets, response status, response size, and application/database error telemetry.",
                "Tune by application route and decode URL-encoded parameters before matching.",
            ),
            sigma_yaml=_validated_sigma(context.report_id, rule),
            kql=_validated_kql(context.report_id, kql_rule),
            attack_mappings=("Initial Access → Exploit Public-Facing Application (T1190), conditional on an exposed web application.",),
        )

    if context.vulnerability_class in {"path_traversal", "server_side_request_forgery"}:
        tokens = ["../", "%2e%2e", "file://"] if context.vulnerability_class == "path_traversal" else ["169.254.169.254", "127.0.0.1", "localhost"]
        rule = {
            "title": f"Potential {_label(context.vulnerability_class)} Probing Related to {article.cve_id or context.report_id}",
            "description": "Detects class-level request indicators. It does not establish successful exploitation.",
            "references": [source_ref],
            "date": date,
            "logsource": {"category": "webserver"},
            "detection": {"selection": {"cs-uri-query|contains": tokens}, "condition": "selection"},
            "falsepositives": ["Security testing", "Legitimate encoded application parameters"],
            "level": "medium",
            "tags": ["attack.initial-access", "attack.t1190"],
        }
        kql_rule = {
            "title": rule["title"],
            "table": "WebRequestLogs",
            "table_note": "Placeholder table name -- bind to your ingested web/WAF request-log table "
                           "(e.g. AzureDiagnostics with Category == 'ApplicationGatewayAccessLog', W3CIISLog, "
                           "or a custom table) and confirm the request-URI column name before deployment.",
            "where": [f"RequestUri has_any ({_kql_string_list(tokens)})"],
            "project": ["TimeGenerated", "RequestUri", "ClientIP"],
        }
        return DetectionPackage(
            status="syntax_validated_experimental",
            rationale="The source identifies a request-oriented vulnerability class with testable class-level request indicators.",
            telemetry=(
                "Collect decoded request target, destination/upstream address, response status, and application error telemetry.",
                "Treat matches as investigation leads; confirm product route and affected version before escalation.",
            ),
            sigma_yaml=_validated_sigma(context.report_id, rule),
            kql=_validated_kql(context.report_id, kql_rule),
            attack_mappings=("Initial Access → Exploit Public-Facing Application (T1190), conditional on an exposed web application.",),
        )

    web_rce = context.vulnerability_class == "command_injection" and bool(
        re.search(r"web|http|server|application|api|remote", source, re.IGNORECASE)
    )
    if web_rce:
        web_service_names = ["w3wp.exe", "httpd", "nginx", "java"]
        interpreter_names = ["cmd.exe", "powershell.exe", "sh", "bash"]
        rule = {
            "title": f"Web Service Spawning a Command Interpreter Related to {article.cve_id or context.report_id}",
            "description": "Detects command interpreters spawned by common web-service processes. Requires product-specific parent-process tuning.",
            "references": [source_ref],
            "date": date,
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection_parent": {"ParentImage|endswith": ["\\w3wp.exe", "/httpd", "/nginx", "/java"]},
                "selection_child": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe", "/bin/sh", "/bin/bash"]},
                "condition": "selection_parent and selection_child",
            },
            "falsepositives": ["Documented administrative hooks", "Approved application maintenance"],
            "level": "high",
            "tags": ["attack.execution", "attack.t1059"],
        }
        kql_rule = {
            "title": rule["title"],
            "table": "DeviceProcessEvents",
            "table_note": "DeviceProcessEvents is a real Microsoft Defender/Sentinel Advanced Hunting table; "
                           "tune the parent-service and interpreter name lists to the affected product's actual "
                           "executable before deployment.",
            "where": [
                f"InitiatingProcessFileName has_any ({_kql_string_list(web_service_names)})",
                f"FileName has_any ({_kql_string_list(interpreter_names)})",
            ],
            "project": ["Timestamp", "DeviceName", "InitiatingProcessFileName", "FileName", "ProcessCommandLine"],
        }
        return DetectionPackage(
            status="syntax_validated_experimental",
            rationale="The source identifies command/code execution and a remotely reachable service context.",
            telemetry=(
                "Collect process lineage for the affected service plus application, WAF, and network egress telemetry.",
                "Replace generic parent-process names with the affected product executable before deployment.",
            ),
            sigma_yaml=_validated_sigma(context.report_id, rule),
            kql=_validated_kql(context.report_id, kql_rule),
            attack_mappings=("Execution → Command and Scripting Interpreter (T1059), conditional on observed child-process execution.",),
        )

    return DetectionPackage(
        status="withheld_insufficient_evidence",
        rationale="The source record does not contain enough product-specific telemetry or observables for a defensible rule.",
        telemetry=(
            "Confirm affected assets and versions, then collect the product's application, authentication, process, and network telemetry.",
            "Use vendor-provided exploit indicators or a validated reproduction before publishing threat-specific detection logic.",
        ),
    )


def _facts(article: DiscoveredArticle, context: ReportContext) -> list[str]:
    items = [
        f'<strong>Source type:</strong> {_esc(context.family_label)}',
        f'<strong>Source publication time:</strong> {_esc(article.published_at or "Not supplied")}',
    ]
    if article.cve_id:
        items.append(f'<strong>CVE:</strong> {_esc(article.cve_id)}')
    if article.cvss_score is not None:
        items.append(f'<strong>CVSS base score:</strong> {_esc(f"{article.cvss_score:.1f}")}')
    if article.cvss_vector:
        items.append(f'<strong>CVSS vector:</strong> <code>{_esc(article.cvss_vector)}</code>')
    if article.cwe_ids:
        items.append(f'<strong>CWE:</strong> {_esc(", ".join(article.cwe_ids))}')
    if article.affected_product or article.affected_vendor:
        items.append(f'<strong>Affected product:</strong> {_esc(article.affected_product or article.affected_vendor)}')
    if article.epss_score is not None:
        percentile = f"; percentile {article.epss_percentile * 100:.1f}%" if article.epss_percentile is not None else ""
        items.append(f'<strong>EPSS:</strong> {_esc(f"{article.epss_score * 100:.3f}%{percentile}")}')
    if article.kev_listed is True:
        details = "CISA KEV listed"
        if article.kev_date_added:
            details += f" on {article.kev_date_added}"
        if article.kev_due_date:
            details += f"; federal due date {article.kev_due_date}"
        items.append(f'<strong>Exploitation evidence:</strong> {_esc(details)}')
    elif article.kev_listed is False:
        items.append('<strong>KEV catalog check:</strong> Not present in the successfully retrieved catalog snapshot; this does not prove absence of exploitation.')
    else:
        items.append('<strong>KEV catalog check:</strong> Unknown or unavailable; no negative claim is made.')
    return items


def _family_analysis(article: DiscoveredArticle, context: ReportContext) -> str:
    """Family-specific assessment. Deliberately does NOT re-quote
    ``article.summary`` -- the Executive Summary section above already
    shows it as the report's first exposure to the source facts, and
    ``_technical_evidence()``'s "Source Evidence Extract" below explicitly
    quotes it as labeled raw evidence. A third, unlabeled repeat here added
    no analytical value and was the exact "hallmark of template-driven
    synthesis" duplication found in real published reports (verified live
    against the JWR PhaaS and Windows Task Host / CISA reports) -- this
    section's job is the boundary/analysis text alone."""
    if context.family == "ransomware_claim":
        body = _panel(
            '<p style="margin:0"><strong style="color:#f59e0b">Evidence boundary:</strong> '
            'This is a third-party leak-site listing or aggregator record. It is not independent confirmation of compromise scope, '
            'encryption, data theft, initial-access method, or actor attribution beyond the reported claim.</p>',
            "#f59e0b",
            "#120a00",
        )
        actions = _bullets([
            "<strong>P0 — Internal validation:</strong> Check the named organization/domain against incident, EDR, identity, backup, and data-loss alerts; do not contact or name affected parties based only on the claim.",
            "<strong>P1 — Exposure review:</strong> Validate externally exposed services, privileged access, remote-access controls, and immutable-backup health.",
            "<strong>P2 — Escalation:</strong> Activate incident response and legal/privacy workflows only when independent internal or authoritative evidence confirms an incident.",
        ], "#f59e0b")
        return _section("Claim Assessment", body, "#f59e0b") + _section("Defensive Decision Guidance", actions, "#22c55e")

    if context.family == "breach_notice":
        return _section(
            "Disclosure Assessment",
            _panel(
                '<p style="margin:0"><strong>Evidence boundary:</strong> The source is a public breach-record entry. '
                'It does not establish that the reader or their environment is affected.</p>'
            ),
            "#a855f7",
        ) + _section(
            "Defensive Decision Guidance",
            _bullets([
                "<strong>Identity:</strong> Search for corporate identities associated with the disclosed service using an approved exposure-monitoring process; never upload passwords or secrets.",
                "<strong>Access control:</strong> Revoke exposed sessions, require unique credentials, and enforce phishing-resistant MFA where affected accounts are confirmed.",
                "<strong>Privacy:</strong> Route confirmed organizational exposure through legal/privacy assessment before notification decisions.",
            ], "#22c55e"),
            "#22c55e",
        )

    if context.family == "ai_security":
        return _section(
            "AI Security Assessment",
            _panel(
                '<p style="margin:0"><strong>Assessment boundary:</strong> This record is treated as AI-security intelligence. '
                'No vulnerability, successful attack, affected-customer scope, or conventional malware behavior is inferred unless the cited source explicitly supplies it.</p>',
                "#a855f7",
                "#0d0014",
            ),
            "#a855f7",
        ) + _section(
            "Governance and Engineering Actions",
            _bullets([
                "<strong>Model/system inventory:</strong> Identify whether the cited model, provider, framework, or capability exists in approved or shadow AI use.",
                "<strong>Control review:</strong> Map the source-backed risk to model access, tool permissions, data boundaries, evaluation coverage, monitoring, and human-approval controls.",
                "<strong>Evidence collection:</strong> Record reproducible prompts, tool calls, model/version identifiers, policy decisions, and output traces before classifying a security defect.",
            ], "#a855f7"),
            "#22c55e",
        )

    if context.family in {"cve_advisory", "cisa_kev", "cisa_advisory"}:
        prerequisites = _exploit_prerequisites_clause(article.cvss_vector)
        impact = (
            f"Active exploitation is confirmed by the cited evidence; prioritize exposure confirmation and the authoritative remediation action.{prerequisites}"
            if context.exploitation_status == "confirmed"
            else f"Active exploitation is not confirmed by the available evidence.{prerequisites} Prioritization must combine technical severity, exposure, asset criticality, and compensating controls."
        )
        return _section(
            "Technical Analysis",
            _panel(
                f'<p style="margin:0"><strong>Vulnerability class:</strong> {_esc(_label(context.vulnerability_class))}. '
                f'<strong>Assessment:</strong> {_esc(impact)}</p>'
            ),
            "#06b6d4",
        ) + _section(
            "Exposure and Remediation Decisions",
            _bullets([
                "<strong>P0 — Inventory:</strong> Confirm the affected product and version against authoritative vendor/NVD data; prioritize internet-facing and business-critical assets.",
                f'<strong>P0 — Remediation:</strong> {_esc(context.patch_label)}',
                "<strong>P1 — Compensating controls:</strong> Restrict exposure, enforce least privilege, and apply vendor-supported mitigations when immediate remediation is not possible.",
                "<strong>P1 — Retrospective review:</strong> Search only the telemetry relevant to the affected component and validated vulnerability class; absence of alerts does not prove absence of exploitation.",
            ], "#22c55e"),
            "#22c55e",
        )

    if context.family == "ransomware_reporting":
        return _section(
            "Ransomware Activity Reporting",
            _panel(
                '<p style="margin:0"><strong>Evidence boundary:</strong> This record reports on ransomware activity, '
                'tooling, or trends generally. It does not name a specific victim in the reader\'s environment and '
                'must not be treated as a claimed incident against any particular organization.</p>'
            ),
            "#f59e0b",
        ) + _section(
            "Ransomware Readiness Actions",
            _bullets([
                "<strong>Detection coverage:</strong> Confirm detection and alerting coverage for the ransomware behavior or tradecraft described in this record.",
                "<strong>Backup and recovery:</strong> Validate immutable-backup health and recovery-time assumptions against the reported technique, not a specific claimed compromise.",
                "<strong>Escalation:</strong> Route to incident response only if a separate, corroborated indicator or claim names the reader's own organization.",
            ], "#22c55e"),
            "#22c55e",
        )

    if context.family == "threat_actor":
        return _section(
            "Threat Actor Intelligence Assessment",
            _panel(
                '<p style="margin:0"><strong>Evidence boundary:</strong> Actor attribution, TTPs, and infrastructure '
                'described here are as reported by the cited source. This pipeline does not independently corroborate '
                'attribution or confirm that described infrastructure is currently active.</p>',
                "#a855f7",
                "#0d0014",
            ),
            "#a855f7",
        ) + _section(
            "CTI and Hunting Actions",
            _bullets([
                "<strong>Watchlist:</strong> Track the named actor and any aliases in the organization's threat-actor watchlist and CTI platform.",
                "<strong>Telemetry cross-reference:</strong> Check any described infrastructure or indicators against internal DNS, proxy, and EDR telemetry before treating them as active.",
                "<strong>Targeted hunt:</strong> Route confirmed matches to threat hunting for a retrospective sweep; do not assume relevance without one.",
            ], "#a855f7"),
            "#22c55e",
        )

    return _section(
        "Intelligence Assessment",
        _panel(
            '<p style="margin:0"><strong>Evidence boundary:</strong> Conclusions are limited to the cited source record. '
            'No affected-customer scope, attribution, exploitation, or financial impact is inferred.</p>'
        ),
        "#00d4ff",
    ) + _section(
        "Operational Decisions",
        _bullets([
            "<strong>Validate relevance:</strong> Determine whether the cited technology, organization, actor, or behavior exists in the environment.",
            "<strong>Collect evidence:</strong> Preserve source records and internal telemetry before escalating a hypothesis to an incident or vulnerability finding.",
            "<strong>Assign ownership:</strong> Route confirmed exposure to the accountable security, engineering, risk, or privacy owner with an explicit decision deadline.",
        ], "#22c55e"),
        "#22c55e",
    )


def _technical_evidence(article: DiscoveredArticle) -> str:
    rows = "".join(
        f'<div style="padding:8px 0;border-bottom:1px solid #1e293b;color:#cbd5e1;font-family:monospace;font-size:12px;line-height:1.6">{_esc(line)}</div>'
        for line in _source_lines(article)
    )
    return _section(
        "Source Evidence Extract",
        _panel(
            rows
            + '<p style="margin:12px 0 0;color:#64748b;font-size:11px">This extract is escaped and rendered from the ingested source record; generated analysis is not presented as a source fact.</p>'
        ),
        "#475569",
    )


def _detection_section(package: DetectionPackage) -> str:
    status_color = "#22c55e" if package.status == "syntax_validated_experimental" else "#f59e0b"
    status = _panel(
        f'<div style="font-family:monospace;font-size:11px;color:{status_color};font-weight:800;letter-spacing:1px">'
        f'DETECTION STATUS: {_esc(package.status.upper())}</div>'
        f'<p style="margin:8px 0 0">{_esc(package.rationale)}</p>',
        status_color,
    )
    telemetry = _bullets([_esc(item) for item in package.telemetry], "#06b6d4")
    body = status + '<div style="margin-top:12px">' + telemetry + "</div>"
    if package.sigma_yaml:
        body += (
            '<div class="detection-code-block" style="margin-top:14px;border:1px solid #22c55e55;border-radius:8px;overflow:hidden">'
            '<div style="padding:8px 14px;background:#161b22;color:#22c55e;font-family:monospace;font-size:11px">'
            'SIGMA YAML — SYNTAX VALIDATED · EXPERIMENTAL · ENVIRONMENT TUNING REQUIRED</div>'
            f'<pre style="margin:0;padding:16px;background:#07100a;color:#86efac;white-space:pre-wrap;overflow-x:auto;font-size:11px;line-height:1.55"><code>{_esc(package.sigma_yaml)}</code></pre>'
            '</div>'
        )
    if package.kql:
        body += (
            '<div style="margin-top:14px;border:1px solid #22c55e55;border-radius:8px;overflow:hidden">'
            '<div style="padding:8px 14px;background:#161b22;color:#22c55e;font-family:monospace;font-size:11px">'
            'SENTINEL KQL — SYNTAX VALIDATED · EXPERIMENTAL · ENVIRONMENT TUNING REQUIRED</div>'
            f'<pre style="margin:0;padding:16px;background:#07100a;color:#86efac;white-space:pre-wrap;overflow-x:auto;font-size:11px;line-height:1.55"><code>{_esc(package.kql)}</code></pre>'
            '</div>'
        )
    return _section("Detection Engineering", body, "#06b6d4")


def _attack_section(package: DetectionPackage) -> str:
    if not package.attack_mappings:
        return ""
    return _section(
        "MITRE ATT&CK Mapping",
        _bullets([_esc(item) for item in package.attack_mappings], "#a855f7")
        + _panel(
            "Mappings are conditional analytical aids, not claims that the technique occurred. Promote a mapping to observed only after telemetry confirms the behavior.",
            "#a855f7",
            "#0d0014",
        ),
        "#a855f7",
    )


def _references(article: DiscoveredArticle, context: ReportContext) -> str:
    refs = [f'<a href="{_esc(article.url)}" target="_blank" rel="noopener noreferrer" style="color:#60a5fa">Primary source record</a>']
    if article.cve_id:
        refs.append(
            f'<a href="https://nvd.nist.gov/vuln/detail/{_esc(article.cve_id)}" target="_blank" rel="noopener noreferrer" style="color:#60a5fa">NVD — {_esc(article.cve_id)}</a>'
        )
    if article.kev_listed is not None:
        refs.append(
            '<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" style="color:#60a5fa">CISA KEV catalog</a>'
        )
    return _section("References", _bullets(refs, "#475569"), "#475569")


def _provenance(article: DiscoveredArticle, context: ReportContext) -> str:
    rows = [
        ("Report ID", context.report_id),
        ("Source system", article.source),
        ("Source URL", article.url),
        ("Source published", article.published_at or "Not supplied"),
        ("Source-record SHA-256", context.source_record_hash),
        ("Generated UTC", context.generated_at),
        ("Production Mode", context.review_status),
        ("Certification", context.certification_status),
    ]
    cells = "".join(
        f'<div style="padding:8px 10px;border-bottom:1px solid #1e293b">'
        f'<span style="display:inline-block;min-width:170px;color:#64748b;font-family:monospace;font-size:10px;text-transform:uppercase;letter-spacing:1px">{_esc(label)}</span>'
        + (
            f'<a href="{_esc(value)}" target="_blank" rel="noopener noreferrer" style="color:#60a5fa;word-break:break-all">{_esc(value)}</a>'
            if label == "Source URL" else f'<span style="color:#cbd5e1;word-break:break-all">{_esc(value)}</span>'
        )
        + "</div>"
        for label, value in rows
    )
    return _section("Provenance and Certification", _panel(cells, "#334155", "#030912"), "#64748b")


def render_evidence_report(
    article: DiscoveredArticle, config: Config, include_provenance: bool = True,
) -> RenderedReport:
    context = build_report_context(article)
    severity, severity_color = _severity(article)
    package = _detection_package(article, context)

    facts = _section("Verified Facts", _bullets(_facts(article, context), "#22c55e"), "#22c55e")
    classification = (
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px">'
        + "".join(
            _panel(
                f'<div style="color:{color};font-family:monospace;font-size:10px;font-weight:800;letter-spacing:1px;text-transform:uppercase">{_esc(label)}</div>'
                f'<div style="margin-top:6px;color:#e2e8f0;font-size:13px;font-weight:700">{_esc(value)}</div>',
                color,
            )
            for label, value, color in (
                ("Intelligence family", context.family_label, "#00d4ff"),
                ("Technical severity", severity, severity_color),
                ("Exploitation", context.exploitation_label, "#ef4444" if context.exploitation_status == "confirmed" else "#f59e0b"),
                ("Patch/remediation", context.patch_label, "#22c55e" if context.patch_status in {"available", "required_action"} else "#64748b"),
            )
        )
        + "</div>"
    )

    executive_summary = _section(
        "Executive Summary",
        _panel(
            f'<p style="margin:0 0 10px">{_esc(_truncate(article.summary, 1800))}</p>'
            f'<p style="margin:0;color:#94a3b8"><strong style="color:#e2e8f0">Decision:</strong> '
            f'Validate relevance and exposure using the cited source and internal evidence before treating this record as an incident, confirmed compromise, or customer-specific finding.</p>'
        ),
        "#00d4ff",
    )

    body = (
        f'<article data-report-id="{_esc(context.report_id)}" data-source-record-sha256="{context.source_record_hash}" '
        f'data-report-family="{_esc(context.family)}" data-review-status="ai-native-automated" '
        'style="font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;color:#e2e8f0">'
        f'<div style="margin:0 0 24px;padding:16px 20px;background:#00080f;border:1px solid {severity_color}66;border-radius:8px">'
        f'<div style="color:{severity_color};font-family:monospace;font-size:11px;font-weight:900;letter-spacing:1.5px">'
        f'{_esc(context.family_label.upper())} · {severity}</div>'
        f'<div style="margin-top:8px;color:#94a3b8;font-size:12px">{_esc(context.report_id)} · Generated {_esc(context.generated_at)}</div>'
        '</div>'
        + executive_summary
        + _section("Threat Classification and Evidence Status", classification, "#ef4444")
        + facts
        + _family_analysis(article, context)
        + _technical_evidence(article)
        + _attack_section(package)
        + _detection_section(package)
        + _references(article, context)
        + (_provenance(article, context) if include_provenance else "")
        + '<div style="margin-top:24px">'
        + _panel(
            f'<strong style="color:#e2e8f0">{_esc(context.review_status)}.</strong> '
            f'{_esc(context.certification_status)}. Customer-specific action requires '
            'exposure validation and accountable human approval.'
        )
        + '</div>'
        + "</article>"
    )

    return RenderedReport(html=body, context=context, detection_status=package.status)
