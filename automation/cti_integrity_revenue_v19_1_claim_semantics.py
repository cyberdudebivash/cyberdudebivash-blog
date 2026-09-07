"""Claim-semantics hardening for CTI Integrity + Revenue v19.1.

The final v19.1 gate must reject unsupported *positive* capability claims while
allowing explicit negative disclosures such as "IOCs are not established".
This module replaces only v19.1's keyword patterns; it does not weaken any
underlying ReportX/evidence/publication control.
"""
from __future__ import annotations

import re

from . import cti_integrity_revenue_v19_1 as _v19_1

_INSTALLED = False

# If the same sentence explicitly says the named artifact is not established,
# available, present, provided, or asserted, the mention is an evidence-boundary
# disclosure rather than a positive product/content claim. The lookahead is
# intentionally bounded to a single sentence and 180 characters.
_NEGATED_SUFFIX = (
    r"(?![^.!?]{0,180}\b(?:is|are|was|were|remain|remains)\s+"
    r"(?:explicitly\s+)?not\s+(?:established|available|present|provided|asserted)\b)"
)


def _pattern(term: str) -> re.Pattern[str]:
    return re.compile(term + _NEGATED_SUFFIX, re.I)


def install_claim_semantics_v19_1() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    _v19_1._ARTIFACT_PATTERNS = {
        "ioc": _pattern(r"\bIOCs?\b|\bindicator pack\b"),
        "sigma": _pattern(r"\bSIGMA(?:\s+rules?|\s+pack)?\b"),
        "yara": _pattern(r"\bYARA(?:\s+rules?|\s+pack)?\b"),
        "attack_chain": _pattern(r"\battack chain\b"),
        "attack_mapping": _pattern(r"\bMITRE\s+ATT&?CK(?:\s+mapping)?\b"),
    }
    _INSTALLED = True
