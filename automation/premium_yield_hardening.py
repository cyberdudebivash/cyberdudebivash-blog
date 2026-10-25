"""Production yield hardening for premium Blogger intelligence reports.

This layer addresses the second-order production bottlenecks observed after
PR #163 restored publication on 2026-09-03. The first post-fix production run
proved Blogger, discovery, evidence gating, and fetch-back healthy, but only
one of five selected reports published. The remaining loss was caused by
four generation-side inefficiencies:

* the primary Groq model was already at its model-scoped daily token ceiling,
  yet later tasks retried it after Groq supplied a long reset time;
* secondary Key Judgements used the same expensive primary-model ordering as
  the long-form narrative even though their output is small structured JSON
  and is independently evidence-validated before acceptance;
* premium structural preflight counted core headings more strictly than the
  authoritative public gate, causing unnecessary fallback generation;
* otherwise strong LLM responses could contain a small number of evidence-law
  violations or truncate the terminal Executive Recommendations / References
  sections.

The implementation remains fail closed. It never lowers the 2,200-word public
floor, ReportX/evidence-graph controls, mandatory heading gate, LLM-authorship
requirement, or Blogger fetch-back verification. It reduces wasted provider
calls, makes the generation prompt carry the pipeline evidence boundary,
conservatively downgrades unsupported wording, and permits only bounded
terminal-section recovery. The stricter 25-section policy is installed by
``premium_yield_contract_guard`` after this layer.
"""

from __future__ import annotations

import html as html_lib
import re
import time
from dataclasses import replace
from typing import Callable, Optional
from urllib.parse import urlsplit

import requests

from . import key_judgements as _key_judgements
from . import llm_client as _llm
from . import premium_incident_recovery as _recovery
from . import premium_provider_budget as _budget
from . import premium_publication as _premium
from . import report_integrity as _integrity
from .content_discovery import DiscoveredArticle
from .logger import setup_logger

logger = setup_logger("premium_yield_hardening")

_TAIL_REPAIRABLE_CORE = frozenset({"executive recommendations", "references"})
_MODEL_COOLDOWNS: dict[tuple[str, str], float] = {}
# A Groq HTTP 404 is non-retryable for a particular model in this process.
# The 2026-10-25 publisher repeatedly attempted the same failing Qwen model.
# Never persist this inference across jobs: models and provider routing change.
_GROQ_404_THIS_RUN: set[tuple[str, str]] = set()

_ORIGINAL_OPENAI_CALL: Optional[Callable] = None
_ORIGINAL_TRY_PROVIDER: Optional[Callable] = None
_ORIGINAL_PREMIUM_CALL: Optional[Callable] = None
_ORIGINAL_PROMPT_BUILDER: Optional[Callable] = None
_ORIGINAL_RAW_CONTRACT_COMPLETE: Optional[Callable] = None
_INSTALLED = False


def _cooldown_key(url: str, model: str) -> tuple[str, str]:
    return str(url), str(model)


def _cooldown_remaining(url: str, model: str) -> float:
    key = _cooldown_key(url, model)
    expires = _MODEL_COOLDOWNS.get(key)
    if expires is None:
        return 0.0
    remaining = expires - time.monotonic()
    if remaining <= 0:
        _MODEL_COOLDOWNS.pop(key, None)
        return 0.0
    return remaining


def _activate_model_cooldown(url: str, model: str, retry_after: float) -> None:
    if retry_after <= 0:
        return
    key = _cooldown_key(url, model)
    expires = time.monotonic() + retry_after
    # Never shorten a provider-declared reset already observed for this model.
    _MODEL_COOLDOWNS[key] = max(_MODEL_COOLDOWNS.get(key, 0.0), expires)
    logger.info(
        "Provider model cooldown activated for current process",
        extra={"model": model, "retry_after_seconds": round(retry_after, 2)},
    )


def quota_aware_openai_call(
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
    sleep_fn=time.sleep,
):
    """Remember long provider-declared 429 resets for the remainder of a run.

    ``llm_client`` already skips a pointless retry when Retry-After exceeds
    its bounded wait ceiling. Production then immediately retried the same
    exhausted 120B model on the next article and again on Key Judgements.
    This wrapper converts the provider evidence into a process-local circuit
    breaker. No cooldown state survives the GitHub Actions job.
    """
    if _ORIGINAL_OPENAI_CALL is None:
        raise RuntimeError("premium yield hardening is not installed")

    try:
        content = _ORIGINAL_OPENAI_CALL(
            url=url,
            api_key=api_key,
            model=model,
            prompt=prompt,
            max_tokens=max_tokens,
            extra_headers=extra_headers,
            sleep_fn=sleep_fn,
        )
    except requests.exceptions.HTTPError as exc:
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        # Cache only the exact known Groq chat-completions endpoint, and only
        # within this process. A single 404 is evidence this exact model cannot
        # be used right now; retrying it for every report wastes the run budget.
        # This is NOT evidence every Groq model or every provider is offline.
        if status == 404 and url == _llm._GROQ_URL:
            _GROQ_404_THIS_RUN.add(_cooldown_key(url, model))
            logger.warning("Groq model HTTP 404 quarantined for this run",
                           extra={"model": model, "error_code": "GROQ_MODEL_HTTP_404"})
        if status == 429:
            raw_retry_after = _llm._raw_retry_after_seconds(response)
            if raw_retry_after is not None and raw_retry_after > _llm._MAX_BACKOFF_SECONDS:
                _activate_model_cooldown(url, model, raw_retry_after)
        raise
    else:
        # Success is authoritative evidence that an old process-local cooldown
        # has expired or was stale.
        _MODEL_COOLDOWNS.pop(_cooldown_key(url, model), None)
        return content


def quota_aware_try_provider(
    name: str,
    url: str,
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
    extra_headers: dict,
    sleep_fn,
    attempts: Optional[list],
):
    """Skip a model whose provider-declared reset is still in the future."""
    if _ORIGINAL_TRY_PROVIDER is None:
        raise RuntimeError("premium yield hardening is not installed")

    if url == _llm._GROQ_URL and _cooldown_key(url, model) in _GROQ_404_THIS_RUN:
        if attempts is not None:
            attempts.append({
                "provider": name,
                "model": model,
                "ok": False,
                "error": "groq_http_404_quarantined_this_run",
            })
        return None

    remaining = _cooldown_remaining(url, model)
    if remaining > 0:
        logger.info(
            "Skipping provider model still inside declared cooldown",
            extra={
                "provider": name,
                "model": model,
                "retry_after_seconds": round(remaining, 2),
            },
        )
        if attempts is not None:
            attempts.append(
                {
                    "provider": name,
                    "model": model,
                    "ok": False,
                    "error": "provider_cooldown_active",
                    "retry_after_seconds": round(remaining, 2),
                }
            )
        return None

    return _ORIGINAL_TRY_PROVIDER(
        name=name,
        url=url,
        api_key=api_key,
        model=model,
        prompt=prompt,
        max_tokens=max_tokens,
        extra_headers=extra_headers,
        sleep_fn=sleep_fn,
        attempts=attempts,
    )


def _secondary_groq_config(config):
    """Route small structured Key Judgements away from the 120B primary first.

    The first configured fallback is the preferred secondary model. The
    primary model remains last in the Groq sequence, so quality still has a
    final Groq fallback if every smaller independent model quota is unavailable.
    Non-Groq provider ordering is unchanged.
    """
    primary = str(config.llm_model_groq or "").strip()
    fallbacks = [
        str(model).strip()
        for model in config.llm_model_groq_fallbacks
        if str(model).strip()
    ]
    ordered: list[str] = []
    for model in [*fallbacks, primary]:
        if model and model not in ordered:
            ordered.append(model)
    if not ordered:
        return config
    return replace(
        config,
        llm_model_groq=ordered[0],
        llm_model_groq_fallbacks=tuple(ordered[1:]),
    )


def call_quota_efficient_key_judgements(
    config,
    prompt: str,
    max_tokens: int = 2000,
    attempts=None,
    sleep_fn=time.sleep,
):
    """Preserve shared pacing while spending small-model quota first."""
    _budget._pace_premium_request(sleep_fn)
    routed = _secondary_groq_config(config)
    return _budget._ORIGINAL_KEY_JUDGEMENTS_LLM_CALL(
        routed,
        prompt,
        max_tokens=max_tokens,
        attempts=attempts,
        sleep_fn=sleep_fn,
    )


def _normalized_headings(content: str) -> set[str]:
    return {
        _premium._normalized_heading(value)
        for value in _premium._headings(content)
    }


def _core_heading_hits(headings: set[str]) -> set[str]:
    # Deliberately identical to assess_enterprise_report()'s public-gate
    # semantics: numbered/prefixed headings still satisfy the core heading.
    return {
        core
        for core in _premium._CORE_HEADINGS
        if any(core == heading or core in heading for heading in headings)
    }


def authoritative_raw_contract_metrics(content: str) -> tuple[int, int, int]:
    headings = _normalized_headings(content)
    return (
        _premium._word_count(content),
        len(headings),
        len(_core_heading_hits(headings)),
    )


def _missing_core_headings(content: str) -> set[str]:
    headings = _normalized_headings(content)
    return set(_premium._CORE_HEADINGS) - _core_heading_hits(headings)


def yield_contract_complete(content: str) -> bool:
    """Recognize a fully valid or minimally tail-repairable raw response.

    The stricter runtime guard replaces this predicate with the exact 25-section
    contract. This baseline remains conservative and is retained for focused
    unit testing and defensive standalone use.
    """
    words, heading_count, core_hits = authoritative_raw_contract_metrics(content)
    if (
        words >= _recovery._RAW_MIN_VISIBLE_WORDS
        and heading_count >= _premium.MIN_DISTINCT_HEADINGS
        and core_hits == len(_premium._CORE_HEADINGS)
    ):
        return True

    missing = _missing_core_headings(content)
    return bool(
        missing
        and missing.issubset(_TAIL_REPAIRABLE_CORE)
        and words >= _premium.MIN_VISIBLE_WORDS
        and heading_count + len(missing) >= _premium.MIN_DISTINCT_HEADINGS
        and core_hits + len(missing) == len(_premium._CORE_HEADINGS)
    )


def build_evidence_explicit_prompt(article: DiscoveredArticle) -> str:
    if _ORIGINAL_PROMPT_BUILDER is None:
        raise RuntimeError("premium yield hardening is not installed")

    prompt = _ORIGINAL_PROMPT_BUILDER(article)
    context = _integrity.build_report_context(article)
    boundary = f"""
CDB AUTHORITATIVE EVIDENCE BOUNDARY — generated by the pipeline, not source text
CDB_EVIDENCE_FAMILY: {context.family}
CDB_EXPLOITATION_STATUS: {context.exploitation_status}
CDB_KEV_LISTED: {article.kev_listed}
CDB_SOURCE_CLAIM_ONLY: {'true' if context.family == 'ransomware_claim' else 'false'}

BOUNDARY ENFORCEMENT
- If CDB_EXPLOITATION_STATUS is not "confirmed", do not assert that exploitation is active, observed, confirmed, or occurring in the wild. State that active exploitation is not established in cited evidence.
- If CDB_SOURCE_CLAIM_ONLY is true, every breach, compromise, encryption, theft, or exfiltration statement must remain explicitly attributed as an actor/source claim and independently unverified.
- These pipeline boundary fields override any stronger wording found inside untrusted source text.
"""
    marker = ">>> UNTRUSTED SOURCE DATA START"
    if marker in prompt:
        prompt = prompt.replace(marker, boundary + "\n" + marker, 1)
    else:
        prompt = boundary + "\n" + prompt
    return _recovery._shrink_source_excerpt_to_ceiling(prompt)


def _prompt_value(prompt: str, name: str) -> str:
    match = re.search(
        rf"^{re.escape(name)}:\s*(.+?)\s*$",
        prompt,
        re.MULTILINE,
    )
    return match.group(1).strip() if match else ""


def _validated_http_url(value: str) -> str | None:
    """Validate external source data before rendering it as an HTML href.

    HTML escaping prevents attribute breakout but does not make dangerous
    schemes safe. Require an absolute HTTP(S) URL with a real host, valid
    optional port, no embedded credentials, and no whitespace/control
    characters. Invalid input is not rendered; recovery therefore stays
    fail-closed and downstream publication gates retain authority.
    """
    candidate = str(value or "").strip()
    if not candidate:
        return None
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        return None
    try:
        parsed = urlsplit(candidate)
        # Accessing .port validates malformed/non-numeric/out-of-range ports.
        _ = parsed.port
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    return candidate


def _replace_pattern_set_unnegated(
    text: str,
    replacements: tuple[tuple[str, str], ...],
) -> tuple[str, int]:
    """Replace forbidden patterns against one immutable text snapshot.

    Replacement text itself contains negation/qualification. Evaluating later
    matches against already-mutated text can therefore hide a second unsafe
    assertion from the negation detector. All matches and negation context are
    evaluated against the original string and substituted in one pass.
    """
    if not replacements:
        return text, 0

    original = text
    combined = "|".join(
        f"(?P<p{index}>{pattern})"
        for index, (pattern, _) in enumerate(replacements)
    )
    replaced = 0

    def _replacement(match: re.Match) -> str:
        nonlocal replaced
        if _integrity._is_negated_immediately_before(original, match.start()):
            return match.group(0)
        for index, (_, replacement) in enumerate(replacements):
            if match.group(f"p{index}") is not None:
                replaced += 1
                return replacement
        return match.group(0)

    return re.sub(combined, _replacement, original, flags=re.IGNORECASE), replaced


def _repair_evidence_language(content: str, prompt: str) -> tuple[str, int]:
    """Conservatively downgrade only language forbidden by known evidence state."""
    repaired = content
    changes = 0
    exploitation_status = _prompt_value(prompt, "CDB_EXPLOITATION_STATUS").lower()
    family = _prompt_value(prompt, "CDB_EVIDENCE_FAMILY").lower()

    if exploitation_status and exploitation_status != "confirmed":
        replacements = (
            (
                r"\bactively exploited\b",
                "not established as actively exploited in cited evidence",
            ),
            (
                r"\bexploited in the wild\b",
                "not established as exploited in the wild in cited evidence",
            ),
            (
                r"\bobserved exploitation\b",
                "no independently verified observed exploitation",
            ),
            (
                r"\bconfirmed exploitation\b",
                "no confirmed exploitation in cited evidence",
            ),
            (
                r"\bexploitation (?:has been|was) observed\b",
                "exploitation has not been observed in cited evidence",
            ),
        )
        repaired, count = _replace_pattern_set_unnegated(repaired, replacements)
        changes += count

    if family == "ransomware_claim":
        replacements = (
            (
                r"\bconfirms? (?:a |the )?(?:breach|compromise)\b",
                "reports a claimed breach or compromise",
            ),
            (
                r"\b(?:the )?(?:breach|compromise|data theft) (?:is|has been|was) confirmed\b",
                "the incident is reported as an actor claim and is not independently confirmed",
            ),
            (
                r"\bdata (?:has been|was) (?:confirmed )?(?:stolen|exfiltrated)\b",
                "data theft or exfiltration is claimed by the actor and is not independently verified",
            ),
            (
                r"\bvictim(?:'s)? (?:data|network|systems?) (?:has been|was|is) (?:confirmed )?compromised\b",
                "compromise of the victim environment is claimed by the actor and is not independently verified",
            ),
        )
        repaired, count = _replace_pattern_set_unnegated(repaired, replacements)
        changes += count

    return repaired, changes


def _tail_sections(content: str, prompt: str) -> tuple[str, int]:
    """Baseline terminal recovery; production runtime installs the stricter guard.

    This function remains independently safe because SOURCE URL is untrusted
    feed data. It refuses References recovery unless the URL is a validated
    absolute HTTP(S) URL before HTML escaping and href rendering.
    """
    missing = _missing_core_headings(content)
    if not missing or not missing.issubset(_TAIL_REPAIRABLE_CORE):
        return content, 0

    words = _premium._word_count(content)
    heading_count = len(_normalized_headings(content))
    if words < _premium.MIN_VISIBLE_WORDS:
        return content, 0
    if heading_count + len(missing) < _premium.MIN_DISTINCT_HEADINGS:
        return content, 0
    if (
        set(_premium._CORE_HEADINGS) - missing
    ) - _core_heading_hits(_normalized_headings(content)):
        return content, 0

    source_url = _prompt_value(prompt, "SOURCE URL")
    source_title = _prompt_value(prompt, "SOURCE TITLE") or "Primary cited source"
    family = _prompt_value(prompt, "CDB_EVIDENCE_FAMILY").lower()
    exploitation_status = _prompt_value(prompt, "CDB_EXPLOITATION_STATUS").lower()
    additions: list[str] = []

    if "executive recommendations" in missing:
        if family == "ransomware_claim":
            recommendations = (
                "<li><strong>Claim handling:</strong> Treat the leak-site or actor statement as a third-party claim until independent internal or external evidence establishes compromise, encryption, theft, or exfiltration.</li>"
                "<li><strong>Exposure validation:</strong> Check authoritative asset, identity, endpoint, network, SaaS, and backup telemetry for source-specific evidence before declaring an incident.</li>"
                "<li><strong>Evidence preservation:</strong> Preserve relevant logs and forensic artifacts so the claim can be confirmed or refuted without destroying chronology.</li>"
                "<li><strong>Escalation:</strong> Escalate containment and notification decisions from verified organizational evidence and applicable obligations, not from the actor claim alone.</li>"
            )
        else:
            exploitation_clause = (
                " Do not represent exploitation as active unless a cited source or verified KEV evidence establishes it."
                if exploitation_status and exploitation_status != "confirmed"
                else ""
            )
            recommendations = (
                "<li><strong>Exposure decision:</strong> Validate affected assets, software, identities, dependencies, or services against authoritative inventory and telemetry before treating this intelligence record as evidence of compromise.</li>"
                f"<li><strong>Evidence boundary:</strong> Keep source-reported facts, analyst assessment, and internal enterprise evidence separate.{exploitation_clause}</li>"
                "<li><strong>Remediation governance:</strong> Apply only remediation or mitigations established by the cited source or authoritative vendor guidance; otherwise use compensating controls and verify the change path before production rollout.</li>"
                "<li><strong>Validation:</strong> Preserve pre-change telemetry and perform post-change verification so remediation effectiveness and residual exposure can be demonstrated.</li>"
            )
        additions.append(
            f"<h3>Executive Recommendations</h3><ul>{recommendations}</ul>"
        )

    if "references" in missing:
        validated_url = _validated_http_url(source_url)
        if validated_url is None:
            # Do not partially repair a two-section tail if References cannot
            # be safely bound to the actual canonical source.
            return content, 0
        safe_url = html_lib.escape(validated_url, quote=True)
        safe_title = html_lib.escape(source_title)
        additions.append(
            "<h3>References</h3><ul>"
            f'<li><strong>Primary cited source:</strong> <a href="{safe_url}" target="_blank" rel="noopener">{safe_title}</a></li>'
            "</ul>"
        )

    if not additions:
        return content, 0
    return content + "\n" + "\n".join(additions), len(additions)


def evidence_safe_quality_llm(
    config,
    prompt: str,
    max_tokens: int = 3000,
    attempts=None,
    sleep_fn=time.sleep,
):
    """Run existing quality-aware generation, then apply bounded safe repairs."""
    if _ORIGINAL_PREMIUM_CALL is None:
        raise RuntimeError("premium yield hardening is not installed")

    result = _ORIGINAL_PREMIUM_CALL(
        config,
        prompt,
        max_tokens=max_tokens,
        attempts=attempts,
        sleep_fn=sleep_fn,
    )
    if not result:
        return None

    content, provider = result
    content, evidence_repairs = _repair_evidence_language(content, prompt)
    content, tail_repairs = _tail_sections(content, prompt)
    if evidence_repairs or tail_repairs:
        logger.info(
            "Premium generation yield repair applied before authoritative gates",
            extra={
                "provider": provider,
                "evidence_repairs": evidence_repairs,
                "tail_sections_added": tail_repairs,
                "visible_words": _premium._word_count(content),
                "distinct_headings": len(_normalized_headings(content)),
            },
        )
    return content, provider


def install_yield_hardening_overrides() -> None:
    """Install additive premium-runtime yield controls after incident recovery."""
    global _ORIGINAL_OPENAI_CALL, _ORIGINAL_TRY_PROVIDER, _ORIGINAL_PREMIUM_CALL
    global _ORIGINAL_PROMPT_BUILDER, _ORIGINAL_RAW_CONTRACT_COMPLETE, _INSTALLED

    if _INSTALLED:
        return

    _ORIGINAL_OPENAI_CALL = _llm._call_openai_compat
    _ORIGINAL_TRY_PROVIDER = _llm._try_provider
    _llm._call_openai_compat = quota_aware_openai_call
    _llm._try_provider = quota_aware_try_provider

    # Replace the provider-budget Key Judgements wrapper with the same shared
    # pacing gate plus a small-model-first order. Independent judgement
    # verification remains unchanged inside key_judgements.py.
    _key_judgements.call_llm = call_quota_efficient_key_judgements

    _ORIGINAL_RAW_CONTRACT_COMPLETE = _recovery._raw_contract_complete
    _recovery._raw_contract_metrics = authoritative_raw_contract_metrics
    _recovery._raw_contract_complete = yield_contract_complete

    _ORIGINAL_PROMPT_BUILDER = _premium.build_premium_analyst_prompt
    _premium.build_premium_analyst_prompt = build_evidence_explicit_prompt

    _ORIGINAL_PREMIUM_CALL = _premium._premium_llm_call
    _premium._premium_llm_call = evidence_safe_quality_llm

    _INSTALLED = True
