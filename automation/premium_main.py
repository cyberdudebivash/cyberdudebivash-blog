"""Production entry point for premium-grade Blogger syndication."""

from __future__ import annotations

import sys

from . import main as _main
from .astra_cash_conversion_v19 import install_astra_cash_conversion_v19
from .astra_revenue_intelligence_v18 import (
    install_astra_revenue_presentation_v18,
    install_astra_revenue_runtime_v18,
)
from .astra_revenue_yield_alignment_v18_1 import install_astra_revenue_yield_alignment_v18_1
from .cti_dossier_presentation import install_cti_dossier_presentation
from .cti_dossier_v8 import install_cti_dossier_v8
from .cti_dossier_v9 import install_cti_dossier_v9
from .cti_dossier_v10 import install_cti_dossier_v10
from .cti_evidence_convergence import install_cti_evidence_convergence
from .cti_evidence_convergence_v7 import install_cti_evidence_convergence_v7
from .cti_integrity_revenue_v19_1 import install_cti_integrity_revenue_v19_1
from .cti_integrity_revenue_v19_1_claim_semantics import install_claim_semantics_v19_1
from .generation_evidence_admission import install_generation_evidence_admission
from .premium_capacity_allocator_v13 import install_capacity_aware_allocator_v13
from .premium_capacity_recovery import install_premium_capacity_recovery
from .premium_capacity_runtime_binding import install_capacity_runtime_binding_fix
from .premium_evidence_compiler import install_premium_evidence_compiler_overrides
from .premium_factory_throughput import install_factory_throughput_overrides
from .premium_incident_recovery import install_incident_recovery_overrides
from .premium_provider_budget import install_provider_budget_overrides
from .premium_publication import install_runtime_overrides
from .premium_quota_deferral_v12 import install_quota_deferral_v12
from .premium_quota_scheduler_v11 import install_quota_aware_scheduler_v11
from .premium_release_hardening import install_release_hardening
from .premium_source_rss_v15 import install_source_rich_rss_v15
from .premium_yield_contract_guard import install_yield_contract_guard
from .premium_yield_hardening import install_yield_hardening_overrides
from .premium_zero_cost_mesh_v16 import install_zero_cost_mesh_v16
from .premium_zero_cost_mesh_v16_hardening import install_zero_cost_mesh_v16_hardening
from .premium_puter_user_pays_v17 import install_puter_user_pays_v17
from .provider_quota_ledger import install_provider_quota_ledger


def main() -> int:
    """Install the production runtime stack in its required dependency order."""
    # Install order is a production invariant. Provider-budget/recovery/yield
    # controls preserve the proven pre-Stage-2 safety chain; factory throughput
    # then adds family scheduling and model-scoped pacing. premium_publication
    # snapshots that active runtime into the production transformer/publisher.
    #
    # v15 source-rich RSS installs before the pipeline starts discovery. It
    # patches only the external global RSS parser alias and preserves publisher-
    # supplied content:encoded/Atom content as bounded source evidence while the
    # legacy 1,500-character summary contract remains unchanged. It deliberately
    # does not patch first-party canonical RSS, does not fetch article pages, and
    # introduces no new network calls or trust in previously generated reports.
    #
    # Stage-2 installs the durable quota ledger and deterministic evidence
    # compiler after the legacy generation/runtime layers. Stage-3 reconciles
    # final evidence language and provider capability against the complete live
    # runtime graph. CTI Dossier v5 installs strictly after Stage-3. v6 remains
    # in the chain for backward compatibility; v7 installs with an explicit
    # function marker so the historical v5/v6 wrapper-name collision cannot
    # suppress convergence. Stage-4/v8 binds active article context to provider
    # candidate selection and rejects unsupported high-impact claims. Stage-5/v9
    # installs bounded <=900-token continuation recovery. v10 rebinds that
    # recovery wrapper around the ACTUAL authority_transformer.call_llm consumer.
    # v11 installs last on the legacy generation path: it reserves 1,000-OTPM
    # Qwen models for <=900-token chunk work, honors real Retry-After pacing, and
    # can seed a bounded chunked report when long-form Groq capacity is absent.
    # v12 installs after v11 on run-status semantics only: provider-declared
    # active quota reset windows become DEGRADED/DEFERRED instead of a false
    # systemic pipeline failure, while evidence and publication gates stay hard.
    # v13 wraps the active factory scheduler. During active/recent TPD saturation
    # it admits only source-rich candidates that can plausibly use deterministic
    # evidence compilation, preventing scarce calls from being burned on known-
    # thin reports. It never relaxes any publication gate.
    #
    # v16 installs after every quota/capacity layer so it owns the final live LLM
    # consumer without bypassing those controls. It preserves the proven Groq
    # path, then adds Gemini Free Tier and NVIDIA NIM free API Catalog endpoints,
    # then OpenRouter's live-discovered zero-priced model. DeepSeek/Anthropic are
    # hard-disabled unless ALLOW_PAID_LLM=true. Gemini/NIM are additionally
    # gated by explicit PUBLIC_DATA_ONLY controls. Their provider identities are
    # registered with the analytical-depth contract so genuine LLM enrichment is
    # never mislabeled as deterministic fallback. The adjacent v16 hardening
    # layer gives all long-form free providers the established 4,400-token
    # completion budget and persists only non-secret provider-attempt telemetry.
    #
    # v17 installs strictly after v16 hardening. Puter is intentionally outside
    # the zero-cost mesh because backend/CI use requires an operator auth token,
    # so the token owner's Puter allowance is the metered resource. The fallback
    # is disabled by default, requires explicit PUBLIC_DATA_ONLY opt-in, performs
    # a monthly-allowance preflight before every request, caps calls per run, and
    # passes only PUTER_AUTH_TOKEN plus minimal process environment to its Node 24
    # bridge. No Puter token or allowance amount is persisted in public telemetry.
    #
    # v18 installs its runtime after v17 so the proven provider mesh remains the
    # inner generation authority. It adds an internal commercial-delivery score
    # to scheduler ordering (never a threat/customer risk score), and uses the
    # existing free-model mesh for at most two evidence-bounded targeted
    # continuation passes when a genuine candidate is below the unchanged
    # 2200/18/18 public contract. Run telemetry contains aggregate scores/yield
    # only — never prompts, generated content, credentials, or customer data.
    #
    # v18.1 installs immediately after v18 and aligns continuation completion to
    # the exact Stage-2 pre-compiler semantic contract: useful words, substantive
    # paragraphs and substantive list items. The deterministic compiler owns all
    # headings, so v18.1 forbids headings in continuation fragments rather than
    # wasting scarce provider quota on renderer-owned structure. No floor changes.
    #
    # Dossier v8 remains the authoritative fail-closed final-content integrity
    # layer: it blocks prompt/reasoning leakage and residual duplicate canonical
    # sections. Dossier v9 adds the premium SOC/CTI command-center experience.
    # Dossier v10 installs strictly after v9 and adds evidence-graph traceability,
    # family-adaptive exposure validation, provenance chronology, intelligence-gap
    # tracking, canonical decision surfacing, machine-readable capability links,
    # and conservative removal of inapplicable/legacy UI. v9/v10 are fail-open
    # presentation layers and cannot weaken v8 fail-closed publication integrity.
    #
    # v18 commercial presentation installs after Dossier v10. It is a
    # deterministic product-access surface mapped to the repository's existing
    # Free / Starter / Pro / Enterprise entitlements. It never alters intelligence
    # assertions or creates a second billing/entitlement system.
    #
    # v19 installs strictly outside v18 as the final presentation wrapper. It
    # preserves v18's tier recommendation but rewrites qualified paid CTI CTAs to
    # the focused /buy.html checkout surface, eliminating an unnecessary pricing-
    # page hop. It also adds aggregate checkout-link telemetry only. Canonical
    # prices remain server-owned in api/_lib/payment-utils.js and all payment
    # verification remains server-owned in api/v1/billing.
    #
    # v19.1 installs strictly outside v19 as the final rendered-artifact
    # authority. Its bounded claim-semantics helper first distinguishes explicit
    # negative disclosures ("IOCs are not established") from unsupported positive
    # capability claims. The final layer then repairs deterministic presentation
    # contradictions observed in a live CVE dossier (severity/OG mismatch,
    # unsupported artifact claims, source-only certification display,
    # corroboration and operational-depth labels, public TLP assignment,
    # malformed related titles and assessment conversion links) and fails closed
    # if any contradiction survives. It does not change ReportX tier computation,
    # provider routing, prices, entitlements, payment verification, or the
    # underlying evidence graph.
    install_source_rich_rss_v15()
    install_provider_budget_overrides()
    install_incident_recovery_overrides(_main)
    install_yield_hardening_overrides()
    install_yield_contract_guard()
    install_factory_throughput_overrides(_main)
    install_runtime_overrides(_main)
    install_provider_quota_ledger()
    install_premium_evidence_compiler_overrides(_main)
    install_release_hardening(_main)
    install_cti_dossier_presentation(_main)
    install_cti_evidence_convergence(_main)
    install_cti_evidence_convergence_v7(_main)
    install_generation_evidence_admission(_main)
    install_premium_capacity_recovery(_main)
    install_capacity_runtime_binding_fix()
    install_quota_aware_scheduler_v11(_main)
    install_quota_deferral_v12(_main)
    install_capacity_aware_allocator_v13(_main)
    install_zero_cost_mesh_v16(_main)
    install_zero_cost_mesh_v16_hardening(_main)
    install_puter_user_pays_v17(_main)
    install_astra_revenue_runtime_v18(_main)
    install_astra_revenue_yield_alignment_v18_1()
    install_cti_dossier_v8(_main)
    install_cti_dossier_v9(_main)
    install_cti_dossier_v10(_main)
    install_astra_revenue_presentation_v18(_main)
    install_astra_cash_conversion_v19(_main)
    install_claim_semantics_v19_1()
    install_cti_integrity_revenue_v19_1(_main)
    return _main.main()


if __name__ == "__main__":
    sys.exit(main())