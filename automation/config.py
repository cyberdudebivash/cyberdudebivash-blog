"""
CYBERDUDEBIVASH® SENTINEL APEX — Configuration Module
Central configuration loaded from environment variables.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


def _parse_csv_env(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _parse_bool_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    # Blogger OAuth2
    blogger_client_id: str = ""
    blogger_client_secret: str = ""
    blogger_refresh_token: str = ""
    blogger_blog_id: str = ""

    # LLM providers. Production policy defaults to zero-paid routing:
    # Groq free pool → Gemini Free Tier → NVIDIA NIM free endpoint →
    # OpenRouter zero-priced model → defer. Paid providers remain configurable
    # for a future commercial phase but cannot be called unless the operator
    # explicitly sets ALLOW_PAID_LLM=true.
    groq_api_key: str = ""
    gemini_api_key: str = ""
    nvidia_nim_api_key: str = ""
    deepseek_api_key: str = ""
    openrouter_api_key: str = ""
    anthropic_api_key: str = ""
    allow_paid_llm: bool = False
    gemini_public_data_only: bool = False
    nvidia_nim_public_data_only: bool = False

    # External data source API keys
    nvd_api_key: str = ""
    alienvault_otx_key: str = ""

    # Model selection per provider
    # P0-REPORTX-2026-08-19: "llama-3.3-70b-versatile" was deprecated by Groq
    # for free/developer-tier usage (announced 2026-06-17, deprecation dated
    # 2026-08-16). "openai/gpt-oss-120b" is the current general-purpose
    # replacement used by this factory.
    llm_model_groq: str = "openai/gpt-oss-120b"
    # Groq free/on_demand TPD is model-scoped. Fallback models therefore add
    # independent daily headroom under the same configured key.
    llm_model_groq_fallbacks: tuple[str, ...] = (
        "openai/gpt-oss-20b",
        "qwen/qwen3.8-27b",
    )

    # P0-ZERO-COST-MESH-V16-2026-09-07: Gemini is enabled only for public CTI
    # workloads. The production workflow sets GEMINI_PUBLIC_DATA_ONLY=true;
    # callers that do not make that explicit cannot send data to Gemini.
    # Model IDs are environment-overridable so catalog changes do not require
    # weakening provider or evidence controls.
    llm_model_gemini: str = "gemini-3.7-flash"
    llm_model_gemini_fallbacks: tuple[str, ...] = (
        "gemini-3.5-flash",
        "gemini-3.1-flash-lite",
    )

    # NVIDIA Build API Catalog hosted endpoints are treated as opportunistic
    # free prototype capacity, never as an enterprise SLA.  Every default below
    # is currently advertised by NVIDIA as a Free Endpoint and remains
    # environment-overridable for catalog churn.
    llm_model_nvidia_nim: str = "nvidia/nemotron-3.5-lightning-30b-a3b"
    llm_model_nvidia_nim_fallbacks: tuple[str, ...] = (
        "nvidia/llama-3.3-nemotron-super-49b-v1",
        "meta/llama-3.3-70b-instruct",
    )

    llm_model_deepseek: str = "deepseek-chat"
    # OpenRouter has no fixed model default: llm_client.py discovers a current
    # zero-priced :free model from OpenRouter's own catalog at call time.
    claude_model: str = "claude-opus-5"

    # Google Search Console
    google_search_console_key: str = ""

    # Social amplification — Twitter/X API v2 (OAuth 1.0a)
    twitter_api_key: str = ""
    twitter_api_secret: str = ""
    twitter_access_token: str = ""
    twitter_access_secret: str = ""

    # Newsletter (link to signup page — Substack, ConvertKit, etc.)
    newsletter_signup_url: str = "https://cyberdudebivash.substack.com"

    # Source platform
    source_rss_url: str = "https://blog.cyberdudebivash.in/rss.xml"
    source_live_intel_url: str = "https://blog.cyberdudebivash.in/live-intel.json"
    source_sitemap_url: str = "https://blog.cyberdudebivash.in/sitemap.xml"
    source_base_url: str = "https://blog.cyberdudebivash.in"

    # Target Blogger — target_blog_url is the underlying Blogspot hosting
    # implementation detail. public_cti_url is the customer-facing canonical
    # identity used in public structured data and report surfaces.
    target_blog_url: str = "https://cyberbivash.blogspot.com"
    public_cti_url: str = "https://cti.cyberdudebivash.in"
    blogger_api_base: str = "https://www.googleapis.com/blogger/v3"

    # Pipeline control — production observations show Blogger accepts five
    # consecutive writes before quota throttling. Stay below that boundary.
    max_posts_per_run: int = 5
    max_article_age_hours: int = 72
    retry_attempts: int = 3
    retry_base_delay: float = 2.0

    # State persistence
    state_file: str = "data/published_posts.json"
    logs_dir: str = "logs"

    # Brand
    brand_name: str = "CYBERDUDEBIVASH®"
    brand_tagline: str = "Defending the Future with AI-Powered Cybersecurity"
    brand_url: str = "https://cyberdudebivash.com"
    sentinel_apex_url: str = "https://intel.cyberdudebivash.com"
    api_url: str = "https://intel.cyberdudebivash.com/api"
    tools_url: str = "https://tools.cyberdudebivash.com"
    corporate_url: str = "https://cyberdudebivash.in"
    contact_email: str = "bivash@cyberdudebivash.com"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            blogger_client_id=os.environ.get("BLOGGER_CLIENT_ID", ""),
            blogger_client_secret=os.environ.get("BLOGGER_CLIENT_SECRET", ""),
            blogger_refresh_token=os.environ.get("BLOGGER_REFRESH_TOKEN", ""),
            blogger_blog_id=os.environ.get("BLOGGER_BLOG_ID", ""),
            groq_api_key=os.environ.get("GROQ_API_KEY", ""),
            gemini_api_key=os.environ.get("GEMINI_API_KEY", ""),
            nvidia_nim_api_key=os.environ.get("NVIDIA_NIM_API_KEY", ""),
            deepseek_api_key=os.environ.get("DEEPSEEK_API_KEY", ""),
            openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            allow_paid_llm=_parse_bool_env("ALLOW_PAID_LLM", False),
            gemini_public_data_only=_parse_bool_env("GEMINI_PUBLIC_DATA_ONLY", False),
            nvidia_nim_public_data_only=_parse_bool_env("NVIDIA_NIM_PUBLIC_DATA_ONLY", False),
            nvd_api_key=os.environ.get("NVD_API_KEY", ""),
            alienvault_otx_key=os.environ.get("ALIENVAULT_OTX_KEY", ""),
            google_search_console_key=os.environ.get("GOOGLE_SEARCH_CONSOLE_KEY", ""),
            twitter_api_key=os.environ.get("TWITTER_API_KEY", ""),
            twitter_api_secret=os.environ.get("TWITTER_API_SECRET", ""),
            twitter_access_token=os.environ.get("TWITTER_ACCESS_TOKEN", ""),
            twitter_access_secret=os.environ.get("TWITTER_ACCESS_SECRET", ""),
            newsletter_signup_url=os.environ.get(
                "NEWSLETTER_SIGNUP_URL", "https://cyberdudebivash.substack.com"
            ),
            public_cti_url=os.environ.get("PUBLIC_CTI_URL", "https://cti.cyberdudebivash.in"),
            max_posts_per_run=int(os.environ.get("MAX_POSTS_PER_RUN", "5")),
            llm_model_groq=os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b"),
            llm_model_groq_fallbacks=_parse_csv_env(
                "GROQ_FALLBACK_MODELS",
                ("openai/gpt-oss-20b", "qwen/qwen3.8-27b"),
            ),
            llm_model_gemini=os.environ.get("GEMINI_MODEL", "gemini-3.7-flash"),
            llm_model_gemini_fallbacks=_parse_csv_env(
                "GEMINI_FALLBACK_MODELS",
                ("gemini-3.5-flash", "gemini-3.1-flash-lite"),
            ),
            llm_model_nvidia_nim=os.environ.get(
                "NVIDIA_NIM_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b"
            ),
            llm_model_nvidia_nim_fallbacks=_parse_csv_env(
                "NVIDIA_NIM_FALLBACK_MODELS",
                (
                    "nvidia/llama-3.3-nemotron-super-49b-v1",
                    "meta/llama-3.3-70b-instruct",
                ),
            ),
        )

    def validate(self) -> list[str]:
        """Return list of missing required config keys."""
        missing = []
        if not self.blogger_client_id:
            missing.append("BLOGGER_CLIENT_ID")
        if not self.blogger_client_secret:
            missing.append("BLOGGER_CLIENT_SECRET")
        if not self.blogger_refresh_token:
            missing.append("BLOGGER_REFRESH_TOKEN")
        if not self.blogger_blog_id:
            missing.append("BLOGGER_BLOG_ID")
        return missing