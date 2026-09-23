"""
CYBERDUDEBIVASH® SENTINEL APEX — Blogger Syndication Engine
Main orchestration pipeline. Runs content discovery → transformation → publication.

Usage:
    python -m automation.main              # Full pipeline
    python -m automation.main --dry-run    # Validate without publishing
    python -m automation.main --health     # Health check only
"""

import argparse
import json
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .authority_transformer import AuthorityTransformer
from .blogger_publisher import BloggerPublisher, BloggerPublishError, BloggerAuthError, BloggerRateLimitError
from .canonical_rss import discover_local_canonical_rss
from .config import Config
from .content_discovery import ContentDiscoveryEngine, DiscoveredArticle, PublicationState
from .logger import setup_logger
from .publication_scheduler import (
    candidate_discovery_limit,
    classify_publication_family,
    is_canonical_report,
    select_publication_batch,
)
from .publication_verifier import fetch_back_and_verify
from .report_integrity import PublicationIntegrityError, compute_artifact_hash
from .search_console_submitter import SearchConsoleSubmitter
from .social_amplifier import SocialAmplifier

logger = setup_logger("main")


def _write_run_report(report: dict, logs_dir: str) -> None:
    """Persist a JSON run report for observability and auditing."""
    Path(logs_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = Path(logs_dir) / f"run-{ts}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info("Run report written", extra={"path": str(path)})


def _requeue_unattempted(
    remaining: list[DiscoveredArticle],
    state: PublicationState,
    reason: str,
) -> int:
    """Queue articles that were discovered but never attempted this run
    because a fatal error (auth or rate-limit) stopped the pipeline early.

    Without this, only the one article that triggered the error was ever
    queued for retry — every other not-yet-attempted article in the batch
    depended on being rediscovered from its original source next run, which
    isn't guaranteed for sources with a small rolling window (e.g. RSS
    feeds). Log analysis across all historical runs showed this early-break
    path is common (roughly 1 in 5 runs overall, effectively every run in
    the most recent week), so the gap was worth closing rather than noting.
    """
    for article in remaining:
        state.add_to_retry_queue(article, f"not attempted — pipeline stopped early: {reason}")
    return len(remaining)


def _merge_retry_and_fresh(
    retry_articles: list[DiscoveredArticle],
    fresh_articles: list[DiscoveredArticle],
    state: PublicationState,
) -> list[DiscoveredArticle]:
    """Legacy-compatible fresh-over-retry merge helper.

    Existing unit tests and certification documentation import this helper
    directly. The live pipeline now delegates finite-slot allocation to
    publication_scheduler.select_publication_batch(), but this function is
    retained as a stable compatibility surface for callers that only need
    duplicate-safe concatenation.
    """
    fresh_hashes = {article.content_hash for article in fresh_articles}
    fresh_urls = {article.url.strip() for article in fresh_articles if article.url}
    retry_deduped = [
        article for article in retry_articles
        if not state.is_published(article.content_hash)
        and not state.is_source_url_published(article.url)
        and article.content_hash not in fresh_hashes
        and article.url.strip() not in fresh_urls
    ]
    return retry_deduped + fresh_articles


def run_health_check(config: Config) -> bool:
    """Verify all external dependencies are reachable."""
    logger.info("Running health check")
    issues = config.validate()
    if issues:
        logger.error("Missing required config", extra={"missing": issues})
        return False

    publisher = BloggerPublisher(config)
    ok = publisher.health_check()
    if not ok:
        logger.error("Blogger health check failed")
        return False

    logger.info("All health checks passed")
    return True


def _empty_selection_metrics() -> dict:
    return {
        "candidate_count": 0,
        "fresh_candidates": 0,
        "retry_candidates": 0,
        "canonical_candidates": 0,
        "fresh_selected": 0,
        "retry_selected": 0,
        "strategic_selected": 0,
        "vulnerability_selected": 0,
        "canonical_selected": 0,
        "selected_families": {},
        "selected_sources": {},
    }


def _article_selection_key(article: DiscoveredArticle) -> str:
    """Stable per-run identity for attempted/backfill de-duplication."""
    content_hash = str(getattr(article, "content_hash", "") or "").strip()
    if content_hash:
        return f"hash:{content_hash}"
    return f"url:{str(getattr(article, 'url', '') or '').strip()}"


def _publication_attempt_limit(publish_target: int) -> int:
    """Bound transformation attempts independently from successful writes.

    P0-2026-09-23: the public Blogger write cap is a *successful publication*
    budget, not an attempt budget. If a source-backed candidate correctly
    fails the premium integrity gate, the factory may try a replacement while
    retaining the same public write ceiling. The cap is deliberately small so
    a bad source window cannot turn into unbounded LLM/API work.
    """
    target = max(0, int(publish_target or 0))
    if target == 0:
        return 0
    return min(6, max(target, target * 3))


def _next_backfill_candidate(
    retry_articles: list[DiscoveredArticle],
    fresh_articles: list[DiscoveredArticle],
    attempted_keys: set[str],
) -> tuple[DiscoveredArticle | None, str | None]:
    """Select one unattempted replacement using the active production scheduler."""
    remaining_retry = [
        article for article in retry_articles
        if _article_selection_key(article) not in attempted_keys
    ]
    remaining_fresh = [
        article for article in fresh_articles
        if _article_selection_key(article) not in attempted_keys
    ]
    if not remaining_retry and not remaining_fresh:
        return None, None

    selection = select_publication_batch(
        remaining_retry,
        remaining_fresh,
        1,
    )
    if not selection.articles:
        return None, None

    candidate = selection.articles[0]
    key = _article_selection_key(candidate)
    if key in attempted_keys:
        return None, None
    source_kind = "retry" if any(
        _article_selection_key(article) == key for article in remaining_retry
    ) else "fresh"
    return candidate, source_kind


def run_pipeline(config: Config, dry_run: bool = False) -> dict:
    """Execute the full syndication pipeline."""
    run_start = datetime.now(timezone.utc).isoformat()
    report = {
        "run_start": run_start,
        "run_end": None,
        "dry_run": dry_run,
        "discovered": 0,
        "published": 0,
        "failed": 0,
        "skipped": 0,
        "requeued": 0,
        "integrity_blocked": 0,
        "fetch_back_discrepancies": 0,
        "publish_target": max(0, int(config.max_posts_per_run or 0)),
        "publication_attempt_limit": _publication_attempt_limit(config.max_posts_per_run),
        "backfill_selected": 0,
        **_empty_selection_metrics(),
        "posts": [],
        "errors": [],
    }

    logger.info("Pipeline started", extra={"dry_run": dry_run, "run_start": run_start})

    # Validate config
    missing = config.validate()
    if missing and not dry_run:
        msg = f"Missing required secrets: {missing}"
        logger.error(msg)
        report["errors"].append(msg)
        report["run_status"] = "FAILED"
        report["run_end"] = datetime.now(timezone.utc).isoformat()
        _write_run_report(report, config.logs_dir)
        return report

    # The Blogger write budget remains the original config value (normally 5).
    # Discovery gets a bounded wider candidate window so source-priority sorting
    # cannot discard strategic intelligence before the commercial scheduler can
    # make a cross-family decision.
    discovery_config = replace(
        config,
        max_posts_per_run=candidate_discovery_limit(config.max_posts_per_run),
    )
    discovery = ContentDiscoveryEngine(discovery_config)
    transformer = AuthorityTransformer(config)
    publisher = BloggerPublisher(config) if not dry_run else None
    submitter = SearchConsoleSubmitter(config)
    amplifier = SocialAmplifier(config)

    # --- Retry Queue ---
    retry_items = discovery.state.get_retry_queue()
    retry_articles: list[DiscoveredArticle] = []
    for item in retry_items:
        try:
            article = DiscoveredArticle.from_dict(item)
        except (KeyError, TypeError):
            continue  # Malformed persisted entry — ignore, never break publication.
        if discovery.state.is_published(article.content_hash):
            continue
        if discovery.state.is_source_url_published(article.url):
            continue
        retry_articles.append(article)

    if retry_articles:
        logger.info("Loaded retry queue", extra={"retry_count": len(retry_articles)})

    # --- Content Discovery ---
    # First-party repo RSS is read directly from the checked-out artifact so a
    # just-generated malware/campaign/breach report does not have to wait for a
    # deployment/CDN propagation cycle before Blogger can see it. The existing
    # remote own-RSS source still runs below and remains the fallback.
    canonical_fresh = discover_local_canonical_rss(
        config,
        discovery.state,
        max_items=discovery_config.max_posts_per_run,
    )
    external_fresh = discovery.discover()
    fresh_articles = canonical_fresh + external_fresh

    selection = select_publication_batch(
        retry_articles,
        fresh_articles,
        config.max_posts_per_run,
    )
    articles = list(selection.articles)
    report.update(selection.metrics)
    publish_target = max(0, int(config.max_posts_per_run or 0))
    attempt_limit = _publication_attempt_limit(publish_target)
    attempted_keys = {_article_selection_key(article) for article in articles}

    def _enqueue_quality_backfill(reason: str) -> None:
        """Append one replacement without increasing the successful write cap."""
        if dry_run:
            return
        if report["published"] >= publish_target:
            return
        if len(articles) >= attempt_limit:
            return

        candidate, source_kind = _next_backfill_candidate(
            retry_articles,
            fresh_articles,
            attempted_keys,
        )
        if candidate is None:
            return

        key = _article_selection_key(candidate)
        attempted_keys.add(key)
        articles.append(candidate)
        report["backfill_selected"] += 1
        report["discovered"] = len(articles)

        family = classify_publication_family(candidate)
        source = str(candidate.source or "unknown")
        report.setdefault("selected_families", {})
        report.setdefault("selected_sources", {})
        report["selected_families"][family] = report["selected_families"].get(family, 0) + 1
        report["selected_sources"][source] = report["selected_sources"].get(source, 0) + 1
        if source_kind == "fresh":
            report["fresh_selected"] = int(report.get("fresh_selected", 0)) + 1
        elif source_kind == "retry":
            report["retry_selected"] = int(report.get("retry_selected", 0)) + 1

        logger.warning(
            "Premium candidate blocked; queued quality-preserving backfill",
            extra={
                "reason": reason,
                "replacement_title": candidate.title[:100],
                "replacement_family": family,
                "backfill_selected": report["backfill_selected"],
                "attempt_limit": attempt_limit,
                "publish_target": publish_target,
            },
        )
    report["canonical_candidates"] = len(canonical_fresh)
    # Preserve the historical `discovered` field semantics used by workflow
    # summaries: this is the selected/attempted publication batch, while the
    # new candidate_count field exposes the larger pre-allocation pool.
    report["discovered"] = len(articles)

    logger.info(
        "Commercial publication allocation complete",
        extra={
            "candidate_count": report["candidate_count"],
            "canonical_candidates": report["canonical_candidates"],
            "selected": report["discovered"],
            "fresh_selected": report["fresh_selected"],
            "retry_selected": report["retry_selected"],
            "strategic_selected": report["strategic_selected"],
            "vulnerability_selected": report["vulnerability_selected"],
            "selected_families": report["selected_families"],
            "selected_sources": report["selected_sources"],
        },
    )

    if not articles:
        logger.info("No new articles to syndicate this run")
        report["run_status"] = "SUCCESS"
        report["run_end"] = datetime.now(timezone.utc).isoformat()
        _write_run_report(report, config.logs_dir)
        return report

    # --- Transform and Publish ---
    for idx, article in enumerate(articles):
        # The list may grow when a quality-blocked candidate is replaced.
        # Never let replacement attempts increase the successful Blogger write
        # budget established by config/search-recovery policy.
        if not dry_run and report["published"] >= publish_target:
            break
        post_result = {
            "source_url": article.url,
            "title": article.title,
            "content_hash": article.content_hash,
            "scheduler_family": classify_publication_family(article),
            "canonical_handoff": is_canonical_report(article),
            "status": "pending",
            "blogger_post_id": None,
            "blogger_url": None,
            "error": None,
        }

        try:
            # Transform content
            transformed = transformer.transform(article)
            post_result["blogger_title"] = transformed["title"]
            post_result["labels"] = transformed["labels"]
            post_result["content_source"] = transformed["content_source"]
            post_result["llm_attempts"] = transformed.get("llm_attempts", [])
            for field in (
                "report_id",
                "source_record_hash",
                "report_family",
                "review_status",
                "certification_status",
                "achieved_tier",
                "quality_score",
                "quality_score_eligible",
                "detection_status",
                "generated_at",
                "preview_certification",
            ):
                post_result[field] = transformed.get(field)

            if dry_run:
                logger.info(
                    "DRY RUN — would publish",
                    extra={
                        "title": transformed["title"][:60],
                        "labels": transformed["labels"],
                        "scheduler_family": post_result["scheduler_family"],
                        "canonical_handoff": post_result["canonical_handoff"],
                    },
                )
                post_result["status"] = "dry_run"
                report["skipped"] += 1
            else:
                # RX-P1-ARTIFACT-BINDING (mandate Section 17/34): the
                # exact artifact validate_publication() certified inside
                # transform() must be the exact artifact submitted to
                # Blogger. transformed["content"] is passed through
                # unmodified from transform()'s return to publish_post()'s
                # call below (verified: nothing in this loop rewrites it
                # between the two) -- so today this recomputation always
                # matches and is a proven no-op, exactly like the FLASH/
                # contradiction gates above. It becomes real, load-bearing
                # protection the moment any future code path between
                # certification and this call mutates the content, instead
                # of silently publishing a legacy/short artifact under a
                # premium certification.
                publish_input_hash = compute_artifact_hash(transformed["content"])
                if publish_input_hash != transformed.get("certified_artifact_hash"):
                    raise PublicationIntegrityError([
                        f"certified artifact hash mismatch: certified="
                        f"{transformed.get('certified_artifact_hash')!r}, "
                        f"publish_input={publish_input_hash!r} -- content "
                        "changed after certification"
                    ])

                # Publish to Blogger
                blogger_post = publisher.publish_post(
                    title=transformed["title"],
                    content=transformed["content"],
                    labels=transformed["labels"],
                    is_draft=False,
                    image_url=transformed.get("image_url"),
                )

                blogger_post_id = blogger_post["id"]
                blogger_url = blogger_post.get("url", "")

                # ReportX Phase 1Q post-publication fetch-back (mandate
                # Section 26): a real, separate GET call verifying what
                # Blogger now actually persists for this exact post matches
                # what was submitted -- Phase 1P's status==LIVE check above
                # only proves Blogger accepted the request, not that the
                # stored content itself is intact. Runs inline, immediately
                # after publish, and never raises (see
                # fetch_back_and_verify()'s own docstring) -- a verification
                # finding must never be confused with, or escalate into, a
                # publish failure on a post that is already live.
                fetch_back = fetch_back_and_verify(
                    publisher, blogger_post_id,
                    transformed["title"], transformed["content"], transformed["labels"],
                )
                if not fetch_back.verified:
                    report["fetch_back_discrepancies"] += 1
                    logger.warning(
                        "Post-publication fetch-back found a discrepancy",
                        extra={
                            "post_id": blogger_post_id,
                            "blogger_url": blogger_url,
                            "defects": list(fetch_back.defects),
                        },
                    )

                # Persist state
                discovery.state.mark_published(
                    article,
                    blogger_post_id,
                    blogger_url,
                    publication_metadata=transformed,
                )

                # Submit to Google Search Console
                if blogger_url:
                    submitter.submit_url(blogger_url)

                # Social amplification — Twitter/X auto-post
                social_result = amplifier.amplify({
                    "title": article.title,
                    "blogger_title": transformed["title"],
                    "labels": transformed["labels"],
                    "blogger_url": blogger_url,
                })

                post_result.update({
                    "status": "published",
                    "blogger_post_id": blogger_post_id,
                    "blogger_url": blogger_url,
                    "social": social_result,
                    "fetch_back": fetch_back.to_dict(),
                })
                report["published"] += 1

                logger.info(
                    "Article syndicated",
                    extra={
                        "title": transformed["title"][:60],
                        "blogger_url": blogger_url,
                        "post_id": blogger_post_id,
                        "scheduler_family": post_result["scheduler_family"],
                        "canonical_handoff": post_result["canonical_handoff"],
                        "social": social_result,
                    },
                )

                # Brief pause between posts to respect API rate limits
                if article != articles[-1]:
                    time.sleep(2.0)

        except PublicationIntegrityError as e:
            logger.error(
                "Publication integrity gate blocked report",
                extra={"url": article.url, "issues": e.issues},
            )
            post_result["status"] = "integrity_blocked"
            post_result["error"] = str(e)
            post_result["integrity_issues"] = e.issues
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1
            report["integrity_blocked"] += 1
            _enqueue_quality_backfill("integrity_blocked")

        except BloggerAuthError as e:
            logger.error("Authentication error — stopping pipeline", extra={"error": str(e)})
            post_result["status"] = "auth_error"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            report["failed"] += 1
            report["posts"].append(post_result)
            report["requeued"] += _requeue_unattempted(articles[idx + 1:], discovery.state, str(e))
            break  # Auth errors are fatal; stop the run

        except BloggerRateLimitError as e:
            # Blogger's quota is exhausted for the window, not for this one
            # article — every remaining article in this run would burn more
            # calls on a doomed retry (and risk tripping Google's abuse
            # detection, per the hint in BloggerAuthError above). Record this
            # article for retry next run and stop instead of working through
            # the rest of the batch.
            logger.error(
                "Rate limit exhausted — stopping run early to avoid burning further quota",
                extra={"url": article.url, "error": str(e)},
            )
            post_result["status"] = "rate_limited"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1
            report["posts"].append(post_result)
            report["requeued"] += _requeue_unattempted(articles[idx + 1:], discovery.state, str(e))
            break  # Quota exhaustion is effectively fatal for this run

        except BloggerPublishError as e:
            logger.error("Publish failed", extra={"url": article.url, "error": str(e)})
            post_result["status"] = "publish_error"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1
            _enqueue_quality_backfill("publish_error")

        except Exception as e:
            logger.exception("Unexpected error processing article", extra={"url": article.url})
            post_result["status"] = "error"
            post_result["error"] = str(e)
            report["errors"].append(str(e))
            discovery.state.record_failure(article.url, str(e))
            discovery.state.add_to_retry_queue(article, str(e))
            report["failed"] += 1

        report["posts"].append(post_result)

    # discovered/attempted is dynamic because integrity-preserving backfill may
    # append replacement candidates during the loop.
    report["discovered"] = len(report["posts"])
    report["attempted"] = len(report["posts"])
    report["run_end"] = datetime.now(timezone.utc).isoformat()
    report["run_status"] = _pipeline_run_status(report)

    logger.info(
        "Pipeline complete",
        extra={
            "run_status": report["run_status"],
            "candidate_count": report["candidate_count"],
            "discovered": report["discovered"],
            "published": report["published"],
            "failed": report["failed"],
            "skipped": report["skipped"],
            "strategic_selected": report["strategic_selected"],
            "vulnerability_selected": report["vulnerability_selected"],
            "selected_families": report["selected_families"],
            "integrity_blocked": report["integrity_blocked"],
            "fetch_back_discrepancies": report["fetch_back_discrepancies"],
        },
    )

    _write_run_report(report, config.logs_dir)
    return report


# Post statuses that mean the pipeline itself is unhealthy and needs operator
# attention now: an expired/revoked credential (BloggerAuthError) that will
# fail identically on every future run until rotated, or an exception outside
# the pipeline's own error taxonomy -- the one bucket nothing here is
# designed to produce. Every other failure status the loop above can record
# (integrity_blocked, rate_limited, publish_error) is already handled by
# design: the evidence gate correctly kept an unverified report out of
# publication, or the article was queued for automatic retry next run. None
# of those are evidence the pipeline is broken, so none of them may redden
# an otherwise-successful run.
_TERMINAL_POST_STATUSES = {"auth_error", "error"}


def _pipeline_run_status(report: dict) -> str:
    """Classify a completed run as SUCCESS / DEGRADED / FAILED.

    Mirrors the mandate's 3-state run-verdict model: a run where every
    article either published or was correctly, healthily handled (integrity
    block, self-healing rate limit, a single retryable publish error) is
    DEGRADED, not FAILED -- partial success is real signal, not something to
    hide, but it must never be confused with a systemic outage. Only a
    terminal post status (see _TERMINAL_POST_STATUSES) makes a run FAILED.
    """
    if any(post.get("status") in _TERMINAL_POST_STATUSES for post in report.get("posts", [])):
        return "FAILED"
    if int(report.get("failed", 0)) > 0:
        return "DEGRADED"
    return "SUCCESS"


def _pipeline_exit_code(report: dict) -> int:
    """Non-zero only for a FAILED run (see _pipeline_run_status). A DEGRADED
    run -- e.g. one article correctly blocked by the evidence-integrity gate
    while the rest of the batch published -- exits 0: the pipeline did its
    job. DEGRADED is still surfaced distinctly via report["run_status"] and
    the workflow summary, never silently folded into a plain SUCCESS."""
    return 1 if report.get("run_status") == "FAILED" else 0


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH® SENTINEL APEX Blogger Syndication Engine"
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate without publishing")
    parser.add_argument("--health", action="store_true", help="Run health check only")
    parser.add_argument("--max-posts", type=int, default=None, help="Override max posts per run")
    args = parser.parse_args()

    config = Config.from_env()
    if args.max_posts:
        config.max_posts_per_run = args.max_posts

    setup_logger("main", config.logs_dir)

    if args.health:
        ok = run_health_check(config)
        return 0 if ok else 1

    report = run_pipeline(config, dry_run=args.dry_run)

    # A FAILED run (broken credential, or an exception outside the
    # pipeline's own error taxonomy) must surface as a workflow failure.
    # A DEGRADED run -- an integrity block, a self-healing rate limit, or a
    # queued-for-retry publish error alongside otherwise-successful
    # publications -- exits 0: the pipeline correctly did its job and must
    # not have that success hidden behind a red workflow run. See
    # _pipeline_run_status() for the full classification.
    return _pipeline_exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
