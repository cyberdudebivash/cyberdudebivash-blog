"""
CYBERDUDEBIVASH® SENTINEL APEX — Blogger Publisher Module
Handles OAuth2 token refresh and article publication to Blogger via API v3.
Implements retry logic, failure recovery, and audit logging.
"""

import html
import re
import time
from typing import Optional

import requests

from .config import Config
from .logger import setup_logger

logger = setup_logger("blogger_publisher")

BLOGGER_API_BASE = "https://www.googleapis.com/blogger/v3"
TOKEN_URL = "https://oauth2.googleapis.com/token"

# Blogger renders post content on index pages until its jump break. Large CTI
# reports otherwise trigger automatic pagination, collapsing a requested list
# of recent reports to a single post on desktop and mobile.
_JUMP_BREAK = "<!--more-->"
_FIRST_PARAGRAPH = re.compile(r"</p\\s*>", re.IGNORECASE)
_MAX_INDEX_EXCERPT_BYTES = 4096


def with_index_jump_break(content: str, title: str) -> str:
    """Bound homepage HTML without truncating the canonical report body.

    Keep an existing editor-authored jump break. Prefer the first complete
    paragraph for the index; when a report has no early paragraph, use a
    short escaped title teaser before the full report. The post permalink
    always retains the entire original body after the marker.
    """
    if _JUMP_BREAK in content:
        return content
    first = _FIRST_PARAGRAPH.search(content)
    if first and len(content[:first.end()].encode("utf-8")) <= _MAX_INDEX_EXCERPT_BYTES:
        return content[:first.end()] + _JUMP_BREAK + content[first.end():]
    teaser = f'<p class="cdb-index-excerpt">{html.escape(title, quote=True)}</p>'
    return teaser + _JUMP_BREAK + content


class BloggerAuthError(Exception):
    pass


class BloggerPublishError(Exception):
    pass


class BloggerRateLimitError(BloggerPublishError):
    """Raised when every retry attempt for a post was rejected with HTTP 429.
    Subclasses BloggerPublishError so existing callers that catch the base
    class are unaffected; callers that want to stop the run early on
    quota exhaustion (rather than burn it further on the next article)
    can catch this more specific type instead."""
    pass


class BloggerPublisher:
    """Publishes posts to Blogger via API v3 with OAuth2 refresh token auth."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0

    # ------------------------------------------------------------------ #
    # Authentication                                                        #
    # ------------------------------------------------------------------ #

    def _get_access_token(self) -> str:
        """Return a valid access token, refreshing if needed."""
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token

        logger.info("Refreshing Blogger OAuth2 access token")
        resp = requests.post(
            TOKEN_URL,
            data={
                "client_id": self.config.blogger_client_id,
                "client_secret": self.config.blogger_client_secret,
                "refresh_token": self.config.blogger_refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=15,
        )

        if not resp.ok:
            hint = ""
            if "invalid_grant" in resp.text:
                hint = (
                    " — BLOGGER_REFRESH_TOKEN has been revoked or expired by Google "
                    "(commonly triggered by a burst of API calls tripping abuse detection). "
                    "Reauthorize the Blogger OAuth app and rotate the BLOGGER_REFRESH_TOKEN "
                    "GitHub Actions secret to restore publishing."
                )
            raise BloggerAuthError(
                f"Token refresh failed {resp.status_code}: {resp.text[:200]}{hint}"
            )

        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expiry = time.time() + int(data.get("expires_in", 3600))
        logger.info("Access token refreshed successfully")
        return self._access_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------ #
    # Blog metadata                                                         #
    # ------------------------------------------------------------------ #

    def get_blog_info(self) -> dict:
        """Fetch blog metadata to verify connectivity."""
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}"
        resp = requests.get(url, headers=self._headers(), timeout=15)
        resp.raise_for_status()
        return resp.json()

    def list_recent_posts(self, max_results: int = 10) -> list[dict]:
        """List recent Blogger posts for deduplication cross-check."""
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts"
        resp = requests.get(
            url,
            headers=self._headers(),
            params={"maxResults": max_results, "status": "live"},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.json().get("items", [])

    def list_posts_page(self, page_token: Optional[str] = None, max_results: int = 25) -> dict:
        """List one page of live posts, newest first, with real Blogger API
        pagination (nextPageToken) — unlike list_recent_posts() (capped,
        single-page, built for the small dedup-lookback it's actually used
        for), this is what a legacy remediation scan over the full post
        history needs to walk forward through in bounded batches, exactly
        the "never rewrite thousands of posts in one shot" staged-batch
        requirement automation/backfill_social_previews.py implements.
        Returns the raw {"items": [...], "nextPageToken": "..." | absent}
        shape so the caller decides when to stop (absent token = last page)."""
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts"
        params = {"maxResults": max_results, "status": "live", "fetchBodies": "true"}
        if page_token:
            params["pageToken"] = page_token
        resp = requests.get(url, headers=self._headers(), params=params, timeout=20)
        resp.raise_for_status()
        return resp.json()

    def get_post(self, post_id: str) -> dict:
        """Fetch one post by ID with its full body (ReportX Phase 1Q,
        mandate Section 26 "post-publication fetch-back") -- the real,
        separate GET this closes the loop with: ``publish_post()`` sends
        ``fetchBody=false`` on its own create response (a deliberate,
        unrelated optimization -- the caller already has the content it
        just sent), so a successful create response alone never proves
        what Blogger now actually persists and serves. This calls the same
        ``GET /posts/{postId}`` endpoint ``list_recent_posts()`` already
        uses in bulk, for one specific post by ID instead."""
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts/{post_id}"
        resp = requests.get(url, headers=self._headers(), timeout=20)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------ #
    # Publishing                                                            #
    # ------------------------------------------------------------------ #

    def publish_post(
        self,
        title: str,
        content: str,
        labels: list[str],
        is_draft: bool = False,
        image_url: Optional[str] = None,
    ) -> dict:
        """
        Create a new Blogger post with retry logic.
        Returns the created post object from the Blogger API.

        image_url, when given, is sent via the Post resource's real
        "images" field (verified against the Blogger API v3 discovery
        schema: images: [{url: string}], not read-only, not excluded from
        insert) so the post has an explicit, Sentinel-APEX-branded social
        card instead of relying only on Blogger's own first-image-in-body
        heuristic (which _assemble_html()'s inline SVG thumbnail exists
        for). Blogger's own Posts resource has no equivalent field for
        meta description/OG/Twitter tags — that gap is a platform
        limitation, not something this method can wire around.
        """
        payload = {
            "kind": "blogger#post",
            "title": title,
            "content": content,
            "labels": labels,
        }
        if image_url:
            payload["images"] = [{"url": image_url}]

        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts"
        params = {"isDraft": "true" if is_draft else "false", "fetchBody": "false"}

        last_error = "no attempt made"
        auth_refreshed = False

        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                resp = requests.post(
                    url,
                    headers=self._headers(),
                    json=payload,
                    params=params,
                    timeout=30,
                )

                if resp.status_code == 429:
                    last_error = f"HTTP 429 rate limited: {resp.text[:300]}"
                    wait = self.config.retry_base_delay * (2 ** attempt)
                    logger.warning(
                        "Blogger API rate limited — backing off",
                        extra={"attempt": attempt, "wait_seconds": wait, "body": resp.text[:300]},
                    )
                    time.sleep(wait)
                    continue

                if resp.status_code == 401:
                    # Refresh once; a second 401 means the credential itself is
                    # rejected (revoked refresh token, wrong scope, blog access
                    # removed) — retrying cannot fix that.
                    if auth_refreshed:
                        raise BloggerAuthError(
                            f"Blogger API rejected refreshed token (HTTP 401): {resp.text[:300]}"
                        )
                    logger.info("Access token rejected, refreshing once")
                    last_error = f"HTTP 401 unauthorized: {resp.text[:300]}"
                    self._access_token = None
                    auth_refreshed = True
                    continue

                if not resp.ok:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
                resp.raise_for_status()
                post_data = resp.json()

                # ReportX Phase 1P hard gate (mandate Section 26): an HTTP
                # 200 only proves Blogger ACCEPTED the request -- it does
                # not by itself prove the post is actually live. Blogger's
                # own Post resource carries a "status" field (LIVE/DRAFT/
                # SCHEDULED) in its create response; if a live publish was
                # requested but the response says otherwise, that is a real,
                # detectable Blogger-side failure mode (a quota/permission
                # edge case silently downgrading to a draft) that raise_for_
                # status() alone can never catch. Deliberately permissive
                # when the field is absent -- this must never invent a
                # failure the response didn't actually report, and every
                # existing caller/test whose mocked response has no
                # "status" key keeps its current behavior exactly.
                if not is_draft:
                    reported_status = post_data.get("status")
                    if reported_status and reported_status != "LIVE":
                        raise BloggerPublishError(
                            f"Blogger accepted the publish request (HTTP {resp.status_code}) but "
                            f"reports status={reported_status!r}, not LIVE, for a non-draft publish "
                            f"request -- post_id={post_data.get('id')!r}"
                        )

                logger.info(
                    "Post published successfully",
                    extra={
                        "post_id": post_data.get("id"),
                        "url": post_data.get("url"),
                        "status": post_data.get("status"),
                        "title": title[:60],
                        "attempt": attempt,
                    },
                )
                return post_data

            except requests.RequestException as e:
                last_error = str(e)
                if attempt == self.config.retry_attempts:
                    raise BloggerPublishError(
                        f"Failed after {attempt} attempts: {last_error}"
                    ) from e
                wait = self.config.retry_base_delay * (2 ** attempt)
                logger.warning(
                    "Publish attempt failed, retrying",
                    extra={"attempt": attempt, "error": last_error, "wait": wait},
                )
                time.sleep(wait)

        if last_error.startswith("HTTP 429"):
            raise BloggerRateLimitError(f"All retry attempts exhausted — last error: {last_error}")
        raise BloggerPublishError(f"All retry attempts exhausted — last error: {last_error}")

    def update_post(self, post_id: str, title: str, content: str, labels: list[str]) -> dict:
        """Update an existing Blogger post with bounded retry and auth recovery."""
        payload = {
            "kind": "blogger#post",
            "id": post_id,
            "title": title,
            "content": content,
            "labels": labels,
        }
        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts/{post_id}"
        last_error = "no attempt made"
        auth_refreshed = False

        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                resp = requests.put(url, headers=self._headers(), json=payload, timeout=30)
                if resp.status_code == 429:
                    last_error = f"HTTP 429 rate limited: {resp.text[:300]}"
                    if attempt < self.config.retry_attempts:
                        time.sleep(self.config.retry_base_delay * (2 ** attempt))
                    continue
                if resp.status_code == 401:
                    if auth_refreshed:
                        raise BloggerAuthError(
                            f"Blogger API rejected refreshed token (HTTP 401): {resp.text[:300]}"
                        )
                    self._access_token = None
                    auth_refreshed = True
                    last_error = f"HTTP 401 unauthorized: {resp.text[:300]}"
                    continue
                if not resp.ok:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt == self.config.retry_attempts:
                    raise BloggerPublishError(
                        f"Update failed after {attempt} attempts: {last_error}"
                    ) from exc
                time.sleep(self.config.retry_base_delay * (2 ** attempt))

        if last_error.startswith("HTTP 429"):
            raise BloggerRateLimitError(
                f"Update retry attempts exhausted — last error: {last_error}"
            )
        raise BloggerPublishError(f"Update retry attempts exhausted — last error: {last_error}")

    def patch_post_preview(
        self, post_id: str, content: Optional[str] = None, image_url: Optional[str] = None,
    ) -> dict:
        """Narrowly update ONLY a post's content and/or social-preview image
        field via Blogger API v3's real PATCH method (blogs.posts.patch —
        distinct from blogs.posts.update, which is a full PUT requiring
        title/content/labels together and risks clobbering a field silently
        omitted by a caller reconstructing them from scratch).

        Built for automation/backfill_social_previews.py: legacy remediation
        needs to replace only the broken first <img> in an already-published
        post's content (data: URI -> real HTTPS card) without touching its
        title or labels at all. PATCH's partial-update semantics make that
        safe by construction; update_post()'s PUT semantics do not.

        At least one of content/image_url must be given -- an empty PATCH
        body is a caller bug, not a valid narrow update, so this fails
        fast rather than sending a no-op request that would still count
        against the API's write quota.
        """
        if content is None and image_url is None:
            raise ValueError("patch_post_preview: at least one of content, image_url is required")

        payload: dict = {"kind": "blogger#post", "id": post_id}
        if content is not None:
            payload["content"] = content
        if image_url:
            payload["images"] = [{"url": image_url}]

        url = f"{BLOGGER_API_BASE}/blogs/{self.config.blogger_blog_id}/posts/{post_id}"
        last_error = "no attempt made"
        auth_refreshed = False

        for attempt in range(1, self.config.retry_attempts + 1):
            try:
                resp = requests.patch(url, headers=self._headers(), json=payload, timeout=30)
                if resp.status_code == 429:
                    last_error = f"HTTP 429 rate limited: {resp.text[:300]}"
                    if attempt < self.config.retry_attempts:
                        time.sleep(self.config.retry_base_delay * (2 ** attempt))
                    continue
                if resp.status_code == 401:
                    if auth_refreshed:
                        raise BloggerAuthError(
                            f"Blogger API rejected refreshed token (HTTP 401): {resp.text[:300]}"
                        )
                    self._access_token = None
                    auth_refreshed = True
                    last_error = f"HTTP 401 unauthorized: {resp.text[:300]}"
                    continue
                if not resp.ok:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:300]}"
                resp.raise_for_status()
                logger.info(
                    "Post preview patched successfully",
                    extra={"post_id": post_id, "fields": list(payload.keys() - {"kind", "id"}), "attempt": attempt},
                )
                return resp.json()
            except requests.RequestException as exc:
                last_error = str(exc)
                if attempt == self.config.retry_attempts:
                    raise BloggerPublishError(
                        f"Preview patch failed after {attempt} attempts: {last_error}"
                    ) from exc
                time.sleep(self.config.retry_base_delay * (2 ** attempt))

        if last_error.startswith("HTTP 429"):
            raise BloggerRateLimitError(
                f"Preview patch retry attempts exhausted — last error: {last_error}"
            )
        raise BloggerPublishError(f"Preview patch retry attempts exhausted — last error: {last_error}")

    def health_check(self) -> bool:
        """Verify Blogger API connectivity and credentials."""
        try:
            info = self.get_blog_info()
            logger.info(
                "Blogger health check passed",
                extra={"blog_name": info.get("name"), "blog_id": info.get("id")},
            )
            return True
        except Exception as e:
            logger.error("Blogger health check failed", extra={"error": str(e)})
            return False
