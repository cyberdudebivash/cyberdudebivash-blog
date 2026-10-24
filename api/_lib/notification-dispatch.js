/**
 * SENTINEL APEX — Watchlist Notification Dispatch (Alert Delivery v1)
 *
 * The layer between "a new change event was matched to a watcher"
 * (change-engine.js) and an actual email/webhook leaving this server.
 * Two responsibilities, deliberately kept separate from notification-
 * store.js's persistence and webhook-signing.js's crypto/SSRF concerns:
 *
 *   dispatchNewEvent()      -- called once per (owner, event) right after
 *                               change-engine.js fans an event out to its
 *                               feed; decides which channels are eligible
 *                               and enqueues them. Never sends anything
 *                               itself -- enqueue-only, so change detection
 *                               never blocks on network I/O.
 *   processDueDeliveries()  -- the actual sender. Reused for BOTH a
 *                               channel's first attempt and every retry --
 *                               one code path, not two, since
 *                               notification-store.js models a first
 *                               attempt as "already due at enqueue time"
 *                               rather than as a special case.
 *
 * Reuses, does not reinvent: api/_lib/resend.js's sendEmail()/
 * canSendEmail() (the same transactional-email client the registration
 * welcome-email flow already uses), api/_lib/webhook-signing.js's HMAC
 * scheme and SSRF guard, api/_lib/watchlist-store.js's getWatchlist()
 * (ownership-checked, public-shaped) for the watchlist name shown in an
 * alert.
 *
 * Scheduling posture (Alert Orchestration v1): scripts/deliver-watchlist-
 * notifications.js now runs on a GitHub Actions native schedule (see
 * .github/workflows/alert-delivery.yml) rather than manually-only --
 * still not sub-30-minute "real-time" (this repo's own dispatch-intel.js
 * documents GitHub's native scheduler as unreliable below that cadence),
 * and this module's content still says what changed and why, never
 * "instantly" or "in real time". What DID change this round: this
 * function is now safe to invoke concurrently/at-least-once, which it
 * was not before -- see processDueDeliveries()'s own doc for the atomic
 * claim/lease mechanism that makes that true.
 */
'use strict';

const redis = require('./redis');
const resend = require('./resend');
const store = require('./watchlist-store');
const notify = require('./notification-store');
const { signPayload, isSafeWebhookUrl } = require('./webhook-signing');

// Lazy require, same reasoning as change-engine.js's own loadIntelLib():
// change-engine.js will require this module (to call dispatchNewEvent()
// right after fanning an event out to a watcher's feed), so requiring
// change-engine.js back at this module's top would be a load-order
// circular require. By the time processDueDeliveries() actually runs
// (never during either module's own initial load), both are already
// fully initialized.
function loadChangeEngine() {
  return require('./change-engine');
}

const WEBHOOK_TIMEOUT_MS = 8000;
const MAX_WEBHOOK_RESPONSE_BYTES = 4096; // only used for the truncated error detail we log
const DASHBOARD_URL = 'https://blog.cyberdudebivash.in/api-dashboard.html';
const WEBHOOK_PAYLOAD_SCHEMA_VERSION = '1.0';

/* ───────────────────────── retry classification ───────────────────────── */

// Deterministic retry classification (orchestration mandate Phase 21/25),
// applied at the point that knows the failure's actual shape (an HTTP
// status here) rather than reconstructed later from a flattened error
// string. Anything NOT in this explicit permanent list defaults to
// retryable -- a false "retryable" costs one wasted attempt inside an
// already-bounded budget; a false "permanent" would drop a possibly-
// transient failure (an unlisted 5xx variant, a status this table simply
// doesn't anticipate) before the retry budget ever got to help.
const PERMANENT_HTTP_STATUSES = new Set([400, 401, 403, 404, 405, 410, 422]);

function isRetryableHttpStatus(status) {
  return !PERMANENT_HTTP_STATUSES.has(status);
}

// Bounded Retry-After parser (Phase 22): accepts the numeric-seconds form
// (the common case) and the HTTP-date form. Anything else, non-positive,
// or unparseable is ignored -- falls back to the normal backoff table
// rather than trusting a malformed or hostile header value. The upper
// bound itself is enforced by notification-store.js's
// MAX_RETRY_AFTER_SECONDS at the point the value is actually applied, not
// here -- this function only parses, it does not decide policy.
function parseRetryAfterSeconds(headerValue) {
  if (!headerValue) return null;
  const trimmed = String(headerValue).trim();
  if (/^\d+$/.test(trimmed)) {
    const seconds = parseInt(trimmed, 10);
    return seconds > 0 ? seconds : null;
  }
  const asDate = Date.parse(trimmed);
  if (Number.isNaN(asDate)) return null;
  const seconds = Math.round((asDate - Date.now()) / 1000);
  return seconds > 0 ? seconds : null;
}

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* ───────────────────────── email content ───────────────────────── */

// Mirrors auth.js's buildWelcomeEmail() structure exactly (subject/text/
// html triple, plain-language body, single template). Unlike
// buildWelcomeEmail()'s inputs (mostly server-generated: API key, fixed
// URLs), watchlistName and entity-derived text here can contain whatever
// characters a customer's own watchlist name or an upstream source
// record contains -- every interpolated value is escaped for the html
// body (the text body needs no escaping; it is never parsed as markup).
function buildWatchlistAlertEmail({ event, watchlistName, dashboardUrl = DASHBOARD_URL }) {
  const entityLabel = event.entity_type === 'cve' ? event.entity_id : `Campaign: ${event.entity_id}`;
  const subject = `[${event.importance}] ${entityLabel} — ${humanizeChangeType(event.change_type)}`;
  const text = [
    `A change was detected on a watchlist you own.`,
    '',
    `Watchlist: ${watchlistName}`,
    `Entity: ${entityLabel}`,
    `Change: ${humanizeChangeType(event.change_type)}`,
    `Importance: ${event.importance}`,
    event.reason ? `Why it matters: ${event.reason}` : '',
    event.recommended_action ? `Recommended action: ${event.recommended_action}` : '',
    '',
    `View this in your dashboard: ${dashboardUrl}`,
    '',
    'This alert reflects a real, detected change in canonical intelligence — not a routine data refresh.',
    '',
    '— CYBERDUDEBIVASH SENTINEL APEX',
  ].filter(line => line !== '').join('\n');
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:560px;margin:0 auto;color:#1a1a1a">
<p>A change was detected on a watchlist you own.</p>
<table style="border-collapse:collapse;margin:12px 0" cellpadding="4">
<tr><td style="color:#666">Watchlist</td><td><strong>${escapeHtml(watchlistName)}</strong></td></tr>
<tr><td style="color:#666">Entity</td><td><strong>${escapeHtml(entityLabel)}</strong></td></tr>
<tr><td style="color:#666">Change</td><td>${escapeHtml(humanizeChangeType(event.change_type))}</td></tr>
<tr><td style="color:#666">Importance</td><td>${escapeHtml(event.importance)}</td></tr>
</table>
${event.reason ? `<p><strong>Why it matters:</strong> ${escapeHtml(event.reason)}</p>` : ''}
${event.recommended_action ? `<p><strong>Recommended action:</strong> ${escapeHtml(event.recommended_action)}</p>` : ''}
<p><a href="${escapeHtml(dashboardUrl)}">View this in your dashboard</a></p>
<p style="color:#666;font-size:13px">This alert reflects a real, detected change in canonical intelligence — not a routine data refresh.</p>
<p>— CYBERDUDEBIVASH SENTINEL APEX</p>
</div>`;
  return { subject, text, html };
}

function humanizeChangeType(changeType) {
  return String(changeType || '').replace(/_/g, ' ').toLowerCase();
}

/* ───────────────────────── per-channel delivery ───────────────────────── */

async function deliverEmailChannel({ email, event, watchlistName }) {
  // Neither "not configured" nor "no recipient yet" is treated as a
  // permanent failure -- an operator-side RESEND_API_KEY gap or a
  // customer adding a recipient before the next attempt can both resolve
  // it without any code change, so this stays in the normal retry cycle
  // rather than dead-lettering (Phase 21: unlisted/ambiguous defaults to
  // retryable, never blindly permanent).
  if (!resend.canSendEmail()) return { success: false, error: 'EMAIL_NOT_CONFIGURED', retryable: true };
  if (!email) return { success: false, error: 'NO_RECIPIENT', retryable: true };
  const { subject, text, html } = buildWatchlistAlertEmail({ event, watchlistName });
  try {
    await resend.sendEmail({ to: email, subject, html, text });
    return { success: true };
  } catch (e) {
    const status = e && e.status;
    return {
      success: false,
      error: e && e.message ? e.message : 'SEND_FAILED',
      retryable: status ? isRetryableHttpStatus(status) : true,
    };
  }
}

async function deliverWebhookChannel({ url, secret, event, watchlistId, watchlistName, deliveryId }) {
  const check = await isSafeWebhookUrl(url);
  // Permanent, not retryable: an SSRF-blocked destination is a
  // configuration problem the customer must fix, and retrying it on
  // every cycle just repeats a DNS lookup against a URL we already
  // decided cannot be delivered to (Phase 25's own "invalid destination
  // configuration" example) -- fast-tracking to a visible terminal state
  // gets the customer to "fix your webhook URL" sooner than 5 silent
  // retry cycles would.
  if (!check.safe) return { success: false, error: `UNSAFE_URL:${check.reason}`, retryable: false };

  const payload = JSON.stringify({
    schema_version: WEBHOOK_PAYLOAD_SCHEMA_VERSION,
    id: `evt_${event.event_id}`,
    delivery_id: deliveryId,
    type: 'watchlist.change_event',
    created_at: new Date().toISOString(),
    data: {
      event_id: event.event_id, entity_type: event.entity_type, entity_id: event.entity_id,
      change_type: event.change_type, importance: event.importance,
      before: event.before, after: event.after, observed_at: event.observed_at,
      source_refs: event.source_refs, evidence_refs: event.evidence_refs,
      reason: event.reason, recommended_action: event.recommended_action,
      watchlist: { id: watchlistId, name: watchlistName },
    },
  });
  const timestampSeconds = Math.floor(Date.now() / 1000);
  const signature = signPayload(secret, timestampSeconds, payload);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'POST',
      redirect: 'error', // never follow a redirect -- see webhook-signing.js's SSRF-guard docstring
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'X-Sentinel-Signature': signature,
        'X-Sentinel-Event': 'watchlist.change_event',
        // Stable across every retry of this same semantic delivery (see
        // notification-store.js's buildDeliveryId doc) -- recipients
        // should dedupe on this, not on the HTTP request itself, since a
        // retry is a NEW request carrying the SAME delivery.
        'X-Sentinel-Delivery-Id': deliveryId,
        'User-Agent': 'SentinelApex-Webhooks/1.0',
      },
      body: payload,
    });
    if (res.ok) return { success: true };
    const detail = await res.text().catch(() => '');
    return {
      success: false,
      error: `HTTP_${res.status}:${detail.slice(0, MAX_WEBHOOK_RESPONSE_BYTES)}`,
      retryable: isRetryableHttpStatus(res.status),
      retryAfterSeconds: parseRetryAfterSeconds(res.headers.get('retry-after')),
    };
  } catch (e) {
    const reason = e && e.name === 'AbortError' ? 'TIMEOUT' : (e && e.message) || 'NETWORK_ERROR';
    return { success: false, error: reason, retryable: true };
  } finally {
    clearTimeout(timer);
  }
}

// The pending-delivery record only carries ownerId, not the account's
// email -- that lives in the customer-identity store (auth.js's
// handleRegister writes user:id:{userId} -> API-key hash, and the full
// record including email is at user:key:{hash}). This is the same
// 2-hop lookup auth.js's own registration path uses, reused here rather
// than duplicating a userId->email index that doesn't otherwise exist.
// Returns '' (never throws) if the account was deleted or the lookup
// fails -- a missing account email correctly falls through to
// deliverEmailChannel's own NO_RECIPIENT failure, not a crash.
async function getOwnerAccountEmail(ownerId) {
  try {
    const hash = await redis.get(`user:id:${ownerId}`);
    if (!hash) return '';
    const flat = await redis.hgetall(`user:key:${hash}`);
    if (!flat || !Array.isArray(flat)) return '';
    const idx = flat.indexOf('email');
    return idx !== -1 ? (flat[idx + 1] || '') : '';
  } catch (_) {
    return '';
  }
}

/* ───────────────────────── orchestration ───────────────────────── */

// Called once per (owner, event) immediately after change-engine.js fans
// an event out to a watcher's feed. Reads CURRENT preferences (not a
// snapshot from watchlist-creation time) so a customer who enables
// notifications after already watching an entity still gets alerted on
// the next real change. Enqueue-only -- no network I/O here.
async function dispatchNewEvent({ ownerId, watchlistId, event }) {
  const prefs = await notify.getPreferences(ownerId);
  const channels = [];
  if (prefs.email_enabled) {
    // Only an explicit override needs a fresh lookup skipped -- otherwise
    // confirm the account actually has a resolvable email before
    // enqueueing a channel that could never succeed. A cheap read now
    // avoids a guaranteed NO_RECIPIENT failure (and a wasted retry
    // schedule) at delivery time later.
    const hasTarget = prefs.email_override || await getOwnerAccountEmail(ownerId);
    if (hasTarget) channels.push('email');
  }
  if (prefs.webhook_enabled && prefs.webhook_url && prefs.has_webhook_secret) channels.push('webhook');
  if (channels.length === 0) {
    // Missing account email or incomplete enabled webhook is not a customer opt-out.
    // Only an explicit disable of both channels is safe to mark skipped.
    const disabled = !prefs.email_enabled && !prefs.webhook_enabled;
    return { enqueued: false, channels: [],
      skip_reason: disabled ? 'ALL_CHANNELS_DISABLED' : 'CHANNEL_CONFIGURATION_UNAVAILABLE' };
  }
  const result = await notify.enqueuePendingDelivery({ ownerId, eventId: event.event_id, watchlistId, channels });
  // enqueuePendingDelivery() reports created=true when *any* channel is new.
  // If only one of two channels was inserted, the other may already have
  // been sent and its terminal job deleted. Never report that partial
  // materialization as a complete fanout intent.
  const newlyCreated = result && Array.isArray(result.channels_created)
    ? result.channels_created : [];
  const allCreated = result && result.created === true &&
    newlyCreated.length === channels.length &&
    new Set(newlyCreated).size === channels.length &&
    channels.every(channel => newlyCreated.includes(channel));
  return { enqueued: Boolean(allCreated), channels };
}

// The sender. Safe to invoke repeatedly/CONCURRENTLY is now an explicit
// design goal, not an assumption to avoid violating -- notify.
// claimDeliveryChannel()'s atomic conditional UPDATE (D1) makes at-least-
// once scheduling (an overlapping cron run, a manual run racing a
// scheduled one, a retried GitHub Actions job) safe at the application
// level regardless of what triggers this function or how many times (see
// notification-store.js's CLAIM_LEASE_MS doc). This is the orchestration
// mandate's core non-negotiable: never assume the trigger mechanism
// itself provides exactly-once execution.
//
// notify.getDuePendingDeliveries() returns flat per-(owner,event,channel)
// job rows (one D1 table row each) rather than the pre-D1 Redis version's
// grouped-by-event records with a nested channels_pending array -- see
// notification-store.js's module header for the schema rationale. This
// function groups them back by (owner_id, event_id) below purely so the
// underlying event/watchlist/preferences are fetched once per event
// rather than once per channel -- an efficiency detail carried over from
// the old code, not a correctness one: each job is still claimed,
// delivered, and resolved fully independently of any sibling channel on
// the same event. There is also no separate per-channel "is this one
// actually due yet" check anymore (the old code needed one because a
// whole grouped record could be returned once its SOONEST-due channel
// was due, even while a sibling channel's own next_attempt_at was still
// in the future) -- getDuePendingDeliveries()'s own WHERE clause already
// filters to genuinely-due rows one at a time, so every job reaching this
// loop is due by construction.
async function processDueDeliveries({ limit = 100 } = {}) {
  const jobs = await notify.getDuePendingDeliveries(limit);
  const results = {
    records_processed: 0, attempts: 0, delivered: 0, retried: 0, dead_lettered: 0,
    // Additive fields -- kept alongside the field names above so
    // scripts/deliver-watchlist-notifications.js's existing console.log
    // lines keep working unchanged (Principle 5).
    claimed: 0, skipped_claimed_elsewhere: 0, cancelled: 0,
  };

  const groups = new Map();
  for (const job of jobs) {
    const key = `${job.owner_id}:${job.event_id}`;
    if (!groups.has(key)) groups.set(key, { owner_id: job.owner_id, event_id: job.event_id, watchlist_id: job.watchlist_id, jobs: [] });
    groups.get(key).jobs.push(job);
  }

  for (const group of groups.values()) {
    results.records_processed++;
    const event = await loadChangeEngine().getEventById(group.event_id);
    const watchlistResult = group.watchlist_id ? await store.getWatchlist(group.watchlist_id, group.owner_id) : null;
    const watchlistName = watchlistResult && watchlistResult.watchlist ? watchlistResult.watchlist.name : '(deleted watchlist)';
    const prefs = await notify.getPreferences(group.owner_id);

    for (const job of group.jobs) {
      const channel = job.channel;

      // A customer who disabled this channel between enqueue and delivery
      // must not receive it -- cancel cleanly, not as a failure/retry/
      // dead-letter (orchestration mandate Phase 74).
      const stillEligible = channel === 'email'
        ? prefs.email_enabled
        : channel === 'webhook'
          ? Boolean(prefs.webhook_enabled && prefs.webhook_url && prefs.has_webhook_secret)
          : false;
      if (!stillEligible) {
        await notify.cancelDeliveryChannel({ deliveryId: job.delivery_id });
        await notify.recordDelivery(group.owner_id, {
          channel, eventId: group.event_id, watchlistId: group.watchlist_id,
          status: 'cancelled', error: 'CHANNEL_DISABLED', attempt: job.attempt_count,
        });
        results.cancelled++;
        continue;
      }

      // Atomic claim: if another concurrent invocation already holds this
      // job (or held it recently enough that its lease hasn't expired),
      // skip it THIS cycle without touching its state -- its own lease
      // recovers it if that other invocation never finishes (crash-safe
      // by construction, not by a cleanup sweep). getDuePendingDeliveries()
      // already filtered to jobs whose lease (if any) had expired at read
      // time, so a claim failure here means a DIFFERENT invocation
      // claimed it in the gap between that read and this call, not a
      // stale lease this call itself could have taken.
      const claim = await notify.claimDeliveryChannel({ deliveryId: job.delivery_id });
      if (!claim.claimed) { results.skipped_claimed_elsewhere++; continue; }
      results.claimed++;

      try {
        // The underlying event or watchlist may have been deleted between
        // enqueue and delivery -- fail this channel out cleanly (dead-letter
        // after retries, same as any other failure) rather than throwing.
        if (!event) {
          const disposition = await notify.recordAttemptOutcome({ deliveryId: job.delivery_id, claimToken: claim.claimToken, success: false });
          await notify.recordDelivery(group.owner_id, {
            channel, eventId: group.event_id, watchlistId: group.watchlist_id,
            status: 'failed', error: 'EVENT_NOT_FOUND', attempt: job.attempt_count,
          });
          results.attempts++;
          if (disposition === 'retrying') results.retried++;
          else if (disposition === 'dead_lettered') results.dead_lettered++;
          continue;
        }

        let outcome;
        if (channel === 'email') {
          const email = prefs.email_override || await getOwnerAccountEmail(group.owner_id);
          outcome = await deliverEmailChannel({ email, event, watchlistName });
        } else if (channel === 'webhook') {
          const secret = await notify.getWebhookSecret(group.owner_id);
          outcome = secret
            ? await deliverWebhookChannel({
                url: prefs.webhook_url, secret, event, watchlistId: group.watchlist_id, watchlistName,
                deliveryId: job.delivery_id,
              })
            : { success: false, error: 'NO_SECRET_CONFIGURED', retryable: true };
        } else {
          outcome = { success: false, error: 'UNKNOWN_CHANNEL', retryable: false };
        }

        results.attempts++;
        const disposition = await notify.recordAttemptOutcome({
          deliveryId: job.delivery_id, claimToken: claim.claimToken,
          success: outcome.success, retryable: outcome.retryable, retryAfterSeconds: outcome.retryAfterSeconds,
        });
        await notify.recordDelivery(group.owner_id, {
          channel, eventId: group.event_id, watchlistId: group.watchlist_id,
          status: outcome.success ? 'delivered' : 'failed', error: outcome.error,
          attempt: job.attempt_count + 1,
        });
        if (disposition === 'delivered') results.delivered++;
        else if (disposition === 'retrying') results.retried++;
        else if (disposition === 'dead_lettered') results.dead_lettered++;
      } finally {
        // Best-effort early release -- see releaseDeliveryChannel's own
        // doc for why correctness never depends on this line running.
        await notify.releaseDeliveryChannel({ deliveryId: job.delivery_id, claimToken: claim.claimToken });
      }
    }
  }

  return results;
}

module.exports = {
  WEBHOOK_PAYLOAD_SCHEMA_VERSION,
  isRetryableHttpStatus,
  parseRetryAfterSeconds,
  buildWatchlistAlertEmail,
  deliverEmailChannel,
  deliverWebhookChannel,
  dispatchNewEvent,
  processDueDeliveries,
};
