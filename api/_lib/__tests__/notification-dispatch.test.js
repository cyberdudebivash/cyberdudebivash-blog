'use strict';

jest.mock('../redis', () => {
  const { createFakeRedis } = require('../__fixtures__/fake-redis');
  const instance = createFakeRedis();
  global.__fakeRedisForTest = instance;
  return instance;
});

// notification-store.js (which this module's processDueDeliveries()/
// dispatchNewEvent() call for all delivery-state reads/writes) is now
// D1-backed, not Redis-backed -- watchlist-store.js (still Redis-backed,
// out of scope for this migration) and getOwnerAccountEmail()'s own
// direct redis.js calls are the only reason the redis mock above is still
// needed in this file.
jest.mock('../d1', () => {
  const { createFakeD1 } = require('../__fixtures__/fake-d1');
  const instance = createFakeD1();
  global.__fakeD1ForTest = instance;
  return instance;
});

const fakeResendState = { canSend: true, sendImpl: null };
jest.mock('../resend', () => ({
  canSendEmail: () => fakeResendState.canSend,
  sendEmail: (...args) => (fakeResendState.sendImpl ? fakeResendState.sendImpl(...args) : Promise.resolve({ id: 'email_test' })),
}));

// getEventById is the only change-engine surface notification-dispatch.js
// actually calls (lazily, to break the load-order cycle -- see that
// module's loadChangeEngine() docstring) -- mocked here so these tests
// don't need the full intel/watchable-state dependency chain just to
// produce a test event.
const fakeEvents = {};
jest.mock('../change-engine', () => ({
  getEventById: jest.fn((id) => Promise.resolve(fakeEvents[id] || null)),
}));

const dispatch = require('../notification-dispatch');
const notify = require('../notification-store');
const store = require('../watchlist-store');

function makeEvent(overrides = {}) {
  return {
    event_id: 'evt_1', entity_type: 'cve', entity_id: 'CVE-2026-1234',
    change_type: 'CVE_KEV_ADDED', importance: 'HIGH',
    before: { cisa_kev: false }, after: { cisa_kev: true },
    observed_at: new Date().toISOString(),
    source_refs: ['cisa_kev'], evidence_refs: ['CISA KEV catalog'],
    reason: 'This CVE was added to the CISA Known Exploited Vulnerabilities catalog.',
    recommended_action: 'Patch immediately per CISA federal mandate timelines.',
    ...overrides,
  };
}

beforeEach(() => {
  global.__fakeRedisForTest._reset();
  global.__fakeD1ForTest._reset();
  Object.keys(fakeEvents).forEach(k => delete fakeEvents[k]);
  fakeResendState.canSend = true;
  fakeResendState.sendImpl = null;
  global.fetch = undefined;
});

afterEach(() => {
  global.fetch = undefined;
});

/* ───────────────────────── email content ───────────────────────── */

describe('buildWatchlistAlertEmail', () => {
  test('includes entity, importance, reason, and recommended action', () => {
    const email = dispatch.buildWatchlistAlertEmail({ event: makeEvent(), watchlistName: 'My Watchlist' });
    expect(email.subject).toContain('HIGH');
    expect(email.subject).toContain('CVE-2026-1234');
    expect(email.text).toContain('My Watchlist');
    expect(email.text).toContain('CISA Known Exploited Vulnerabilities');
    expect(email.html).toContain('CISA federal mandate');
  });

  test('escapes a malicious watchlist name in the html body but not the text body', () => {
    const malicious = '<script>alert(1)</script>My List';
    const email = dispatch.buildWatchlistAlertEmail({ event: makeEvent(), watchlistName: malicious });
    expect(email.html).not.toContain('<script>alert(1)</script>');
    expect(email.html).toContain('&lt;script&gt;');
    expect(email.text).toContain(malicious); // text body is never parsed as markup -- no escaping needed
  });

  test('escapes a malicious reason/recommended_action from upstream event data', () => {
    const event = makeEvent({
      reason: '<img src=x onerror=alert(1)>',
      recommended_action: '"><svg onload=alert(2)>',
    });
    const email = dispatch.buildWatchlistAlertEmail({ event, watchlistName: 'L' });
    expect(email.html).not.toContain('<img src=x onerror=alert(1)>');
    expect(email.html).not.toContain('<svg onload=alert(2)>');
  });

  test('campaign entities are labeled distinctly from CVEs', () => {
    const email = dispatch.buildWatchlistAlertEmail({
      event: makeEvent({ entity_type: 'campaign', entity_id: 'CAMP-001' }), watchlistName: 'L',
    });
    expect(email.text).toContain('Campaign: CAMP-001');
  });
});

/* ───────────────────────── per-channel delivery ───────────────────────── */

describe('deliverEmailChannel', () => {
  test('succeeds when resend is configured and an address is given', async () => {
    const result = await dispatch.deliverEmailChannel({ email: 'a@example.com', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(true);
  });

  test('fails with EMAIL_NOT_CONFIGURED when resend has no API key', async () => {
    fakeResendState.canSend = false;
    const result = await dispatch.deliverEmailChannel({ email: 'a@example.com', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(false);
    expect(result.error).toBe('EMAIL_NOT_CONFIGURED');
  });

  test('fails with NO_RECIPIENT when no address is resolvable', async () => {
    const result = await dispatch.deliverEmailChannel({ email: '', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(false);
    expect(result.error).toBe('NO_RECIPIENT');
  });

  test('a resend API error is caught and reported, not thrown', async () => {
    fakeResendState.sendImpl = () => Promise.reject(new Error('Resend error: invalid domain'));
    const result = await dispatch.deliverEmailChannel({ email: 'a@example.com', event: makeEvent(), watchlistName: 'L' });
    expect(result.success).toBe(false);
    expect(result.error).toContain('invalid domain');
  });
});

describe('deliverWebhookChannel', () => {
  test('succeeds on a 2xx response and signs the request', async () => {
    let captured = null;
    global.fetch = jest.fn((url, opts) => {
      captured = { url, opts };
      return Promise.resolve({ ok: true, status: 200 });
    });
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 'test_secret', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(true);
    expect(captured.url).toBe('https://example.com/hook');
    expect(captured.opts.method).toBe('POST');
    expect(captured.opts.redirect).toBe('error');
    expect(captured.opts.headers['X-Sentinel-Signature']).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    const body = JSON.parse(captured.opts.body);
    expect(body.type).toBe('watchlist.change_event');
    expect(body.data.event_id).toBe('evt_1');
    expect(body.data.watchlist.id).toBe('wl_1');
  });

  test('rejects delivery to an unsafe URL before ever calling fetch', async () => {
    global.fetch = jest.fn();
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://169.254.169.254/latest/meta-data', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain('UNSAFE_URL');
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('a non-2xx response is a failure carrying the status and a bounded error detail', async () => {
    global.fetch = jest.fn(() => Promise.resolve({
      ok: false, status: 500, text: () => Promise.resolve('x'.repeat(10000)), headers: { get: () => null },
    }));
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain('HTTP_500');
    expect(result.error.length).toBeLessThan(4200);
  });

  test('a network error is caught and reported, not thrown', async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error('ECONNREFUSED')));
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toBe('ECONNREFUSED');
  });

  test('a hung request times out rather than blocking forever', async () => {
    global.fetch = jest.fn((url, opts) => new Promise((resolve, reject) => {
      opts.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    }));
    const result = await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
    });
    expect(result.success).toBe(false);
    expect(result.error).toBe('TIMEOUT');
  }, 15000);

  test('includes a stable X-Sentinel-Delivery-Id header and matching delivery_id/schema_version in the payload', async () => {
    let captured = null;
    global.fetch = jest.fn((url, opts) => { captured = opts; return Promise.resolve({ ok: true, status: 200 }); });
    await dispatch.deliverWebhookChannel({
      url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L',
      deliveryId: 'dlv_usr_a_evt_1_webhook',
    });
    expect(captured.headers['X-Sentinel-Delivery-Id']).toBe('dlv_usr_a_evt_1_webhook');
    const body = JSON.parse(captured.body);
    expect(body.delivery_id).toBe('dlv_usr_a_evt_1_webhook');
    expect(body.schema_version).toBe(dispatch.WEBHOOK_PAYLOAD_SCHEMA_VERSION);
  });

  test('classifies a permanent HTTP status (404) as non-retryable', async () => {
    global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 404, text: () => Promise.resolve('not found'), headers: { get: () => null } }));
    const result = await dispatch.deliverWebhookChannel({ url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L' });
    expect(result.retryable).toBe(false);
  });

  test('classifies a transient HTTP status (503) as retryable', async () => {
    global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 503, text: () => Promise.resolve('unavailable'), headers: { get: () => null } }));
    const result = await dispatch.deliverWebhookChannel({ url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L' });
    expect(result.retryable).toBe(true);
  });

  test('an SSRF-blocked URL is classified as non-retryable', async () => {
    const result = await dispatch.deliverWebhookChannel({ url: 'https://127.0.0.1/x', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L' });
    expect(result.retryable).toBe(false);
  });

  test('a network error is classified as retryable', async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error('ECONNRESET')));
    const result = await dispatch.deliverWebhookChannel({ url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L' });
    expect(result.retryable).toBe(true);
  });

  test('parses a numeric-seconds Retry-After header on a 429', async () => {
    global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 429, text: () => Promise.resolve(''), headers: { get: (h) => h.toLowerCase() === 'retry-after' ? '120' : null } }));
    const result = await dispatch.deliverWebhookChannel({ url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L' });
    expect(result.retryAfterSeconds).toBe(120);
  });

  test('ignores a malformed Retry-After header, falling back to normal backoff', async () => {
    global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 429, text: () => Promise.resolve(''), headers: { get: () => 'not-a-valid-value' } }));
    const result = await dispatch.deliverWebhookChannel({ url: 'https://example.com/hook', secret: 's', event: makeEvent(), watchlistId: 'wl_1', watchlistName: 'L' });
    expect(result.retryAfterSeconds).toBeNull();
  });
});

describe('isRetryableHttpStatus / parseRetryAfterSeconds — pure classification helpers', () => {
  test('permanent statuses are not retryable', () => {
    for (const status of [400, 401, 403, 404, 405, 410, 422]) {
      expect(dispatch.isRetryableHttpStatus(status)).toBe(false);
    }
  });

  test('transient and unlisted statuses default to retryable', () => {
    for (const status of [408, 425, 429, 500, 502, 503, 504, 418, 599]) {
      expect(dispatch.isRetryableHttpStatus(status)).toBe(true);
    }
  });

  test('parseRetryAfterSeconds accepts the numeric-seconds form', () => {
    expect(dispatch.parseRetryAfterSeconds('30')).toBe(30);
  });

  test('parseRetryAfterSeconds accepts a future HTTP-date form', () => {
    const future = new Date(Date.now() + 60000).toUTCString();
    const seconds = dispatch.parseRetryAfterSeconds(future);
    expect(seconds).toBeGreaterThan(50);
    expect(seconds).toBeLessThanOrEqual(60);
  });

  test('parseRetryAfterSeconds rejects zero, negative, and garbage values', () => {
    expect(dispatch.parseRetryAfterSeconds('0')).toBeNull();
    expect(dispatch.parseRetryAfterSeconds('-5')).toBeNull();
    expect(dispatch.parseRetryAfterSeconds('not-a-date')).toBeNull();
    expect(dispatch.parseRetryAfterSeconds(null)).toBeNull();
  });
});

/* ───────────────────────── orchestration ───────────────────────── */

describe('dispatchNewEvent — enqueue-only', () => {
  test('enqueues email when enabled and the owner has a resolvable account email', async () => {
    // user:id / user:key mirrors auth.js's real registration write shape.
    await global.__fakeRedisForTest.set('user:id:usr_a', 'hash123');
    await global.__fakeRedisForTest.hmset('user:key:hash123', { email: 'owner@example.com' });
    const result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    expect(result.enqueued).toBe(true);
    expect(result.channels).toEqual(['email']);
  });

  test('does not enqueue email when the account has no resolvable email and no override is set', async () => {
    const result = await dispatch.dispatchNewEvent({ ownerId: 'usr_no_account', watchlistId: 'wl_1', event: makeEvent() });
    expect(result.enqueued).toBe(false);
  });

  test('an explicit email_override enqueues email even with no resolvable account email', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'override@example.com' });
    const result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    expect(result.channels).toEqual(['email']);
  });

  test('enqueues webhook only when enabled, a URL is set, AND a secret exists', async () => {
    await notify.updatePreferences('usr_a', { email_enabled: false, webhook_enabled: true, webhook_url: 'https://example.com/hook' });
    // No secret yet -- webhook must not be enqueued.
    let result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent({ event_id: 'evt_a' }) });
    expect(result.enqueued).toBe(false);

    await notify.rotateWebhookSecret('usr_a');
    result = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent({ event_id: 'evt_b' }) });
    expect(result.channels).toEqual(['webhook']);
  });

  test('enqueuing for the same event twice is idempotent (matches the underlying store guarantee)', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    const second = await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: 'wl_1', event: makeEvent() });
    expect(second.enqueued).toBe(false);
  });
});

describe('processDueDeliveries — the sender (first attempt and retries share one path)', () => {
  test('delivers a due email successfully and records it in the delivery log', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    await store.createWatchlist({ ownerId: 'usr_a', name: 'My Watchlist' });
    const watchlists = await store.listWatchlists('usr_a');
    const wlId = watchlists[0].id;
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: wlId, event: fakeEvents['evt_1'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(1);
    expect(results.attempts).toBe(1);

    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log).toHaveLength(1);
    expect(log[0].status).toBe('delivered');
    expect(log[0].channel).toBe('email');
  });

  test('a failed delivery is scheduled for retry, not immediately dead-lettered', async () => {
    fakeResendState.sendImpl = () => Promise.reject(new Error('temporary failure'));
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(0);
    expect(results.retried).toBe(1);
    expect(await notify.listDeadLetters('usr_a', { limit: 10 })).toHaveLength(0);

    // Not due again immediately -- the next sweep finds nothing to do.
    const again = await dispatch.processDueDeliveries({ limit: 10 });
    expect(again.attempts).toBe(0);
  });

  test('an event deleted between enqueue and delivery fails cleanly instead of throwing', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    // Enqueue references an event_id that was never registered in fakeEvents.
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_missing', watchlistId: null, channels: ['email'] });
    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.attempts).toBe(1);
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log[0].error).toBe('EVENT_NOT_FOUND');
  });

  test('a watchlist deleted between enqueue and delivery falls back to a labeled placeholder name, not a crash', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    fakeEvents['evt_1'] = makeEvent();
    let capturedSubjectAndBody = null;
    fakeResendState.sendImpl = (args) => { capturedSubjectAndBody = args; return Promise.resolve({ id: 'x' }); };
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_1', watchlistId: 'wl_does_not_exist', channels: ['email'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(1);
    expect(capturedSubjectAndBody.html).toContain('(deleted watchlist)');
  });

  test('respects the limit parameter across multiple due owners', async () => {
    for (const owner of ['usr_a', 'usr_b', 'usr_c']) {
      await notify.updatePreferences(owner, { email_override: `${owner}@example.com` });
      fakeEvents[`evt_${owner}`] = makeEvent({ event_id: `evt_${owner}` });
      await dispatch.dispatchNewEvent({ ownerId: owner, watchlistId: null, event: fakeEvents[`evt_${owner}`] });
    }
    const results = await dispatch.processDueDeliveries({ limit: 2 });
    expect(results.records_processed).toBe(2);
  });

  test('email and webhook channels on the same event are both attempted independently', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com', webhook_enabled: true, webhook_url: 'https://example.com/hook' });
    await notify.rotateWebhookSecret('usr_a');
    global.fetch = jest.fn(() => Promise.resolve({ ok: true, status: 200 }));
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(2);
    expect(global.fetch).toHaveBeenCalledTimes(1);
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log.map(d => d.channel).sort()).toEqual(['email', 'webhook']);
  });

  test('a channel disabled between enqueue and delivery is cancelled cleanly, not sent or retried', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    let sendCount = 0;
    fakeResendState.sendImpl = () => { sendCount++; return Promise.resolve({ id: 'x' }); };
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });
    // Customer disables email AFTER the alert was already enqueued.
    await notify.updatePreferences('usr_a', { email_enabled: false });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.cancelled).toBe(1);
    expect(results.attempts).toBe(0); // never actually attempted a send
    expect(sendCount).toBe(0);
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log[0].status).toBe('cancelled');
    expect(log[0].error).toBe('CHANNEL_DISABLED');
  });

  test('a 404 webhook response dead-letters on the very first attempt (permanent-failure fast path)', async () => {
    await notify.updatePreferences('usr_a', { webhook_enabled: true, webhook_url: 'https://example.com/hook' });
    await notify.rotateWebhookSecret('usr_a');
    global.fetch = jest.fn(() => Promise.resolve({ ok: false, status: 404, text: () => Promise.resolve('gone'), headers: { get: () => null } }));
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.delivered).toBe(0);
    expect(results.retried).toBe(0);
    expect(results.dead_lettered).toBe(1);
    const deadLetters = await notify.listDeadLetters('usr_a', { limit: 10 });
    expect(deadLetters[0].attempts).toBe(1);
    expect(deadLetters[0].reason).toBe('PERMANENT_FAILURE');
  });

  test('a 429 with Retry-After reschedules using that value rather than the default backoff', async () => {
    await notify.updatePreferences('usr_a', { webhook_enabled: true, webhook_url: 'https://example.com/hook' });
    await notify.rotateWebhookSecret('usr_a');
    global.fetch = jest.fn(() => Promise.resolve({
      ok: false, status: 429, text: () => Promise.resolve(''),
      headers: { get: (h) => h.toLowerCase() === 'retry-after' ? '5' : null },
    }));
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    await dispatch.processDueDeliveries({ limit: 10 });
    // Default first-retry backoff is 2 minutes -- a 5-second Retry-After
    // should make it due again well before that, not after.
    await new Promise(r => setTimeout(r, 5100));
    const results = await dispatch.processDueDeliveries({ limit: 10 });
    expect(results.attempts).toBe(1);
  }, 10000);

  test('overlapping concurrent invocations deliver a channel exactly once (atomic claim)', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    let sendCount = 0;
    fakeResendState.sendImpl = () => { sendCount++; return Promise.resolve({ id: 'x' }); };
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    // Two "simultaneous" sweeps racing the same due channel -- only one
    // may win the atomic D1 claim (notification-store.js's conditional
    // UPDATE, see claimDeliveryChannel()), so exactly one send happens
    // regardless of scheduler overlap (the orchestration mandate's core
    // non-negotiable: never assume the trigger provides exactly-once
    // execution on its own).
    const [a, b] = await Promise.all([
      dispatch.processDueDeliveries({ limit: 10 }),
      dispatch.processDueDeliveries({ limit: 10 }),
    ]);
    expect(sendCount).toBe(1);
    expect(a.delivered + b.delivered).toBe(1);
    expect(a.skipped_claimed_elsewhere + b.skipped_claimed_elsewhere).toBe(1);
    const log = await notify.listDeliveries('usr_a', { limit: 10 });
    expect(log).toHaveLength(1); // one recorded attempt, not two
  });

  test('a claim released after a fast delivery lets an immediate next sweep find nothing left to do', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    await dispatch.processDueDeliveries({ limit: 10 });
    const again = await dispatch.processDueDeliveries({ limit: 10 });
    expect(again.records_processed).toBe(0); // record was fully resolved and removed
  });

  // D1-specific failure injection: simulates a worker that successfully
  // claims a job then crashes/errors before recordAttemptOutcome can
  // finish writing (a D1 write failure mid-flight, not a delivery
  // failure). The claim must still be released via the try/finally in
  // processDueDeliveries() -- proving a crash here does not leak the
  // claim until its 90s lease naturally expires.
  test('a D1 failure while recording the outcome still releases the claim via finally, not leaking it until lease expiry', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });

    const originalRunMutationWithChanges = global.__fakeD1ForTest.runMutationWithChanges;
    let failNext = true;
    global.__fakeD1ForTest.runMutationWithChanges = (...args) => {
      // Fail exactly the claim's own resolution write (recordAttemptOutcome
      // calling DELETE on success), not the claimDeliveryChannel() call
      // that must succeed first for this scenario to be meaningful.
      if (failNext && args[0].startsWith('DELETE FROM notification_delivery_jobs WHERE delivery_id=? AND claim_token=?')) {
        failNext = false;
        throw new Error('simulated D1 write failure');
      }
      return originalRunMutationWithChanges(...args);
    };

    await expect(dispatch.processDueDeliveries({ limit: 10 })).rejects.toThrow('simulated D1 write failure');
    global.__fakeD1ForTest.runMutationWithChanges = originalRunMutationWithChanges;

    // The claim was released (not leaked) despite the crash -- an
    // immediate next sweep can claim and deliver it again, it does not
    // have to wait out the full 90s lease.
    const recovered = await dispatch.processDueDeliveries({ limit: 10 });
    expect(recovered.delivered).toBe(1);
  });

  test('stale successful provider response never creates a false delivered receipt', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    fakeEvents['evt_1'] = makeEvent();
    await dispatch.dispatchNewEvent({ ownerId: 'usr_a', watchlistId: null, event: fakeEvents['evt_1'] });
    const spy = jest.spyOn(notify, 'recordAttemptOutcome').mockResolvedValueOnce('unresolved');
    try {
      const result = await dispatch.processDueDeliveries({ limit: 1 });
      expect(result.attempts).toBe(1);
      expect(result.unresolved).toBe(1);
      expect(result.delivered).toBe(0);
      expect(await notify.listDeliveries('usr_a', { limit: 10 })).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
  });

  test('missing-event stale claim does not fabricate a failed delivery receipt', async () => {
    await notify.updatePreferences('usr_a', { email_override: 'a@example.com' });
    await notify.enqueuePendingDelivery({ ownerId: 'usr_a', eventId: 'evt_missing', watchlistId: null, channels: ['email'] });
    const spy = jest.spyOn(notify, 'recordAttemptOutcome').mockResolvedValueOnce('unresolved');
    try {
      const result = await dispatch.processDueDeliveries({ limit: 1 });
      expect(result.attempts).toBe(1);
      expect(result.unresolved).toBe(1);
      expect(result.dead_lettered).toBe(0);
      expect(await notify.listDeliveries('usr_a', { limit: 10 })).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
  });

});
