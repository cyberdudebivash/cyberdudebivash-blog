'use strict';
/**
 * SENTINEL APEX — Cloudflare Runtime Dependency Guard (Phase 45-48)
 *
 * Static-source regression guard for the Cloudflare-Only Runtime tranches
 * (Alert Orchestration v1 / PR #137, Cloudflare-Only Alert Runtime v1 /
 * PR #138, Cloudflare-Only Runtime Completion v2). Precise, not naive: this
 * does NOT assert "no file in this codebase may use Redis" -- auth,
 * billing, and the 35-file ReportX/Intelligence Factory surface are
 * DELIBERATELY still Redis-backed (see
 * docs/audits/SENTINEL-APEX-AUTH-BILLING-DEFERRAL-AUDIT-V2.md and
 * SENTINEL-APEX-REPORTX-INTEL-FACTORY-RUNTIME-AUDIT-V2.md) and asserting
 * otherwise would be both wrong today and an obstacle to those subsystems'
 * own future migrations. This guard only watches the specific files this
 * platform has already, deliberately, migrated to D1 -- catching an
 * accidental re-introduction of a Redis dependency (e.g. a bad merge, a
 * copy-pasted snippet from an old version) in exactly those files.
 *
 * Reads source text directly rather than require()-ing modules: these are
 * static-shape assertions ("does this file's source still mention
 * redis.get"), not behavioral tests -- the real behavioral coverage for
 * every file named here already exists in its own __tests__ suite.
 */
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

// Matches a real Redis client call (`redis.get(`, `this.redis.hset(`, ...)
// or a require of the Redis client module. Deliberately does NOT match the
// word "redis" in comments/strings alone -- several of these files
// legitimately mention "Redis" in header comments explaining what they
// used to be (the migration history), which is exactly the kind of prose
// a naive `grep -i redis` guard would false-positive on.
const REDIS_CALL_RE = /\bredis\.\w+\(/g;
const REDIS_REQUIRE_RE = /require\(\s*['"][^'"]*\/redis['"]\s*\)/;
const D1_REQUIRE_RE = /require\(\s*['"][^'"]*\/d1['"]\s*\)/;

// Call-sites and the require statement are tracked separately on purpose:
// a Tier 1 file must have neither; a Tier 2 file legitimately has exactly
// one require (it needs the module) but a BOUNDED number of call sites --
// conflating the two into one number would make the Tier 2 bound ambiguous
// about which part is allowed to be non-zero.
function redisCallSiteCount(src) {
  return (src.match(REDIS_CALL_RE) || []).length;
}
function hasRedisRequire(src) {
  return REDIS_REQUIRE_RE.test(src);
}

describe('Cloudflare Runtime Dependency Guard', () => {
  describe('Tier 1 -- fully migrated to D1, must carry zero Redis dependency', () => {
    const FULLY_MIGRATED = [
      'api/_lib/watchlist-store.js',
      'api/_lib/change-engine.js',
      'api/_lib/change-detector.js',
      'api/_lib/watchable-state.js',
      'api/_lib/notification-store.js',
      'scripts/evaluate-watchlist-changes.js',
      'scripts/deliver-watchlist-notifications.js',
    ];

    test.each(FULLY_MIGRATED)('%s has zero live Redis calls or requires', (rel) => {
      const src = read(rel);
      expect(redisCallSiteCount(src)).toBe(0);
      expect(hasRedisRequire(src)).toBe(false);
    });
  });

  describe('Tier 2 -- mixed by design, Redis usage must stay bounded (documented, not growing)', () => {
    // notification-dispatch.js's getOwnerAccountEmail() is the one
    // deliberate, deferred Redis call remaining in the D1-backed
    // alert-delivery path (customer-identity lookup; auth is LEGACY, not
    // migrated this tranche). An upper bound, not exact equality, so the
    // guard fails on GROWTH (a regression toward re-Redis-ifying delivery
        // state) without being brittle to a harmless refactor that reduces it.
    test('notification-dispatch.js Redis usage has not grown past its documented, bounded scope', () => {
      const src = read('api/_lib/notification-dispatch.js');
      expect(hasRedisRequire(src)).toBe(true); // still legitimately mixed -- if this ever flips to false, this guard (and its Tier 2 bound below) should move to Tier 1 instead of being loosened
      const calls = redisCallSiteCount(src);
      expect(calls).toBeGreaterThan(0);
      expect(calls).toBeLessThanOrEqual(2); // getOwnerAccountEmail()'s two redis.get() calls -- see the file's own header
    });
  });

  describe('Tier 3 -- must still require the D1 client (catches an accidental revert away from D1)', () => {
    // notification-dispatch.js is deliberately NOT in this list -- verified
    // directly against its source, it holds no D1 handle of its own and
    // delegates all D1-backed state through watchlist-store.js and
    // notification-store.js (both asserted below), which is correct
    // orchestrator-vs-store architecture, not a migration gap.
    const MUST_USE_D1 = [
      'api/_lib/watchlist-store.js',
      'api/_lib/change-engine.js',
      'api/_lib/notification-store.js',
    ];

    test.each(MUST_USE_D1)('%s still requires the D1 client', (rel) => {
      const src = read(rel);
      expect(D1_REQUIRE_RE.test(src)).toBe(true);
    });
  });

  describe('Migration tooling -- exempt from Tier 1 (reads Redis by design), but must stay dry-run-safe', () => {
    const MIGRATION_TOOLS = [
      'scripts/migrate-notifications-redis-to-d1.js',
      'scripts/migrate-watchlists-redis-to-d1.js',
    ];

    test.each(MIGRATION_TOOLS)('%s defaults to dry-run and only writes to D1 behind an explicit --apply flag', (rel) => {
      const src = read(rel);
      expect(src).toMatch(/argv\.includes\(\s*['"]--apply['"]\s*\)/);
      // Every write call in these tools is guarded by `if (!apply) ...`
      // (skip/return) somewhere before the write -- a full behavioral
      // proof lives in each tool's own header contract; this is the
      // cheap static tripwire that the flag itself hasn't been removed.
    });
  });

  describe('D1 schema + binding configuration -- structural drift guards', () => {
    test('the watchlists/change-detection migration file still exists', () => {
      expect(fs.existsSync(path.join(ROOT, 'migrations/0002_watchlists_change_detection.sql'))).toBe(true);
    });

    test('wrangler.jsonc still points at the shared sentinel-apex-core D1 database', () => {
      const src = read('wrangler.jsonc');
      expect(src).toMatch(/"database_name"\s*:\s*"sentinel-apex-core"/);
    });
  });

  describe('GitHub Actions alert-delivery bridge -- preflight gating regression guard', () => {
    // As of the Cloudflare-Only Runtime Completion v2 tranche, BOTH the
    // evaluate and deliver steps depend on BOTH stores (watchlists/change-
    // detection moved to D1 alongside the already-D1-backed delivery
    // state). A regression here would silently re-open the "D1-independent
    // evaluate path" that existed before this tranche and no longer
    // reflects reality.
    test('both customer steps follow a fail-closed Redis+D1 secret presence gate and cannot silently skip', () => {
      const doc = yaml.load(read('.github/workflows/alert-delivery.yml'));
      const steps = doc.jobs['alert-delivery'].steps;
      const gateIndex = steps.findIndex(s => s.run === 'node scripts/alert-delivery-execution-gate.cjs');
      const evaluateIndex = steps.findIndex(s => s.run === 'node scripts/evaluate-watchlist-changes.js');
      const deliveryIndex = steps.findIndex(s => s.run === 'node scripts/deliver-watchlist-notifications.js --limit=50');
      expect(gateIndex).toBeGreaterThan(-1);
      expect(evaluateIndex).toBeGreaterThan(gateIndex);
      expect(deliveryIndex).toBeGreaterThan(evaluateIndex);
      const gate = steps[gateIndex];
      const requiredFlags = [
        'HAS_REDIS_URL', 'HAS_REDIS_TOKEN', 'HAS_CF_ACCOUNT',
        'HAS_CF_DB', 'HAS_CF_TOKEN'
      ];
      for (const key of requiredFlags) {
        expect(gate.env[key]).toMatch(/^\\$\\{\\{ secrets\\.[A-Z0-9_]+ != '' \\}\\}$/);
      }
      for (const step of [gate, steps[evaluateIndex], steps[deliveryIndex]]) {
        expect(step.if).toBeUndefined();
        expect(step['continue-on-error']).not.toBe(true);
      }
      const script = read('scripts/alert-delivery-execution-gate.cjs');
      expect(script).toMatch(/process\\.exitCode\\s*=\\s*1/);
      expect(script).toMatch(/env\\[flag\\]\\s*!==\\s*'true'/);
    });
  });

  describe('Workers-runtime DNS compatibility -- regression guard (Cloudflare Live Cutover v1)', () => {
    // dns.lookup()/dns.promises.lookup() are documented by Cloudflare as
    // unsupported under Workers nodejs_compat (throw "Not implemented" --
    // developers.cloudflare.com/workers/runtime-apis/nodejs/dns/), found
    // this round by direct doc verification after this exact function was
    // re-examined for live-cutover readiness. resolve4()/resolve6() are
    // the supported equivalents and are what webhook-signing.js's SSRF
    // guard now uses. This guard exists so a future edit can't silently
    // reintroduce dns.lookup() into the one file in this codebase that
    // performs a DNS resolution on the Workers-deployed alert-delivery
    // path -- a regression that would only surface once deployed to a
    // real Worker (local Node/Jest testing does not catch it, and even
    // this platform's own local `wrangler dev --local` probe of this
    // exact wrangler version did NOT catch it -- see the Live Cutover v1
    // certification's SSRF section for that discrepancy).
    test('webhook-signing.js does not call dns.lookup or dns.promises.lookup', () => {
      // Strips full-line `//` comments first -- this file's own header
      // explains why (its Redis checks hit the same class of trap): the
      // module's real header comment here explains the switch away from
      // dns.lookup() in prose, which would otherwise false-positive a
      // naive whole-file regex the same way a Redis-history comment could
      // trip the Tier 1 checks above.
      const codeOnly = read('api/_lib/webhook-signing.js')
        .split('\n')
        .filter(line => !line.trim().startsWith('//'))
        .join('\n');
      expect(codeOnly).not.toMatch(/dns\.lookup\(/);
      expect(codeOnly).not.toMatch(/dns\.promises\.lookup\(/);
    });

    test('webhook-signing.js uses resolve4/resolve6 for its SSRF DNS check', () => {
      const src = read('api/_lib/webhook-signing.js');
      expect(src).toMatch(/dns\.promises\.resolve4\(/);
      expect(src).toMatch(/dns\.promises\.resolve6\(/);
    });
  });
});
