'use strict';

/**
 * Canonical commercial-tier ordering and data-access profiles.
 *
 * Why this module exists: every paid-capability gate in the API previously
 * hand-wrote `tier === 'pro' || tier === 'enterprise'`. The `team` plan
 * (Sentinel Team, priced above Pro and advertised with IOC access, STIX 2.1
 * export and SIEM export) matched neither literal, so a Team customer was
 * silently served free-tier data and 403s on capabilities Pro customers get.
 * The code comments at those gates state the intent was always
 * "free/starter excluded"; this module encodes that intent once.
 *
 * Pure data + pure functions: no Redis, no I/O, safe to require from any
 * handler or library (including ones whose tests mock ./middleware).
 */

const TIERS = Object.freeze(['free', 'starter', 'pro', 'team', 'enterprise']);

// Response-shaping profile per tier. `team` receives the Pro data profile:
// it must never receive less than the cheaper Pro plan, and enterprise-only
// fields (raw attribution signals, scoring breakdowns) are not part of the
// published Team offer, so they are not granted here.
const DATA_PROFILES = Object.freeze({
  free: 'free',
  starter: 'free',
  pro: 'pro',
  team: 'pro',
  enterprise: 'enterprise',
});

function tierRank(tier) {
  return TIERS.indexOf(tier);
}

/**
 * True when `tier` is the same as or above `minimum` in the paid ladder.
 * Unknown/missing caller tiers are never elevated (fail closed).
 */
function tierAtLeast(tier, minimum) {
  const need = tierRank(minimum);
  if (need < 0) throw new Error(`tierAtLeast: unknown minimum tier "${minimum}"`);
  const have = tierRank(tier);
  return have >= 0 && have >= need;
}

function dataProfile(tier) {
  return Object.prototype.hasOwnProperty.call(DATA_PROFILES, tier) ? DATA_PROFILES[tier] : 'free';
}

module.exports = { TIERS, DATA_PROFILES, tierRank, tierAtLeast, dataProfile };
