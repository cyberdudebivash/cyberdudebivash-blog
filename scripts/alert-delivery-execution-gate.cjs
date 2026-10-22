#!/usr/bin/env node
'use strict';

/**
 * Production alert-delivery truth gate (GitHub Actions only).
 *
 * GitHub Actions maps expression checks of secret presence to literal
 * 'true'/'false'. Never pass or print secret VALUES to this module.
 * Missing requirements must fail the job before any Redis/D1 request.
 *
 * This gate verifies configuration presence, NOT runtime connectivity,
 * credentials validity or actual customer notification delivery.
 */
const REQUIRED_FLAGS = Object.freeze({
  HAS_REDIS_URL: 'REDIS_URL_ABSENT',
  HAS_REDIS_TOKEN: 'REDIS_TOKEN_ABSENT',
  HAS_CF_ACCOUNT: 'CF_ACCOUNT_ABSENT',
  HAS_CF_DB: 'CF_D1_DATABASE_ABSENT',
  HAS_CF_TOKEN: 'CF_D1_TOKEN_ABSENT',
});

function assessAlertDeliveryPrerequisites(env = {}) {
  const missing = Object.entries(REQUIRED_FLAGS)
    .filter(([flag]) => env[flag] !== 'true')
    .map(([, code]) => code);
  return { ok: missing.length === 0, codes: missing };
}

if (require.main === module) {
  const result = assessAlertDeliveryPrerequisites(process.env);
  if (!result.ok) {
    // Status codes alone: never leak tokens, Redis URLs, account IDs or DB IDs.
    console.error('::error title=P0 Alert Delivery Unavailable::CONFIGURATION_NOT_READY: ' + result.codes.join(','));
    console.error('P0: Watchlist evaluation and alert delivery did NOT run. A green workflow is prohibited.');
    process.exitCode = 1;
  } else {
    console.log('PASS: Required secret-presence preflight for alert-delivery execution.');
  }
}

module.exports = { REQUIRED_FLAGS, assessAlertDeliveryPrerequisites };
