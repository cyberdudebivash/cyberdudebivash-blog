'use strict';

/**
 * Registration must not consume a paid-before-register tier until its user
 * record AND both durable lookup keys have been written successfully.
 *
 * Compare-and-delete protects concurrent billing updates: never delete a
 * newer paid-tier record merely because registration read an older one.
 * This module never logs or returns payment metadata.
 */
const CONSUME_EXACT_PENDING_TIER_SCRIPT = [
  'local current = redis.call("GET", KEYS[1])',
  'if current ~= ARGV[1] then return 0 end',
  'return redis.call("DEL", KEYS[1])',
].join('\n');

async function consumePendingTierAfterRegistration(redis, key, observedValue) {
  if (!redis || typeof redis.eval !== 'function' ||
      typeof key !== 'string' || !key.startsWith('user:pending:tier:') ||
      key.length <= 'user:pending:tier:'.length ||
      typeof observedValue !== 'string' || !observedValue) {
    throw new Error('SOC_PENDING_TIER_CLEANUP_INVALID_ARGUMENT');
  }
  const receipt = await redis.eval(CONSUME_EXACT_PENDING_TIER_SCRIPT, [key], [observedValue]);
  if (receipt !== 0 && receipt !== 1) {
    throw new Error('SOC_PENDING_TIER_CLEANUP_UNVERIFIED_RECEIPT');
  }
  return receipt === 1;
}

module.exports = { consumePendingTierAfterRegistration, CONSUME_EXACT_PENDING_TIER_SCRIPT };
