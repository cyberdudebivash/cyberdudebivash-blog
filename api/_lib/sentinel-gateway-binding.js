'use strict';

/**
 * Holder for the `SENTINEL_GATEWAY` service binding (wrangler.jsonc
 * "services"), registered by workers/lib/router.js like the D1/R2 bindings.
 * Dependency-free so the router can import it without loading any handler.
 */
let binding = null;

function setSentinelGatewayBinding(value) {
  binding = value && typeof value.fetch === 'function' ? value : null;
}

function getSentinelGatewayBinding() {
  return binding;
}

module.exports = { setSentinelGatewayBinding, getSentinelGatewayBinding };
