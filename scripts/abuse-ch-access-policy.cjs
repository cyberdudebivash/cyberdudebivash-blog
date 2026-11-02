'use strict';

/**
 * Fail-closed abuse.ch provider access policy for commercial SOC ingestion.
 *
 * Do not send an Auth-Key unless the owner has approved the provider's
 * commercial-use terms. Never place credentials in URLs, logs, metrics or Git.
 * This module is pure and makes no network calls or production changes.
 */
const APPROVED = 'true';
const KEY_FORMAT = /^[A-Za-z0-9_-]{12,256}$/;

function abuseChHeaders({ key, commercialUseApproved } = {}) {
  if (commercialUseApproved !== APPROVED) {
    throw new Error('ABUSE_CH_COMMERCIAL_USE_NOT_APPROVED');
  }
  if (typeof key !== 'string' || !KEY_FORMAT.test(key)) {
    throw new Error('ABUSE_CH_AUTH_KEY_MISSING_OR_INVALID');
  }
  return { 'Auth-Key': key };
}

function authenticatedRedirectUrl(currentUrl, redirectLocation, headers = {}) {
  const current = new URL(currentUrl);
  const next = new URL(redirectLocation, current);
  const hasProviderKey = Object.keys(headers).some(k => k.toLowerCase() === 'auth-key');
  // An upstream redirect to an unrelated domain must never receive a provider
  // token. Reject rather than strip silently and claim authenticated success.
  if (hasProviderKey && next.origin !== current.origin) {
    throw new Error('ABUSE_CH_CROSS_ORIGIN_AUTH_REDIRECT_DENIED');
  }
  return next.href;
}

module.exports = { abuseChHeaders, authenticatedRedirectUrl };
