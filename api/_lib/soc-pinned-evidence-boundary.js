'use strict';

/**
 * Composition only: pinned credentialed proxy -> independent SHA256 of source
 * bytes -> signed/MFA/revocation-checked OIDC analyst -> primary D1 review.
 *
 * This is NOT a public Worker endpoint or an onboarded EDR/SIEM connector.
 * Upstream operator-managed proxy, token authority, IdP and migrations must
 * be independently approved before a pilot. No mock is valid for customer SOC.
 */
const {createSocPinnedEvidenceProxy}=require('./soc-pinned-evidence-proxy');
const {createSocDetectionSourceBoundary}=require('./soc-detection-source-boundary');

function createSocPinnedEvidenceBoundary({
  nativeD1,oidc,bindings,resolveToken,
  providerFetcher,identityFetcher,nowMillis,
  maxBytes=262144,timeoutMs=6000,
}={}){
  const {readAuthorizedEvent}=createSocPinnedEvidenceProxy({
    bindings,resolveToken,
    ...(providerFetcher?{fetcher:providerFetcher}:{}),
    maxBytes,timeoutMs,
  });
  const service=createSocDetectionSourceBoundary({
    nativeD1,oidc,readAuthorizedEvent,
    ...(identityFetcher?{fetcher:identityFetcher}:{}),
    ...(nowMillis?{nowMillis}:{}),
    maxBytes,timeoutMs,
  });
  return Object.freeze({review:service.review,linkToIncident:service.linkToIncident});
}
module.exports={createSocPinnedEvidenceBoundary};
