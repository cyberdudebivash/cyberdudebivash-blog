'use strict';

/**
 * SENTINEL APEX SOC: source-only composition of real cryptographically
 * verified tenant analyst identity, primary-D1 session and independent bytes.
 *
 * No public Worker route, no customer evidence source adapter, no automated
 * incident, no Cloudflare credentials or production mutation.
 *
 * The injected readAuthorizedEvent MUST be an operator-approved tenant-aware
 * provider client with its own configured source IDs and credentials. NEVER
 * allow request/HTTP body data to select its base URL or authentication.
 */
const {createSocOidcVerifier}=require('./soc-oidc-verifier');
const {createSocSessionAuthority}=require('./soc-session-authority');
const {createSocDetectionReviewService}=require('./soc-detection-review-service');
const {createSocSourceByteVerifier}=require('./soc-source-byte-verifier');

function createSocDetectionSourceBoundary({
  nativeD1,oidc,readAuthorizedEvent,fetcher,nowMillis,
  maxBytes=262144,timeoutMs=6000,
}={}) {
  if(!nativeD1||typeof nativeD1.withSession!=='function'||
     !oidc||typeof oidc!=='object'||Array.isArray(oidc)||
     typeof readAuthorizedEvent!=='function')
    throw new Error('SOC_EVIDENCE_BOUNDARY_NOT_CONFIGURED');
  const clock=typeof nowMillis==='function'?nowMillis:()=>Date.now();
  const sessionAuthority=createSocSessionAuthority({
    db:nativeD1,now:()=>Math.floor(clock()/1000),
  });
  const verifyIdentity=createSocOidcVerifier({
    issuer:oidc.issuer,audience:oidc.audience,jwksUrl:oidc.jwksUrl,
    checkRevocation:sessionAuthority.checkRevocation,
    now:clock,...(fetcher?{fetcher}:{}),
  });
  const verifySourceEvidence=createSocSourceByteVerifier({
    readAuthorizedEvent,maxBytes,timeoutMs,
  });
  const service=createSocDetectionReviewService({
    nativeD1,verifyIdentity,verifySourceEvidence,
    now:()=>new Date(clock()).toISOString(),
  });
  return Object.freeze({
    review:service.review,
    linkToIncident:service.linkToIncident,
  });
}

module.exports={createSocDetectionSourceBoundary};
