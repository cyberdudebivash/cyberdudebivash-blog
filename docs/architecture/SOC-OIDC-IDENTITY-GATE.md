# SENTINEL APEX SOC — OIDC Access-Token Identity Gate

**Status:** Source-library security preflight. NO production identity-provider configuration and NO customer sign-in enabled.

## Source implementation

api/_lib/soc-oidc-verifier.js is a configured verifier factory for RSA-2048+ RS256 OIDC-style **access tokens**. It deliberately rejects ID tokens with the wrong token type (requires at+jwt) and never uses header-provided URLs or client-supplied keys. Only a deployment-configured HTTPS issuer, audience and same-origin JWKS URL may supply public keys.

The returned callable verifies RSA signatures through WebCrypto, exact issuer, recipient audience (and azp when applicable), issued/not-before/expiration timestamps, a maximum one-hour lifetime, JWT ID, and an MFA marker. It then requires a *separate* trusted revocation callback to return true; missing revocation authority, timeouts and key errors deny access.

It returns only verified issuer/subject identity. It does NOT authorize tenant access or role; the Phase 3 incident service independently resolves the user's active membership and permissions in D1.

## Production release blockers

- A legitimate enterprise IdP issuer and SOC API-specific audience have not been selected, approved or configured.
- A trustworthy revocation/session authority and MFA assurance mapping must be implemented and reviewed. The callback is a hard dependency, not a bypass parameter.
- The same-origin JWKS policy is intentionally restrictive. Providers using a different trusted JWKS origin require a reviewed pinning policy change; do not weaken URL checks indiscriminately.
- Session login / OAuth authorization code + PKCE, CSRF protection, nonce/state handling, cookie controls, identity-provider logout and access-token rotation remain outside this PR.
- Validate token type/profile semantics with the selected IdP; some providers do not issue typed JWT access tokens or an amr claim. Unsupported token shapes remain rejected until an explicitly validated provider adapter exists.
- The JWT verifier library has NO Cloudflare router registration, no public API route, no Worker secret values and no production deployment authority.
- Unit tests generate disposable signing keys. They do not constitute a pen-test of the full IdP login, token storage or customer tenant security boundary.

## Acceptance and next integration

1. Exact-head Jest, security and Cloudflare build checks pass.
2. Complete an adversarial review against RFC 8725, OpenID Connect Core and the chosen IdP's published token profile.
3. Verify trusted origin metadata, JWKS rotation behavior, blocked algorithm substitutions, revocation outage, expired token, absent MFA and wrong audience.
4. Implement and test the provider-specific login, session and revocation adapter in a separate scoped PR, then bind to the tenant service behind feature flags with negative cross-tenant tests.
5. Do not expose any customer SOC API or migrate DNS until proof and operator approval.

**GO:** independent code review and tests. **NO-GO:** production login, customer SOC and sales SLA.
