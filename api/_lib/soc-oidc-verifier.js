'use strict';

/**
 * SENTINEL APEX SOC — fail-closed, provider-configured RS256 access-token verifier.
 * Source library only: no HTTP route, login session, or live IdP configuration.
 *
 * Security policy:
 * - Operator-pinned HTTPS issuer, audience and same-origin JWKS endpoint.
 * - Only signed, type-tagged (at+jwt), RSA-2048+ RS256 access tokens.
 * - JOSE headers cannot choose keys via jku, x5u, embedded JWK or any URL.
 * - Exact issuer/audience, exp/iat/nbf, limited lifetime, signed MFA evidence,
 *   named JWT ID (jti), and a mandatory live revocation/denylist hook.
 * - JWKS fetched over fixed HTTPS with redirects denied and small hard cap;
 *   bounded in-memory cache. Missing cache or revocation service fails closed.
 *
 * This is an authentication primitive, NOT a replacement for tenant DB RBAC.
 * Wire only after an IdP, revocation authority and full browser/session
 * controls have been independently reviewed and accepted.
 */
const { webcrypto } = require('node:crypto');
const subtle = (globalThis.crypto && globalThis.crypto.subtle) || webcrypto.subtle;
const ENC = new TextEncoder();

class SocOidcError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SocOidcError';
    this.code = code;
  }
}
function reject(code) { throw new SocOidcError(code); }
function jsonSegment(segment, maxBytes) {
  if (typeof segment !== 'string' || !/^[A-Za-z0-9_-]+$/.test(segment)) reject('JWT_FORMAT');
  let raw;
  try { raw = Buffer.from(segment, 'base64url'); }
  catch (_) { reject('JWT_FORMAT'); }
  if (!raw.length || raw.length > maxBytes) reject('JWT_SIZE');
  try {
    const value = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
    if (!value || typeof value !== 'object' || Array.isArray(value)) reject('JWT_FORMAT');
    return value;
  } catch (_) { reject('JWT_FORMAT'); }
}
function validateUrl(url, expected) {
  if (typeof url !== 'string') reject('OIDC_CONFIGURATION');
  let parsed;
  try { parsed = new URL(url); } catch (_) { reject('OIDC_CONFIGURATION'); }
  if (parsed.protocol !== 'https:' || !parsed.hostname ||
      parsed.username || parsed.password || parsed.hash || parsed.search ||
      (expected && parsed.origin !== expected)) reject('OIDC_CONFIGURATION');
  return parsed;
}
function getAudience(aud, required, azp) {
  if (typeof aud === 'string') return aud === required && (azp === undefined || azp === required);
  if (!Array.isArray(aud) || !aud.length || aud.length > 8 ||
      !aud.every(x => typeof x === 'string')) return false;
  if (!aud.includes(required)) return false;
  return aud.length === 1 ? (azp === undefined || azp === required) : azp === required;
}
function numericDate(value) { return Number.isSafeInteger(value) && value > 0; }

function createSocOidcVerifier({
  issuer,
  audience,
  jwksUrl,
  fetcher = globalThis.fetch,
  checkRevocation,
  now = () => Date.now(),
} = {}) {
  const issuerURL = validateUrl(issuer);
  const jwksURL = validateUrl(jwksUrl, issuerURL.origin);
  if (issuerURL.pathname !== '/' && issuerURL.pathname.endsWith('/') && issuer !== issuerURL.toString()) {
    reject('OIDC_CONFIGURATION');
  }
  if (typeof audience !== 'string' || audience.length < 3 || audience.length > 256 ||
      typeof fetcher !== 'function' || typeof checkRevocation !== 'function') {
    reject('OIDC_CONFIGURATION');
  }

  const pinnedIssuer = issuer;
  const pinnedAudience = audience;
  const fixedJwks = jwksURL.toString();
  let cache = null;
  let inFlight = null;
  const cacheSeconds = 120;

  async function fetchKeys() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetcher(fixedJwks, {
        method:'GET',redirect:'error',cache:'no-store',signal:controller.signal,
        headers:{Accept:'application/json'},
      });
      if (!response || !response.ok) reject('JWKS_UNAVAILABLE');
      const length = Number(response.headers && response.headers.get('content-length'));
      if (Number.isFinite(length) && length > 96 * 1024) reject('JWKS_OVERSIZE');
      // Bound bytes WHILE reading; checking length only after response.text()
      // would still allow an oversized provider response to allocate memory.
      let text;
      if (response.body && typeof response.body.getReader === 'function') {
        const reader = response.body.getReader();
        const chunks = [];
        let length = 0;
        try {
          while (true) {
            const next = await reader.read();
            if (next.done) break;
            length += next.value.byteLength;
            if (length > 96 * 1024) reject('JWKS_OVERSIZE');
            chunks.push(next.value);
          }
          const bytes = new Uint8Array(length);
          let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.byteLength; }
          text = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
        } finally {
          await reader.cancel().catch(() => {});
          reader.releaseLock();
        }
      } else {
        text = await response.text();
        if (Buffer.byteLength(text,'utf8') > 96 * 1024) reject('JWKS_OVERSIZE');
      }
      let keys;
      try { keys = JSON.parse(text).keys; } catch (_) { reject('JWKS_INVALID'); }
      if (!Array.isArray(keys) || !keys.length || keys.length > 32) reject('JWKS_INVALID');
      if (!keys.every(key => key && typeof key === 'object' && typeof key.kid === 'string')) reject('JWKS_INVALID');
      return {keys,expires:Date.now() + cacheSeconds * 1000};
    } catch (error) {
      if (error instanceof SocOidcError) throw error;
      reject('JWKS_UNAVAILABLE');
    } finally {
      clearTimeout(timeout);
    }
  }
  async function getKeys() {
    if (cache && cache.expires > Date.now()) return cache.keys;
    if (!inFlight) inFlight = fetchKeys().then(entry => {cache=entry;return entry.keys;})
      .finally(() => {inFlight=null;});
    return inFlight;
  }

  async function verifyIdentity(token) {
    if (typeof token !== 'string' || token.length < 20 || token.length > 8192) reject('JWT_FORMAT');
    const parts = token.split('.');
    if (parts.length !== 3) reject('JWT_FORMAT');
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = jsonSegment(encodedHeader, 2048);
    const payload = jsonSegment(encodedPayload, 6144);
    if (header.alg !== 'RS256' || header.typ !== 'at+jwt' ||
        typeof header.kid !== 'string' || header.kid.length < 1 || header.kid.length > 128 ||
        ['jku','x5u','jwk','crit','enc','zip'].some(name => name in header)) reject('JWT_HEADER');
    if (payload.iss !== pinnedIssuer || typeof payload.sub !== 'string' ||
        !payload.sub || payload.sub.length > 512 ||
        !getAudience(payload.aud,pinnedAudience,payload.azp)) reject('JWT_CLAIMS');

    const seconds = Math.floor(now() / 1000);
    if (!numericDate(payload.exp) || !numericDate(payload.iat) ||
        payload.exp <= seconds || payload.iat > seconds + 60 ||
        payload.iat < seconds - 3600 || payload.exp <= payload.iat ||
        payload.exp - payload.iat > 3600 ||
        (payload.nbf !== undefined && (!numericDate(payload.nbf) || payload.nbf > seconds + 60))) {
      reject('JWT_EXPIRED_OR_INVALID_TIME');
    }
    if (typeof payload.jti !== 'string' || payload.jti.length < 16 || payload.jti.length > 256 ||
        !Array.isArray(payload.amr) || !payload.amr.includes('mfa')) reject('JWT_ASSURANCE');

    const keys = await getKeys();
    const eligible = keys.filter(k => k.kid === header.kid &&
      k.kty === 'RSA' && (k.alg === undefined || k.alg === 'RS256') &&
      (k.use === undefined || k.use === 'sig') &&
      (k.key_ops === undefined || (Array.isArray(k.key_ops) && k.key_ops.includes('verify'))) &&
      typeof k.n === 'string' && typeof k.e === 'string' &&
      !['d','p','q','dp','dq','qi','oth'].some(secret => secret in k));
    if (eligible.length !== 1 ||
        !/^[A-Za-z0-9_-]+$/.test(eligible[0].n) ||
        Buffer.from(eligible[0].n,'base64url').length < 256) reject('JWKS_KEY');
    let key;
    try {
      key = await subtle.importKey('jwk', eligible[0],
        {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['verify']);
    } catch (_) { reject('JWKS_KEY'); }
    if (!/^[A-Za-z0-9_-]+$/.test(encodedSignature)) reject('JWT_FORMAT');
    const signature = Buffer.from(encodedSignature,'base64url');
    let valid = false;
    try {
      valid = await subtle.verify({name:'RSASSA-PKCS1-v1_5'},key,signature,
        ENC.encode(encodedHeader+'.'+encodedPayload));
    } catch (_) { reject('JWT_SIGNATURE'); }
    if (!valid) reject('JWT_SIGNATURE');
    let active;
    try {
      active = await checkRevocation({
        issuer:pinnedIssuer,subject:payload.sub,jti:payload.jti,
        expiresAt:payload.exp,tokenIssuedAt:payload.iat,
      });
    } catch (_) { reject('REVOCATION_UNAVAILABLE'); }
    if (active !== true) reject('JWT_REVOKED');
    return Object.freeze({verified:true,issuer:pinnedIssuer,subject:payload.sub});
  }

  return Object.freeze(verifyIdentity);
}

module.exports = {createSocOidcVerifier,SocOidcError};
