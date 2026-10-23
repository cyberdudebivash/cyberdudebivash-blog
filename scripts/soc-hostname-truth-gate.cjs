#!/usr/bin/env node
'use strict';

/**
 * Read-only, fail-closed P0 SOC public-hostname identity gate.
 * Separate from the legacy blog.cyberdudebivash.in CTI release gate.
 * Default mode reads local source only; --live performs bounded public GETs.
 * Never changes DNS, Cloudflare, customer data, billing or release state.
 */
const fs = require('node:fs');
const path = require('node:path');

const ORIGIN = 'https://soc.cyberdudebivash.in';
const MAX_BYTES = 2_000_000;
const ROUTES = Object.freeze([
  '/',
  '/soc-readiness-assessment.html',
  '/about.html',
  '/terms.html',
]);
const LEGAL_ROUTES = new Set(['/about.html', '/terms.html']);
const UNSUPPORTED = /\b(?:SOC 2 Type II certified|24\/7 managed SOC is live)\b/i;
const INCORPORATED = /\bCyberDudeBivash\s+(?:Private\s+Limited|Pvt\.?\s*Ltd\.?)\b/i;

function attribute(tag, name) {
  // Only fixed, internal attribute names are accepted; never user input.
  const match = tag.match(new RegExp('(?:^|\\s)' + name + '\\s*=\\s*(?:"([^"]*)"|\\x27([^\\x27]*)\\x27)', 'i'));
  return match ? (match[1] ?? match[2]) : null;
}
function tags(html, element) {
  return html.match(new RegExp('<' + element + '\\b[^>]*>', 'gi')) || [];
}
// Inspect rendered legal/service copy, not historical asset URLs or script metadata.
function visibleBodyText(html) {
  const body = html.match(/<body\b[^>]*>([\s\S]*?)<\/body\s*>/i);
  if (!body) return '';
  return body[1]
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(?:script|style|template|noscript)\b[^>]*>[\s\S]*?<\/(?:script|style|template|noscript)\s*>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
function assess(route, html) {
  if (!ROUTES.includes(route) || typeof html !== 'string' || !html.trim() ||
      Buffer.byteLength(html, 'utf8') > MAX_BYTES) return ['INVALID_HTML'];
  const expected = ORIGIN + route;
  const canonical = tags(html, 'link')
    .filter(tag => (attribute(tag, 'rel') || '').toLowerCase().split(/\s+/).includes('canonical'))
    .map(tag => attribute(tag, 'href'));
  const ogUrls = tags(html, 'meta')
    .filter(tag => (attribute(tag, 'property') || '').toLowerCase() === 'og:url')
    .map(tag => attribute(tag, 'content'));
  const errors = [];
  if (canonical.length !== 1 || canonical[0] !== expected) errors.push('SOC_CANONICAL_MISMATCH');
  if (ogUrls.length !== 1 || ogUrls[0] !== expected) errors.push('SOC_OG_URL_MISMATCH');
  if (INCORPORATED.test(html)) errors.push('UNSUPPORTED_INCORPORATION');
  if (UNSUPPORTED.test(html)) errors.push('UNSUPPORTED_SERVICE_OR_CERTIFICATION');
  if (LEGAL_ROUTES.has(route) && !html.includes('CYBERDUDEBIVASH ECOSYSTEM'))
    errors.push('SELLER_IDENTITY_MISSING');
  if (route === '/terms.html' && /\bblog\.cyberdudebivash\.in\b/i.test(visibleBodyText(html)))
    errors.push('LEGACY_VISIBLE_LEGAL_HOST');
  if (route === '/about.html') {
    const copy = visibleBodyText(html);
    if (/\bwe monitor\b.{0,160}\baround the clock\b/i.test(copy))
      errors.push('UNVERIFIED_CONTINUOUS_MONITORING_COPY');
    if (/\bX\s*\/\s*Twitter\s*:\s*@cdbsentinelapex\b/i.test(copy))
      errors.push('RETIRED_SOCIAL_IDENTITY');
    if (!/(?:not an active 24\/7 monitoring service|(?:continuous\s+)?managed customer monitoring.{0,160}(?:not offered|subject to|requires))/i.test(copy))
      errors.push('MANAGED_SERVICE_BOUNDARY_MISSING');
  }
  if (route === '/soc-readiness-assessment.html') {
    if (!html.includes('not an active 24/7 monitoring service'))
      errors.push('SERVICE_BOUNDARY_MISSING');
    if (!html.includes('contact@cyberdudebivash.in'))
      errors.push('ENQUIRY_CONTACT_MISSING');
  }
  return errors;
}
async function fetchLive(route) {
  const url = new URL(route, ORIGIN);
  if (url.origin !== ORIGIN) throw new Error('ORIGIN_REJECTED');
  const response = await fetch(url, {
    redirect: 'manual',
    headers: {'Accept': 'text/html', 'Cache-Control': 'no-cache'},
    signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) throw new Error('HTTP_NOT_200');
  if (!/^text\/html(?:;|$)/i.test(response.headers.get('content-type') || ''))
    throw new Error('NOT_HTML');
  const chunks = [];
  let size = 0;
  const reader = response.body?.getReader();
  if (!reader) throw new Error('EMPTY_RESPONSE');
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) throw new Error('BODY_OVERSIZE');
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks).toString('utf8');
}
async function run(mode = 'source', root = process.cwd()) {
  if (!['source', 'live'].includes(mode)) throw new Error('MODE_INVALID');
  const output = [];
  for (const route of ROUTES) {
    try {
      const html = mode === 'live'
        ? await fetchLive(route)
        : fs.readFileSync(path.join(root, route === '/' ? 'index.html' : route.slice(1)), 'utf8');
      const errors = assess(route, html);
      output.push({route, pass: errors.length === 0, errors});
    } catch (err) {
      const safe = new Set(['ORIGIN_REJECTED','HTTP_NOT_200','NOT_HTML','EMPTY_RESPONSE','BODY_OVERSIZE']);
      output.push({route, pass:false, errors:[safe.has(err.message) ? err.message : 'SOURCE_OR_FETCH_FAILED']});
    }
  }
  return output;
}
if (require.main === module) {
  const mode = process.argv.length === 3 && process.argv[2] === '--live' ? 'live' :
    process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === '--source') ? 'source' : null;
  if (!mode) { console.error('Usage: node scripts/soc-hostname-truth-gate.cjs [--source|--live]'); process.exitCode = 2; }
  else run(mode).then(rows => {
    for (const row of rows)
      console.log((row.pass ? 'PASS' : 'HOLD') + ' ' + row.route + ' ' + (row.errors.join(',') || 'SOC_HOSTNAME_IDENTITY_OK'));
    if (rows.some(row => !row.pass)) process.exitCode = 1;
  }).catch(() => { console.error('HOLD SOC_HOSTNAME_GATE_ERROR'); process.exitCode = 1; });
}
module.exports = {ORIGIN, ROUTES, assess, run};
