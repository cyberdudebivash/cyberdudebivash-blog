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
  '/privacy.html',
  '/security-disclosure.html',
  '/contact.html',
]);
// Customer-visible legal and contact identity must be independently checked,
// not inferred from the homepage or older, blog-hosted metadata.
const LEGAL_ROUTES = new Set([
  '/about.html', '/terms.html', '/privacy.html',
  '/security-disclosure.html', '/contact.html',
]);
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
  // Only head metadata counts as canonical/OG evidence. A tag planted in the
  // body cannot establish search identity, and missing/duplicate heads HOLD.
  const heads = html.match(/<head\b[^>]*>[\s\S]*?<\/head\s*>/gi) || [];
  const bodyOffset = html.search(/<body\b/i);
  const head = heads.length === 1 &&
    (bodyOffset < 0 || html.indexOf(heads[0]) < bodyOffset) ? heads[0] : '';
  const canonical = tags(head, 'link')
    .filter(tag => (attribute(tag, 'rel') || '').toLowerCase().split(/\s+/).includes('canonical'))
    .map(tag => attribute(tag, 'href'));
  const ogUrls = tags(head, 'meta')
    .filter(tag => (attribute(tag, 'property') || '').toLowerCase() === 'og:url')
    .map(tag => attribute(tag, 'content'));
  const errors = [];
  if (!head) errors.push('DOCUMENT_HEAD_MISSING_OR_AMBIGUOUS');
  // A head-only or malformed response cannot pass legal copy checks.
  // Brand text inside comments, scripts or metadata is not customer-visible.
  const hasBody = /<body\b[^>]*>[\s\S]*?<\/body\s*>/i.test(html);
  const copy = hasBody ? visibleBodyText(html) : '';
  if (!hasBody || !copy) errors.push('VISIBLE_BODY_MISSING');
  if (canonical.length !== 1 || canonical[0] !== expected) errors.push('SOC_CANONICAL_MISMATCH');
  if (ogUrls.length !== 1 || ogUrls[0] !== expected) errors.push('SOC_OG_URL_MISMATCH');
  if (INCORPORATED.test(html)) errors.push('UNSUPPORTED_INCORPORATION');
  if (UNSUPPORTED.test(html)) errors.push('UNSUPPORTED_SERVICE_OR_CERTIFICATION');
  if (LEGAL_ROUTES.has(route) && !copy.includes('CYBERDUDEBIVASH ECOSYSTEM'))
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
    // The scope limitation must be customer-visible; metadata cannot satisfy it.
    if (!copy.includes('not an active 24/7 monitoring service'))
      errors.push('SERVICE_BOUNDARY_MISSING');
    // An email address in a comment, script or unrelated text is not an enquiry CTA.
    const bodyMarkup = html.match(/<body\b[^>]*>([\s\S]*?)<\/body\s*>/i)?.[1] || '';
    const linkMarkup = bodyMarkup
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(?:script|style|template|noscript)\b[^>]*>[\s\S]*?<\/(?:script|style|template|noscript)\s*>/gi, ' ');
    const enquiryLink = tags(linkMarkup, 'a').some(tag => {
      const href = attribute(tag, 'href') || '';
      return /^mailto:contact@cyberdudebivash\.in(?:\?|$)/i.test(href) &&
        !/\s(?:hidden|inert)(?:\s|=|>)/i.test(tag) &&
        !/\saria-hidden\s*=\s*["']true["']/i.test(tag) &&
        !/\sstyle\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden)/i.test(tag);
    });
    if (!enquiryLink) errors.push('ENQUIRY_CONTACT_MISSING');
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
