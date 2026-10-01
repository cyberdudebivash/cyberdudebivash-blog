'use strict';

/**
 * Strict IOC normalization, validation and safety filtering.
 *
 * Regex here CLASSIFIES a value that a structured, allowlisted source already
 * supplied in an explicit indicator field. It never establishes maliciousness
 * and is never applied to prose (see ICF-P0-009: advisory text produced vendor
 * domains, fix-commit SHAs and 169.254.169.254 as "IOCs").
 *
 * Every rejection carries a stable reason code so pipeline telemetry can count
 * safety-filter hits without exposing raw values publicly.
 */

const TYPES = Object.freeze(['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5']);

// ── IPv4 ──────────────────────────────────────────────────────────────────
function parseIPv4(value) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n, i) => n > 255 || (m[i + 1].length > 1 && m[i + 1][0] === '0'))) return null;
  return o;
}

// Non-public IPv4 space (IANA special-purpose registry). Any hit is rejected:
// such values cannot be attacker-controlled internet infrastructure and
// blocking them breaks customer networks (e.g. 169.254.169.254 cloud metadata).
const IPV4_RESERVED = [
  ['0.0.0.0', 8, 'unspecified'], ['10.0.0.0', 8, 'private'], ['100.64.0.0', 10, 'cgnat'],
  ['127.0.0.0', 8, 'loopback'], ['169.254.0.0', 16, 'link_local'], ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'ietf_protocol'], ['192.0.2.0', 24, 'documentation'], ['192.88.99.0', 24, 'relay_anycast'],
  ['192.168.0.0', 16, 'private'], ['198.18.0.0', 15, 'benchmarking'], ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'], ['224.0.0.0', 4, 'multicast'], ['240.0.0.0', 4, 'reserved'],
];
const ipv4ToInt = o => ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
const IPV4_RANGES = IPV4_RESERVED.map(([base, bits, reason]) => {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { net: (ipv4ToInt(parseIPv4(base)) & mask) >>> 0, mask, reason };
});
function ipv4Reserved(octets) {
  const n = ipv4ToInt(octets);
  const hit = IPV4_RANGES.find(r => ((n & r.mask) >>> 0) === r.net);
  return hit ? hit.reason : null;
}

// ── IPv6 ──────────────────────────────────────────────────────────────────
function expandIPv6(value) {
  if (!/^[0-9a-f:]+$/i.test(value) || value.length > 39) return null;
  const parts = value.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const fill = parts.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (parts.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return groups.map(g => parseInt(g, 16));
}
function ipv6Reserved(g) {
  if (g.every(x => x === 0)) return 'unspecified';
  if (g.slice(0, 7).every(x => x === 0) && g[7] === 1) return 'loopback';
  if ((g[0] & 0xffc0) === 0xfe80) return 'link_local';
  if ((g[0] & 0xfe00) === 0xfc00) return 'unique_local';
  if ((g[0] & 0xff00) === 0xff00) return 'multicast';
  if (g[0] === 0x2001 && g[1] === 0x0db8) return 'documentation';
  if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) return 'ipv4_mapped';
  return null;
}
const ipv6Canonical = g => g.map(x => x.toString(16)).join(':');

// ── Domains ───────────────────────────────────────────────────────────────
// Registrable domains that are never customer IOCs on their own: our own
// properties, platform/code hosting, package registries, CDNs, major
// vendors and documentation hosts. A URL on such a host can still be an IOC
// (full path; e.g. a malware payload on raw.githubusercontent.com) but is
// flagged shared_hosting so it is never turned into a domain block.
const PROTECTED_DOMAINS = new Set([
  'cyberdudebivash.in', 'cyberdudebivash.com', 'blogspot.com', 'blogger.com',
  'github.com', 'githubusercontent.com', 'github.io', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
  'npmjs.com', 'npmjs.org', 'pypi.org', 'pythonhosted.org', 'rubygems.org', 'crates.io', 'nuget.org', 'maven.org', 'packagist.org', 'golang.org', 'go.dev', 'docker.com', 'docker.io',
  'microsoft.com', 'windows.com', 'windows.net', 'office.com', 'live.com', 'azure.com', 'azureedge.net', 'msftconnecttest.com',
  'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'gmail.com', 'youtube.com', 'goo.gl', 'g.co',
  'apple.com', 'icloud.com', 'amazon.com', 'amazonaws.com', 'cloudfront.net', 'cloudflare.com', 'cloudflare.net', 'workers.dev', 'pages.dev',
  'akamai.net', 'akamaized.net', 'akamaihd.net', 'fastly.net', 'jsdelivr.net', 'unpkg.com', 'cdnjs.com',
  'mozilla.org', 'wikipedia.org', 'readthedocs.io', 'stackoverflow.com', 'medium.com', 'reddit.com', 'twitter.com', 'x.com', 't.co', 'facebook.com', 'linkedin.com', 'telegram.org', 't.me', 'discord.com', 'discord.gg', 'dropbox.com', 'mediafire.com', 'mega.nz', 'pastebin.com', 'bit.ly',
  'abuse.ch', 'virustotal.com', 'mitre.org', 'cve.org', 'nist.gov', 'cisa.gov',
]);
// Hosts where attacker content is common but the domain itself is shared;
// URL IOCs allowed (flagged), domain IOCs rejected.
const SHARED_HOSTING = new Set(['githubusercontent.com', 'github.com', 'gitlab.com', 'bitbucket.org', 'amazonaws.com', 'cloudfront.net', 'googleapis.com', 'googleusercontent.com', 'workers.dev', 'pages.dev', 'azureedge.net', 'windows.net', 'dropbox.com', 'mediafire.com', 'mega.nz', 'pastebin.com', 'discord.com', 'discord.gg', 'telegram.org', 't.me', 'blogspot.com', 'github.io', 'docker.io', 'sourceforge.net', 'jsdelivr.net', 'unpkg.com']);
const RESERVED_TLDS = new Set(['example', 'test', 'invalid', 'localhost', 'local', 'internal', 'lan', 'home', 'corp', 'onion']);
const EXAMPLE_DOMAINS = new Set(['example.com', 'example.net', 'example.org']);
// Two-label public suffixes common in IOC data; enough to compute the
// registrable domain for the protection check without a full PSL dependency.
const TWO_LABEL_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'org.in', 'net.in', 'gov.in', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.cn', 'com.tr', 'co.kr', 'com.mx', 'co.za', 'com.sg', 'com.hk', 'com.tw', 'com.ru', 'com.ua']);

function registrableDomain(host) {
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const last2 = labels.slice(-2).join('.');
  return TWO_LABEL_SUFFIXES.has(last2) ? labels.slice(-3).join('.') : last2;
}

const PLACEHOLDER_HEX = ['0123456789', '1234567890', 'abcdef0123', 'abcdef1234', '9876543210', 'deadbeefdeadbeef', 'cafebabecafebabe'];

const CVE_RE = /^cve-\d{4}-\d{4,}$/i;
const VERSION_RE = /^v?\d+(?:\.\d+){1,3}(?:[-+][0-9a-z.]+)?$/i;

function checkDomain(raw) {
  const host = String(raw).trim().toLowerCase().replace(/\.$/, '');
  if (!host || host.length > 253) return { ok: false, reason: 'domain_syntax' };
  if (CVE_RE.test(host)) return { ok: false, reason: 'cve_identifier' };
  if (parseIPv4(host) || expandIPv6(host)) return { ok: false, reason: 'domain_is_ip' };
  if (VERSION_RE.test(host)) return { ok: false, reason: 'version_string' };
  const labels = host.split('.');
  if (labels.length < 2 || labels.some(l => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l) && !/^xn--[a-z0-9-]{1,59}$/.test(l))) return { ok: false, reason: 'domain_syntax' };
  const tld = labels[labels.length - 1];
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return { ok: false, reason: 'domain_syntax' };
  if (RESERVED_TLDS.has(tld)) return { ok: false, reason: 'reserved_tld' };
  const reg = registrableDomain(host);
  if (EXAMPLE_DOMAINS.has(reg)) return { ok: false, reason: 'example_domain' };
  return { ok: true, host, registrable: reg, protected: PROTECTED_DOMAINS.has(reg), shared_hosting: SHARED_HOSTING.has(reg) };
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * Validate and normalize one indicator. Returns
 *   { ok: true, type, value, display_value, flags: {...} }  or
 *   { ok: false, reason }.
 * `type` is the source-declared type mapped to our vocabulary; values are
 * never re-typed by guessing.
 */
function validateIndicator(type, rawValue) {
  if (!TYPES.includes(type)) return { ok: false, reason: 'unsupported_type' };
  const value = String(rawValue == null ? '' : rawValue).trim();
  if (!value || value.length > 2048 || /[\u0000-\u001f\u007f\s]/.test(value)) return { ok: false, reason: 'value_syntax' };

  if (type === 'ipv4') {
    const o = parseIPv4(value);
    if (!o) return { ok: false, reason: 'ipv4_syntax' };
    const reserved = ipv4Reserved(o);
    if (reserved) return { ok: false, reason: 'ipv4_' + reserved };
    const v = o.join('.');
    return { ok: true, type, value: v, display_value: defang(type, v), flags: {} };
  }
  if (type === 'ipv6') {
    const g = expandIPv6(value.toLowerCase());
    if (!g) return { ok: false, reason: 'ipv6_syntax' };
    const reserved = ipv6Reserved(g);
    if (reserved) return { ok: false, reason: 'ipv6_' + reserved };
    const v = ipv6Canonical(g);
    return { ok: true, type, value: v, display_value: defang(type, v), flags: {} };
  }
  if (type === 'domain') {
    const d = checkDomain(value);
    if (!d.ok) return d;
    if (d.protected) return { ok: false, reason: 'protected_domain' };
    return { ok: true, type, value: d.host, display_value: defang(type, d.host), flags: {} };
  }
  if (type === 'url') {
    let u;
    try { u = new URL(value); } catch (_) { return { ok: false, reason: 'url_syntax' }; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, reason: 'url_scheme' };
    if (u.username || u.password) return { ok: false, reason: 'url_credentials' };
    const host = u.hostname.replace(/^\[|\]$/g, '');
    let flags = {};
    const o = parseIPv4(host);
    if (o) {
      const reserved = ipv4Reserved(o);
      if (reserved) return { ok: false, reason: 'url_host_ipv4_' + reserved };
    } else if (expandIPv6(host)) {
      const reserved = ipv6Reserved(expandIPv6(host));
      if (reserved) return { ok: false, reason: 'url_host_ipv6_' + reserved };
    } else {
      const d = checkDomain(host);
      if (!d.ok) return { ok: false, reason: 'url_host_' + d.reason };
      if (d.registrable === 'cyberdudebivash.in' || d.registrable === 'cyberdudebivash.com' || d.registrable === 'abuse.ch') return { ok: false, reason: 'url_host_self_or_source' };
      // A bare protected host with no path is a homepage, not a payload.
      if (d.protected && (u.pathname === '/' || u.pathname === '') && !u.search) return { ok: false, reason: 'url_protected_homepage' };
      if (d.protected || d.shared_hosting) flags = { shared_hosting: true };
    }
    const v = u.href;
    return { ok: true, type, value: v, display_value: defang(type, v), flags };
  }
  // Hashes: lowercase hex of the exact length. The caller is responsible for
  // only passing values from an explicit file/sample-hash field.
  const len = { sha256: 64, sha1: 40, md5: 32 }[type];
  const v = value.toLowerCase();
  if (!new RegExp('^[0-9a-f]{' + len + '}$').test(v)) return { ok: false, reason: type + '_syntax' };
  if (/^(.)\1+$/.test(v)) return { ok: false, reason: 'hash_degenerate' };
  // Placeholder/sample digests from documentation and test fixtures (e.g.
  // abcdef1234567890…). A 10-hex-digit ascending run occurs in a random
  // digest with probability < 1e-10, so this never drops a real sample.
  if (PLACEHOLDER_HEX.some(p => v.includes(p))) return { ok: false, reason: 'hash_placeholder' };
  return { ok: true, type, value: v, display_value: v, flags: {} };
}

function defang(type, value) {
  if (type === 'ipv4') return value.replace(/\./g, '[.]');
  if (type === 'ipv6') return value.replace(/:/g, '[:]');
  if (type === 'domain') return value.replace(/\.(?=[^.]+$)/, '[.]');
  if (type === 'url') return value.replace(/^http/i, 'hxxp').replace(/\.(?=[^./:]+(?::\d+)?(?:\/|$))/, '[.]');
  return value;
}

module.exports = { TYPES, validateIndicator, defang, registrableDomain, PROTECTED_DOMAINS, SHARED_HOSTING };
