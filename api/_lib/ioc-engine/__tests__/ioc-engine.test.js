'use strict';

// Evidence-only IOC engine: validation, adapters, persistence, confidence,
// aging, publication gate, STIX 2.1, refresh isolation and the required
// negative controls (values that must never become customer IOCs).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { validateIndicator, defang, registrableDomain } = require('../validate');
const { parseSource, SourceFormatError, splitCsvLine } = require('../adapters');
const store = require('../store');
const { patternFor, toStixIndicator, buildStixBundle, escapeStixString } = require('../stix');
const { queryFeed, QueryError, projectGraph, runtimeFeedStatus } = require('../feed');
const { refresh, fetchSource, assertSourceUrl } = require('../../../../scripts/refresh-ioc-intelligence');

const CONFIG = require('../../../../config/ioc-sources.json');
const SRC = Object.fromEntries(CONFIG.sources.map(s => [s.id, s]));
const NOW = '2026-10-01T06:00:00.000Z';

// The mandated negative controls, with the reason each must be refused.
const NEGATIVE_CONTROLS = [
  ['domain', 'github.com', 'protected_domain'],
  ['domain', 'microsoft.com', 'protected_domain'],
  ['ipv4', '169.254.169.254', 'ipv4_link_local'],
  ['ipv4', '127.0.0.1', 'ipv4_loopback'],
  ['domain', 'localhost', 'domain_syntax'],
  ['domain', 'CVE-2026-12345', 'cve_identifier'],
  ['sha1', 'abcdef1234567890abcdef1234567890abcdef12', 'hash_placeholder'],
];
const NEGATIVE_VALUES = NEGATIVE_CONTROLS.map(([, v]) => v.toLowerCase());

// ── Fixture exports in the exact shapes of the live abuse.ch exports ──────
function threatfoxExport(extra = {}) {
  const rec = (value, type, conf, malware, first = '2026-09-28 10:00:00', last = '2026-09-30 20:00:00') =>
    [{ ioc_value: value, ioc_type: type, threat_type: 'botnet_cc', malware: 'win.x', malware_printable: malware, first_seen_utc: first, last_seen_utc: last, confidence_level: conf, reference: null, tags: 'c2,CVE-2026-0001', reporter: 'r' }];
  return JSON.stringify({
    1001: rec('45.9.148.10:443', 'ip:port', 100, 'Cobalt Strike'),
    1002: rec('evil-c2-panel.top', 'domain', 75, 'Vidar'),
    1003: rec('http://45.9.148.11/gate.php', 'url', 90, 'Lumma'),
    1004: rec('5d41402abc4b2a76b9719d911017c592', 'md5_hash', 100, 'AsyncRAT'),
    1005: rec('7c4a8d09ca3762af61e59520943dc26494f8941b', 'sha1_hash', 100, null), // no malware context
    1006: rec('weak-signal.top', 'domain', 50, 'Unknown'),                      // below source confidence
    // Negative controls delivered *by the source itself*:
    2001: rec('github.com', 'domain', 100, 'X'),
    2002: rec('microsoft.com', 'domain', 100, 'X'),
    2003: rec('169.254.169.254:80', 'ip:port', 100, 'X'),
    2004: rec('127.0.0.1:443', 'ip:port', 100, 'X'),
    2005: rec('localhost', 'domain', 100, 'X'),
    2006: rec('CVE-2026-12345', 'domain', 100, 'X'),
    2007: rec('abcdef1234567890abcdef1234567890abcdef12', 'sha1_hash', 100, 'X'),
    ...extra,
  });
}
function urlhausExport() {
  const rec = (url, status, added = '2026-09-29 08:00:00 UTC', last = '2026-09-30 22:00:00 UTC') =>
    [{ dateadded: added, url, url_status: status, last_online: last, threat: 'malware_download', tags: ['elf', 'mirai'], urlhaus_link: 'x', reporter: 'r' }];
  return JSON.stringify({
    501: rec('http://45.9.148.12/bins/x86', 'online'),
    502: rec('http://45.9.148.13/old', 'offline'),
    503: rec('http://169.254.169.254/latest/meta-data/', 'online'),
    504: rec('https://github.com/', 'online'),
    505: rec('https://raw.githubusercontent.com/a/b/main/payload.exe', 'online'),
    506: rec('http://45.9.148.11/gate.php', 'online'), // same URL as ThreatFox 1003 => corroboration
  });
}
function feodoExport() {
  return JSON.stringify([
    { ip_address: '45.9.148.10', port: 443, status: 'online', first_seen: '2026-09-01 00:00:00', last_online: '2026-09-30', malware: 'QakBot' },
    { ip_address: '10.0.0.5', port: 443, status: 'online', first_seen: '2026-09-01 00:00:00', last_online: '2026-09-30', malware: 'QakBot' },
  ]);
}
function bazaarExport() {
  return [
    '################################################################',
    '# MalwareBazaar recent malware samples (CSV)                   #',
    '# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"',
    '"2026-09-30 18:00:00", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "a", "b", "r", "f", "exe", "m", "AgentTesla", "n/a", "n/a", "n/a", "n/a", "n/a"',
    '"2026-09-30 17:00:00", "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9", "a", "b", "r", "f", "exe", "m", "n/a", "n/a", "n/a", "n/a", "n/a", "n/a"',
    '"2026-09-30 16:00:00", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "a", "b", "r", "f", "exe", "m", "Fake", "n/a", "n/a", "n/a", "n/a", "n/a"',
  ].join('\n');
}
const EXPORTS = { threatfox: threatfoxExport, urlhaus: urlhausExport, feodotracker: feodoExport, malwarebazaar: bazaarExport };

function allCandidates() {
  return CONFIG.sources.flatMap(s => parseSource(s, EXPORTS[s.id]()).candidates);
}
function buildStoreAndFeed(now = NOW, runs) {
  const st = store.emptyStore();
  store.mergeCandidates(st, allCandidates(), CONFIG.sources, now);
  st.last_success_at = now;
  store.refreshDerived(st, CONFIG.sources, now, []);
  const okRuns = runs || Object.fromEntries(CONFIG.sources.map(s => [s.id, { state: 'ok', checked_at: now }]));
  return { st, feed: store.buildFeed(st, CONFIG, okRuns, now) };
}

describe('validateIndicator — negative controls (must never become customer IOCs)', () => {
  test.each(NEGATIVE_CONTROLS)('%s %s is rejected (%s)', (type, value, reason) => {
    const r = validateIndicator(type, value);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe(reason);
  });

  test('negative controls are also refused under every other type a source could declare', () => {
    for (const [, value] of NEGATIVE_CONTROLS) {
      for (const t of ['ipv4', 'ipv6', 'domain', 'sha256', 'md5']) {
        expect(validateIndicator(t, value).ok).toBe(false);
      }
    }
    expect(validateIndicator('url', 'http://169.254.169.254/latest/meta-data/').ok).toBe(false);
    expect(validateIndicator('url', 'http://127.0.0.1/x').ok).toBe(false);
    expect(validateIndicator('url', 'http://localhost/x').ok).toBe(false);
    expect(validateIndicator('url', 'https://github.com/').ok).toBe(false);
    expect(validateIndicator('url', 'https://www.microsoft.com/').ok).toBe(false);
  });
});

describe('validateIndicator — strict syntax and safety rules', () => {
  test.each([
    ['0.1.2.3', 'ipv4_unspecified'], ['10.1.2.3', 'ipv4_private'], ['100.64.0.1', 'ipv4_cgnat'],
    ['172.16.5.4', 'ipv4_private'], ['192.168.1.1', 'ipv4_private'], ['192.0.2.10', 'ipv4_documentation'],
    ['198.51.100.7', 'ipv4_documentation'], ['203.0.113.9', 'ipv4_documentation'], ['198.18.0.1', 'ipv4_benchmarking'],
    ['224.0.0.1', 'ipv4_multicast'], ['255.255.255.255', 'ipv4_reserved'],
  ])('reserved IPv4 %s -> %s', (ip, reason) => {
    expect(validateIndicator('ipv4', ip)).toEqual({ ok: false, reason });
  });

  test('IPv4 syntax: leading zeros, out-of-range octets and partial addresses are refused', () => {
    for (const v of ['045.9.148.10', '256.1.1.1', '1.2.3', '1.2.3.4.5', '1.2.3. 4', 'a.b.c.d']) {
      expect(validateIndicator('ipv4', v).ok).toBe(false);
    }
    expect(validateIndicator('ipv4', '45.9.148.10')).toMatchObject({ ok: true, value: '45.9.148.10', display_value: '45[.]9[.]148[.]10' });
  });

  test('IPv6: reserved space refused, public address normalized', () => {
    for (const v of ['::', '::1', 'fe80::1', 'fd00::1', 'ff02::1', '2001:db8::1', '::ffff:1.2.3.4', '1:2:3']) {
      expect(validateIndicator('ipv6', v).ok).toBe(false);
    }
    expect(validateIndicator('ipv6', '2a01:4F8::1')).toMatchObject({ ok: true, value: '2a01:4f8:0:0:0:0:0:1' });
  });

  test('domains: subdomains of protected registrable domains are refused; lookalikes are not', () => {
    expect(validateIndicator('domain', 'learn.microsoft.com').reason).toBe('protected_domain');
    expect(validateIndicator('domain', 'raw.githubusercontent.com').reason).toBe('protected_domain');
    expect(validateIndicator('domain', 'nvd.nist.gov').reason).toBe('protected_domain');
    expect(validateIndicator('domain', 'blog.cyberdudebivash.in').reason).toBe('protected_domain');
    expect(validateIndicator('domain', 'microsoftupdateassist.net')).toMatchObject({ ok: true, display_value: 'microsoftupdateassist[.]net' });
    expect(validateIndicator('domain', 'foo.example.com').reason).toBe('example_domain');
    expect(validateIndicator('domain', 'host.internal').reason).toBe('reserved_tld');
    expect(validateIndicator('domain', '1.2.3.4').reason).toBe('domain_is_ip');
    expect(validateIndicator('domain', 'v1.2.3').reason).toBe('version_string');
    expect(registrableDomain('a.b.example.co.uk')).toBe('example.co.uk');
  });

  test('URLs: scheme, credentials, own/source hosts and shared hosting', () => {
    expect(validateIndicator('url', 'ftp://45.9.148.10/x').reason).toBe('url_scheme');
    expect(validateIndicator('url', 'http://user:pw@45.9.148.10/x').reason).toBe('url_credentials');
    expect(validateIndicator('url', 'https://blog.cyberdudebivash.in/x').reason).toBe('url_host_self_or_source');
    expect(validateIndicator('url', 'https://urlhaus.abuse.ch/url/1/').reason).toBe('url_host_self_or_source');
    const shared = validateIndicator('url', 'https://raw.githubusercontent.com/a/b/main/p.exe');
    expect(shared).toMatchObject({ ok: true, flags: { shared_hosting: true } });
    expect(shared.display_value).toBe('hxxps://raw.githubusercontent[.]com/a/b/main/p.exe');
    expect(validateIndicator('url', 'http://45.9.148.11/gate.php').display_value).toBe('hxxp://45.9.148[.]11/gate.php');
  });

  test('hashes: exact length lowercase hex; degenerate and placeholder digests refused', () => {
    expect(validateIndicator('sha256', 'A'.repeat(64)).reason).toBe('hash_degenerate');
    expect(validateIndicator('md5', '5d41402abc4b2a76b9719d911017c59').reason).toBe('md5_syntax');
    expect(validateIndicator('sha256', '0123456789abcdef'.repeat(4)).reason).toBe('hash_placeholder');
    expect(validateIndicator('md5', '5D41402ABC4B2A76B9719D911017C592')).toMatchObject({ ok: true, value: '5d41402abc4b2a76b9719d911017c592' });
  });

  test('control characters, whitespace and unsupported types are refused', () => {
    expect(validateIndicator('domain', 'evil\u0000.top').reason).toBe('value_syntax');
    expect(validateIndicator('domain', 'evil .top').reason).toBe('value_syntax');
    expect(validateIndicator('email', 'a@b.top').reason).toBe('unsupported_type');
    expect(defang('sha256', 'ab')).toBe('ab');
  });
});

describe('adapters — structured fields only, provenance on every candidate', () => {
  test('ThreatFox: ip:port mapped to ipv4 + port context; low confidence and context-less hashes skipped; negative controls rejected', () => {
    const { candidates, tally } = parseSource(SRC.threatfox, threatfoxExport());
    const values = candidates.map(c => c.value);
    expect(values).toEqual(expect.arrayContaining(['45.9.148.10', 'evil-c2-panel.top', 'http://45.9.148.11/gate.php', '5d41402abc4b2a76b9719d911017c592']));
    for (const v of NEGATIVE_VALUES) expect(values).not.toContain(v);
    expect(values).not.toContain('weak-signal.top');
    expect(values).not.toContain('7c4a8d09ca3762af61e59520943dc26494f8941b');
    expect(tally.skipped.below_source_confidence).toBe(1);
    expect(tally.skipped.hash_without_context).toBe(1);
    expect(tally.rejected).toMatchObject({ protected_domain: 2, ipv4_link_local: 1, ipv4_loopback: 1, domain_syntax: 1, cve_identifier: 1, hash_placeholder: 1 });
    const ip = candidates.find(c => c.value === '45.9.148.10');
    expect(ip.type).toBe('ipv4');
    expect(ip.context.port).toBe(443);
    expect(ip.observation).toMatchObject({ source: 'threatfox', source_record_id: '1001', source_url: 'https://threatfox.abuse.ch/ioc/1001/', source_confidence: 100, first_seen: '2026-09-28T10:00:00.000Z', last_seen: '2026-09-30T20:00:00.000Z' });
    expect(ip.related_cves).toEqual(['CVE-2026-0001']); // source-supplied tag, not text extraction
  });

  test('URLhaus: online only; metadata/homepage URLs refused; shared hosting flagged', () => {
    const { candidates, tally } = parseSource(SRC.urlhaus, urlhausExport());
    const values = candidates.map(c => c.value);
    expect(values).toContain('http://45.9.148.12/bins/x86');
    expect(values).not.toContain('http://45.9.148.13/old');
    expect(values).not.toContain('http://169.254.169.254/latest/meta-data/');
    expect(values).not.toContain('https://github.com/');
    expect(tally.skipped.not_online).toBe(1);
    expect(candidates.find(c => c.value.includes('githubusercontent')).flags).toEqual({ shared_hosting: true });
  });

  test('Feodo: private address refused; MalwareBazaar: unsigned and placeholder hashes refused', () => {
    expect(parseSource(SRC.feodotracker, feodoExport()).candidates.map(c => c.value)).toEqual(['45.9.148.10']);
    const bz = parseSource(SRC.malwarebazaar, bazaarExport());
    expect(bz.candidates.map(c => c.value)).toEqual(['2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae']);
    expect(bz.tally.skipped.hash_without_context).toBe(1);
    expect(bz.tally.rejected.hash_placeholder).toBe(1);
    expect(bz.candidates[0].observation.source_url).toBe('https://bazaar.abuse.ch/sample/2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae/');
  });

  test('malformed exports throw (source marked failed), malformed records are skipped', () => {
    expect(() => parseSource(SRC.threatfox, '<html>error</html>')).toThrow(SourceFormatError);
    expect(() => parseSource(SRC.threatfox, '[]')).toThrow(SourceFormatError);
    expect(() => parseSource(SRC.feodotracker, '{}')).toThrow(SourceFormatError);
    expect(() => parseSource(SRC.malwarebazaar, 'a,b,c\n1,2,3')).toThrow(SourceFormatError);
    const r = parseSource(SRC.threatfox, JSON.stringify({ abc: [{}], 7: 'x', 8: [null] }));
    expect(r.candidates).toEqual([]);
    expect(r.tally.skipped.malformed_record).toBe(3);
    expect(splitCsvLine('"a, b", "c""d"')).toEqual(['a, b', 'c"d']);
  });

  test('per-source cap is deterministic (newest first, then value)', () => {
    const capped = { ...SRC.threatfox, per_source_cap: 2 };
    const a = parseSource(capped, threatfoxExport()).candidates.map(c => c.value);
    const b = parseSource(capped, threatfoxExport()).candidates.map(c => c.value);
    expect(a).toEqual(b);
    expect(a).toHaveLength(2);
  });
});

describe('store — persistence, multi-source dedupe, confidence, aging, revocation', () => {
  test('the same value from two sources is one indicator with both observations and corroborated confidence', () => {
    const { st } = buildStoreAndFeed();
    const url = st.indicators['url|http://45.9.148.11/gate.php'];
    expect(url.observations.map(o => o.source).sort()).toEqual(['threatfox', 'urlhaus']);
    expect(url.sources).toEqual(['threatfox', 'urlhaus']);
    expect(url.confidence).toBe('VERY_HIGH');
    expect(url.confidence_basis).toEqual(['source_assertion:HIGH', 'corroborated_by_2_sources']);
    const ip = st.indicators['ipv4|45.9.148.10'];
    expect(ip.sources).toEqual(['feodotracker', 'threatfox']);
  });

  test('confidence is deterministic and follows the documented model', () => {
    expect(store.scoreConfidence([{ source: 'threatfox', source_confidence: 75 }], 'ACTIVE').confidence).toBe('MEDIUM');
    expect(store.scoreConfidence([{ source: 'threatfox', source_confidence: 90 }], 'ACTIVE').confidence).toBe('HIGH');
    expect(store.scoreConfidence([{ source: 'threatfox', source_confidence: 90 }], 'STALE').confidence).toBe('MEDIUM');
    expect(store.scoreConfidence([{ source: 'unknown' }], 'ACTIVE').confidence).toBe('LOW');
    const { feed: a } = buildStoreAndFeed();
    const { feed: b } = buildStoreAndFeed();
    expect(a.items).toEqual(b.items);
  });

  test('type-specific aging: ACTIVE -> STALE -> EXPIRED from the source last_seen', () => {
    const t0 = Date.parse('2026-09-30T20:00:00Z');
    const at = days => new Date(t0 + days * 86400000);
    expect(store.lifecycle('ipv4', '2026-09-30T20:00:00Z', at(6)).status).toBe('ACTIVE');
    expect(store.lifecycle('ipv4', '2026-09-30T20:00:00Z', at(8)).status).toBe('STALE');
    expect(store.lifecycle('ipv4', '2026-09-30T20:00:00Z', at(31)).status).toBe('EXPIRED');
    expect(store.lifecycle('domain', '2026-09-30T20:00:00Z', at(31)).status).toBe('STALE');
    expect(store.lifecycle('sha256', '2026-09-30T20:00:00Z', at(200)).status).toBe('STALE');
    expect(store.lifecycle('url', 'not-a-date', at(0)).status).toBe('EXPIRED');
  });

  test('absence from later exports never deletes: indicators persist and age; expired are not published', () => {
    const { st } = buildStoreAndFeed();
    const later = '2026-10-15T00:00:00.000Z'; // no new candidates in this run
    store.refreshDerived(st, CONFIG.sources, later, []);
    expect(st.indicators['ipv4|45.9.148.10'].status).toBe('STALE');
    expect(st.indicators['domain|evil-c2-panel.top'].status).toBe('ACTIVE');
    const feed = store.buildFeed(st, CONFIG, {}, later);
    expect(feed.items.find(i => i.value === '45.9.148.10').status).toBe('STALE');
    const muchLater = '2026-11-20T00:00:00.000Z';
    store.refreshDerived(st, CONFIG.sources, muchLater, []);
    expect(st.indicators['ipv4|45.9.148.10'].status).toBe('EXPIRED');
    expect(store.buildFeed(st, CONFIG, {}, muchLater).items.find(i => i.value === '45.9.148.10')).toBeUndefined();
  });

  test('operator revocation and safety-filter revocation (a stored value that now fails validation)', () => {
    const { st } = buildStoreAndFeed();
    // Simulate a corrupted / legacy store entry carrying a negative-control value.
    st.indicators['ipv4|169.254.169.254'] = { ...st.indicators['ipv4|45.9.148.10'], value: '169.254.169.254', id: 'x', status: 'ACTIVE' };
    store.refreshDerived(st, CONFIG.sources, NOW, [{ type: 'domain', value: 'evil-c2-panel.top', reason: 'false_positive_reported' }]);
    expect(st.indicators['ipv4|169.254.169.254']).toMatchObject({ status: 'REVOKED', status_reason: 'safety_filter:ipv4_link_local' });
    expect(st.indicators['domain|evil-c2-panel.top']).toMatchObject({ status: 'REVOKED', status_reason: 'false_positive_reported' });
    const feed = store.buildFeed(st, CONFIG, {}, NOW);
    expect(feed.items.map(i => i.value)).not.toContain('169.254.169.254');
    expect(feed.items.map(i => i.value)).not.toContain('evil-c2-panel.top');
    expect(feed.revocations.map(r => r.value)).toEqual(expect.arrayContaining(['169.254.169.254', 'evil-c2-panel.top']));
  });

  test('observations from a source removed from the allowlist are dropped ("no source = no customer IOC")', () => {
    const { st } = buildStoreAndFeed();
    const reduced = CONFIG.sources.map(s => (s.id === 'malwarebazaar' ? { ...s, enabled: false } : s));
    store.refreshDerived(st, reduced, NOW, []);
    expect(Object.values(st.indicators).some(e => e.sources.includes('malwarebazaar'))).toBe(false);
  });

  test('feed: every item has provenance, valid lifecycle fields and recommended action; no negative control', () => {
    const { feed } = buildStoreAndFeed();
    expect(store.validateFeed(feed, CONFIG)).toEqual([]);
    expect(feed.items.length).toBeGreaterThan(0);
    for (const i of feed.items) {
      expect(i.observations.length).toBeGreaterThan(0);
      expect(i.source_url).toMatch(/^https:\/\/(threatfox|urlhaus|feodotracker|bazaar)\.abuse\.ch\//);
      expect(i.provenance_hash).toMatch(/^[0-9a-f]{64}$/);
      expect(['block', 'alert', 'hunt']).toContain(i.detection.recommended_action);
      expect(NEGATIVE_VALUES).not.toContain(i.value);
    }
    expect(feed.items.find(i => i.flags.shared_hosting).detection.recommended_action).toBe('alert');
    expect(feed.items.find(i => i.confidence === 'MEDIUM').detection.recommended_action).toBe('alert');
  });

  test('validateFeed refuses a hand-edited feed (negative control injected, provenance stripped, unknown source)', () => {
    const { feed } = buildStoreAndFeed();
    const bad = JSON.parse(JSON.stringify(feed));
    bad.items[0].value = '169.254.169.254';
    bad.items[1].observations = [];
    bad.items[2].observations[0].source = 'random-blog';
    const problems = store.validateFeed(bad, CONFIG);
    expect(problems.join('\n')).toMatch(/value fails validation/);
    expect(problems.join('\n')).toMatch(/no provenance/);
    expect(problems.join('\n')).toMatch(/not allowlisted/);
  });

  test('honest status: healthy with zero indicators, degraded on partial failure, unavailable when all fail and empty', () => {
    const empty = store.emptyStore();
    const ok = Object.fromEntries(CONFIG.sources.map(s => [s.id, { state: 'ok' }]));
    const f0 = store.buildFeed(empty, CONFIG, ok, NOW);
    expect(f0.feed_status).toMatchObject({ status: 'healthy', indicator_count: 0 });
    expect(f0.items).toEqual([]);
    expect(store.buildFeed(empty, CONFIG, { ...ok, urlhaus: { state: 'failed' } }, NOW).feed_status.status).toBe('degraded');
    expect(store.buildFeed(empty, CONFIG, {}, NOW).feed_status.status).toBe('unavailable');
  });

  test('public summary carries no indicator values', () => {
    const { feed } = buildStoreAndFeed();
    const summary = JSON.stringify(store.buildPublicSummary(feed));
    for (const i of feed.items) expect(summary).not.toContain(i.value);
    expect(store.buildPublicSummary(feed).items).toEqual([]);
  });
});

describe('STIX 2.1', () => {
  const STIX_PATTERN = /^\[(ipv4-addr|ipv6-addr|domain-name|url):value = '(?:[^'\\]|\\['\\])*'\]$|^\[file:hashes\.('SHA-256'|'SHA-1'|MD5) = '[0-9a-f]+'\]$/;

  test('object-path patterns per type; hashes use file:hashes, never file:value or artifact', () => {
    expect(patternFor('ipv4', '45.9.148.10')).toBe("[ipv4-addr:value = '45.9.148.10']");
    expect(patternFor('domain', 'a.top')).toBe("[domain-name:value = 'a.top']");
    expect(patternFor('sha256', 'ab')).toBe("[file:hashes.'SHA-256' = 'ab']");
    expect(patternFor('sha1', 'ab')).toBe("[file:hashes.'SHA-1' = 'ab']");
    expect(patternFor('md5', 'ab')).toBe("[file:hashes.MD5 = 'ab']");
    expect(patternFor('email', 'x')).toBeNull();
  });

  test('string values are escaped (quote/backslash injection cannot break the pattern)', () => {
    expect(escapeStixString("a'b\\c")).toBe("a\\'b\\\\c");
    expect(patternFor('url', "http://x.top/a'] OR [x:y = 'z")).toBe("[url:value = 'http://x.top/a\\'] OR [x:y = \\'z']");
  });

  test('bundle: deterministic indicator ids, spec fields, valid_until > valid_from, provenance references', () => {
    const { feed } = buildStoreAndFeed();
    const b1 = buildStixBundle(feed.items, 'bundle--00000000-0000-4000-8000-000000000000');
    const b2 = buildStixBundle(feed.items, 'bundle--00000000-0000-4000-8000-000000000001');
    expect(b1.type).toBe('bundle');
    expect(b1).not.toHaveProperty('spec_version'); // not a STIX 2.1 bundle property
    const inds = b1.objects.filter(o => o.type === 'indicator');
    expect(inds).toHaveLength(feed.items.length);
    expect(inds.map(o => o.id)).toEqual(b2.objects.filter(o => o.type === 'indicator').map(o => o.id));
    for (const o of inds) {
      expect(o.id).toMatch(/^indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      expect(o.spec_version).toBe('2.1');
      expect(o.pattern).toMatch(STIX_PATTERN);
      expect(o.pattern_type).toBe('stix');
      expect(o.valid_until > o.valid_from).toBe(true);
      expect(o.modified >= o.created).toBe(true);
      expect(o.confidence).toBeGreaterThanOrEqual(0);
      expect(o.confidence).toBeLessThanOrEqual(100);
      expect(o.external_references[0].url).toMatch(/^https:\/\/[a-z]+\.abuse\.ch\//);
      expect(o.created_by_ref).toBe(b1.objects[0].id);
    }
  });

  test('an indicator without a stable id or valid time is dropped, not emitted invalid', () => {
    expect(toStixIndicator({ type: 'ipv4', value: '45.9.148.10', first_seen: 'x', stix_id: 'indicator--a' })).toBeNull();
    expect(toStixIndicator({ type: 'ipv4', value: '45.9.148.10', first_seen: NOW, stix_id: '' })).toBeNull();
  });
});

describe('feed query (API filters)', () => {
  const { feed } = buildStoreAndFeed();
  test('filters: type, confidence floor, source, malware, cve, status, since; deterministic order', () => {
    expect(queryFeed(feed.items, { type: 'URL' }).items.every(i => i.type === 'url')).toBe(true);
    expect(queryFeed(feed.items, { confidence: 'very_high' }).items.map(i => i.value)).toEqual(['http://45.9.148.11/gate.php', '45.9.148.10']);
    expect(queryFeed(feed.items, { source: 'malwarebazaar' }).total).toBe(1);
    expect(queryFeed(feed.items, { malware: 'cobalt' }).items[0].value).toBe('45.9.148.10');
    expect(queryFeed(feed.items, { cve: 'cve-2026-0001' }).total).toBeGreaterThan(0);
    expect(queryFeed(feed.items, { status: 'stale' }).total).toBe(0);
    expect(queryFeed(feed.items, { since: '2026-10-02' }).total).toBe(0);
    expect(queryFeed(feed.items, { min_confidence: '0.9' }).items.every(i => i.confidence_score >= 90)).toBe(true);
    expect(queryFeed(feed.items, {}).items.map(i => i.id)).toEqual(feed.items.map(i => i.id).slice(0, 50));
  });

  test('pagination is capped and invalid parameters are rejected', () => {
    expect(queryFeed(feed.items, { limit: '100000' }).limit).toBe(200);
    expect(queryFeed(feed.items, { limit: 'x', page: '-3' })).toMatchObject({ limit: 50, page: 1 });
    expect(() => queryFeed(feed.items, { type: 'email' })).toThrow(QueryError);
    expect(() => queryFeed(feed.items, { confidence: 'ULTRA' })).toThrow(QueryError);
    expect(() => queryFeed(feed.items, { since: 'yesterday' })).toThrow(QueryError);
    expect(() => queryFeed(feed.items, { malware: 'x'.repeat(101) })).toThrow(QueryError);
    expect(() => queryFeed(feed.items, { status: 'expired' })).toThrow(QueryError);
  });

  test('runtime status reports freshness of the published file', () => {
    expect(runtimeFeedStatus(feed, Date.parse(NOW) + 3600000).freshness).toBe('fresh');
    expect(runtimeFeedStatus(feed, Date.parse(NOW) + 7 * 3600000).freshness).toBe('stale');
    expect(runtimeFeedStatus({ items: [] }).status).toBe('unavailable');
  });
});

describe('graph projection — pseudo-IOC cleanup by provenance', () => {
  test('IOC nodes without provenance (and their edges) are removed; evidence-backed nodes added; input untouched', () => {
    const { feed } = buildStoreAndFeed();
    const graph = {
      nodes: {
        'CVE-2026-1': { id: 'CVE-2026-1', type: 'CVE', name: 'CVE-2026-1' },
        'ioc:ipv4:169.254.169.254': { id: 'ioc:ipv4:169.254.169.254', type: 'IOC', name: '169.254.169.254', attributes: { ioc_type: 'ipv4' } },
        'ioc:domain:github.com': { id: 'ioc:domain:github.com', type: 'IOC', name: 'github.com', attributes: { ioc_type: 'domain' } },
      },
      edges: [{ source: 'CVE-2026-1', target: 'ioc:ipv4:169.254.169.254', type: 'linked_to' }],
      stats: { total_nodes: 3, iocs: 2, edges: 1 },
    };
    const snapshot = JSON.stringify(graph);
    const p = projectGraph(graph, feed);
    const names = Object.values(p.nodes).filter(n => n.type === 'IOC').map(n => n.name);
    expect(names).not.toContain('169.254.169.254');
    expect(names).not.toContain('github.com');
    expect(names).toHaveLength(feed.items.length);
    expect(p.edges).toEqual([]);
    expect(p.stats).toMatchObject({ iocs: feed.items.length, edges: 0 });
    expect(Object.values(p.nodes).filter(n => n.type === 'IOC').every(n => n.attributes.provenance.source_url)).toBe(true);
    expect(JSON.stringify(graph)).toBe(snapshot);
    expect(projectGraph(graph, { items: [] }).nodes['CVE-2026-1']).toBeDefined();
  });
});

describe('refresh — isolation, last-known-good, atomic publish, SSRF/size guards', () => {
  let dir;
  let paths;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ioc-refresh-'));
    paths = { config: path.join(dir, 'ioc-sources.json'), store: path.join(dir, 'store.json'), feed: path.join(dir, 'feed.json'), summary: path.join(dir, 'iocs.json') };
    fs.writeFileSync(paths.config, JSON.stringify(CONFIG));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const okFetcher = async s => ({ text: EXPORTS[s.id](), status: 200, etag: `"${s.id}"`, bytes: 1 });

  test('run 1 publishes; run 2 with every source down keeps the last-known-good indicators (degraded)', async () => {
    const r1 = await refresh({ now: NOW, fetcher: okFetcher, paths });
    expect(r1.published).toBe(true);
    expect(r1.feed_status.status).toBe('healthy');
    const n1 = JSON.parse(fs.readFileSync(paths.feed, 'utf8')).items.length;
    const r2 = await refresh({ now: '2026-10-01T07:00:00.000Z', fetcher: async () => { throw new Error('timeout'); }, paths });
    expect(r2.published).toBe(true);
    expect(r2.feed_status.status).toBe('degraded');
    expect(r2.telemetry.urlhaus).toMatchObject({ state: 'failed', error: 'timeout' });
    const feed2 = JSON.parse(fs.readFileSync(paths.feed, 'utf8'));
    expect(feed2.items.length).toBe(n1);
    expect(fs.readdirSync(dir).filter(f => f.includes('.tmp-'))).toEqual([]);
  });

  test('one malformed source fails alone; the others are ingested', async () => {
    const fetcher = async s => (s.id === 'threatfox' ? { text: '<html>', status: 200 } : okFetcher(s));
    const r = await refresh({ now: NOW, fetcher, paths });
    expect(r.telemetry.threatfox).toMatchObject({ state: 'failed', error: 'invalid_json' });
    expect(r.telemetry.urlhaus.state).toBe('ok');
    expect(r.feed_status.status).toBe('degraded');
    expect(r.published).toBe(true);
  });

  test('conditional GET: stored validators are sent and 304 is not_modified', async () => {
    await refresh({ now: NOW, fetcher: okFetcher, paths });
    const seen = {};
    const r = await refresh({ now: NOW, fetcher: async (s, cache) => { seen[s.id] = cache; return { notModified: true, status: 304 }; }, paths });
    expect(seen.threatfox).toEqual({ etag: '"threatfox"', last_modified: null });
    expect(r.feed_status.status).toBe('healthy');
  });

  test('a feed that fails validation is not written (previous files remain)', async () => {
    await refresh({ now: NOW, fetcher: okFetcher, paths });
    const before = fs.readFileSync(paths.feed, 'utf8');
    const cfg = { ...CONFIG, feed_cap: -1 }; // forces "feed exceeds cap"
    fs.writeFileSync(paths.config, JSON.stringify(cfg));
    const r = await refresh({ now: '2026-10-01T08:00:00.000Z', fetcher: okFetcher, paths });
    expect(r.published).toBe(false);
    expect(fs.readFileSync(paths.feed, 'utf8')).toBe(before);
  });

  test('SSRF guard: only https abuse.ch hosts from config', () => {
    expect(() => assertSourceUrl('http://threatfox.abuse.ch/export/json/recent/')).toThrow('source_url_not_allowed');
    expect(() => assertSourceUrl('https://169.254.169.254/latest/meta-data/')).toThrow('source_url_not_allowed');
    expect(() => assertSourceUrl('https://abuse.ch.evil.top/x')).toThrow('source_url_not_allowed');
    expect(() => assertSourceUrl('https://u:p@urlhaus.abuse.ch/x')).toThrow('source_url_not_allowed');
    expect(() => assertSourceUrl('https://urlhaus.abuse.ch:8443/x')).toThrow('source_url_not_allowed');
    expect(assertSourceUrl('https://urlhaus.abuse.ch/downloads/json_recent/').hostname).toBe('urlhaus.abuse.ch');
  });

  test('oversized responses are aborted; redirects are refused', async () => {
    const realFetch = global.fetch;
    try {
      let opts;
      global.fetch = async (url, o) => { opts = o; return new Response('x'.repeat(2048), { status: 200 }); };
      await expect(fetchSource({ ...SRC.feodotracker, max_bytes: 1024 }, null)).rejects.toThrow('response_too_large');
      expect(opts.redirect).toBe('error');
      global.fetch = async () => new Response('[]', { status: 200, headers: { 'content-length': '999999999' } });
      await expect(fetchSource(SRC.feodotracker, null)).rejects.toThrow('response_too_large');
      global.fetch = async () => new Response('no', { status: 401 });
      await expect(fetchSource(SRC.feodotracker, null)).rejects.toThrow('http_401');
    } finally {
      global.fetch = realFetch;
    }
  });
});

describe('committed production feed (data/ioc-feed.json)', () => {
  const feed = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../../data/ioc-feed.json'), 'utf8'));
  test('passes the publication gate and contains no negative control', () => {
    expect(store.validateFeed(feed, CONFIG)).toEqual([]);
    const values = feed.items.map(i => i.value.toLowerCase());
    for (const v of NEGATIVE_VALUES) expect(values).not.toContain(v);
  });
  test('public summary file carries no indicator values', () => {
    const pub = fs.readFileSync(path.join(__dirname, '../../../intel/iocs.json'), 'utf8');
    for (const i of feed.items.slice(0, 50)) expect(pub).not.toContain(i.value);
    expect(JSON.parse(pub).items).toEqual([]);
  });
});
