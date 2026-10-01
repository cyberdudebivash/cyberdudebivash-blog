'use strict';

/**
 * Source adapters: parse one allowlisted export (already fetched, bounded
 * text) into candidate observations with full provenance.
 *
 * Contract (docs/architecture/IOC-INTELLIGENCE-PIPELINE.md):
 * - Only the source's explicit indicator field is read. The type comes from
 *   the source's own type field or from the field it is published in (a
 *   MalwareBazaar `sha256_hash` column is a SHA-256); nothing is guessed from
 *   free text.
 * - Every candidate carries source, source record id, record URL and the
 *   source's own timestamps. No source record => no candidate.
 * - Every value passes validateIndicator(); rejections are counted by reason.
 * - A malformed export throws (the source is marked failed and the
 *   last-known-good store is kept); malformed individual records are counted
 *   and skipped.
 */

const { validateIndicator } = require('./validate');

const MAX_RECORDS = 50000;           // hard ceiling per export, regardless of size
const MAX_FIELD = 2048;
const CVE_TAG = /^CVE-\d{4}-\d{4,7}$/i;

class SourceFormatError extends Error {}

// abuse.ch timestamps are UTC without a zone ("2026-09-30 20:01:28" or
// "... UTC"); date-only values occur in Feodo `last_online`.
function toIso(value) {
  if (value == null || value === '') return null;
  const s = String(value).trim().replace(/\s*UTC$/i, '');
  const m = /^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2}))?$/.exec(s);
  if (!m) return null;
  const d = new Date(`${m[1]}T${m[2] || '00:00:00'}Z`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function str(value, max = 200) {
  if (value == null) return null;
  const s = String(value).trim();
  if (!s || s.toLowerCase() === 'n/a' || s.toLowerCase() === 'none') return null;
  return s.slice(0, max);
}

function tagList(value) {
  const arr = Array.isArray(value) ? value : String(value || '').split(',');
  return [...new Set(arr.map(t => str(t, 64)).filter(Boolean))].slice(0, 12);
}

function recordUrl(source, id) {
  return String(source.record_url_template || '').replace('{id}', encodeURIComponent(String(id)));
}

function makeTally() {
  return { records: 0, candidates: 0, rejected: {}, skipped: {} };
}
function bump(map, key) { map[key] = (map[key] || 0) + 1; }

function accept(out, tally, source, type, rawValue, obs) {
  if (String(rawValue == null ? '' : rawValue).length > MAX_FIELD) { bump(tally.rejected, 'value_too_long'); return; }
  const v = validateIndicator(type, rawValue);
  if (!v.ok) { bump(tally.rejected, v.reason); return; }
  tally.candidates++;
  out.push({
    type: v.type,
    value: v.value,
    display_value: v.display_value,
    flags: v.flags,
    observation: {
      source: source.id,
      source_record_id: String(obs.record_id),
      source_url: recordUrl(source, obs.record_id),
      source_published_at: obs.published_at,
      first_seen: obs.first_seen,
      last_seen: obs.last_seen || obs.first_seen,
      source_confidence: obs.source_confidence,
      source_status: obs.source_status || null,
    },
    context: obs.context,
    tags: obs.tags || [],
    related_cves: (obs.tags || []).filter(t => CVE_TAG.test(t)).map(t => t.toUpperCase()),
    related_malware: obs.malware ? [obs.malware] : [],
  });
}

function parseJson(text) {
  try { return JSON.parse(text); } catch (_) { throw new SourceFormatError('invalid_json'); }
}

// ── ThreatFox: { "<ioc_id>": [ { ioc_value, ioc_type, ... } ] } ────────────
const THREATFOX_TYPES = { domain: 'domain', url: 'url', sha256_hash: 'sha256', sha1_hash: 'sha1', md5_hash: 'md5' };

function parseThreatFox(text, source) {
  const data = parseJson(text);
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new SourceFormatError('unexpected_shape');
  const out = [];
  const tally = makeTally();
  const minConf = Number(source.min_source_confidence || 0);
  for (const [id, list] of Object.entries(data).slice(0, MAX_RECORDS)) {
    const r = Array.isArray(list) ? list[0] : null;
    tally.records++;
    if (!r || typeof r !== 'object' || !/^\d+$/.test(id)) { bump(tally.skipped, 'malformed_record'); continue; }
    const conf = Number(r.confidence_level);
    if (!Number.isFinite(conf) || conf < minConf) { bump(tally.skipped, 'below_source_confidence'); continue; }
    let type = THREATFOX_TYPES[r.ioc_type];
    let value = r.ioc_value;
    let port = null;
    if (r.ioc_type === 'ip:port') {
      const m = /^(.+):(\d{1,5})$/.exec(String(value || ''));
      if (!m) { bump(tally.rejected, 'ip_port_syntax'); continue; }
      value = m[1].replace(/^\[|\]$/g, '');
      port = Number(m[2]);
      type = value.includes(':') ? 'ipv6' : 'ipv4';
    }
    if (!type) { bump(tally.skipped, 'unsupported_source_type'); continue; }
    const malware = str(r.malware_printable, 100);
    // A hash is only an IOC with malware context (ICF: no context-less hashes).
    if (/^(sha256|sha1|md5)$/.test(type) && !malware) { bump(tally.skipped, 'hash_without_context'); continue; }
    const first = toIso(r.first_seen_utc);
    if (!first) { bump(tally.skipped, 'missing_timestamp'); continue; }
    accept(out, tally, source, type, value, {
      record_id: id,
      published_at: first,
      first_seen: first,
      last_seen: toIso(r.last_seen_utc) || first,
      source_confidence: conf,
      context: { threat_type: str(r.threat_type, 64), malware, malware_id: str(r.malware, 100), port, reporter: str(r.reporter, 64) },
      tags: tagList(r.tags),
      malware,
    });
  }
  return { candidates: out, tally };
}

// ── URLhaus: { "<url_id>": [ { url, url_status, dateadded, last_online, threat, tags } ] }
function parseUrlhaus(text, source) {
  const data = parseJson(text);
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new SourceFormatError('unexpected_shape');
  const out = [];
  const tally = makeTally();
  for (const [id, list] of Object.entries(data).slice(0, MAX_RECORDS)) {
    const r = Array.isArray(list) ? list[0] : null;
    tally.records++;
    if (!r || typeof r !== 'object' || !/^\d+$/.test(id)) { bump(tally.skipped, 'malformed_record'); continue; }
    const status = str(r.url_status, 16);
    if (source.online_only && status !== 'online') { bump(tally.skipped, 'not_online'); continue; }
    const added = toIso(r.dateadded);
    if (!added) { bump(tally.skipped, 'missing_timestamp'); continue; }
    const tags = tagList(r.tags);
    accept(out, tally, source, 'url', r.url, {
      record_id: id,
      published_at: added,
      first_seen: added,
      last_seen: toIso(r.last_online) || added,
      source_confidence: null,
      source_status: status,
      context: { threat_type: str(r.threat, 64), url_status: status, reporter: str(r.reporter, 64) },
      tags,
      malware: null,
    });
  }
  return { candidates: out, tally };
}

// ── Feodo Tracker: [ { ip_address, port, status, first_seen, last_online, malware } ]
function parseFeodo(text, source) {
  const data = parseJson(text);
  if (!Array.isArray(data)) throw new SourceFormatError('unexpected_shape');
  const out = [];
  const tally = makeTally();
  for (const r of data.slice(0, MAX_RECORDS)) {
    tally.records++;
    if (!r || typeof r !== 'object' || !r.ip_address) { bump(tally.skipped, 'malformed_record'); continue; }
    const first = toIso(r.first_seen);
    if (!first) { bump(tally.skipped, 'missing_timestamp'); continue; }
    const malware = str(r.malware, 100);
    const status = str(r.status, 16);
    accept(out, tally, source, String(r.ip_address).includes(':') ? 'ipv6' : 'ipv4', r.ip_address, {
      record_id: r.ip_address,
      published_at: first,
      first_seen: first,
      last_seen: toIso(r.last_online) || first,
      source_confidence: null,
      source_status: status,
      context: { threat_type: 'botnet_cc', malware, port: Number.isInteger(r.port) ? r.port : null, c2_status: status, asn: Number.isInteger(r.as_number) ? r.as_number : null, country: str(r.country, 2) },
      tags: [],
      malware,
    });
  }
  return { candidates: out, tally };
}

// ── MalwareBazaar recent CSV ────────────────────────────────────────────
// Quoted CSV with `# ` comment lines; the header is the last comment line.
function splitCsvLine(line) {
  const cells = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') quoted = false; else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { cells.push(cur.trim()); cur = ''; } else cur += c;
  }
  cells.push(cur.trim());
  return cells;
}

function parseBazaar(text, source) {
  const lines = String(text).split(/\r?\n/);
  const headerLine = lines.filter(l => l.startsWith('#') && l.includes('sha256_hash')).pop();
  if (!headerLine) throw new SourceFormatError('missing_header');
  const header = splitCsvLine(headerLine.replace(/^#\s*/, ''));
  const col = name => header.indexOf(name);
  for (const required of ['first_seen_utc', 'sha256_hash', 'signature']) {
    if (col(required) < 0) throw new SourceFormatError('missing_column_' + required);
  }
  const out = [];
  const tally = makeTally();
  for (const line of lines) {
    if (!line || line.startsWith('#')) continue;
    if (tally.records >= MAX_RECORDS) break;
    tally.records++;
    const cells = splitCsvLine(line);
    if (cells.length !== header.length) { bump(tally.skipped, 'malformed_record'); continue; }
    const get = name => cells[col(name)];
    const signature = str(get('signature'), 100);
    if (source.require_signature && !signature) { bump(tally.skipped, 'hash_without_context'); continue; }
    const first = toIso(get('first_seen_utc'));
    if (!first) { bump(tally.skipped, 'missing_timestamp'); continue; }
    const sha256 = get('sha256_hash');
    accept(out, tally, source, 'sha256', sha256, {
      record_id: sha256,
      published_at: first,
      first_seen: first,
      last_seen: first,
      source_confidence: null,
      context: { threat_type: 'payload', malware: signature, file_type: str(get('file_type_guess'), 32), reporter: str(get('reporter'), 64) },
      tags: [],
      malware: signature,
    });
  }
  return { candidates: out, tally };
}

const PARSERS = {
  threatfox_recent_json: parseThreatFox,
  urlhaus_recent_json: parseUrlhaus,
  feodo_ipblocklist_json: parseFeodo,
  malwarebazaar_recent_csv: parseBazaar,
};

/**
 * Parse one export. Throws SourceFormatError on an unparseable export.
 * Candidates are capped per source deterministically: newest last_seen
 * first, then value, so the same export always yields the same set.
 */
function parseSource(source, text) {
  const parser = PARSERS[source.format];
  if (!parser) throw new SourceFormatError('unsupported_format');
  const { candidates, tally } = parser(text, source);
  const sorted = candidates.sort((a, b) =>
    (b.observation.last_seen || '').localeCompare(a.observation.last_seen || '') ||
    a.type.localeCompare(b.type) || a.value.localeCompare(b.value));
  // One candidate per type:value per source (a source may list a value twice).
  const seen = new Set();
  const unique = [];
  for (const c of sorted) {
    const key = c.type + '|' + c.value;
    if (seen.has(key)) { bump(tally.skipped, 'duplicate_in_source'); continue; }
    seen.add(key);
    unique.push(c);
  }
  const cap = Number(source.per_source_cap) || 0;
  const kept = cap > 0 ? unique.slice(0, cap) : unique;
  tally.capped = unique.length - kept.length;
  tally.accepted = kept.length;
  return { candidates: kept, tally };
}

module.exports = { parseSource, SourceFormatError, PARSERS, toIso, splitCsvLine };
