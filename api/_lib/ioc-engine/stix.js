'use strict';

/**
 * STIX 2.1 export for evidence-backed feed indicators.
 *
 * Replaces the previous builder in api/v1/intel.js, which emitted random ids
 * per request, the invalid pattern `[file:value = ...]` for hashes, an
 * `artifact:value` fallback that is not a STIX object path, and unescaped
 * values. Every indicator here:
 * - uses its precomputed deterministic UUIDv5 id (stable across exports);
 * - uses a STIX 2.1 Cyber Observable pattern for its exact type with string
 *   escaping per the STIX patterning grammar (\\ and \');
 * - carries valid_from/valid_until, a 0-100 confidence, TLP marking and an
 *   external_reference to the source record that supports it.
 * Pure: no crypto or I/O at request time.
 */

// STIX 2.1 §7.2.1.4 predefined TLP:WHITE marking (TLP 2.0 CLEAR equivalent).
const TLP_WHITE_MARKING = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9';
const IDENTITY = Object.freeze({
  type: 'identity',
  spec_version: '2.1',
  id: 'identity--6a1c8a8e-3a4b-5f0e-8f3a-2b9d7c1e4f60',
  created: '2026-10-01T00:00:00.000Z',
  modified: '2026-10-01T00:00:00.000Z',
  name: 'CYBERDUDEBIVASH SENTINEL APEX',
  identity_class: 'organization',
});

const HASH_KEYS = { sha256: "'SHA-256'", sha1: "'SHA-1'", md5: 'MD5' };

function escapeStixString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function patternFor(type, value) {
  const v = `'${escapeStixString(value)}'`;
  switch (type) {
    case 'ipv4': return `[ipv4-addr:value = ${v}]`;
    case 'ipv6': return `[ipv6-addr:value = ${v}]`;
    case 'domain': return `[domain-name:value = ${v}]`;
    case 'url': return `[url:value = ${v}]`;
    case 'sha256':
    case 'sha1':
    case 'md5': return `[file:hashes.${HASH_KEYS[type]} = ${v}]`;
    default: return null;
  }
}

function stixTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function toStixIndicator(ioc) {
  const pattern = patternFor(ioc.type, ioc.value);
  const validFrom = stixTime(ioc.first_seen);
  if (!pattern || !validFrom || !/^indicator--/.test(ioc.stix_id || '')) return null;
  const created = stixTime(ioc.ingested_at) || validFrom;
  let modified = stixTime(ioc.updated_at) || created;
  if (modified < created) modified = created;
  let validUntil = stixTime(ioc.expires_at);
  if (validUntil && validUntil <= validFrom) validUntil = null; // spec: valid_until > valid_from
  const malware = (ioc.related_malware || []).join(', ');
  const ind = {
    type: 'indicator',
    spec_version: '2.1',
    id: ioc.stix_id,
    created_by_ref: IDENTITY.id,
    created,
    modified,
    name: `${ioc.type}: ${ioc.display_value || ioc.value}`,
    description: [
      malware ? `Associated malware (per source): ${malware}.` : null,
      ioc.context && ioc.context.threat_type ? `Source threat type: ${ioc.context.threat_type}.` : null,
      `Status ${ioc.status}; confidence ${ioc.confidence} (${(ioc.confidence_basis || []).join(', ')}).`,
      `Recommended action: ${ioc.detection ? ioc.detection.recommended_action : 'hunt'}.`,
    ].filter(Boolean).join(' '),
    indicator_types: ['malicious-activity'],
    pattern,
    pattern_type: 'stix',
    pattern_version: '2.1',
    valid_from: validFrom,
    confidence: Number(ioc.confidence_score) || 0,
    labels: [...new Set([...(ioc.tags || []), ...(ioc.related_malware || [])])].slice(0, 16),
    object_marking_refs: [TLP_WHITE_MARKING],
    external_references: (ioc.observations || []).map(o => ({
      source_name: o.source,
      url: o.source_url,
      external_id: o.source_record_id,
    })).concat((ioc.related_cves || []).map(c => ({ source_name: 'cve', external_id: c }))),
  };
  if (validUntil) ind.valid_until = validUntil;
  if (!ind.labels.length) delete ind.labels;
  return ind;
}

function buildStixBundle(iocs, bundleId) {
  const objects = [IDENTITY, ...iocs.map(toStixIndicator).filter(Boolean)];
  return { type: 'bundle', id: bundleId, objects };
}

module.exports = { TLP_WHITE_MARKING, IDENTITY, escapeStixString, patternFor, toStixIndicator, buildStixBundle };
