#!/usr/bin/env node
'use strict';

/**
 * Verify served CVSS scores against the NVD CVE API 2.0 and write the
 * corrections ledger consumed by api/_lib/cvss-corrections.js.
 *
 * Why: legacy records persisting in the rolling api/intel/live.json window
 * and in api/intel/cve/*.json carried a CVSS of 9.5 that did not match the
 * authoritative score (e.g. CVE-2026-32202 served 9.5; Microsoft scores it
 * 4.3). The pipeline rewrites those data files every 30 minutes, so the
 * correction lives in a stable, reviewed ledger (data/cvss-corrections.json)
 * that is applied where intelligence is served and published.
 *
 * Score selection (deterministic, explainable):
 *   1. NVD Primary (nvd@nist.gov): v3.1 > v4.0 > v3.0 > v2
 *   2. otherwise CNA Secondary:    v3.1 > v4.0 > v3.0
 *   3. otherwise null  -> NOT_ASSESSED (never a guessed number)
 *
 * Usage:
 *   node scripts/verify-cvss-provenance.js --ids-file cohort.txt [--out data/cvss-corrections.json]
 *   NVD_API_KEY=... raises the NVD rate limit (50 req/30s instead of 5).
 */

const fs = require('fs');
const path = require('path');

const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=';
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const PRIMARY_ORDER = ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2'];
const SECONDARY_ORDER = ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30'];

function selectScore(nvdCve) {
  const metrics = (nvdCve && nvdCve.metrics) || {};
  const pick = (order, predicate) => {
    for (const key of order) {
      const m = (metrics[key] || []).find(predicate);
      if (m && m.cvssData && typeof m.cvssData.baseScore === 'number') {
        return { score: m.cvssData.baseScore, vector: m.cvssData.vectorString || null, metric: key, source: m.source || null, type: m.type || null };
      }
    }
    return null;
  };
  return pick(PRIMARY_ORDER, m => m.type === 'Primary')
    || pick(SECONDARY_ORDER, m => m.type === 'Secondary')
    || null;
}

function ledgerEntry(id, nvdPayload, checkedAt) {
  const vulns = (nvdPayload && nvdPayload.vulnerabilities) || [];
  if (!vulns.length) return { id, verified_cvss: null, status: 'NOT_FOUND_IN_NVD', evidence: null, checked_at: checkedAt };
  const chosen = selectScore(vulns[0].cve);
  if (!chosen) return { id, verified_cvss: null, status: 'NOT_ASSESSED', evidence: null, checked_at: checkedAt };
  return { id, verified_cvss: chosen.score, status: 'VERIFIED', evidence: chosen, checked_at: checkedAt };
}

async function verify(ids, { fetchImpl = fetch, delayMs, apiKey = process.env.NVD_API_KEY, now = () => new Date().toISOString(), log = () => {} } = {}) {
  const wait = delayMs !== undefined ? delayMs : (apiKey ? 700 : 6500);
  const entries = [];
  const failures = [];
  for (const [i, id] of ids.entries()) {
    if (!CVE_RE.test(id)) { failures.push({ id, error: 'not a CVE id' }); continue; }
    let attempt = 0;
    for (;;) {
      attempt += 1;
      try {
        const res = await fetchImpl(NVD_URL + encodeURIComponent(id), { headers: apiKey ? { apiKey } : {} });
        if (res.status === 403 || res.status === 429 || res.status >= 500) throw new Error('http ' + res.status);
        if (!res.ok) { failures.push({ id, error: 'http ' + res.status }); break; }
        entries.push(ledgerEntry(id, await res.json(), now()));
        break;
      } catch (e) {
        if (attempt >= 3) { failures.push({ id, error: e.message }); break; }
        await new Promise(r => setTimeout(r, wait * 2 * attempt));
      }
    }
    log(`${i + 1}/${ids.length} ${id}`);
    if (i < ids.length - 1) await new Promise(r => setTimeout(r, wait));
  }
  return { entries, failures };
}

function mergeLedger(existing, { entries, failures }, servedById = {}) {
  const byId = new Map(((existing && existing.entries) || []).map(e => [e.id, e]));
  for (const e of entries) byId.set(e.id, { ...e, served_cvss: servedById[e.id] !== undefined ? servedById[e.id] : (byId.get(e.id) || {}).served_cvss });
  return {
    schema_version: 1,
    description: 'CVSS scores verified against the NVD CVE API 2.0. Applied by api/_lib/cvss-corrections.js where intelligence is served and published. Unverifiable scores are withheld (null), never guessed.',
    selection_rule: 'NVD Primary v3.1>v4.0>v3.0>v2, else CNA Secondary v3.1>v4.0>v3.0, else null (NOT_ASSESSED)',
    source: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    entries: [...byId.values()].sort((a, b) => a.id.localeCompare(b.id)),
    unresolved: failures,
  };
}

async function main(argv) {
  const arg = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
  const idsFile = arg('--ids-file');
  const out = arg('--out') || path.join(__dirname, '..', 'data', 'cvss-corrections.json');
  const served = arg('--served-json');
  if (!idsFile) { console.error('usage: --ids-file <file> [--out <ledger>] [--served-json <id->cvss map>]'); return 2; }
  const ids = [...new Set(fs.readFileSync(idsFile, 'utf8').split(/\s+/).filter(Boolean))];
  const existing = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : null;
  const result = await verify(ids, { log: m => console.log(m) });
  const servedById = served ? JSON.parse(fs.readFileSync(served, 'utf8')) : {};
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(mergeLedger(existing, result, servedById), null, 2) + '\n');
  console.log(`ledger: ${result.entries.length} verified/assessed, ${result.failures.length} unresolved -> ${out}`);
  return result.failures.length ? 1 : 0;
}

if (require.main === module) main(process.argv.slice(2)).then(code => process.exit(code));

module.exports = { selectScore, ledgerEntry, verify, mergeLedger, NVD_URL };
