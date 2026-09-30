'use strict';

// ICF-P0-006: the API, public feeds and pages served a CVSS of 9.5 that did not
// match the authoritative score (e.g. CVE-2026-32202: Microsoft 4.3). These tests
// cover the NVD verifier's deterministic selection rule, the committed ledger's
// integrity, and that every serving path applies it.

const verifier = require('../../../scripts/verify-cvss-provenance');
const corrections = require('../cvss-corrections');
const intel = require('../intel');

const metric = (score, source, type, vector = 'CVSS:3.1/AV:N') => ({ source, type, cvssData: { baseScore: score, vectorString: vector } });

describe('verifier score selection', () => {
  test('NVD Primary wins over CNA Secondary; v3.1 preferred', () => {
    const cve = { metrics: {
      cvssMetricV31: [metric(8.2, 'cna@example', 'Secondary'), metric(7.5, 'nvd@nist.gov', 'Primary')],
      cvssMetricV2: [metric(9.3, 'nvd@nist.gov', 'Primary', 'AV:N')],
    } };
    expect(verifier.selectScore(cve)).toMatchObject({ score: 7.5, source: 'nvd@nist.gov', metric: 'cvssMetricV31' });
  });

  test('CNA Secondary used only when NVD has not scored; nothing -> null', () => {
    expect(verifier.selectScore({ metrics: { cvssMetricV31: [metric(4.3, 'secure@microsoft.com', 'Secondary')] } }))
      .toMatchObject({ score: 4.3, source: 'secure@microsoft.com' });
    expect(verifier.selectScore({ metrics: {} })).toBeNull();
  });

  test('ledger entry statuses never invent a score', () => {
    expect(verifier.ledgerEntry('CVE-2026-0001', { vulnerabilities: [] }, 't')).toMatchObject({ status: 'NOT_FOUND_IN_NVD', verified_cvss: null });
    expect(verifier.ledgerEntry('CVE-2026-0001', { vulnerabilities: [{ cve: { metrics: {} } }] }, 't')).toMatchObject({ status: 'NOT_ASSESSED', verified_cvss: null });
  });

  test('verify() retries throttling and records unresolved ids instead of guessing', async () => {
    let calls = 0;
    const fetchImpl = async () => {
      calls += 1;
      if (calls === 1) return { ok: false, status: 429 };
      return { ok: true, status: 200, json: async () => ({ vulnerabilities: [{ cve: { metrics: { cvssMetricV31: [metric(7.3, 'nvd@nist.gov', 'Primary')] } } }] }) };
    };
    const r = await verifier.verify(['CVE-2024-27199', 'not-a-cve'], { fetchImpl, delayMs: 0, now: () => 't' });
    expect(r.entries).toEqual([expect.objectContaining({ id: 'CVE-2024-27199', verified_cvss: 7.3, status: 'VERIFIED' })]);
    expect(r.failures).toEqual([{ id: 'not-a-cve', error: 'not a CVE id' }]);
  });
});

describe('committed ledger integrity', () => {
  const { LEDGER } = corrections;
  test('every entry is evidence-backed or explicitly withheld', () => {
    expect(LEDGER.entries.length).toBeGreaterThan(0);
    for (const e of LEDGER.entries) {
      expect(e.id).toMatch(/^CVE-\d{4}-\d{4,7}$/);
      expect(['VERIFIED', 'NOT_ASSESSED', 'NOT_FOUND_IN_NVD']).toContain(e.status);
      expect(Date.parse(e.checked_at)).not.toBeNaN();
      if (e.status === 'VERIFIED') {
        expect(typeof e.verified_cvss).toBe('number');
        expect(e.evidence).toEqual(expect.objectContaining({ score: e.verified_cvss, source: expect.any(String), metric: expect.stringMatching(/^cvssMetricV/) }));
      } else {
        expect(e.verified_cvss).toBeNull();
      }
    }
  });
});

describe('applyCvssCorrection', () => {
  const [entry] = corrections.LEDGER.entries.filter(e => e.status === 'VERIFIED');

  test('ledger records get the verified score with provenance; others are untouched', () => {
    const fixed = corrections.applyCvssCorrection({ id: entry.id, cvss: 9.5, title: 't' });
    expect(fixed.cvss).toBe(entry.verified_cvss);
    expect(fixed.cvss_status).toBe('VERIFIED');
    expect(fixed.cvss_source).toMatch(/^NVD CVE API 2\.0 \(/);
    const other = { id: 'CVE-1999-0001', cvss: 5 };
    expect(corrections.applyCvssCorrection(other)).toBe(other);
    const noCvss = { id: entry.id, title: 'no score field' };
    expect(corrections.applyCvssCorrection(noCvss)).toBe(noCvss);
  });

  test('withheld ledger entries serve null, never the unsupported number', () => {
    const withheld = corrections.LEDGER.entries.find(e => e.status !== 'VERIFIED');
    if (!withheld) return;
    expect(corrections.applyCvssCorrection({ id: withheld.id, cvss: 9.5 }).cvss).toBeNull();
  });
});

describe('serving paths apply the ledger', () => {
  const byId = new Map(corrections.LEDGER.entries.map(e => [e.id, e]));
  const expected = id => { const e = byId.get(id); return e.status === 'VERIFIED' ? e.verified_cvss : null; };

  test('getIntel(live): every ledger CVE is served with its verified score, for every tier', () => {
    for (const tier of ['free', 'pro', 'team', 'enterprise']) {
      const { items } = intel.getIntel('live', tier, { limit: '100' });
      for (const it of items.filter(i => byId.has(i.id))) expect([it.id, it.cvss]).toEqual([it.id, expected(it.id)]);
    }
  });

  test('getCVEDetail: ledger CVE detail no longer carries the unsupported score', () => {
    const sample = corrections.LEDGER.entries.slice(0, 25);
    let checked = 0;
    for (const e of sample) {
      const { found, item } = intel.getCVEDetail(e.id, 'pro');
      if (!found || !Object.prototype.hasOwnProperty.call(item, 'cvss')) continue;
      checked += 1;
      expect([e.id, item.cvss]).toEqual([e.id, expected(e.id)]);
    }
    expect(checked).toBeGreaterThan(0);
  });

  test('correctedScore (used by the search index CVE docs) prefers the ledger, else passes through', () => {
    expect(corrections.correctedScore(entry0().id, 9.5)).toBe(expected(entry0().id));
    expect(corrections.correctedScore('CVE-1999-0001', 5)).toBe(5);
    expect(corrections.correctedScore('CVE-1999-0001', undefined)).toBeNull();
  });

  function entry0() { return corrections.LEDGER.entries[0]; }
});

describe('legacy record integrity (ICF-P1-003)', () => {
  test('a record sourced from the CISA KEV catalog is never served as not-KEV', () => {
    const r = corrections.reconcileLegacyRecord({ id: 'CVE-2026-0001', source: 'cisa_kev', cisa_kev: false });
    expect(r.cisa_kev).toBe(true);
    expect(r.kev_status_basis).toMatch(/CISA KEV catalog/);
    const merged = corrections.reconcileLegacyRecord({ id: 'CVE-2026-0002', source: 'nvd', merged_sources: ['nvd', 'cisa_kev'], cisa_kev: false });
    expect(merged.cisa_kev).toBe(true);
    const unrelated = { id: 'CVE-2026-0003', source: 'nvd', cisa_kev: false };
    expect(corrections.reconcileLegacyRecord(unrelated)).toBe(unrelated);
  });

  test('joined "a ; b" references are split into valid URLs; notes are dropped', () => {
    const r = corrections.reconcileLegacyRecord({ refs: ['https://msrc.example/a ; https://nvd.example/b', 'https://x.example/c'] });
    expect(r.refs).toEqual(['https://msrc.example/a', 'https://nvd.example/b', 'https://x.example/c']);
  });

  test('served API feed: every KEV-sourced item carries cisa_kev true and no joined refs', () => {
    const { items } = intel.getIntel('live', 'enterprise', { limit: '100' });
    const kevSourced = items.filter(i => i.source === 'cisa_kev');
    for (const i of kevSourced) expect([i.id, i.cisa_kev]).toEqual([i.id, true]);
    for (const i of items) for (const ref of i.refs || []) expect(ref).not.toMatch(/\s;\s/);
  });
});

describe('unvetted legacy indicators (ICF-P0-009)', () => {
  test('advisory/news-sourced records do not serve regex-extracted IOCs', () => {
    const r = corrections.reconcileLegacyRecord({ id: 'CVE-2026-0004', sources: ['github_advisories'], iocs: [
      { type: 'domain', value: 'typo3.org' }, { type: 'ipv4', value: '169.254.169.254' }, { type: 'indicator', value: 'CVE-2026-0004' }] });
    expect(r.iocs).toEqual([]);
    expect(r).toMatchObject({ ioc_status: 'WITHHELD_UNVETTED', ioc_withheld_count: 3 });
  });

  test('structured indicator feeds keep their indicators', () => {
    const rec = { id: 'THREATFOX-1', source: 'threatfox', iocs: [{ type: 'domain', value: 'bad.example' }] };
    expect(corrections.reconcileLegacyRecord(rec)).toBe(rec);
  });

  test('served CVE detail (Pro) carries no unvetted indicators', () => {
    const fs = require('fs');
    const path = require('path');
    const dir = path.join(__dirname, '..', '..', 'intel', 'cve');
    const withIocs = fs.readdirSync(dir).filter(f => f.endsWith('.json')).slice(0, 400)
      .map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'))).filter(d => (d.iocs || []).length).slice(0, 10);
    expect(withIocs.length).toBeGreaterThan(0);
    for (const d of withIocs) {
      const { found, item } = intel.getCVEDetail(d.id, 'pro');
      expect(found).toBe(true);
      if (!(d.sources || []).some(s => corrections.STRUCTURED_IOC_SOURCES.has(s))) expect([d.id, item.iocs]).toEqual([d.id, []]);
    }
  });
});
