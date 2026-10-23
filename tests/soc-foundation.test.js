'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const preview = fs.readFileSync(path.join(root, 'soc-preview.html'), 'utf8');
const manifest = fs.readFileSync(path.join(root, 'scripts', 'build-cloudflare-assets.js'), 'utf8');
const wrangler = fs.readFileSync(path.join(root, 'wrangler.jsonc'), 'utf8');
const adr = fs.readFileSync(path.join(root, 'docs', 'architecture', 'SENTINEL-APEX-SOC-TRANSFORMATION-2026-10-21.md'), 'utf8');
const runbook = fs.readFileSync(path.join(root, 'docs', 'runbooks', 'SOC-DOMAIN-CUTOVER.md'), 'utf8');

describe('SOC foundation release boundary', () => {
  test('Preview is explicitly non-indexable with one existing-origin canonical', () => {
    expect(preview).toMatch(/<meta\s+name="robots"\s+content="noindex,nofollow,noarchive">/i);
    expect(preview).toMatch(/<link\s+rel="canonical"\s+href="https:\/\/blog\.cyberdudebivash\.in\/soc-preview\.html">/i);
    expect(preview).toMatch(/<html lang="en">/);
    expect(preview).toMatch(/<a class="skip" href="#main">/);
  });

  test('No false certification, customer activity, delivery or continuous-service claims', () => {
    expect(preview).toMatch(/not a released managed SOC/i);
    expect(preview).toMatch(/No SOC 2 Type I\/II certification is claimed/i);
    expect(preview).toMatch(/not a claim that customer telemetry or response coverage is currently live/i);
    expect(preview).toMatch(/requires explicit written scope and acceptance/i);
    expect(preview).not.toMatch(/CyberDudeBivash Pvt\.\s*Ltd\./i);
    expect(preview).not.toMatch(/guaranteed profits|fortune\s*500 customers|live customer incidents/i);
  });

  test('Only approved existing public service entry points and scoped manual enquiry', () => {
    for (const endpoint of ['/intelligence.html','/customer-assurance.html','/detection-quality.html','/enterprise-onboarding.html']) {
      expect(preview).toContain('href="' + endpoint + '"');
      expect(fs.existsSync(path.join(root, endpoint.slice(1)))).toBe(true);
    }
    expect(preview).toContain('mailto:contact@cyberdudebivash.in');
    expect(preview).not.toMatch(/\/api\/v1\/workbench\//);
    expect(preview).not.toMatch(/<form\b|checkout\.razorpay\.com|ANALYST_KEYS/i);
  });

  test('Preview is allowlisted and additive SOC hostname preserves the legacy CTI domain', () => {
    expect(manifest).toMatch(/['"]soc-preview\.html['"]/);
    // A second Worker custom-domain mapping is not a completed cutover:
    // legacy CTI remains mapped; the SOC hostname has its own release gates.
    const legacyRoutes = wrangler.match(/"pattern"\s*:\s*"blog\.cyberdudebivash\.in"/g) || [];
    const socRoutes = wrangler.match(/"pattern"\s*:\s*"soc\.cyberdudebivash\.in"/g) || [];
    expect(legacyRoutes).toHaveLength(1);
    expect(socRoutes).toHaveLength(1);
    expect(wrangler).not.toMatch(/"pattern"\s*:\s*"\*\.cyberdudebivash\.in"/);
    // Domain configuration alone does not prove canonical, legal,
    // tenant-isolation or production deployment acceptance.
  });

  test('Architecture forbids tenant leaks and domain cutover before proof', () => {
    expect(adr).toMatch(/server-derived.*tenant_id/i);
    expect(adr).toMatch(/cross-tenant/i);
    expect(adr).toMatch(/NO-GO hostname/i);
    expect(runbook).toMatch(/path-preserving 308 redirects/i);
    expect(runbook).toMatch(/does not initiate DNS/i);
  });
});