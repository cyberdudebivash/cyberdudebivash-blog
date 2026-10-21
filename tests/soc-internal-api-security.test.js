'use strict';

/**
 * Source-level invariant checks for every analyst-authenticated SOC route.
 * These complement the analyst-auth behavioral tests: they ensure new or
 * restored broad CORS headers cannot silently expose credentialed responses
 * to third-party browser origins during the internal-only SOC phase.
 */
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const handlers = [
  'api/v1/workbench/investigations.js',
  'api/v1/workbench/cases.js',
  'api/v1/workbench/dashboard.js',
  'api/v1/workbench/search.js',
  'api/v1/intelligence/graph.js',
  'api/v1/intelligence/objects.js',
  'api/v1/intelligence/correlations.js',
  'api/v1/intelligence/publish.js',
  'api/v1/intelligence/similarity.js',
];

describe.each(handlers)('Internal-only SOC endpoint %s', (file) => {
  const code = fs.readFileSync(path.join(root, file), 'utf8');

  test('retains an enforced analyst identity guard', () => {
    expect(code).toMatch(/const \{\s*requireAnalyst\s*\} = require\(['"]\.\.\/\.\.\/_lib\/analyst-auth['"]\)/);
    expect(code).toMatch(/await requireAnalyst\(req,\s*res,\s*fail\)/);
    expect(code).toMatch(/if\s*\(!caller\)\s*return/);
  });

  test('does not authorize third-party browser origins', () => {
    expect(code).not.toMatch(/['"]Access-Control-Allow-Origin['"]\s*:/i);
    expect(code).not.toMatch(/Access-Control-Allow-Credentials/i);
    expect(code).not.toMatch(/req\.headers\.origin/i);
  });

  test('marks success, failure and preflight responses as non-cacheable', () => {
    expect(code).toMatch(/['"]Cache-Control['"]\s*:\s*['"]no-store,\s*no-cache,\s*must-revalidate['"]/);
    expect(code).toMatch(/Object\.entries\(CORS_HEADERS\)\.forEach/);
    expect(code).toMatch(/req\.method\s*===\s*['"]OPTIONS['"]/);
  });
});

test('The internal workbench UI calls its own same-origin API, not a remote host', () => {
  const html = fs.readFileSync(path.join(root, 'workbench.html'), 'utf8');
  expect(html).toContain('fetch(' + '\x60' + '\u0024{API}\u0024{path}');
  expect(html).toContain('sessionStorage.setItem');
  expect(html).not.toContain('localStorage.setItem');
});

test('Internal SOC endpoints remain unlinked from the public SOC preview', () => {
  const preview = fs.readFileSync(path.join(root, 'soc-preview.html'), 'utf8');
  expect(preview).not.toMatch(/\/api\/v1\/workbench\/|X-Analyst-Key|ANALYST_KEYS/i);
});
