'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { build, countFiles, OUT, HEADERS_FILE_CONTENT } = require('./build-cloudflare-assets');

// Mirrors Cloudflare's own documented splat semantics for a _headers
// pattern: "a splat pattern -- signified by an asterisk (*) -- will
// greedily match all characters" and "you may only include a single
// splat in the URL" (confirmed against Cloudflare's _headers docs before
// writing this, not assumed) -- exactly the subset HEADERS_FILE_CONTENT
// actually uses (/*, /*.ext, /prefix/*), so a single-splat prefix/suffix
// match is sufficient here without reimplementing full path-to-regexp.
function patternMatches(pattern, requestPath) {
  if (!pattern.includes('*')) return pattern === requestPath;
  const starIndex = pattern.indexOf('*');
  const prefix = pattern.slice(0, starIndex);
  const suffix = pattern.slice(starIndex + 1);
  return (
    requestPath.startsWith(prefix) &&
    requestPath.endsWith(suffix) &&
    requestPath.length >= prefix.length + suffix.length
  );
}

// Parses the _headers file format (blank-line-separated blocks; first
// line of a block is the pattern, subsequent indented lines are
// "Header-Name: value") well enough to check cascade safety below.
// Deliberately independent of any parser Wrangler itself uses -- this is
// a safety net over HEADERS_FILE_CONTENT as authored, not a test of
// Cloudflare's own runtime behavior (that's Section 5's real-Workerd job).
function parseHeadersFile(content) {
  return content
    .split(/\n\s*\n/)
    .map(block => block.split('\n').map(l => l.trim()).filter(Boolean))
    .filter(lines => lines.length > 0 && !lines[0].startsWith('#'))
    .map(lines => ({
      pattern: lines[0],
      headerNames: lines.slice(1).map(l => l.split(':')[0].trim()),
    }));
}

// Path-segment-aware, not substring-aware: an earlier version of this
// test matched "data"/"platform"/"automation"/"tests"/"lib"/etc. as plain
// substrings anywhere in the path, which flags hundreds of entirely
// legitimate posts/**.html and api/intel/products/**.json paths whose
// slugs are real article titles ("...data-breach...",
// "...automation...", "north-korean-hackers-posing-as-fake-it-workers...")
// — a false-positive rate that makes the check worthless. Directory names
// must match a full path SEGMENT exactly; files must match a full
// BASENAME exactly (or a narrow suffix for .env*/.patch/.bundle). Both
// are case-insensitive.

const PROHIBITED_DIR_SEGMENTS = new Set([
  'sentinel-apex', 'eito', 'platform', 'prompts', 'scripts', 'docs',
  'marketing', 'backups', 'node_modules', '.git', '.wrangler', 'workers',
  'tests', 'tests-js', 'lib', 'types', 'automation', 'blogger-theme',
  'logs', 'data', 'coverage',
]);

const PROHIBITED_EXACT_FILENAMES = new Set([
  'claude.md', 'business-transformation-roadmap-2026.md',
  'audit-report-2026-05-28.md', 'operations.md', 'runbooks.md',
  'package.json', 'package-lock.json', 'jest.config.js', 'jest.setup.ts',
  'tsconfig.json',
  'intel-memory.json', 'intel-state.json', 'ai-security-intel-memory.json',
  'ai-security-intel-state.json', 'pipeline-health-history.json',
  'fetch-live-intel.js', 'ai-security-intel-engine.js',
  'generate-cve-pages.js', 'generate-intelligence-hub.js',
  'generate-rss.js', 'generate-search-index.py',
  'build-detections-page.js', 'build-detections.js',
  'build-evi-page.js', 'build-evi.js', 'build-research.js',
]);

function isProhibited(relPath) {
  const lower = relPath.toLowerCase();
  const segments = lower.split('/');
  const basename = segments[segments.length - 1];

  if (segments.some(seg => PROHIBITED_DIR_SEGMENTS.has(seg))) return true;
  if (PROHIBITED_EXACT_FILENAMES.has(basename)) return true;
  if (basename.startsWith('.env')) return true;
  if (basename.endsWith('.patch') || basename.endsWith('.bundle')) return true;
  return false;
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

describe('build-cloudflare-assets', () => {
  let outputFiles;

  test('build() runs and produces a non-trivial dist-public/', () => {
    const outDir = build();
    assert.equal(outDir, OUT);
    assert.ok(fs.existsSync(outDir));
    const count = countFiles(outDir);
    assert.ok(count > 100, `expected a substantial file count, got ${count}`);
    outputFiles = walk(outDir).map(f => path.relative(outDir, f).replace(/\\/g, '/'));
  });

  test('no output path matches a prohibited directory segment or filename', () => {
    const offenders = outputFiles.filter(isProhibited);
    assert.deepEqual(offenders, [], `prohibited paths leaked into dist-public/:\n${offenders.join('\n')}`);
  });

  // Regression guard for the false-positive bug this test previously had:
  // real content whose slug/filename merely contains one of the prohibited
  // words as a substring must NOT be flagged.
  test('legitimate content containing prohibited words as substrings is not flagged', () => {
    const legitimateExamples = [
      'posts/nissan-employee-data-breached-in-oracle-peoplesoft-hack.html',
      'posts/rockwell-automation-patches-vulnerabilities-in-ics-controlle.html',
      'posts/north-korean-hackers-posing-as-fake-it-workers-behind-nearly.html',
      'api/intel/cve/CVE-2026-13760-npm-aws-cdk-lib.json',
      'api/intel/products/mokn-raises-15-million-for-phish-back-platform.json',
    ];
    for (const p of legitimateExamples) {
      assert.equal(isProhibited(p), false, `${p} should not be flagged`);
    }
  });

  test('no .js file exists anywhere under the output api/ tree', () => {
    const jsUnderApi = outputFiles.filter(f => f.startsWith('api/') && f.endsWith('.js'));
    assert.deepEqual(jsUnderApi, [], `handler source leaked as a static asset:\n${jsUnderApi.join('\n')}`);
  });

  test('expected public artifacts are present', () => {
    const mustExist = [
      'index.html', 'robots.txt', 'rss.xml', 'sitemap.xml',
      'search-index.json', 'live-intel.json',
      'apex-v13.css', 'analytics-engine.js', 'banner-orchestrator.js',
      'soc-cti-console.css', 'soc-triage-workspace.js',
      'soc-hybrid-workspace.js', 'soc-evidence-drawer.js',
    ];
    for (const f of mustExist) {
      assert.ok(outputFiles.includes(f), `expected ${f} in dist-public/ but it was missing`);
    }
    assert.ok(outputFiles.some(f => f.startsWith('posts/') && f.endsWith('.html')), 'expected at least one posts/*.html');
    assert.ok(outputFiles.some(f => f.startsWith('api/intel/') && f.endsWith('.json')), 'expected at least one api/intel/*.json');
  });

  test('_headers is written to the build output and matches the exported constant', () => {
    assert.ok(outputFiles.includes('_headers'), 'expected _headers in dist-public/');
    const onDisk = fs.readFileSync(path.join(OUT, '_headers'), 'utf8');
    assert.equal(onDisk, HEADERS_FILE_CONTENT);
  });

  after(() => {
    // dist-public/ is a generated build artifact (gitignored) — leaving it
    // populated on disk after the test run is fine and mirrors what a real
    // deploy step would produce; nothing to clean up for correctness.
  });
});

describe('_headers cascade safety', () => {
  const blocks = parseHeadersFile(HEADERS_FILE_CONTENT);

  test('every block has at least one header and a pattern starting with /', () => {
    assert.ok(blocks.length >= 8, `expected at least 8 rule blocks, got ${blocks.length}`);
    for (const { pattern, headerNames } of blocks) {
      assert.ok(pattern.startsWith('/'), `pattern "${pattern}" must start with /`);
      assert.ok(headerNames.length > 0, `block "${pattern}" has no headers`);
    }
  });

  test('no pattern uses more than one splat (Cloudflare only supports a single splat per URL)', () => {
    for (const { pattern } of blocks) {
      const stars = (pattern.match(/\*/g) || []).length;
      assert.ok(stars <= 1, `pattern "${pattern}" has ${stars} splats, Cloudflare allows at most 1`);
    }
  });

  // The actual regression guard: for a representative sample of real
  // request paths (drawn from PUBLIC_DIRS/PUBLIC_ROOT_FILES categories,
  // not invented), no header name may be set by more than one block whose
  // pattern matches that path -- otherwise Cloudflare comma-joins the
  // duplicate into a corrupted single value on the wire (e.g.
  // "DENY, DENY"), exactly the failure mode this file's design avoids.
  test('no header name is set by more than one matching block, for representative real paths', () => {
    const samplePaths = [
      '/', '/index.html', '/about.html', '/posts/some-post.html',
      '/cve/CVE-2026-00000.html', '/apex-v13.css', '/mobile-first.css',
      '/analytics-engine.js', '/banner-orchestrator.js', '/rss.xml',
      '/sitemap.xml', '/robots.txt', '/api/intel/cve/CVE-2026-1.json',
      '/api/intel/products/example.json', '/favicon.ico', '/og-image.png',
      '/site.webmanifest', '/search-index.json', '/live-intel.json',
      '/.well-known/security.txt', '/detections/rules/example.yml',
    ];

    for (const requestPath of samplePaths) {
      const matchingBlocks = blocks.filter(b => patternMatches(b.pattern, requestPath));
      assert.ok(matchingBlocks.length >= 1, `no block matches ${requestPath} (expected at least the global /* rule)`);

      const seen = new Map(); // header name -> pattern that first set it
      for (const { pattern, headerNames } of matchingBlocks) {
        for (const name of headerNames) {
          const key = name.toLowerCase();
          assert.ok(
            !seen.has(key),
            `${requestPath}: header "${name}" is set by both "${seen.get(key)}" and "${pattern}" -- ` +
              `Cloudflare will comma-join these into one corrupted value`
          );
          seen.set(key, pattern);
        }
      }
    }
  });

  test('the /*.html and / blocks set identical header sets (root has no extension to match /*.html)', () => {
    const htmlBlock = blocks.find(b => b.pattern === '/*.html');
    const rootBlock = blocks.find(b => b.pattern === '/');
    assert.ok(htmlBlock && rootBlock, 'expected both /*.html and / blocks to exist');
    assert.deepEqual(rootBlock.headerNames.sort(), htmlBlock.headerNames.sort());
  });

  test('the global /* block does not set Content-Security-Policy or Permissions-Policy (matches vercel.json\'s catch-all)', () => {
    const globalBlock = blocks.find(b => b.pattern === '/*');
    assert.ok(globalBlock, 'expected a /* block');
    assert.ok(!globalBlock.headerNames.some(h => /content-security-policy|permissions-policy/i.test(h)));
  });
});
