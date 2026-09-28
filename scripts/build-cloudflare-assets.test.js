'use strict';

const { test, describe, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { resolveRoute } = require('../workers/lib/route-table');

function staticMarkupOnly(html) {
  return String(html)
    .replace(/<script\b[\s\S]*?<\/script>/gi, '')
    .replace(/<style\b[\s\S]*?<\/style>/gi, '');
}
const { build, countFiles, OUT, HEADERS_FILE_CONTENT, injectCustomerExperience, validatePublicHtmlStructure, hasUndefinedMetadataArtifacts } = require('./build-cloudflare-assets');

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

test('CVE undefined-metadata detector ignores legitimate technical code but rejects broken generated metadata', () => {
  assert.equal(hasUndefinedMetadataArtifacts('<pre><code>function f(){ return undefined }</code></pre>'), false);
  assert.equal(hasUndefinedMetadataArtifacts('<p>JavaScript undefined behavior is discussed here.</p>'), false);
  assert.equal(hasUndefinedMetadataArtifacts('<link rel="canonical" href="https://blog.cyberdudebivash.in/cve/undefined.html">'), true);
  assert.equal(hasUndefinedMetadataArtifacts('<meta property="og:url" content="https://blog.cyberdudebivash.in/cve/undefined.html">'), true);
  assert.equal(hasUndefinedMetadataArtifacts('<meta name="description" content="undefined">'), true);
  assert.equal(hasUndefinedMetadataArtifacts('<title> — CYBERDUDEBIVASH SENTINEL APEX</title>'), true);
  assert.equal(hasUndefinedMetadataArtifacts('{"url":"https://blog.cyberdudebivash.in/cve/undefined.html"}'), true);
});

test('customer experience injector handles valid HTML and malformed public HTML is rejected', () => {
  const valid = '<!doctype html><html><head><title>x</title></head><body><main>x</main></body></html>';
  const injected = injectCustomerExperience(valid);
  assert.match(injected, /customer-experience\.css\?v=20260928-cx2/);
  assert.match(injected, /customer-experience\.js\?v=20260928-cx2/);
  assert.throws(
    () => validatePublicHtmlStructure('<html><head><style>truncated', 'broken.html'),
    /Malformed public HTML: broken\.html/
  );
});

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
      'index.html', 'customer-assurance.html', 'service-status.html', 'customer-incident-response.html', 'enterprise-onboarding.html', 'cti-delivery-acceptance.html', 'leads.html', 'robots.txt', 'rss.xml', 'sitemap.xml',
      'search-index.json', 'live-intel.json', 'api/intel/customer-assurance.json', 'api/intel/service-assurance.json', 'api/intel/customer-incident-response.json', 'api/intel/cti-delivery-acceptance.json',
      'apex-v13.css', 'apex-command-center.css', 'responsive-platform.css', 'customer-experience.css', 'apex-command-center.js', 'customer-experience.js', 'analytics-engine.js', 'banner-orchestrator.js',
      'soc-cti-console.css', 'soc-triage-workspace.js', 'soc-taxonomy-pivots.js',
      'soc-hybrid-workspace.js', 'soc-evidence-drawer.js',
    ];
    for (const f of mustExist) {
      assert.ok(outputFiles.includes(f), `expected ${f} in dist-public/ but it was missing`);
    }
    assert.ok(outputFiles.includes('breaking/index.html'), 'expected breaking/index.html in dist-public/');
    assert.ok(outputFiles.some(f => f.startsWith('posts/') && f.endsWith('.html')), 'expected at least one posts/*.html');
    assert.ok(outputFiles.some(f => f.startsWith('api/intel/') && f.endsWith('.json')), 'expected at least one api/intel/*.json');
  });

  test('every built HTML page receives the global customer experience layer', () => {
    const htmlFiles = outputFiles.filter(f => f.endsWith('.html'));
    assert.ok(htmlFiles.length > 100, 'expected a substantial number of public HTML pages');
    for (const rel of htmlFiles) {
      const html = fs.readFileSync(path.join(OUT, rel), 'utf8');
      assert.match(html, /\/customer-experience\.css\?v=20260928-cx2/, rel + ' missing customer experience CSS');
      assert.match(html, /\/customer-experience\.js\?v=20260928-cx2/, rel + ' missing customer experience JS');
      assert.match(html, /name=["']viewport["']/i, rel + ' missing viewport metadata');
      assert.match(html, /viewport-fit=cover/i, rel + ' missing safe-area viewport support');
      assert.match(html, /<html[^>]+lang=["']en["']/i, rel + ' missing document language');
      assert.match(html, /<meta\s+charset=["']?utf-8["']?/i, rel + ' missing UTF-8 declaration');
    }
  });

  test('all internal links in public HTML resolve to a built asset or Worker route', () => {
    const files = new Set(outputFiles);
    const offenders = [];
    const publicOrigin = 'https://blog.cyberdudebivash.in';

    function existsAsPublicPath(requestPath) {
      const route = resolveRoute(requestPath);
      if (route) {
        if (route.type === 'blocked') return false;
        if (route.type === 'handler' || route.type === 'redirect') return true;
        if (route.type === 'asset') return files.has(route.path.replace(/^\//, ''));
      }

      const rel = requestPath.replace(/^\//, '');
      if (!rel) return files.has('index.html');
      if (files.has(rel)) return true;
      if (files.has(rel + '.html')) return true;
      if (files.has(path.posix.join(rel, 'index.html'))) return true;
      return false;
    }

    for (const rel of outputFiles.filter(f => f.endsWith('.html'))) {
      const html = fs.readFileSync(path.join(OUT, rel), 'utf8');
      const markup = staticMarkupOnly(html);
      const hrefs = [...markup.matchAll(/\bhref\s*=\s*["']([^"']+)["']/gi)].map(m => m[1].trim());
      for (const raw of hrefs) {
        if (!raw || raw.startsWith('#') || /^(?:mailto|tel|data|blob):/i.test(raw) || raw.startsWith('//')) continue;

        let requestPath = null;
        if (/^https?:\/\//i.test(raw)) {
          let url;
          try { url = new URL(raw); } catch { offenders.push(rel + ' -> malformed URL: ' + raw); continue; }
          if (url.origin !== publicOrigin) continue;
          requestPath = url.pathname;
        } else if (raw.startsWith('/')) {
          requestPath = raw.split(/[?#]/, 1)[0];
        } else {
          const clean = raw.split(/[?#]/, 1)[0];
          if (!clean) continue;
          requestPath = '/' + path.posix.normalize(path.posix.join(path.posix.dirname(rel), clean));
        }

        if (!existsAsPublicPath(requestPath)) offenders.push(rel + ' -> ' + raw);
      }
    }

    assert.deepEqual(offenders, [], 'unresolved internal links:\n' + offenders.slice(0, 100).join('\n'));
  });

  test('public forms and interactive controls avoid broken static patterns', () => {
    const offenders = [];
    for (const rel of outputFiles.filter(f => f.endsWith('.html'))) {
      const html = fs.readFileSync(path.join(OUT, rel), 'utf8');
      const markup = staticMarkupOnly(html);
      if (/<form\b[^>]*\baction\s*=\s*["']\s*javascript:/i.test(markup)) offenders.push(rel + ': javascript form action');
      if (/<button\b[^>]*\bdisabled\b[^>]*>\s*<\/button>/i.test(markup)) offenders.push(rel + ': empty disabled button');
      if (/<a\b[^>]*\bhref\s*=\s*["']\s*javascript:/i.test(markup)) offenders.push(rel + ': javascript link');
      if (/<input\b[^>]*type=["'](?:submit|button)["'][^>]*value=["']\s*["']/i.test(markup)) offenders.push(rel + ': empty input button label');
    }
    assert.deepEqual(offenders, [], 'public controls contain broken static patterns:\n' + offenders.slice(0, 100).join('\n'));
  });

  test('no public HTML artifact contains dead-link URL patterns', () => {
    const offenders = [];
    for (const rel of outputFiles.filter(f => f.endsWith('.html'))) {
      const html = fs.readFileSync(path.join(OUT, rel), 'utf8');
      const markup = staticMarkupOnly(html);
      if (/href=["']#["']/i.test(markup)) offenders.push(rel + ': href="#"');
      if (/href=["']\s*["']/i.test(markup)) offenders.push(rel + ': empty href');
      if (/href=["']javascript:/i.test(markup)) offenders.push(rel + ': javascript href');
    }
    assert.deepEqual(offenders, [], 'public pages still containing dead-link patterns:\n' + offenders.join('\n'));
  });

  test('built CVE pages contain no historical undefined metadata artifacts', () => {
    const offenders = [];
    for (const rel of outputFiles.filter(f => /^cve\/CVE-\d{4}-\d+\.html$/i.test(f))) {
      const html = fs.readFileSync(path.join(OUT, rel), 'utf8');
      if (hasUndefinedMetadataArtifacts(html)) offenders.push(rel);
    }
    assert.deepEqual(offenders, [], 'CVE pages still contain undefined metadata:\n' + offenders.join('\n'));
  });

  test('EVI research data artifact is published', () => {
    assert.ok(outputFiles.includes('data/exploitation-velocity-index.json'));
    const data = JSON.parse(fs.readFileSync(path.join(OUT, 'data/exploitation-velocity-index.json'), 'utf8'));
    assert.match(String(data.index || ''), /Exploitation Velocity Index/i);
  });

  test('SOC 2 customer-release surfaces do not publish unconditional response-time guarantees', () => {
    const contact = fs.readFileSync(path.join(OUT, 'contact.html'), 'utf8');
    assert.doesNotMatch(contact, /24\s+(?:business\s+)?hours?/i, 'contact page must not invent a public response-time SLA');
    assert.doesNotMatch(contact, /response[^.]{0,80}guarantee/i, 'contact page must not publish an unsupported response guarantee');

    const incident = fs.readFileSync(path.join(OUT, 'customer-incident-response.html'), 'utf8');
    assert.match(incident, /No public response-time guarantee is created by this page/i);
    assert.match(incident, /security@cyberdudebivash\.in/);
    assert.match(incident, /contact@cyberdudebivash\.in/);
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
      '/cve/CVE-2026-00000.html', '/apex-v13.css', '/mobile-first.css', '/responsive-platform.css',
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
