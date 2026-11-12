'use strict';
// RSS item dates must be a post's own first-party publication date, never invented.
//
// Verified 2026-11-12: the committed rss.xml carried "GitHub Internal Repository Breach —
// Consolidated Intelligence" with pubDate "Thu, 12 Nov 2026 12:00:00 +0000" and a link to a report
// whose own datePublished is 2026-05-20. The item came from an archival redirect stub with no
// date metadata; generate-rss.js fell back to "today" for it, so a May advisory looked newly
// published every time the feed was regenerated. A second fallback dated any undated file name
// containing "2026" as the constant 2026-04-22. Both are removed: a post without a verifiable
// date is excluded (and logged), the output depends only on the posts, never on the clock.
// Fixtures are SYNTHETIC. The real posts/ directory is never read or written.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { buildRSS, extractDate, toRFC822 } = require('../generate-rss.js');

const page = ({ title, canonical, date, body = 'SYNTHETIC body text for a fixture report.' }) => `<!DOCTYPE html><html><head>
<title>${title} | CYBERDUDEBIVASH SENTINEL APEX</title>
<meta name="description" content="${title} description">
${canonical ? `<link rel="canonical" href="${canonical}">` : ''}
${date ? `<script type="application/ld+json">{"@type":"Article","datePublished":"${date}"}</script>` : ''}
</head><body><p>${body}</p></body></html>`;

function run(t, files, nowIso) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rss-fixture-'));
  const postsDir = path.join(dir, 'posts'); fs.mkdirSync(postsDir);
  for (const [name, html] of Object.entries(files)) fs.writeFileSync(path.join(postsDir, name), html);
  const outputFile = path.join(dir, 'rss.xml');
  const warnings = [];
  t.mock.method(console, 'log', () => {});
  t.mock.method(console, 'warn', m => warnings.push(String(m)));
  if (nowIso) t.mock.timers.enable({ apis: ['Date'], now: Date.parse(nowIso) });
  buildRSS({ postsDir, outputFile });
  const xml = fs.readFileSync(outputFile, 'utf8');
  fs.rmSync(dir, { recursive: true, force: true });
  return { xml, warnings };
}
const itemsOf = xml => [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].map(m => ({
  link: (m[1].match(/<link>([^<]*)/) || [])[1], pubDate: (m[1].match(/<pubDate>([^<]*)/) || [])[1] }));

test('extractDate uses the post\'s own JSON-LD datePublished, then a visible date', () => {
  assert.equal(extractDate(page({ title: 'a', date: '2026-05-20' }), 'cve-2026-1.html'), '2026-05-20');
  assert.equal(extractDate('<html><body>Published 5 July 2026 by the team</body></html>', 'x.html'), '2026-07-05');
});

test('no verifiable date means NO date: not a constant, not today', () => {
  const undated = page({ title: 'stub' });
  assert.equal(extractDate(undated, 'cve-2026-21497-vmware-esxi.html'), null, 'file names containing 2026 must not get 2026-04-22');
  assert.equal(extractDate(undated, 'something-april-2026.html'), null);
  assert.equal(extractDate(undated, 'github-confirms-hack.html'), null, 'must not fall back to today');
});

test('an undated archival redirect stub is excluded; the real report keeps its own date', (t) => {
  const { xml, warnings } = run(t, {
    'github-confirms-breach-4k-internal-repos-stolen.html': page({ title: 'GitHub breach full report', date: '2026-05-20',
      canonical: 'https://blog.cyberdudebivash.in/posts/github-confirms-breach-4k-internal-repos-stolen.html' }),
    'github-confirms-hack-impacting-3-800-internal-repositories.html': page({ title: 'GitHub Internal Repository Breach — Consolidated Intelligence',
      canonical: 'https://blog.cyberdudebivash.in/posts/github-confirms-breach-4k-internal-repos-stolen.html' }),
    'cve-2026-90001.html': page({ title: 'Fresh report', date: '2026-11-12' }),
  }, '2026-11-12T20:00:00Z');
  const items = itemsOf(xml);
  assert.equal(items.length, 2, 'the stub is not an item');
  const breach = items.filter(i => /github-confirms-breach/.test(i.link));
  assert.equal(breach.length, 1);
  assert.equal(breach[0].pubDate, toRFC822('2026-05-20'), 'a May advisory is never presented as published today');
  assert.ok(warnings.some(w => /1 post\(s\) excluded: no verifiable publication date/.test(w) && /github-confirms-hack-impacting/.test(w)));
});

test('a historical advisory regenerated "today" keeps its original publication date', (t) => {
  const { xml } = run(t, { 'cve-2026-111.html': page({ title: 'Old advisory', date: '2026-07-05' }) }, '2026-11-12T08:00:00Z');
  assert.equal(itemsOf(xml)[0].pubDate, 'Sun, 05 Jul 2026 12:00:00 +0000');
});

test('the feed is idempotent: identical posts give byte-identical output on different days', (t) => {
  const files = {
    'a.html': page({ title: 'A', date: '2026-11-11' }), 'b.html': page({ title: 'B', date: '2026-11-12' }),
    'undated-2026.html': page({ title: 'No date' }),
  };
  const day1 = run(t, files, '2026-11-12T01:00:00Z').xml;
  t.mock.timers.reset();
  const day2 = run(t, files, '2027-03-01T23:59:00Z').xml.replace(/Copyright \d{4}/, 'Copyright 2026');
  assert.equal(day2, day1.replace(/Copyright \d{4}/, 'Copyright 2026'), 'only the copyright year may follow the clock');
});

test('items are ordered by their real dates and lastBuildDate is the newest item, not the clock', (t) => {
  const { xml } = run(t, { 'old.html': page({ title: 'Old', date: '2026-01-02' }), 'new.html': page({ title: 'New', date: '2026-02-03' }) }, '2030-06-06T00:00:00Z');
  const dates = itemsOf(xml).map(i => i.pubDate);
  assert.deepEqual(dates, [toRFC822('2026-02-03'), toRFC822('2026-01-02')]);
  assert.match(xml, new RegExp('<lastBuildDate>' + toRFC822('2026-02-03').replace(/[+]/g, '\\+') + '</lastBuildDate>'));
});

test('the generator source keeps no date-inventing fallback and stays CLI-compatible', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'generate-rss.js'), 'utf8');
  assert.doesNotMatch(src, /2026-04-22/);
  const fn = src.slice(src.indexOf('function extractDate('), src.indexOf('/** Parse ISO date string'));
  assert.doesNotMatch(fn, /new Date\(/, 'extractDate must not read the clock');
  assert.match(src, /if \(require\.main === module\) buildRSS\(\);/, '`node generate-rss.js` still builds the feed');
});
