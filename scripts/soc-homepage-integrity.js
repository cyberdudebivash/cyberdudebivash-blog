'use strict';

/**
 * Source and build-time fail-closed integrity contract for the public CTI
 * homepage. Assertion only: do not remove reports or auto-repair unknown HTML.
 * A prior P0 defect duplicated 15 KB of homepage scaffold and orphaned a card.
 */
function assertHomepageIntegrity(html, source = 'index.html') {
  const text = String(html);
  const count = regex => (text.match(regex) || []).length;
  const invariants = [
    ['single main landmark', count(/<main(?:\s[^>]*)?>/gi) === 1 && count(/<\/main\s*>/gi) === 1],
    ['single report container', count(/\bid=["']reports["']/gi) === 1],
    ['single main marker', count(/<!--\s*MAIN\s*-->/gi) === 1],
    ['single live feed', count(/\bid=["']live-intel-feed["']/gi) === 1],
    ['single enterprise CTA', count(/<section\b[^>]*class=["'][^"']*\bent-cta-block\b/gi) === 1],
    ['single statistics bar', count(/<div\b[^>]*class=["'][^"']*\bstats-bar\b/gi) === 1],
    ['single AI spotlight', count(/<section\b[^>]*class=["'][^"']*\bai-spotlight\b/gi) === 1],
    ['single featured intelligence', count(/<div\b[^>]*class=["'][^"']*\bfeatured-intel-section\b/gi) === 1],
    ['featured report marker exists', count(/<!--\s*POST 1 — FEATURED\s*-->/gi) === 1],
    ['no orphaned card tail', !/^\s*\)\s+in the ClassDefinition UID validation regex/im.test(text)],
    ['truthful SOC product title', /<title>[^<]*Threat Intelligence\s*&(?:amp;)?\s*SOC Readiness[^<]*<\/title>/i.test(text) &&
      !/<title>[^<]*SOC\s*2\s*&/i.test(text)],
  ];
  const failed = invariants.filter(([, ok]) => !ok).map(([name]) => name);
  if (failed.length) {
    const error = new Error('P0 homepage integrity failure (' + source + '): ' + failed.join('; '));
    error.code = 'HOMEPAGE_INTEGRITY_FAILED';
    throw error;
  }
  return text;
}

module.exports = { assertHomepageIntegrity };
