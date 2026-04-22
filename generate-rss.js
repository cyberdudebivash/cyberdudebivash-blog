#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH SENTINEL APEX — RSS 2.0 Generator
 * Scans /posts/, extracts metadata from HTML, builds production-valid rss.xml
 * Compatible with: LinkedIn, Google News, Feedly, RSS readers
 * Run: node generate-rss.js
 */

const fs = require('fs');
const path = require('path');

// ─── CONFIG ────────────────────────────────────────────────────────────────────
const BASE_URL    = 'https://blog.cyberdudebivash.in';
const POSTS_DIR   = path.join(__dirname, 'posts');
const OUTPUT_FILE = path.join(__dirname, 'rss.xml');
const MAX_ITEMS   = 50;
const FEED_CONFIG = {
  title:       'CyberDudeBivash SENTINEL APEX — Cyber Threat Intelligence',
  link:        BASE_URL,
  feedUrl:     `${BASE_URL}/rss.xml`,
  description: 'Real-time cybersecurity threat intelligence: CVE analysis, zero-day exploits, ransomware tracking, APT campaigns, IOCs, YARA rules & enterprise defense strategies.',
  language:    'en-us',
  copyright:   `Copyright ${new Date().getFullYear()} CyberDudeBivash. All rights reserved.`,
  managingEditor: 'bivash@cyberdudebivash.com (CyberDudeBivash)',
  webMaster:   'bivash@cyberdudebivash.com (CyberDudeBivash)',
  category:    'Cybersecurity',
  ttl:         60,
  imageUrl:    `${BASE_URL}/apex-logo.png`,
};

// ─── HELPERS ───────────────────────────────────────────────────────────────────

/** Escape XML special characters */
function xmlEscape(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Extract a single meta tag content value */
function extractMeta(html, name) {
  const patterns = [
    new RegExp(`<meta\\s+name=["']${name}["']\\s+content=["']([^"']+)["']`, 'i'),
    new RegExp(`<meta\\s+content=["']([^"']+)["']\\s+name=["']${name}["']`, 'i'),
  ];
  for (const rx of patterns) {
    const m = html.match(rx);
    if (m) return m[1].trim();
  }
  return '';
}

/** Extract OG meta tag */
function extractOG(html, property) {
  const patterns = [
    new RegExp(`<meta\\s+property=["']og:${property}["']\\s+content=["']([^"']+)["']`, 'i'),
    new RegExp(`<meta\\s+content=["']([^"']+)["']\\s+property=["']og:${property}["']`, 'i'),
  ];
  for (const rx of patterns) {
    const m = html.match(rx);
    if (m) return m[1].trim();
  }
  return '';
}

/** Extract <title> tag content */
function extractTitle(html) {
  const m = html.match(/<title>([^<]+)<\/title>/i);
  return m ? m[1].trim() : '';
}

/** Extract datePublished from JSON-LD or visible date spans */
function extractDate(html, filename) {
  // Try JSON-LD datePublished
  const jsonLdMatch = html.match(/"datePublished"\s*:\s*"(\d{4}-\d{2}-\d{2})"/i);
  if (jsonLdMatch) return jsonLdMatch[1];

  // Try visible date span patterns: "22 April 2026" or "April 22, 2026"
  const spanMatch = html.match(/(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i);
  if (spanMatch) {
    const months = { january:'01',february:'02',march:'03',april:'04',may:'05',june:'06',
                     july:'07',august:'08',september:'09',october:'10',november:'11',december:'12' };
    const d = spanMatch[1].padStart(2,'0');
    const mo = months[spanMatch[2].toLowerCase()];
    const y = spanMatch[3];
    return `${y}-${mo}-${d}`;
  }

  // Fallback: parse date from filename (e.g. "...april-2026...")
  if (filename.includes('april-2026')) return '2026-04-22';
  if (filename.includes('2026')) return '2026-04-22';

  // Last resort: today
  return new Date().toISOString().slice(0,10);
}

/** Parse ISO date string to RFC 822 format for RSS */
function toRFC822(dateStr) {
  // dateStr: YYYY-MM-DD
  const d = new Date(`${dateStr}T12:00:00Z`);
  return d.toUTCString().replace('GMT', '+0000');
}

/** Extract first 200 words of readable text from HTML body */
function extractSummary(html, maxWords = 200) {
  // Remove script, style, code blocks
  let text = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<code[\s\S]*?<\/code>/gi, '')
    .replace(/<pre[\s\S]*?<\/pre>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#\d+;/g, '')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();

  const words = text.split(' ').filter(w => w.length > 0);
  const snippet = words.slice(0, maxWords).join(' ');
  return snippet.length < text.length ? snippet + '...' : snippet;
}

/** Extract canonical URL from HTML, fallback to computed URL */
function extractCanonical(html, filename) {
  const m = html.match(/<link\s+rel=["']canonical["']\s+href=["']([^"']+)["']/i);
  if (m) return m[1].trim();
  return `${BASE_URL}/posts/${filename}`;
}

/** Extract keywords from meta tags */
function extractKeywords(html) {
  return extractMeta(html, 'keywords');
}

// ─── MAIN ──────────────────────────────────────────────────────────────────────

function buildRSS() {
  console.log('[RSS Generator] Scanning posts directory:', POSTS_DIR);

  if (!fs.existsSync(POSTS_DIR)) {
    console.error('[RSS Generator] ERROR: posts/ directory not found!');
    process.exit(1);
  }

  const postFiles = fs.readdirSync(POSTS_DIR)
    .filter(f => f.endsWith('.html'))
    .sort(); // deterministic order; will sort by date below

  console.log(`[RSS Generator] Found ${postFiles.length} post(s)`);

  const items = [];

  for (const filename of postFiles) {
    const filePath = path.join(POSTS_DIR, filename);
    const html = fs.readFileSync(filePath, 'utf-8');

    // Extract metadata
    const rawTitle = extractTitle(html) || extractOG(html, 'title');
    // Clean title: remove site suffix after " | "
    const title = rawTitle.includes(' | ')
      ? rawTitle.split(' | ').slice(0, -1).join(' | ')
      : rawTitle;

    const description = extractMeta(html, 'description') || extractOG(html, 'description') || extractSummary(html, 50);
    const link        = extractCanonical(html, filename);
    const dateStr     = extractDate(html, filename);
    const keywords    = extractKeywords(html);
    const summary     = extractSummary(html, 200);

    // Determine categories from keywords + filename
    const categories = [];
    if (filename.startsWith('cve-')) categories.push('CVE Analysis', 'Vulnerability Intelligence');
    if (filename.includes('ransomware')) categories.push('Ransomware', 'Threat Intelligence');
    if (filename.includes('apt') || filename.includes('volt-typhoon')) categories.push('APT', 'Nation-State Threats');
    if (filename.includes('ai-') || filename.includes('llm')) categories.push('AI Security');
    if (categories.length === 0) categories.push('Cyber Threat Intelligence');
    categories.push('Cybersecurity');

    items.push({ title, link, description, summary, dateStr, keywords, categories, filename });
  }

  // Sort newest-first by date
  items.sort((a, b) => (b.dateStr > a.dateStr ? 1 : b.dateStr < a.dateStr ? -1 : 0));

  const latestItems = items.slice(0, MAX_ITEMS);
  const lastBuildDate = toRFC822(latestItems[0]?.dateStr || new Date().toISOString().slice(0,10));

  console.log(`[RSS Generator] Building feed with ${latestItems.length} item(s)`);

  // ─── BUILD XML ───────────────────────────────────────────────────────────────

  const itemsXML = latestItems.map(item => {
    const categoryTags = [...new Set(item.categories)]
      .map(c => `    <category>${xmlEscape(c)}</category>`)
      .join('\n');

    // Description: use meta description (SEO-optimized), then summary
    const desc = item.description || item.summary;

    return `  <item>
    <title>${xmlEscape(item.title)}</title>
    <link>${xmlEscape(item.link)}</link>
    <guid isPermaLink="true">${xmlEscape(item.link)}</guid>
    <pubDate>${toRFC822(item.dateStr)}</pubDate>
    <description><![CDATA[${desc}]]></description>
    <content:encoded><![CDATA[<p>${desc}</p><p><a href="${item.link}" target="_blank" rel="noopener">🔗 Read Full Intel Report →</a></p><p><strong>🛡️ Get Premium Threat Intel:</strong> <a href="${BASE_URL}/products.html">CyberDudeBivash Products</a></p>]]></content:encoded>
    <author>bivash@cyberdudebivash.com (CyberDudeBivash)</author>
${categoryTags}
    <source url="${FEED_CONFIG.feedUrl}">${xmlEscape(FEED_CONFIG.title)}</source>
  </item>`;
  }).join('\n\n');

  const rssXML = `<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="/rss-style.xsl"?>
<rss version="2.0"
  xmlns:content="http://purl.org/rss/1.0/modules/content/"
  xmlns:atom="http://www.w3.org/2005/Atom"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:media="http://search.yahoo.com/mrss/">
  <channel>
    <title>${xmlEscape(FEED_CONFIG.title)}</title>
    <link>${FEED_CONFIG.link}</link>
    <atom:link href="${FEED_CONFIG.feedUrl}" rel="self" type="application/rss+xml"/>
    <description>${xmlEscape(FEED_CONFIG.description)}</description>
    <language>${FEED_CONFIG.language}</language>
    <copyright>${xmlEscape(FEED_CONFIG.copyright)}</copyright>
    <managingEditor>${xmlEscape(FEED_CONFIG.managingEditor)}</managingEditor>
    <webMaster>${xmlEscape(FEED_CONFIG.webMaster)}</webMaster>
    <lastBuildDate>${lastBuildDate}</lastBuildDate>
    <pubDate>${lastBuildDate}</pubDate>
    <ttl>${FEED_CONFIG.ttl}</ttl>
    <category>Cybersecurity</category>
    <category>Threat Intelligence</category>
    <category>CVE Analysis</category>
    <category>Zero-Day Exploits</category>
    <generator>CyberDudeBivash SENTINEL APEX RSS Engine v3.0</generator>
    <docs>https://www.rssboard.org/rss-specification</docs>
    <image>
      <url>${FEED_CONFIG.imageUrl}</url>
      <title>${xmlEscape(FEED_CONFIG.title)}</title>
      <link>${FEED_CONFIG.link}</link>
      <width>144</width>
      <height>144</height>
    </image>

${itemsXML}

  </channel>
</rss>`;

  fs.writeFileSync(OUTPUT_FILE, rssXML, 'utf-8');
  console.log(`[RSS Generator] ✅ SUCCESS: ${OUTPUT_FILE}`);
  console.log(`[RSS Generator] Feed URL: ${FEED_CONFIG.feedUrl}`);
  console.log(`[RSS Generator] Items: ${latestItems.length}`);
  console.log(`[RSS Generator] Last build: ${lastBuildDate}`);
}

// ─── ENTRY POINT ──────────────────────────────────────────────────────────────
buildRSS();
