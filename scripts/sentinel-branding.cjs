'use strict';

// Build-time presentation branding. Never run a repository-wide string replace:
// technical identifiers, URLs, scripts, code examples and seller records are not brands.
const fs = require('node:fs');
const path = require('node:path');
const BRAND = /(?<![\w@./-])CYBERDUDEBIVASH(?!(?:\.(?:com|in))|[\w/-])(?:®|&reg;|&#174;|\(R\))?/gi;
const ATTRIBUTION = '<div data-sentinel-attribution="true" style="display:flex;justify-content:center;flex-wrap:wrap;padding:20px 16px;background:#070d18"><a data-sentinel-parent="true" href="https://www.cyberdudebivash.com/" style="display:inline-flex;align-items:center;min-height:44px;padding:10px 16px;border:1px solid #67e8f9;border-radius:8px;color:#ffffff;background:#101c2e;font:700 16px/1.5 system-ui,sans-serif;text-decoration:underline;text-underline-offset:4px">Powered By CYBERDUDEBIVASH</a></div>';
const FOCUS_STYLE = '<style data-sentinel-branding="true">a[data-sentinel-parent]:focus-visible{outline:3px solid #67e8f9;outline-offset:4px}a[data-sentinel-parent]:hover{background:#183048!important}</style>';
const RAW = new Set(['script', 'style', 'code', 'pre', 'svg', 'textarea']);
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
const SELLER = /\b(?:GSTIN|PAN:|seller.of.record|legal.entity|beneficiary|trademarks?|proprietorship|licensor|copyright holder|operated by|trading as|payee|Pvt\.?\s+Ltd\.?|Private\s+Limited)\b/i;

function displayName(value) {
  return value.replace(BRAND, 'SENTINEL APEX')
    .replace(/SENTINEL APEX\s+(?:SENTINEL\s+APEX)(?:™|&trade;)?/gi, 'SENTINEL APEX')
    .replace(/Sentinel Apex/gi, 'SENTINEL APEX');
}

function brandHtml(source, platformName) {
  if (typeof platformName !== 'string' || !platformName.startsWith('SENTINEL APEX')) {
    throw new Error('A canonical SENTINEL APEX platform name is required');
  }
  let raw = null;
  const stack = [];
  const input = String(source).replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script>)/gi, (all, open, text, close) => {
    if (!/type=["']application\/ld\+json["']/i.test(open)) {
      // Narrow legacy UI-template treatment. Operational/payment/license scripts
      // are byte-preserved; only plain text inside literal display tags changes.
      if (/\b(?:UPI|razorpay|payee|beneficiary|payment|license|protocol)\b/i.test(text)) return all;
      const changed = text.replace(/(<(?:div|span|p|h[1-6])\b[^>]*>)([^<>\n]{1,240})(?=<\/)/gi,
        (match, tag, label) => SELLER.test(label) || /\b(?:id|class)=["'][^"']*(?:wire|upi|seller)/i.test(tag) ? match : tag + displayName(label));
      return changed === text ? all : open + changed + close;
    }
    try {
      const document = JSON.parse(text);
      let changed = false;
      function visit(value) {
        if (!value || typeof value !== 'object') return;
        const types = [value['@type']].flat();
        if (types.includes('WebSite')) { changed ||= value.name !== platformName; value.name = platformName; }
        if (types.includes('SoftwareApplication') && typeof value.name === 'string') {
          const name = displayName(value.name); changed ||= value.name !== name; value.name = name;
        }
        Object.values(value).forEach(visit);
      }
      visit(document);
      return changed ? open + JSON.stringify(document, null, 2) + close : all;
    } catch { return all; }
  });
  const tokens = input.match(/<!--[\s\S]*?-->|<![^>]*>|<\/?[A-Za-z][^>"']*(?:(?:"[^"]*"|'[^']*')[^>"']*)*>|[^<]+|</g) || [];
  let out = tokens.map((token) => {
    if (raw) {
      if (new RegExp('^</' + raw + '\\s*>$', 'i').test(token)) raw = null;
      return token;
    }
    if (token.startsWith('<!--') || token.startsWith('<!')) return token;
    if (token.startsWith('<')) {
      const tag = token.match(/^<(\/)?([\w:-]+)/);
      if (!tag) return token;
      const name = tag[2].toLowerCase();
      if (tag[1]) {
        const index = stack.map((item) => item.name).lastIndexOf(name);
        if (index >= 0) stack.splice(index);
        return token;
      }
      if (RAW.has(name)) { raw = name; return token; }
      const protectedHere = stack.some((item) => item.protected) || /data-sentinel-(?:parent|attribution)=/.test(token)
        || /\b(?:id|class)=["'][^"']*(?:seller-of-record|legal-entity|payment-beneficiary|m-wire-|upi-|invoice|receipt|license-identity)[^"']*["']/i.test(token);
      if (!VOID.has(name) && !/\/>$/.test(token)) stack.push({ name, protected: protectedHere });
      if (protectedHere) return token;
      // Only human-readable attributes. Never href/src/id/data-* or handlers.
      let changed = token.replace(/(\s(?:title|alt|aria-label)\s*=\s*)(["'])([\s\S]*?)\2/gi,
        (all, prefix, quote, text) => SELLER.test(text) || /\bUPI\b/i.test(text) ? all : prefix + quote + displayName(text) + quote);
      if (name === 'meta' && /(?:name|property)=["'](?:description|keywords|application-name|og:(?:title|site_name|description|image:alt)|twitter:(?:title|description|image:alt))["']/i.test(token)) {
        changed = changed.replace(/(\scontent\s*=\s*)(["'])([\s\S]*?)\2/i,
          (_, prefix, quote, text) => prefix + quote + (/property=["']og:site_name["']/i.test(token) ? platformName : displayName(text)) + quote);
      }
      return changed;
    }
    return stack.some((item) => item.protected) || SELLER.test(token) ? token : displayName(token);
  }).join('');
  // Every browser page receives one accessible attribution inside a footer.
  // Document fragments are intentionally not wrapped or otherwise rewritten.
  if (!/<body\b/i.test(out) || !/<\/body\s*>/i.test(out)) return out;
  if (!out.includes('data-sentinel-attribution=')) {
    const footer = out.toLowerCase().lastIndexOf('</footer>');
    out = footer >= 0 ? out.slice(0, footer) + ATTRIBUTION + out.slice(footer)
      : out.replace(/<\/body\s*>/i, '<footer aria-label="Platform attribution">' + ATTRIBUTION + '</footer>\n</body>');
  }
  if (!out.includes('data-sentinel-branding=')) out = out.replace(/<\/head\s*>/i, FOCUS_STYLE + '\n</head>');
  return out;
}

function brandDirectory(directory, platformName) {
  let count = 0;
  for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, item.name);
    if (item.isSymbolicLink()) throw new Error('Refusing symlink in public artifact: ' + file);
    if (item.isDirectory()) count += brandDirectory(file, platformName);
    else if (/\.html$/i.test(item.name)) {
      const before = fs.readFileSync(file, 'utf8');
      const after = brandHtml(before, platformName);
      if (before !== after) fs.writeFileSync(file, after);
      count++;
    }
  }
  return count;
}

if (require.main === module) {
  const [directory, platformName] = process.argv.slice(2);
  if (!directory || !fs.statSync(directory).isDirectory()) throw new Error('Existing public artifact directory required');
  console.log('SENTINEL APEX branding: ' + brandDirectory(directory, platformName) + ' HTML files');
}
module.exports = { brandHtml, brandDirectory, displayName };
