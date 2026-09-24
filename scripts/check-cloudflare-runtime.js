'use strict';

// Release gate for the supported HTTP runtime. No credentials or network calls.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { applyBaselineHeaders } = require('../workers/lib/security-headers');
const { HEADERS_FILE_CONTENT } = require('./build-cloudflare-assets');
const root = path.resolve(__dirname, '..');

for (const file of ['vercel.json', '.vercelignore', 'vercel-ignore-build.sh']) {
  assert.equal(fs.existsSync(path.join(root, file)), false, `Retired deployment file reintroduced: ${file}`);
}
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
for (const name of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) {
  assert.ok(name !== 'vercel' && !name.startsWith('@vercel/'), `Retired deployment dependency: ${name}`);
}
const required = ['Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy', 'Content-Security-Policy'];
for (const status of [200, 302, 404, 500]) {
  const response = applyBaselineHeaders(new Response(null, { status }));
  for (const header of required) assert.ok(response.headers.get(header), `${status}: missing ${header}`);
  assert.match(response.headers.get('Cache-Control'), /no-store/, `${status}: dynamic response must not be shared-cacheable`);
}
// Parse the actual generated asset header policy, preserving route blocks.
const blocks = new Map();
let current;
for (const line of HEADERS_FILE_CONTENT.split(/\r?\n/)) {
  if (!line.trim() || line.trimStart().startsWith('#')) continue;
  if (!/^\s/.test(line)) { current = new Map(); blocks.set(line.trim(), current); continue; }
  const match = line.match(/^\s+([^:]+):\s*(.+)$/);
  assert.ok(match && current, 'Malformed generated asset header policy');
  current.set(match[1].toLowerCase(), match[2]);
}
for (const route of ['/', '/*.html']) {
  assert.ok(blocks.has(route), `Missing HTML header policy: ${route}`);
  const effective = new Map([...(blocks.get('/*') || []), ...blocks.get(route)]);
  for (const header of required) assert.ok(effective.get(header.toLowerCase()), `${route}: missing ${header}`);
  assert.match(effective.get('content-security-policy'), /checkout\.razorpay\.com/, `${route}: checkout CSP must be retained`);
}
console.log('Cloudflare runtime gate passed: retired files absent, dynamic and static headers enforced.');
