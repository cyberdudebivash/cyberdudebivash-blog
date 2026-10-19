'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../.github/workflows/cloudflare-production-deploy.yml'),'utf8');

test('production route checker remains fail closed on exact customer marker', () => {
  assert.match(source, /if \[ "\$code" = "200" \] && grep -Fq "\$marker" "\$file"/);
  assert.match(source, /Customer route \$route failed marker/);
  assert.match(source, /customer_route_check "\/api-dashboard\.html" "API Dashboard — CYBERDUDEBIVASH SENTINEL APEX"/);
  assert.match(source, /exit 1\n          }\n\n          customer_route_check/);
});
test('route mismatch records sufficient privacy-bounded evidence', () => {
  for (const snippet of ['sha256sum "$file"','sha256sum "$local_page"','sha256sum "$plain_body"',
    'cf-ray:', 'cache-control:', 'last-modified:', 'etag:', 'cmp -s "$local_page" "$file"',
    'Customer route response evidence:', "grep -oiE '<title"]) assert.ok(source.includes(snippet),snippet);
  assert.match(source, /--proto '=https' --proto-redir '=https'/);
  assert.match(source, /--max-filesize 3000000/);
  assert.ok(!source.includes('cat "$file"'));
});
