'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { getCustomerRouteContracts, verifyBuiltRouteContracts, builtRouteFile } =
  require('../scripts/preflight-customer-route-markers.cjs');
const { brandHtml } = require('../scripts/sentinel-branding.cjs');

const workflow = fs.readFileSync(
  path.join(__dirname, '../.github/workflows/cloudflare-production-deploy.yml'), 'utf8'
);

test('production workflow specifies 13+ unique, safe customer routes', () => {
  const routes = getCustomerRouteContracts(workflow);
  assert.ok(routes.length >= 13);
  assert.equal(new Set(routes.map(r => r.route)).size, routes.length);
  assert.equal(routes.find(r => r.route === '/api-dashboard.html')?.marker,
    'API Dashboard — SENTINEL APEX');
});

test('API dashboard marker matches the final post-branding document title', () => {
  const source = fs.readFileSync(path.join(__dirname, '../api-dashboard.html'), 'utf8');
  const branded = brandHtml(source, 'SENTINEL APEX Research Blog / Intel Factory');
  assert.match(branded, /<title>API Dashboard — SENTINEL APEX<\/title>/);
  assert.doesNotMatch(branded, /API Dashboard — CYBERDUDEBIVASH SENTINEL APEX/);
});

test('pricing and enterprise route markers match transformed customer-facing titles', () => {
  const contracts = getCustomerRouteContracts(workflow);
  const names = [
    ['pricing.html', '/pricing.html', 'Pricing — SENTINEL APEX Threat Intelligence Plans | SENTINEL APEX'],
    ['enterprise.html', '/enterprise.html', 'Enterprise Threat Intelligence Platform — SENTINEL APEX | SENTINEL APEX'],
  ];
  for (const [name, route, title] of names) {
    const source = fs.readFileSync(path.join(__dirname, '..', name), 'utf8');
    const rendered = brandHtml(source, 'SENTINEL APEX Research Blog / Intel Factory');
    const actual = /<title[^>]*>([^<]*)<\/title>/i.exec(rendered)?.[1];
    assert.equal(actual, title);
    assert.equal(contracts.find(contract => contract.route === route)?.marker, actual);
  }
});

test('pre-deploy preflight catches a stale title without touching Cloudflare', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'apex-contract-'));
  try {
    const contracts = getCustomerRouteContracts(workflow);
    for (const contract of contracts) {
      const file = builtRouteFile(root, contract.route);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, '<title>' + contract.marker + '</title>');
    }
    assert.deepEqual(verifyBuiltRouteContracts(workflow, root), { total: contracts.length, failures: [] });
    const dashboard = builtRouteFile(root, '/api-dashboard.html');
    fs.writeFileSync(dashboard, '<title>API Dashboard — obsolete branding</title>');
    const result = verifyBuiltRouteContracts(workflow, root);
    assert.deepEqual(result.failures.map(x => x.route), ['/api-dashboard.html']);
    assert.equal(result.failures[0].problem, 'stale or missing exact marker');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('reject traversal, duplicate routes and accidentally removed mandatory checks', () => {
  assert.throws(() => getCustomerRouteContracts('customer_route_check "/x.html" "x"'),
    /expected at least 13/);
  assert.throws(() => getCustomerRouteContracts(Array(13).fill(
    'customer_route_check "/x.html" "x"').join('\n')), /duplicate/i);
  const unsafe = Array.from({ length: 13 }, (_, i) =>
    'customer_route_check "/' + (i === 0 ? '../secret' : 'route-' + i + '.html') + '" "x"').join('\n');
  assert.throws(() => getCustomerRouteContracts(unsafe), /invalid/i);
});
