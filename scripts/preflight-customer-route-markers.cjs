#!/usr/bin/env node
'use strict';

/**
 * Verifies the EXACT customer-route markers used by the production
 * post-deploy check against the build output BEFORE Cloudflare is changed.
 * Deliberately checks the deployed build, not the unbranded repository HTML.
 *
 * No HTTP, credentials, DNS, Cloudflare or other side effects.
 */
const fs = require('node:fs');
const path = require('node:path');

const MIN_ROUTES = 13;
const EXACT_CHECK = /^\s*customer_route_check\s+"(\/[^"\s]*)"\s+"([^"\r\n]+)"\s*$/gm;

function getCustomerRouteContracts(workflow) {
  if (typeof workflow !== 'string') throw new TypeError('Workflow text required');
  const contracts = [];
  for (const match of workflow.matchAll(EXACT_CHECK)) {
    contracts.push({ route: match[1], marker: match[2] });
  }
  if (contracts.length < MIN_ROUTES) {
    throw new Error('Production route certification missing: expected at least ' + MIN_ROUTES +
      ' static route checks; found ' + contracts.length);
  }
  const seen = new Set();
  for (const { route, marker } of contracts) {
    if (route.includes('..') || route.includes('?') || route.includes('#') ||
        !/^\/[a-zA-Z0-9/_-]+(?:\.html)?\/?$/.test(route) ||
        !marker.trim() || seen.has(route)) {
      throw new Error('Invalid or duplicate production route contract: ' + route);
    }
    seen.add(route);
  }
  return contracts;
}

function builtRouteFile(distDir, route) {
  // Directory URLs resolve to /index.html, same as the deployed shell gate.
  const relative = route.endsWith('/') ? route.slice(1) + 'index.html' : route.slice(1);
  const root = path.resolve(distDir);
  const resolved = path.resolve(root, relative);
  if (!resolved.startsWith(root + path.sep)) throw new Error('Route escaped build root');
  return resolved;
}

function verifyBuiltRouteContracts(workflowText, distDir) {
  const contracts = getCustomerRouteContracts(workflowText);
  const failures = [];
  for (const { route, marker } of contracts) {
    const file = builtRouteFile(distDir, route);
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
      failures.push({ route, problem: 'built HTML missing', file });
      continue;
    }
    const html = fs.readFileSync(file, 'utf8');
    if (!html.includes(marker)) {
      const title = (/<title[^>]*>([^<]*)<\/title>/i.exec(html) || [])[1] || 'not found';
      failures.push({ route, problem: 'stale or missing exact marker', expected: marker, builtTitle: title });
    }
  }
  return { total: contracts.length, failures };
}

function main() {
  const repoRoot = path.resolve(__dirname, '..');
  const workflow = fs.readFileSync(path.join(repoRoot, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');
  const dir = process.argv[2] || path.join(repoRoot, 'dist-public');
  const report = verifyBuiltRouteContracts(workflow, dir);
  for (const failure of report.failures) {
    process.stderr.write('::error::PREDEPLOY MARKER PARITY ' + JSON.stringify(failure) + '\n');
  }
  if (report.failures.length) {
    process.stderr.write('BLOCK: ' + report.failures.length + '/' + report.total +
      ' customer routes diverge between certification and Cloudflare build.\n');
    process.exitCode = 1;
  } else {
    process.stdout.write('PASS: ' + report.total +
      ' customer-route certification markers present in actual Cloudflare build.\n');
  }
}

if (require.main === module) main();
module.exports = { getCustomerRouteContracts, builtRouteFile, verifyBuiltRouteContracts };
