#!/usr/bin/env node
'use strict';
/**
 * P0 source publisher staged-output boundary.
 *
 * The high-frequency publisher writes a bounded set of public intelligence
 * assets. Never commit arbitrary working-tree paths via its legacy git add -A:
 * unexpected code, workflows, customer state or secrets require a separate
 * reviewed change. The check is read-only; it never stages or rewrites data.
 */
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const ROOT = path.join(__dirname, '..');
const MAX_FILES = 1000;
const EXACT = new Set([
  'index.html', 'rss.xml', 'sitemap.xml', 'search-index.json',
  'live-intel.json', 'intel-state.json', 'intel-memory.json',
  'data/ioc-feed.json', 'data/ioc-store.json'
]);
const API_ROOT_FEEDS = new Set([
  'api/intel/live.json', 'api/intel/top-threats.json',
  'api/intel/raw.json', 'api/intel/campaigns.json',
  'api/intel/ransomware.json', 'api/intel/iocs.json',
  'api/intel/threat-graph.json'
]);

function isApprovedPath(file) {
  if (typeof file !== 'string' || !file || Buffer.byteLength(file, 'utf8') > 512 ||
      !/^[\x20-\x7e]+$/.test(file) || file.startsWith('/') || file.includes('\\'))
    return false;
  const parts = file.split('/');
  if (parts.some(p => !p || p === '.' || p === '..' || p.startsWith('.')) ||
      path.posix.normalize(file) !== file)
    return false;
  return EXACT.has(file) || API_ROOT_FEEDS.has(file) ||
    /^posts\/[a-z0-9][a-z0-9-]*\.html$/.test(file) ||
    /^api\/intel\/cve\/CVE-\d{4}-\d{4,7}\.json$/.test(file) ||
    /^api\/intel\/products\/[a-z0-9][a-z0-9-]*\.json$/.test(file);
}

function assessStagedPaths(files, stat=filename=>fs.lstatSync(path.join(ROOT,filename))) {
  if (!Array.isArray(files) || files.length > MAX_FILES ||
      files.some(f => typeof f !== 'string'))
    return {status:'HOLD',reason:'STAGED_PATH_SET_UNAVAILABLE'};
  let rejected = 0;
  for (const filename of files) {
    if (!isApprovedPath(filename)) { rejected++; continue; }
    try {
      const entry = stat(filename);
      // A deleted file, symlink, directory or submodule cannot be published.
      if (!entry || !entry.isFile() || entry.isSymbolicLink()) rejected++;
    } catch (_) { rejected++; }
  }
  return rejected
    ? {status:'HOLD',reason:'UNREVIEWED_OR_NONREGULAR_PUBLISHER_STAGED_PATH',rejected}
    : {status:'PASS',reason:'PUBLISHER_STAGED_PATHS_APPROVED',files:files.length};
}

function stagedPaths() {
  // Disable rename detection so the source of a rename is also inspected.
  // -z preserves unusual pathnames; an unterminated output is rejected.
  const raw = execFileSync('git',[
    'diff','--cached','--name-only','--no-renames','-z'
  ],{cwd:ROOT,encoding:'utf8',maxBuffer:4*1024*1024});
  if (raw && !raw.endsWith('\0')) throw Error('STAGED_PATH_STREAM_INVALID');
  return raw ? raw.slice(0,-1).split('\0') : [];
}

if (require.main === module) {
  try {
    if (process.argv.length !== 2) throw Error('NO_ARGUMENTS_ALLOWED');
    const verdict = assessStagedPaths(stagedPaths());
    if (verdict.status !== 'PASS') {
      // Do not print potentially sensitive, unreviewed filenames to Actions.
      console.error('HOLD: '+verdict.reason+' count='+(verdict.rejected ?? 'unknown'));
      process.exitCode=2;
    } else {
      console.log('PASS: publisher staged '+verdict.files+' approved public assets');
    }
  } catch (_) {
    console.error('HOLD: PUBLISHER_STAGED_OUTPUT_INSPECTION_FAILED');
    process.exitCode=2;
  }
}
module.exports = {isApprovedPath,assessStagedPaths,MAX_FILES};
