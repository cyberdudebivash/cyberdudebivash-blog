#!/usr/bin/env node
'use strict';
/**
 * Content-addressed SOC release manifest + approval verifier (READ-ONLY, ADDITIVE).
 *
 * Why: publisher commits advance `main` every ~25-30 minutes, so an owner approval pinned only to
 * "the SHA that is main right now" is stale before the deploy job reaches its last-mile check.
 * Approval can instead bind to WHAT will be deployed: the exact source SHA plus the digest of each
 * component (static assets, Worker code, Wrangler config/bindings, D1 migrations, the two public
 * feeds), the secret-name set, the target environment, a rollback target and a fresh account-wide
 * cost attestation. A later publisher commit cannot change those bytes.
 *
 * This module does NOT replace or relax scripts/soc-cloudflare-release-sha-gate.cjs, does NOT touch
 * the deploy workflow, and authorizes nothing: a PASS is `PASS_NOT_DEPLOY_AUTHORIZATION`. Wiring it
 * into a workflow needs a separate, explicit approval. No network, no Cloudflare API, no secrets
 * (only secret NAMES are digested), no repository writes except the --out manifest the operator asks for.
 *
 * Digest format is the same as `find . -type f | sort | xargs sha256sum | sha256sum`
 * (lines "<sha256>  ./<path>\n", byte-ordered by path), so an operator can reproduce it by hand.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MANIFEST_SCHEMA = 'cdb-soc-release-manifest/v1';
const APPROVAL_SCHEMA = 'cdb-soc-release-approval/v1';
const SHA40 = /^[a-f0-9]{40}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const VERSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const APPROVED_TARGETS = Object.freeze(['production']);
const MAX_ATTESTATION_AGE_MS = 2 * 60 * 60 * 1000;   // same bound as cloudflare-account-zero-overage-gate.cjs
const MAX_FEED_AGE_MS = 180 * 60 * 1000;             // same genuine-report bound as certify-soc-public-feed-parity.cjs
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const FEED_FILES = Object.freeze(['live-intel.json', 'api/intel/live.json']);
const COMPONENTS = Object.freeze(['assets', 'worker', 'config', 'migrations', 'feed']);

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const byteOrder = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

/** All regular files under `target` (a file or a directory), as POSIX paths relative to `base`. */
function collect(base, target, out) {
  const abs = path.join(base, target);
  const st = fs.lstatSync(abs);
  if (st.isSymbolicLink()) throw new Error('SYMLINK_IN_RELEASE_TREE');
  if (st.isFile()) { out.push(target.split(path.sep).join('/')); return; }
  if (!st.isDirectory()) throw new Error('SPECIAL_FILE_IN_RELEASE_TREE');
  for (const entry of fs.readdirSync(abs)) collect(base, path.join(target, entry), out);
}

/** Digest over the listed files/directories, relative to `base`. Missing path -> throws. */
function digestPaths(base, targets) {
  const files = [];
  for (const t of targets) collect(base, t, files);
  const unique = [...new Set(files)].sort(byteOrder);
  for (const f of unique) {
    if (/[\\\n\r]/.test(f)) throw new Error('UNSUPPORTED_FILE_NAME_IN_RELEASE_TREE');
  }
  const lines = unique.map((f) => `${sha256(fs.readFileSync(path.join(base, f)))}  ./${f}\n`);
  return { digest: sha256(lines.join('')), files: unique.length };
}

/** Digest of one file's bytes. */
function digestFile(file) { return sha256(fs.readFileSync(file)); }

/**
 * Build the manifest of the CURRENT tree. Deterministic: no timestamps, no host paths, byte-ordered.
 * @param {{root:string, sourceSha:string, assetsDir?:string, workerPaths?:string[], configPath?:string, migrationsDir?:string}} o
 */
function buildManifest(o) {
  const root = path.resolve(o.root || '.');
  const sourceSha = String(o.sourceSha || '').toLowerCase();
  if (!SHA40.test(sourceSha)) throw new Error('SOURCE_SHA_INVALID');
  const assetsDir = o.assetsDir || 'dist-public';
  const workerPaths = o.workerPaths || ['workers'];
  const configPath = o.configPath || 'wrangler.jsonc';
  const migrationsDir = o.migrationsDir || 'migrations';

  // assets and migrations are digested relative to their own directory, exactly like
  // `cd dist-public && find . -type f | sort | xargs sha256sum | sha256sum`; the Worker spans several
  // paths, so its lines are relative to the repository root (`find workers -type f | ...`).
  const assets = digestPaths(path.join(root, assetsDir), ['.']);
  const worker = digestPaths(root, workerPaths);
  const config = { digest: digestFile(path.join(root, configPath)) };
  const migrations = fs.existsSync(path.join(root, migrationsDir))
    ? digestPaths(path.join(root, migrationsDir), ['.'])
    : { digest: sha256(''), files: 0 };

  const feedLines = FEED_FILES.map((f) => `${f}=${digestFile(path.join(root, assetsDir, f))}\n`);
  let generatedAt = null; let totalPublished = null;
  try {
    const live = JSON.parse(fs.readFileSync(path.join(root, assetsDir, 'live-intel.json'), 'utf8'));
    generatedAt = typeof live.generatedAt === 'string' ? live.generatedAt : null;
    totalPublished = Number.isSafeInteger(live.totalPublished) ? live.totalPublished : null;
  } catch { /* an unreadable feed leaves generated_at null, which verify() reports as stale */ }
  const feed = { digest: sha256(feedLines.join('')), generated_at: generatedAt, total_published: totalPublished };

  const components = { assets, worker, config, migrations, feed };
  const manifest = { schema: MANIFEST_SCHEMA, source_sha: sourceSha, components };
  manifest.manifest_digest = manifestDigest(manifest);
  return manifest;
}

function manifestDigest(m) {
  const c = m.components;
  return sha256(JSON.stringify([m.schema, m.source_sha, ...COMPONENTS.map((k) => [k, c[k]?.digest ?? null])]));
}

/** Digest of the sorted secret NAMES (never values). */
function digestSecretNames(names) {
  if (!Array.isArray(names) || !names.every((n) => typeof n === 'string' && n.length > 0)) return null;
  return sha256([...new Set(names)].sort(byteOrder).join('\n'));
}

/**
 * Verify an approval against what is about to be deployed.
 * @param {{approval:object, observed:object, now?:string|number|Date}} p
 *   observed = { manifest (rebuilt from the tree being deployed), sourceSha (checked-out HEAD),
 *                targetEnvironment, secretNames (array of names, e.g. from `wrangler secret list`) }
 * @returns {{status:'HOLD'|'PASS_NOT_DEPLOY_AUTHORIZATION', codes:string[]}}
 */
function verifyRelease({ approval, observed, now = Date.now() } = {}) {
  const codes = new Set();
  const nowMs = new Date(now).getTime();
  const hold = () => ({ status: 'HOLD', codes: [...codes].sort() });

  if (!isObj(approval) || approval.schema !== APPROVAL_SCHEMA || !isObj(observed) ||
      !isObj(observed.manifest) || observed.manifest.schema !== MANIFEST_SCHEMA ||
      !isObj(observed.manifest.components) || !Number.isFinite(nowMs)) {
    codes.add('APPROVAL_OR_EVIDENCE_INVALID');
    return hold();
  }
  const m = observed.manifest;
  const a = approval;
  const ac = isObj(a.components) ? a.components : {};

  // 1. Exact source identity: the approved SHA is the SHA of the tree being deployed.
  const sha = (x) => (typeof x === 'string' && SHA40.test(x) ? x : null);
  if (!sha(a.source_sha) || !sha(m.source_sha) || !sha(observed.sourceSha)) codes.add('SOURCE_SHA_INVALID');
  else if (a.source_sha !== m.source_sha || a.source_sha !== observed.sourceSha) codes.add('WRONG_SHA');

  // 2. Every pinned digest must be well-formed before it is compared.
  const pinned = [a.manifest_digest, ...COMPONENTS.map((k) => ac[k])];
  if (!pinned.every((d) => typeof d === 'string' && HEX64.test(d))) codes.add('INVALID_DIGEST_FORMAT');
  if (!HEX64.test(String(m.manifest_digest || ''))) codes.add('INVALID_DIGEST_FORMAT');

  // 3. The manifest must be internally consistent and be the approved one.
  if (HEX64.test(String(m.manifest_digest || '')) && manifestDigest(m) !== m.manifest_digest) {
    codes.add('MANIFEST_DIGEST_MISMATCH');
  }
  if (typeof a.manifest_digest === 'string' && HEX64.test(a.manifest_digest) && a.manifest_digest !== m.manifest_digest) {
    codes.add('MANIFEST_DIGEST_MISMATCH');
  }

  // 4. Each component, named, so a review sees WHAT changed.
  const component = (key, code) => {
    const want = ac[key]; const have = m.components[key]?.digest;
    if (typeof want === 'string' && HEX64.test(want) && typeof have === 'string' && want !== have) codes.add(code);
  };
  component('assets', 'ASSETS_MODIFIED');          // frontend
  component('worker', 'WORKER_CODE_MODIFIED');
  component('config', 'CONFIG_OR_BINDINGS_CHANGED');
  component('migrations', 'MIGRATIONS_CHANGED');
  component('feed', 'FEED_MODIFIED');

  // 5. Secret-name set (names only) must be pinned and unchanged.
  const pinnedSecrets = a.secret_names_digest;
  if (typeof pinnedSecrets !== 'string' || !HEX64.test(pinnedSecrets)) codes.add('SECRETS_SET_NOT_PINNED');
  else {
    const seen = digestSecretNames(observed.secretNames);
    if (seen === null) codes.add('SECRETS_SET_UNVERIFIABLE');
    else if (seen !== pinnedSecrets) codes.add('SECRETS_SET_CHANGED');
  }

  // 6. Target environment: approved, and the one being deployed to.
  if (!APPROVED_TARGETS.includes(a.target_environment) || observed.targetEnvironment !== a.target_environment) {
    codes.add('TARGET_ENVIRONMENT_NOT_APPROVED');
  }

  // 7. A rollback target must exist (a Worker version id) before anything is mutated.
  if (typeof a.rollback_version_id !== 'string' || !VERSION_ID.test(a.rollback_version_id)) {
    codes.add('ROLLBACK_TARGET_MISSING_OR_INVALID');
  }

  // 8. Account-wide cost attestation: present, receipt-shaped, and fresh at deploy time.
  const att = a.financial_attestation;
  if (!isObj(att) || typeof att.sha256 !== 'string' || !HEX64.test(att.sha256) || typeof att.attested_at !== 'string' ||
      !Number.isFinite(Date.parse(att.attested_at))) {
    codes.add('FINANCIAL_ATTESTATION_MISSING');
  } else {
    const age = nowMs - Date.parse(att.attested_at);
    if (age > MAX_ATTESTATION_AGE_MS || age < -FUTURE_SKEW_MS) codes.add('FINANCIAL_ATTESTATION_STALE');
  }

  // 9. Genuine report age is re-evaluated at deploy time against the artifact's own feed timestamp.
  const generated = Date.parse(m.components.feed?.generated_at ?? '');
  if (!Number.isFinite(generated) || nowMs - generated > MAX_FEED_AGE_MS || generated - nowMs > FUTURE_SKEW_MS) {
    codes.add('FEED_NOT_FRESH');
  }

  return codes.size ? hold() : { status: 'PASS_NOT_DEPLOY_AUTHORIZATION', codes: [] };
}

function usage() {
  return [
    'node scripts/soc-release-manifest.cjs build  --sha <40-hex> [--root .] [--out release-manifest.json]',
    'node scripts/soc-release-manifest.cjs verify --manifest <file> --approval <file> --sha <40-hex>',
    '        --target <environment> --secrets <json array of secret names> [--root .]',
  ].join('\n');
}

function arg(argv, name) { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; }

function main(argv) {
  const cmd = argv[0];
  try {
    if (cmd === 'build') {
      const manifest = buildManifest({ root: arg(argv, '--root') || '.', sourceSha: arg(argv, '--sha') });
      const text = JSON.stringify(manifest, null, 2) + '\n';
      const out = arg(argv, '--out');
      if (out) fs.writeFileSync(out, text); else process.stdout.write(text);
      return 0;
    }
    if (cmd === 'verify') {
      const root = arg(argv, '--root') || '.';
      const sourceSha = arg(argv, '--sha');
      const approval = JSON.parse(fs.readFileSync(arg(argv, '--approval'), 'utf8'));
      const supplied = JSON.parse(fs.readFileSync(arg(argv, '--manifest'), 'utf8'));
      // Recompute from the tree on disk: the supplied manifest is only the claim being checked.
      const rebuilt = buildManifest({ root, sourceSha });
      const secretNames = JSON.parse(fs.readFileSync(arg(argv, '--secrets'), 'utf8'));
      const result = verifyRelease({
        approval,
        observed: { manifest: rebuilt, sourceSha, targetEnvironment: arg(argv, '--target'), secretNames },
      });
      if (isObj(supplied) && supplied.manifest_digest !== rebuilt.manifest_digest) result.codes.push('SUPPLIED_MANIFEST_DOES_NOT_MATCH_TREE');
      if (result.codes.length) { console.error(`HOLD: RELEASE_MANIFEST ${[...new Set(result.codes)].sort().join(',')}`); return 2; }
      console.log('PASS: RELEASE_MANIFEST_MATCHES_APPROVAL; NOT DEPLOY AUTHORIZATION');
      return 0;
    }
    console.error(usage());
    return 2;
  } catch (e) {
    console.error(`HOLD: RELEASE_MANIFEST_EVIDENCE_UNAVAILABLE (${String(e && e.message).split('\n')[0].slice(0, 80)})`);
    return 2;
  }
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));

module.exports = {
  MANIFEST_SCHEMA, APPROVAL_SCHEMA, APPROVED_TARGETS, MAX_ATTESTATION_AGE_MS, MAX_FEED_AGE_MS,
  buildManifest, verifyRelease, digestPaths, digestSecretNames, manifestDigest,
};
