#!/usr/bin/env node
'use strict';
/**
 * P0 Cloudflare immutable release pin (READ-ONLY).
 * Require manual dispatch input, independently set release approval,
 * checked-out commit, GitHub run commit and current remote main to agree.
 * Run before build and immediately before the Wrangler deployment.
 * No deployment, customer operations, secret printing, or repository writes.
 */
const cp = require('node:child_process');
const REPO = 'cyberdudebivash/cyberdudebivash-blog';
const SHA = /^[a-f0-9]{40}$/i;
const approvedOrigin = (x) => typeof x === 'string' &&
  /^(?:https:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)cyberdudebivash\/cyberdudebivash-blog(?:\.git)?$/i.test(x.trim());
const norm = x => typeof x === 'string' && SHA.test(x) ? x.toLowerCase() : null;
function verify({event, ref, repository, origin, githubSha, headSha, mainSha, inputSha, approvedSha} = {}) {
  const errors = new Set();
  if (event !== 'workflow_dispatch' || ref !== 'refs/heads/main') errors.add('NOT_MAIN_MANUAL_DISPATCH');
  if (repository !== REPO || !approvedOrigin(origin)) errors.add('UNAPPROVED_REPOSITORY');
  const values = [githubSha, headSha, mainSha, inputSha, approvedSha].map(norm);
  if (values.some(x => !x)) errors.add('RELEASE_SHA_MISSING_OR_INVALID');
  else if (new Set(values).size !== 1) errors.add('RELEASE_SHA_NOT_PINNED_TO_CURRENT_MAIN');
  return {status: errors.size ? 'HOLD' : 'PASS_NOT_DEPLOY_AUTHORIZATION', codes: [...errors].sort()};
}
function git(...args) {
  return cp.execFileSync('git', args, {
    encoding:'utf8', timeout:20000, maxBuffer:4096,
    stdio: ['ignore','pipe','ignore']
  }).trim();
}
function inspectGit() {
  const origin = git('remote','get-url','origin');
  const headSha = git('rev-parse','HEAD');
  // A publisher commit while an operator run waits for approval invalidates
  // the review: always compare against the live main ref, fail closed.
  const remote = git('ls-remote','--heads','origin','refs/heads/main');
  const match = /^([0-9a-f]{40})\s+refs\/heads\/main$/i.exec(remote);
  if (!match) throw new Error('REMOTE_MAIN_UNAVAILABLE');
  return {origin, headSha, mainSha:match[1]};
}
if (require.main === module) {
  try {
    if (process.argv.length !== 2) throw new Error('UNEXPECTED_ARGUMENT');
    const outcome = verify({
      event: process.env.GITHUB_EVENT_NAME,
      ref: process.env.GITHUB_REF,
      repository: process.env.GITHUB_REPOSITORY,
      githubSha: process.env.GITHUB_SHA,
      inputSha: process.env.CDB_SOC_RELEASE_INPUT_SHA,
      approvedSha: process.env.CDB_SOC_APPROVED_RELEASE_SHA,
      ...inspectGit()
    });
    if (outcome.status !== 'PASS_NOT_DEPLOY_AUTHORIZATION') {
      console.error('HOLD: IMMUTABLE_RELEASE_PIN '+outcome.codes.join(','));
      process.exitCode = 2;
    } else {
      console.log('PASS: IMMUTABLE_RELEASE_SHA_PINNED_TO_CURRENT_MAIN; NOT DEPLOY AUTHORIZATION');
    }
  } catch (_) {
    console.error('HOLD: IMMUTABLE_RELEASE_PIN_EVIDENCE_UNAVAILABLE');
    process.exitCode = 2;
  }
}
module.exports = {verify,approvedOrigin,REPO};
