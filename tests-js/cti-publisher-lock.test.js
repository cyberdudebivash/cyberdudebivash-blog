'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createPublisherLock } = require('../scripts/cti-publisher-lock.cjs');

function withLockFile(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdb-cti-lock-'));
  try { return fn(path.join(dir, 'pipeline.lock')); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('exclusive lock prevents a second concurrent publisher and does not overwrite owner', () => {
  withLockFile(lockPath => {
    const warnings = [];
    const first = createPublisherLock({ lockPath });
    const second = createPublisherLock({ lockPath, warn: code => warnings.push(code) });
    assert.equal(first.acquire(), true);
    const original = fs.readFileSync(lockPath, 'utf8');
    assert.equal(second.acquire(), false);
    assert.equal(fs.readFileSync(lockPath, 'utf8'), original);
    assert.deepEqual(warnings, ['CTI_PUBLISHER_LOCK_ALREADY_HELD']);
    assert.equal(second.release(), false);
    assert.equal(fs.existsSync(lockPath), true);
    assert.equal(first.release(), true);
    assert.equal(fs.existsSync(lockPath), false);
    assert.equal(second.acquire(), true);
    assert.equal(second.release(), true);
  });
});

test('malformed or stale preexisting locks are not silently stolen', () => {
  withLockFile(lockPath => {
    const data = '{not-json';
    fs.writeFileSync(lockPath, data, 'utf8');
    const lock = createPublisherLock({lockPath});
    assert.equal(lock.acquire(), false);
    assert.equal(lock.release(), false);
    assert.equal(fs.readFileSync(lockPath, 'utf8'), data);
  });
});

test('unwritable storage fails closed instead of running an unlocked publisher', () => {
  withLockFile(lockPath => {
    const events = [];
    const failFs = {...fs, openSync() { throw Object.assign(new Error('EPERM'), {code:'EPERM'}); }};
    const lock = createPublisherLock({lockPath, fsImpl: failFs, warn: x => events.push(x)});
    assert.equal(lock.acquire(), false);
    assert.equal(fs.existsSync(lockPath), false);
    assert.deepEqual(events, ['CTI_PUBLISHER_LOCK_ACQUIRE_FAILED']);
  });
});

test('file content changed without owner token must never be unlinked', () => {
  withLockFile(lockPath => {
    const warnings = [];
    const lock = createPublisherLock({lockPath, warn: x=>warnings.push(x)});
    assert.equal(lock.acquire(), true);
    fs.writeFileSync(lockPath, '{"token":"another-publisher"}', 'utf8');
    assert.equal(lock.release(), false);
    assert.equal(fs.existsSync(lockPath), true);
    assert.deepEqual(warnings, ['CTI_PUBLISHER_LOCK_OWNER_CHANGED']);
  });
});

test('partial lock creation is cleaned up and the publisher fails closed', () => {
  withLockFile(lockPath => {
    const events = [];
    const failFs = {...fs, writeFileSync() { throw Object.assign(new Error('ENOSPC'), {code:'ENOSPC'}); }};
    const lock = createPublisherLock({lockPath,fsImpl:failFs,warn:x=>events.push(x)});
    assert.equal(lock.acquire(), false);
    assert.equal(fs.existsSync(lockPath), false);
    assert.deepEqual(events, ['CTI_PUBLISHER_LOCK_ACQUIRE_FAILED']);
  });
});

test('source requires a nonzero exit status if publisher cannot acquire lock', () => {
  // Runtime wiring contract, not proof of any production schedule or ingest.
  const source=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
  assert.match(source,/createPublisherLock\(\{\s*lockPath:\s*CFG\.lockPath/);
  assert.match(source,/if\s*\(!acquireLock\(\)\)\s*\{\s*process\.exitCode\s*=\s*2;\s*return;\s*\}/);
  assert.doesNotMatch(source,/function\s+releaseLock\(\)\s*\{\s*try\s*\{\s*if\s*\(fs\.existsSync/);
});
