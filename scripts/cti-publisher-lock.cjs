'use strict';
/**
 * Sentinel APEX CTI publisher lock. All outcomes except an exclusive create
 * are fail-closed. Do not automatically steal a stale lock: an age-based
 * override races an active publisher and can corrupt the publication ledger.
 * An operator may reconcile a stale lock after checking active processes.
 * No secrets, lock contents or filesystem paths are printed by this module.
 */
const fs = require('node:fs');
const crypto = require('node:crypto');

function createPublisherLock({ lockPath, fsImpl = fs, clock = Date.now, warn = () => {} } = {}) {
  if (typeof lockPath !== 'string' || !lockPath.trim() || typeof warn !== 'function') {
    throw new TypeError('CTI_PUBLISHER_LOCK_INVALID_CONFIGURATION');
  }
  let ownerToken = null;
  let ownerIdentity = null;
  const notice = code => warn('CTI_PUBLISHER_LOCK_' + code);

  function acquire() {
    if (ownerToken !== null) return false;
    const token = crypto.randomBytes(16).toString('hex');
    let fd = null;
    let created = false;
    try {
      // 'wx' is an atomic exclusive create, unlike existsSync + writeFileSync.
      fd = fsImpl.openSync(lockPath, 'wx', 0o600);
      created = true;
      const payload = JSON.stringify({ acquired: clock(), pid: process.pid, token });
      fsImpl.writeFileSync(fd, payload, 'utf8');
      const stat = fsImpl.fstatSync(fd);
      fsImpl.closeSync(fd);
      fd = null;
      ownerIdentity = { dev: stat.dev, ino: stat.ino };
      ownerToken = token;
      return true;
    } catch (error) {
      if (fd !== null) {
        try { fsImpl.closeSync(fd); } catch (_) { /* best effort */ }
      }
      // Only an attempt that created the file may clean up a partial write.
      if (created) {
        try { fsImpl.unlinkSync(lockPath); } catch (_) { /* manual reconciliation */ }
      }
      notice(error && error.code === 'EEXIST' ? 'ALREADY_HELD' : 'ACQUIRE_FAILED');
      return false;
    }
  }

  function release() {
    if (ownerToken === null) return false;
    try {
      const stat = fsImpl.statSync(lockPath);
      // Avoid deleting a different lock swapped into this path.
      if (stat.dev !== ownerIdentity.dev || stat.ino !== ownerIdentity.ino) {
        ownerToken = null;
        ownerIdentity = null;
        notice('OWNER_CHANGED');
        return false;
      }
      const record = JSON.parse(fsImpl.readFileSync(lockPath, 'utf8'));
      if (!record || record.token !== ownerToken) {
        ownerToken = null;
        ownerIdentity = null;
        notice('OWNER_CHANGED');
        return false;
      }
      fsImpl.unlinkSync(lockPath);
      ownerToken = null;
      ownerIdentity = null;
      return true;
    } catch (_) {
      notice('RELEASE_FAILED');
      // Never remove an unverified lock; operator reconciliation required.
      return false;
    }
  }

  return { acquire, release };
}

module.exports = { createPublisherLock };
