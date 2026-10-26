'use strict';

// Presence-only preflight. Never expose secret contents or contact a provider.
const FLAGS = Object.freeze(['HAS_REDIS_URL', 'HAS_REDIS_TOKEN', 'HAS_BACKUP_KEY']);

function assessBackupPreflight(env) {
  const missing = FLAGS.filter(flag => env[flag] !== 'true');
  return Object.freeze({ ready: missing.length === 0, missing });
}

if (require.main === module) {
  const result = assessBackupPreflight(process.env);
  if (!result.ready) {
    console.error('::error title=P0 Customer Backup Not Executed::Required backup credentials are absent; no encrypted customer snapshot was produced or uploaded.');
    process.exitCode = 2;
  } else {
    console.log('Backup prerequisite presence confirmed; snapshot creation and artifact upload still require independent successful steps.');
  }
}

module.exports = { assessBackupPreflight };
