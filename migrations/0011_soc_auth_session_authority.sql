-- SENTINEL APEX SOC — Source-only, authoritative OIDC session registry.
-- REQUIRED: migrations 0009 and 0010 applied in order before this migration.
-- Strictly NO production D1 apply, client provisioning or API activation.
-- Only approved server-side identity administration may insert rows.
-- Never persist bearer tokens or un-hashed JWT IDs (jti).
-- Every check MUST use the primary D1 instance (withSession('first-primary')).
-- This is one component of revocation, not a complete OAuth login flow.

CREATE TABLE IF NOT EXISTS soc_auth_subjects (
  issuer TEXT NOT NULL CHECK (substr(issuer,1,8)='https://' AND length(issuer)<=512),
  subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
  status TEXT NOT NULL DEFAULT 'DISABLED' CHECK(status IN('ACTIVE','DISABLED')),
  -- Refresh/session revocation cutoff: tokens issued at or before cutoff fail.
  valid_after_epoch INTEGER NOT NULL DEFAULT 0 CHECK(valid_after_epoch>=0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(issuer,subject)
);

CREATE TABLE IF NOT EXISTS soc_auth_sessions (
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  jti_sha256 TEXT NOT NULL CHECK(
    length(jti_sha256)=64 AND jti_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  token_iat_epoch INTEGER NOT NULL CHECK(token_iat_epoch>0),
  token_exp_epoch INTEGER NOT NULL
    CHECK(token_exp_epoch>token_iat_epoch AND token_exp_epoch-token_iat_epoch<=3600),
  state TEXT NOT NULL DEFAULT 'REVOKED'
    CHECK(state IN ('ACTIVE','REVOKED')),
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY(issuer,subject,jti_sha256),
  FOREIGN KEY(issuer,subject) REFERENCES soc_auth_subjects(issuer,subject)
    ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK((state='REVOKED' AND revoked_at IS NOT NULL)
    OR (state='ACTIVE' AND revoked_at IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_soc_auth_sessions_expiry
  ON soc_auth_sessions(token_exp_epoch,state);

-- Once revoked, the same JTI record cannot be activated again.
-- Rotation must create a distinct, explicitly reviewed session.
CREATE TRIGGER IF NOT EXISTS soc_auth_session_no_reactivation
BEFORE UPDATE ON soc_auth_sessions
WHEN OLD.state='REVOKED' AND NEW.state='ACTIVE'
BEGIN
  SELECT RAISE(ABORT,'SOC revoked session cannot be reactivated');
END;

-- Session identity and JWT fingerprint cannot be reassigned to another user.
CREATE TRIGGER IF NOT EXISTS soc_auth_session_identity_immutable
BEFORE UPDATE ON soc_auth_sessions
WHEN NEW.issuer<>OLD.issuer OR NEW.subject<>OLD.subject
  OR NEW.jti_sha256<>OLD.jti_sha256
  OR NEW.token_iat_epoch<>OLD.token_iat_epoch
  OR NEW.token_exp_epoch<>OLD.token_exp_epoch
BEGIN
  SELECT RAISE(ABORT,'SOC session identity is immutable');
END;

CREATE TRIGGER IF NOT EXISTS soc_auth_session_no_delete
BEFORE DELETE ON soc_auth_sessions
BEGIN
  SELECT RAISE(ABORT,'SOC session hard delete prohibited pending retention policy');
END;

CREATE TRIGGER IF NOT EXISTS soc_auth_subject_no_delete
BEFORE DELETE ON soc_auth_subjects
BEGIN
  SELECT RAISE(ABORT,'SOC subject hard delete prohibited pending retention policy');
END;

-- Existing SOC migrations are never applied automatically. No customer rows.
