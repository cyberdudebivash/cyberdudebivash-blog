"""SOC session authorization schema: SQLite integrity and revocation tests.

Run: python3 -m unittest -v tests.test_soc_auth_sessions
No production D1 or network calls. SQLite enforces the same constraints.
"""
import hashlib
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (ROOT / "migrations" / "0011_soc_auth_session_authority.sql").read_text()
ISSUER = "https://issuer.example"
SUBJECT = "analyst-1"
JTI = "this-is-a-test-id-987654321"
HASH = hashlib.sha256(JTI.encode()).hexdigest()
TIME = "2026-10-21T16:00:00Z"
IAT = 1792598400
EXP = IAT + 600


class AuthSessionSchemaTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)

    def tearDown(self):
        self.db.close()

    def subject(self, status="ACTIVE", epoch=0):
        self.db.execute(
            "INSERT INTO soc_auth_subjects (issuer,subject,status,valid_after_epoch,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?)",
            (ISSUER,SUBJECT,status,epoch,TIME,TIME))

    def session(self, *, jti_hash=HASH, state="ACTIVE", revoked=None, issued=IAT, expires=EXP):
        self.db.execute(
            "INSERT INTO soc_auth_sessions (issuer,subject,jti_sha256,token_iat_epoch,token_exp_epoch,state,created_at,revoked_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ISSUER,SUBJECT,jti_hash,issued,expires,state,TIME,revoked))

    def allowed(self, now=IAT+100):
        return self.db.execute(
            "SELECT 1 FROM soc_auth_sessions s JOIN soc_auth_subjects u "
            "ON u.issuer=s.issuer AND u.subject=s.subject "
            "WHERE s.issuer=? AND s.subject=? AND s.jti_sha256=? "
            "AND s.state='ACTIVE' AND s.revoked_at IS NULL "
            "AND u.status='ACTIVE' AND s.token_iat_epoch>u.valid_after_epoch "
            "AND s.token_iat_epoch=? AND s.token_exp_epoch=? AND s.token_exp_epoch>? LIMIT 1",
            (ISSUER,SUBJECT,HASH,IAT,EXP,now)).fetchone() is not None

    def test_schema_idempotent_no_customers(self):
        self.db.executescript(SCHEMA)
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_auth_subjects").fetchone()[0],0)
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_auth_sessions").fetchone()[0],0)
        self.assertFalse(self.allowed())

    def test_active_registered_session_required(self):
        self.subject()
        self.assertFalse(self.allowed())
        self.session()
        self.assertTrue(self.allowed())
        self.assertFalse(self.allowed(now=EXP))

    def test_disabled_subject_denies(self):
        self.subject("DISABLED")
        self.session()
        self.assertFalse(self.allowed())
        self.db.execute("UPDATE soc_auth_subjects SET status='ACTIVE' WHERE issuer=? AND subject=?", (ISSUER,SUBJECT))
        self.assertTrue(self.allowed())
        self.db.execute("UPDATE soc_auth_subjects SET status='DISABLED' WHERE issuer=? AND subject=?", (ISSUER,SUBJECT))
        self.assertFalse(self.allowed())

    def test_global_logout_cutoff_denies_old_sessions(self):
        self.subject()
        self.session()
        self.assertTrue(self.allowed())
        self.db.execute("UPDATE soc_auth_subjects SET valid_after_epoch=? WHERE issuer=? AND subject=?",
                        (IAT,ISSUER,SUBJECT))
        self.assertFalse(self.allowed())

    def test_individual_revoke_denies(self):
        self.subject()
        self.session()
        self.db.execute(
            "UPDATE soc_auth_sessions SET state='REVOKED',revoked_at=? WHERE issuer=? AND subject=? AND jti_sha256=?",
            (TIME,ISSUER,SUBJECT,HASH))
        self.assertFalse(self.allowed())

    def test_revoked_token_cannot_reactivate(self):
        self.subject()
        self.session(state="REVOKED",revoked=TIME)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_auth_sessions SET state='ACTIVE',revoked_at=NULL WHERE issuer=? AND subject=? AND jti_sha256=?",
                (ISSUER,SUBJECT,HASH))
        self.assertFalse(self.allowed())

    def test_hashed_jti_required(self):
        self.subject()
        for value in ("abc",JTI,"g"*64,"A"*64):
            with self.subTest(hash=value),self.assertRaises(sqlite3.IntegrityError):
                self.session(jti_hash=value)

    def test_session_rejects_unknown_subject(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.session()

    def test_enforces_token_max_one_hour_and_expiry(self):
        self.subject()
        with self.assertRaises(sqlite3.IntegrityError):
            self.session(expires=IAT+3601)
        with self.assertRaises(sqlite3.IntegrityError):
            self.session(expires=IAT)

    def test_token_identity_is_immutable(self):
        self.subject()
        self.session()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_auth_sessions SET token_iat_epoch=? WHERE issuer=? AND subject=? AND jti_sha256=?",
                (IAT+1,ISSUER,SUBJECT,HASH))
        self.assertTrue(self.allowed())

    def test_no_hard_deletes_until_retention_policy(self):
        self.subject()
        self.session()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_auth_sessions WHERE issuer=? AND subject=?", (ISSUER,SUBJECT))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_auth_subjects WHERE issuer=? AND subject=?", (ISSUER,SUBJECT))

    def test_revoked_state_requires_timestamp(self):
        self.subject()
        with self.assertRaises(sqlite3.IntegrityError):
            self.session(state="REVOKED",revoked=None)
        with self.assertRaises(sqlite3.IntegrityError):
            self.session(state="ACTIVE",revoked=TIME)


if __name__ == "__main__":
    unittest.main()
