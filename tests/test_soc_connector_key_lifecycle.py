"""Offline SOC key lifecycle and receipt race-control tests. No Cloudflare access.

python3 -m unittest -v tests.test_soc_connector_key_lifecycle
"""
import datetime as dt
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = [
    (ROOT/"migrations"/f).read_text(encoding="utf-8")
    for f in ("0009_soc_tenant_control_plane.sql",
              "0012_soc_event_receipt_integrity.sql",
              "0013_soc_connector_key_lifecycle.sql")
]
UTC = dt.timezone.utc
NOW = dt.datetime.now(UTC).replace(microsecond=0)
EPOCH = int(NOW.timestamp())
STAMP = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
SOURCE_ID = "evt_" + "b"*64
KEY_ID = "key-20261021"
DIGEST = "a"*64
ATTEST = "c"*64


class ConnectorKeyControls(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for sql in SQL:
            self.db.executescript(sql)
        for tenant in ("acme", "contoso"):
            self.db.execute(
                "INSERT INTO soc_tenants(tenant_id,legal_name,status,data_region,retention_days,created_at,updated_at) "
                "VALUES (?,?,'ACTIVE','IN',30,?,?)",(tenant,tenant,STAMP,STAMP))
            for user, role, state in (
                ("admin","TENANT_ADMIN","ACTIVE"),
                ("viewer","READ_ONLY","ACTIVE"),
                ("disabled","TENANT_ADMIN","REVOKED")):
                self.db.execute(
                    "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) "
                    "VALUES (? ,?,'https://idp.example',?,?,?,?,?)",
                    (tenant,user,f"{tenant}-{user}",role,state,STAMP,STAMP))
            self.db.execute(
                "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,state,created_by,created_at,updated_at) "
                "VALUES (?,'edr','EDR','signed-metadata','APPROVED','admin',?,?)",
                (tenant,STAMP,STAMP))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def enroll(self, key=KEY_ID, tenant="acme", user="admin", start=EPOCH-30, expiry=EPOCH+86400):
        self.db.execute(
            "INSERT INTO soc_connector_signing_keys "
            "(tenant_id,connector_id,key_id,state,valid_from_epoch,expires_epoch,created_by,changed_by,created_at,updated_at) "
            "VALUES (?,'edr',?,'PENDING',?,?,?,?,?,?)",
            (tenant,key,start,expiry,user,user,STAMP,STAMP))

    def change(self, key=KEY_ID, state="ACTIVE", tenant="acme", user="admin"):
        self.db.execute(
            "UPDATE soc_connector_signing_keys SET state=?,changed_by=?,updated_at=?,revoked_at=? "
            "WHERE tenant_id=? AND connector_id='edr' AND key_id=?",
            (state,user,STAMP,STAMP if state=="REVOKED" else None,tenant,key))

    def receipt(self, key=KEY_ID, tenant="acme", event=SOURCE_ID, signed=STAMP):
        self.db.execute(
            "INSERT INTO soc_event_receipts("
            "tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,"
            "created_at,source_signed_at,attestation_sha256,signing_key_id"
            ") VALUES (?,?,'edr',?,?,?,?,?,?,?)",
            (tenant,event,signed,STAMP,DIGEST,STAMP,signed,ATTEST,key))

    def test_empty_registry_no_customer_keys_or_receipts(self):
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_connector_signing_keys").fetchone()[0],0)
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()

    def test_enroll_pending_then_activate_authorized_key(self):
        self.enroll()
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()
        self.change()
        self.receipt()
        states=[x[0] for x in self.db.execute(
            "SELECT action FROM soc_audit_events WHERE tenant_id='acme'")]
        self.assertCountEqual(states,[
            "CONNECTOR_KEY_ENROLLED","CONNECTOR_KEY_ACTIVATED","EVENT_RECEIVED"])
        self.assertEqual(self.db.execute(
            "SELECT signing_key_id FROM soc_event_receipts WHERE tenant_id='acme'"
        ).fetchone()[0],KEY_ID)

    def test_revocation_immediately_rejects_future_receipt(self):
        self.enroll()
        self.change()
        self.change(state="REVOKED")
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()
        with self.assertRaises(sqlite3.IntegrityError):
            self.change()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM soc_event_receipts").fetchone()[0],0)

    def test_cross_tenant_key_not_usable(self):
        self.enroll(tenant="contoso")
        self.change(tenant="contoso")
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt(tenant="acme")
        self.receipt(tenant="contoso")
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_event_receipts WHERE tenant_id='acme'").fetchone()[0],0)

    def test_admin_required_not_read_only_or_revoked_principal(self):
        for user in ("viewer","disabled"):
            with self.subTest(user=user),self.assertRaises(sqlite3.IntegrityError):
                self.enroll(key="key-"+user,user=user)
        self.enroll()
        with self.assertRaises(sqlite3.IntegrityError):
            self.change(user="viewer")
        with self.assertRaises(sqlite3.IntegrityError):
            self.change(user="disabled")

    def test_inactive_tenant_does_not_enroll(self):
        self.db.execute("UPDATE soc_tenants SET status='SUSPENDED' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.enroll()

    def test_key_expiry_and_future_not_before_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.enroll(start=EPOCH-100, expiry=EPOCH+90*86400+1)
        self.enroll(key="future-key",start=EPOCH+600,expiry=EPOCH+86400)
        with self.assertRaises(sqlite3.IntegrityError):
            self.change(key="future-key")
        self.enroll(key="expired-key",start=EPOCH-800,expiry=EPOCH-100)
        with self.assertRaises(sqlite3.IntegrityError):
            self.change(key="expired-key")

    def test_at_most_two_live_keys_during_rotation(self):
        for key in ("key-old-one","key-new-two"):
            self.enroll(key=key)
            self.change(key=key)
        self.enroll(key="key-third")
        with self.assertRaises(sqlite3.IntegrityError):
            self.change(key="key-third")
        self.change(key="key-old-one",state="REVOKED")
        self.change(key="key-third")
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_connector_signing_keys WHERE tenant_id='acme' AND state='ACTIVE'"
        ).fetchone()[0],2)

    def test_old_receipt_retained_after_key_revocation(self):
        self.enroll()
        self.change()
        self.receipt()
        self.change(state="REVOKED")
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM soc_event_receipts").fetchone()[0],1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt(event="evt_"+"c"*64)

    def test_immutable_identity_non_deletion_and_no_status_replay(self):
        self.enroll()
        self.change()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_connector_signing_keys SET key_id='replacement' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.change()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_connector_signing_keys WHERE tenant_id='acme'")

    def test_audit_failure_rolls_back_activation(self):
        self.enroll()
        self.db.executescript("""
        CREATE TRIGGER force_key_audit_failure BEFORE INSERT ON soc_audit_events
        BEGIN SELECT RAISE(ABORT,'test forced audit rejection'); END;
        """)
        with self.assertRaises(sqlite3.IntegrityError):
            self.change()
        self.assertEqual(self.db.execute(
            "SELECT state FROM soc_connector_signing_keys WHERE tenant_id='acme'"
        ).fetchone()[0],"PENDING")

    def test_source_signature_outside_key_lifetime_rejected(self):
        self.enroll()
        self.change()
        old=(NOW-dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt(signed=old)

    def test_no_plaintext_secret_storage_column(self):
        names={c[1] for c in self.db.execute("PRAGMA table_info(soc_connector_signing_keys)")}
        self.assertNotIn("secret",names)
        self.assertNotIn("api_key",names)
        self.assertNotIn("hmac_key",names)


if __name__=="__main__":
    unittest.main()
