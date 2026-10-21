"""SOC source-event metadata: real SQLite tenant/connector and atomic audit rules.

No production data, network or live D1. Run:
python3 -m unittest -v tests.test_soc_event_receipt_integrity
"""
import sqlite3
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
M9=(ROOT/"migrations"/"0009_soc_tenant_control_plane.sql").read_text()
M12=(ROOT/"migrations"/"0012_soc_event_receipt_integrity.sql").read_text()
T="2026-10-21T16:00:00.000Z"
HASH="a"*64
EVENT="evt_"+"b"*64
ATT="c"*64


class SocSourceReceiptTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(M9)
        self.db.executescript(M12)
        for tenant in ("acme","contoso"):
            self.db.execute(
                "INSERT INTO soc_tenants (tenant_id,legal_name,status,data_region,retention_days,created_at,updated_at) "
                "VALUES (?,?, 'ACTIVE','IN',90,?,?)",(tenant,tenant,T,T))
            self.db.execute(
                "INSERT INTO soc_principals (tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) "
                "VALUES (?,?, 'https://idp.example',?,'TENANT_ADMIN','ACTIVE',?,?)",
                (tenant,"operator",tenant+"-sub",T,T))
            self.db.execute(
                "INSERT INTO soc_connectors (tenant_id,connector_id,type,authorized_scope,state,created_by,created_at,updated_at) "
                "VALUES (?,'edr','EDR','signed source metadata','APPROVED','operator',?,?)",
                (tenant,T,T))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def receipt(self, tenant="acme", event=EVENT, digest=HASH, attestation=ATT, ref=None):
        return self.db.execute(
            "INSERT INTO soc_event_receipts "
            "(tenant_id,event_id,connector_id,source_event_at,received_at,"
            "digest_sha256,payload_location_ref,created_at,source_signed_at,attestation_sha256) "
            "VALUES (?,?,'edr',?,?,?,?,?,?,?)",
            (tenant,event,T,T,digest,ref,T,T,attestation))

    def test_receipt_created_with_one_atomic_audit_event(self):
        self.receipt()
        rows=self.db.execute(
            "SELECT action,actor_type,actor_id,resource_id,request_id,outcome "
            "FROM soc_audit_events WHERE tenant_id='acme'").fetchall()
        self.assertEqual(rows,[("EVENT_RECEIVED","SYSTEM",None,EVENT,"event:"+EVENT,"ALLOW")])
        stored=self.db.execute(
            "SELECT digest_sha256,source_signed_at,attestation_sha256 "
            "FROM soc_event_receipts WHERE tenant_id='acme'").fetchone()
        self.assertEqual(stored,(HASH,T,ATT))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_event_receipts").fetchone()[0],1)

    def test_replay_same_tenant_event_rejected_and_no_duplicate_audit(self):
        self.receipt()
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_audit_events").fetchone()[0],1)

    def test_other_tenant_same_event_id_is_independent(self):
        self.receipt()
        self.receipt("contoso")
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_event_receipts").fetchone()[0],2)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_audit_events").fetchone()[0],2)

    def test_unapproved_or_revoked_connector_denied(self):
        self.db.execute(
            "UPDATE soc_connectors SET state='REVOKED' WHERE tenant_id='acme' AND connector_id='edr'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_audit_events").fetchone()[0],0)

    def test_suspended_tenant_denied(self):
        self.db.execute("UPDATE soc_tenants SET status='SUSPENDED' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()

    def test_wrong_deterministic_id_format_rejected(self):
        for event in ("evt_short","fake_"+"b"*64,"evt_"+"z"*64):
            with self.subTest(event=event), self.assertRaises(sqlite3.IntegrityError):
                self.receipt(event=event)

    def test_invalid_signature_attestation_or_payload_digest_rejected(self):
        for attestation in ("bad","C"*64):
            with self.subTest(attestation=attestation),self.assertRaises(sqlite3.IntegrityError):
                self.receipt(attestation=attestation)
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt(digest="A"*64)

    def test_raw_payload_location_reference_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt(ref="r2://customer/raw/event")
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_audit_events").fetchone()[0],0)

    def test_receipt_immutable_and_non_deletable(self):
        self.receipt()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE soc_event_receipts SET digest_sha256=? WHERE tenant_id='acme'",("f"*64,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_event_receipts WHERE tenant_id='acme'")
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_audit_events").fetchone()[0],1)

    def test_unknown_tenant_or_connector_cannot_insert(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt(tenant="unknown")
        self.db.execute("DELETE FROM soc_connectors WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()

    def test_audit_insert_failure_rolls_back_event_write(self):
        # Force a rejected audit append (e.g. invariant/constraint conflict).
        self.db.execute("""
            CREATE TRIGGER deny_test_soc_audit BEFORE INSERT ON soc_audit_events
            BEGIN SELECT RAISE(ABORT,'test forced audit rejection'); END;
        """)
        with self.assertRaises(sqlite3.IntegrityError):
            self.receipt()
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_event_receipts").fetchone()[0],0)


if __name__=="__main__":
    unittest.main()
