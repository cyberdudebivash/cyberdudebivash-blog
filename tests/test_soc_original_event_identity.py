"""SENTINEL APEX SOC — offline D1-compatible provider event identity gate.

No production data, network, raw customer telemetry or remote migration.
"""
import datetime as dt
import hashlib
import json
import sqlite3
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MIGRATIONS=[
  (ROOT / "migrations" / name).read_text(encoding="utf8")
  for name in (
    "0009_soc_tenant_control_plane.sql",
    "0010_soc_incident_audit_invariants.sql",
    "0012_soc_event_receipt_integrity.sql",
    "0013_soc_connector_key_lifecycle.sql",
    "0014_soc_detection_review_provenance.sql",
    "0015_soc_original_event_identity.sql",
  )
]
NOW=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
TS=NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
EPOCH=int(NOW.timestamp())
SECRET_ID="provider-log-20261022-4242"
DIGEST="a"*64
ATT="b"*64
KEY="key-20261022"


def receipt_id(tenant,connector,source_id):
    item=json.dumps([tenant,connector,source_id],separators=(",",":"))
    return "evt_"+hashlib.sha256(item.encode()).hexdigest()


class SourceEventIdentityTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for migration in MIGRATIONS:
            self.db.executescript(migration)
        for tenant in ("acme","contoso"):
            self.db.execute(
                "INSERT INTO soc_tenants(tenant_id,legal_name,status,data_region,retention_days,created_at,updated_at) "
                "VALUES (?,?,'ACTIVE','IN',30,?,?)",(tenant,tenant,TS,TS))
            self.db.execute(
                "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) "
                "VALUES (?,'admin','https://idp.example',?,'TENANT_ADMIN','ACTIVE',?,?)",
                (tenant,tenant+"-subject",TS,TS))
            self.db.execute(
                "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,state,created_by,created_at,updated_at) "
                "VALUES (?,'edr','EDR','signed-source-only','APPROVED','admin',?,?)",
                (tenant,TS,TS))
            self.db.execute(
                "INSERT INTO soc_connector_signing_keys(tenant_id,connector_id,key_id,valid_from_epoch,"
                "expires_epoch,created_by,changed_by,created_at,updated_at) "
                "VALUES (?,'edr',?,? ,?,'admin','admin',?,?)",
                (tenant,KEY,EPOCH-60,EPOCH+3600,TS,TS))
            self.db.execute(
                "UPDATE soc_connector_signing_keys SET state='ACTIVE',changed_by='admin',updated_at=? "
                "WHERE tenant_id=? AND connector_id='edr' AND key_id=?",
                (TS,tenant,KEY))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def put(self, tenant="acme", original=SECRET_ID, event=None):
        if event is None:
            event=receipt_id(tenant,"edr",original or "")
        self.db.execute(
            "INSERT INTO soc_event_receipts("
            "tenant_id,event_id,connector_id,source_event_at,received_at,"
            "digest_sha256,created_at,source_signed_at,attestation_sha256,signing_key_id,source_event_id"
            ") VALUES (?,?,'edr',?,?,?,?,?,?,?,?)",
            (tenant,event,TS,TS,DIGEST,TS,TS,ATT,KEY,original))
        return event

    def test_original_source_identity_is_stored_not_telemetry(self):
        self.put()
        row=self.db.execute(
            "SELECT source_event_id,digest_sha256,payload_location_ref FROM soc_event_receipts WHERE tenant_id='acme'"
        ).fetchone()
        self.assertEqual(row,(SECRET_ID,DIGEST,None))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_audit_events WHERE tenant_id='acme' AND action='EVENT_RECEIVED'"
        ).fetchone()[0],1)

    def test_absent_or_malformed_provider_locator_rejected(self):
        for bad in (None,"","../secrets","https://example.org/payload","x"*129,"UPPERCASE/ID"):
            with self.subTest(bad=bad), self.assertRaises(sqlite3.IntegrityError):
                self.put(original=bad)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_event_receipts WHERE tenant_id='acme'"
        ).fetchone()[0],0)

    def test_original_provider_identity_is_immutable(self):
        self.put()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_event_receipts SET source_event_id='other-source' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_event_receipts WHERE tenant_id='acme'")

    def test_same_source_id_independent_across_tenants(self):
        a=self.put("acme")
        b=self.put("contoso")
        self.assertNotEqual(a,b)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_event_receipts"
        ).fetchone()[0],2)

    def test_duplicate_id_replay_denied_with_no_second_audit(self):
        self.put()
        with self.assertRaises(sqlite3.IntegrityError):
            self.put()
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_audit_events WHERE tenant_id='acme' AND action='EVENT_RECEIVED'"
        ).fetchone()[0],1)

    def test_inactive_connector_rejected_at_final_commit(self):
        self.db.execute("UPDATE soc_connectors SET state='REVOKED' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.put()

    def test_source_id_migration_is_additive_and_historical_data_is_not_backfilled(self):
        database=sqlite3.connect(":memory:")
        database.execute("PRAGMA foreign_keys=ON")
        for sql in MIGRATIONS[:-1]:database.executescript(sql)
        # An empty historical table stays empty; 0015 adds a nullable field.
        database.executescript(MIGRATIONS[-1])
        columns=[c[1] for c in database.execute("PRAGMA table_info(soc_event_receipts)")]
        self.assertIn("source_event_id",columns)
        self.assertEqual(database.execute("SELECT count(*) FROM soc_event_receipts").fetchone()[0],0)
        database.close()


if __name__=="__main__": unittest.main()
