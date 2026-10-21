"""SENTINEL APEX SOC: execute real SQLite incident lifecycle and audit triggers.

This is an offline, deterministic test. No production D1 access, no HTTP, no
customer provisioning. Run: python3 -m unittest -v tests.test_soc_incident_invariants
"""
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
M9 = (ROOT / "migrations/0009_soc_tenant_control_plane.sql").read_text()
M10 = (ROOT / "migrations/0010_soc_incident_audit_invariants.sql").read_text()
TIME = "2026-10-21T15:00:00Z"
DIGEST = "a" * 64


class IncidentIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(M9)
        self.db.executescript(M10)
        self.db.execute("PRAGMA foreign_keys=ON")
        for tenant in ("acme", "contoso"):
            self.db.execute(
                "INSERT INTO soc_tenants(tenant_id,legal_name,status,data_region,retention_days,created_at,updated_at) "
                "VALUES (?,?,'ACTIVE','IN',90,?,?)", (tenant,tenant,TIME,TIME))
            for identity, role, status in (
                ("analyst", "ANALYST", "ACTIVE"),
                ("reader", "READ_ONLY", "ACTIVE"),
                ("revoked", "ANALYST", "REVOKED")):
                self.db.execute(
                    "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (tenant,identity,"https://idp.example",tenant+"-"+identity,role,status,TIME,TIME))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def create(self, tenant="acme", incident="inc1", actor="analyst", request="req-000000000001", state="OPEN", version=1):
        return self.db.execute(
            "INSERT INTO soc_incidents (tenant_id,incident_id,title,severity,state,version,"
            "audit_actor_id,audit_request_id,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (tenant,incident,"Credible pilot finding","HIGH",state,version,actor,request,TIME,TIME)
        )

    def advance(self, *, tenant="acme", incident="inc1", state="TRIAGE", version=1,
                actor="analyst", request="req-000000000002", title=None, owner=None):
        if title is None:
            return self.db.execute(
                "UPDATE soc_incidents SET state=?,version=version+1,updated_at=?,"
                "audit_actor_id=?,audit_request_id=? WHERE tenant_id=? AND incident_id=? AND version=?",
                (state,TIME,actor,request,tenant,incident,version))
        return self.db.execute(
            "UPDATE soc_incidents SET title=?,version=version+1,updated_at=?,"
            "audit_actor_id=?,audit_request_id=? WHERE tenant_id=? AND incident_id=? AND version=?",
            (title,TIME,actor,request,tenant,incident,version))

    def audit(self, tenant="acme"):
        return self.db.execute(
            "SELECT action,actor_id,request_id FROM soc_audit_events WHERE tenant_id=? ORDER BY event_at,audit_id",
            (tenant,)).fetchall()

    def test_create_audits_in_same_statement(self):
        self.create()
        row = self.db.execute("SELECT state,version FROM soc_incidents WHERE tenant_id='acme' AND incident_id='inc1'").fetchone()
        self.assertEqual(row, ("OPEN", 1))
        self.assertEqual(self.audit(), [("INCIDENT_CREATED","analyst","req-000000000001")])

    def test_one_tenant_cannot_reuse_another_tenants_principal(self):
        self.db.execute("DELETE FROM soc_principals WHERE tenant_id='acme' AND principal_id='analyst'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.create("acme","bad","analyst","req-000000000003")
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_incidents").fetchone()[0], 0)

    def test_readonly_and_revoked_cannot_mutate(self):
        for actor in ("reader", "revoked"):
            with self.subTest(actor=actor), self.assertRaises(sqlite3.IntegrityError):
                self.create("acme","attempt-"+actor,actor,"req-000000000004")
        self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance(actor="reader")
        self.assertEqual(len(self.audit()), 1)

    def test_suspended_tenant_cannot_create_or_update(self):
        self.db.execute("UPDATE soc_tenants SET status='SUSPENDED' WHERE tenant_id='contoso'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.create("contoso","suspended","analyst","req-000000000005")
        self.create()
        self.db.execute("UPDATE soc_tenants SET status='SUSPENDED' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance()
        self.assertEqual(len(self.audit()), 1)

    def test_create_rejects_non_open_and_noninitial_version(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.create(state="CLOSED")
        with self.assertRaises(sqlite3.IntegrityError):
            self.create(version=2)

    def test_missing_actor_and_short_request_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.create(actor="")
        with self.assertRaises(sqlite3.IntegrityError):
            self.create(request="short")

    def test_replayed_request_cannot_create_second_incident(self):
        self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.create(incident="inc2")
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_incidents WHERE tenant_id='acme'").fetchone()[0], 1)
        self.assertEqual(len(self.audit()), 1)

    def test_same_request_id_in_another_tenant_is_independent(self):
        self.create()
        self.create("contoso","inc1","analyst","req-000000000001")
        self.assertEqual(len(self.audit("contoso")), 1)

    def test_lifecycle_and_audit(self):
        self.create()
        self.advance(state="TRIAGE",version=1,request="req-000000000002")
        self.advance(state="INVESTIGATING",version=2,request="req-000000000003")
        self.advance(state="RESOLVED",version=3,request="req-000000000004")
        rows = self.db.execute(
            "SELECT version,state FROM soc_incidents WHERE tenant_id='acme' AND incident_id='inc1'").fetchone()
        self.assertEqual(rows, (4, "RESOLVED"))
        audit_actions = [item[0] for item in self.audit()]
        self.assertEqual(audit_actions.count("INCIDENT_STATE_CHANGED"), 3)
        self.assertEqual(audit_actions.count("INCIDENT_CREATED"), 1)

    def test_noop_and_invalid_transitions_fail_without_audit(self):
        self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance(state="OPEN")
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance(state="CLOSED")
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance(state="CONTAINED")
        self.assertEqual(len(self.audit()), 1)

    def test_version_conflict_does_not_append_audit(self):
        self.create()
        self.advance(state="TRIAGE",version=1,request="req-000000000002")
        cursor = self.advance(state="INVESTIGATING",version=1,request="req-000000000003")
        self.assertEqual(cursor.rowcount, 0)
        self.assertEqual(len(self.audit()), 2)

    def test_replayed_update_request_rolls_back_revision(self):
        self.create()
        self.advance(state="TRIAGE",version=1,request="req-000000000002")
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance(state="INVESTIGATING",version=2,request="req-000000000002")
        self.assertEqual(self.db.execute(
            "SELECT version,state FROM soc_incidents WHERE tenant_id='acme'").fetchone(), (2,"TRIAGE"))
        self.assertEqual(len(self.audit()), 2)

    def test_cross_tenant_update_can_change_nothing(self):
        self.create()
        cursor = self.advance(tenant="contoso",incident="inc1")
        self.assertEqual(cursor.rowcount, 0)
        self.assertEqual(len(self.audit("acme")), 1)
        self.assertEqual(len(self.audit("contoso")), 0)

    def test_owner_and_tenant_identity_cannot_be_reassigned(self):
        self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_incidents SET tenant_id='contoso',version=2,"
                "audit_actor_id='analyst',audit_request_id='req-000000000006' WHERE tenant_id='acme'")
        self.assertEqual(len(self.audit()), 1)

    def test_update_without_version_increment_rejected(self):
        self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_incidents SET title='Changed',audit_actor_id='analyst',"
                "audit_request_id='req-000000000007' WHERE tenant_id='acme'")
        self.assertEqual(len(self.audit()), 1)

    def test_close_needs_source_evidence_and_then_is_immutable(self):
        self.create()
        self.advance(state="TRIAGE",version=1,request="req-000000000002")
        self.advance(state="INVESTIGATING",version=2,request="req-000000000003")
        self.advance(state="RESOLVED",version=3,request="req-000000000004")
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance(state="CLOSED",version=4,request="req-000000000005")
        self.db.execute(
            "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,created_by,created_at,updated_at) "
            "VALUES('acme','siem','SIEM','test-only','analyst',?,?)",(TIME,TIME))
        self.db.execute(
            "INSERT INTO soc_event_receipts(tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,created_at) "
            "VALUES('acme','event','siem',?,?,?,?)",(TIME,TIME,DIGEST,TIME))
        self.db.execute(
            "INSERT INTO soc_detections(tenant_id,detection_id,event_id,rule_id,rule_version,severity,created_at) "
            "VALUES('acme','detection','event','example','v1','HIGH',?)",(TIME,))
        self.db.execute(
            "INSERT INTO soc_incident_detections(tenant_id,incident_id,detection_id,linked_at) "
            "VALUES('acme','inc1','detection',?)",(TIME,))
        self.advance(state="CLOSED",version=4,request="req-000000000005")
        with self.assertRaises(sqlite3.IntegrityError):
            self.advance(state="TRIAGE",version=5,request="req-000000000006")
        self.assertEqual(self.db.execute(
            "SELECT state FROM soc_incidents WHERE tenant_id='acme'").fetchone()[0], "CLOSED")

    def test_delete_incident_prohibited(self):
        self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_incidents WHERE tenant_id='acme'")
        self.assertEqual(len(self.audit()), 1)

    def test_append_only_audit_protection_remains(self):
        self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_audit_events WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE soc_audit_events SET action='OTHER' WHERE tenant_id='acme'")


if __name__ == "__main__":
    unittest.main()
