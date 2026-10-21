"""SOC v0 D1 control plane: real SQLite FK, tenant isolation and immutability tests.

Does not require Cloudflare credentials, real customer data, or network access.
Run: python3 -m unittest tests.test_soc_tenant_schema -v
"""
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "migrations" / "0009_soc_tenant_control_plane.sql").read_text(encoding="utf-8")
AT = "2026-10-21T00:00:00Z"
DIGEST = "a" * 64


class TenantSchemaTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(MIGRATION)
        self.seed()

    def tearDown(self):
        self.db.close()

    def seed(self):
        for tenant in ("acme", "contoso"):
            self.db.execute(
                "INSERT INTO soc_tenants(tenant_id,legal_name,data_region,retention_days,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?)", (tenant,tenant,"IN",90,AT,AT))
            self.db.execute(
                "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (tenant,"analyst", "https://idp.example", f"{tenant}-subject","ANALYST","ACTIVE",AT,AT))
            self.db.execute(
                "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?)", (tenant,"siem","SIEM","pilot-only","analyst",AT,AT))
            self.db.execute(
                "INSERT INTO soc_event_receipts(tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,created_at) "
                "VALUES(?,?,?,?,?,?,?)", (tenant,"event","siem",AT,AT,DIGEST,AT))
            self.db.execute(
                "INSERT INTO soc_detections(tenant_id,detection_id,event_id,rule_id,rule_version,severity,created_at) "
                "VALUES(?,?,?,?,?,?,?)", (tenant,"detection","event","rule","v1","MEDIUM",AT))
            self.db.execute(
                "INSERT INTO soc_incidents(tenant_id,incident_id,title,severity,owner_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?)", (tenant,"incident","Authorized test incident","MEDIUM","analyst",AT,AT))
        self.db.commit()

    def test_schema_is_repeatable_and_does_not_seed_customers(self):
        self.db.executescript(MIGRATION)
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_tenants").fetchone()[0], 2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM soc_incidents").fetchone()[0], 2)

    def test_all_scoped_tables_require_tenant_id(self):
        for table in ("soc_principals","soc_connectors","soc_event_receipts",
                      "soc_detections","soc_incidents","soc_incident_detections",
                      "soc_evidence_manifests","soc_audit_events"):
            with self.subTest(table=table):
                columns = self.db.execute(f"PRAGMA table_info({table})").fetchall()
                tenant_column = next((c for c in columns if c[1] == "tenant_id"), None)
                self.assertIsNotNone(tenant_column)
                self.assertEqual(tenant_column[3], 1)  # NOT NULL

    def test_tenant_cannot_activate_without_retention_and_region(self):
        self.db.execute("INSERT INTO soc_tenants(tenant_id,legal_name,created_at,updated_at) "
                        "VALUES('pending','Pending',?,?)", (AT,AT))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE soc_tenants SET status='ACTIVE' WHERE tenant_id='pending'")
        self.db.execute("UPDATE soc_tenants SET retention_days=30,data_region='IN' WHERE tenant_id='pending'")
        self.db.execute("UPDATE soc_tenants SET status='ACTIVE' WHERE tenant_id='pending'")
        self.assertEqual(self.db.execute("SELECT status FROM soc_tenants WHERE tenant_id='pending'").fetchone()[0], "ACTIVE")

    def test_invalid_foreign_tenant_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,created_at,updated_at) "
                "VALUES('unknown','ghost','idp','ghost','ANALYST',?,?)", (AT,AT))

    def test_connector_creator_cannot_cross_tenant(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,created_by,created_at,updated_at) "
                "VALUES('acme','foreign','SIEM','test','contoso-analyst',?,?)", (AT,AT))

    def test_event_cannot_reference_connector_in_another_tenant(self):
        # The connector exists for contoso, not acme.
        self.db.execute(
            "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,created_by,created_at,updated_at) "
            "VALUES('contoso','only-contoso','SIEM','test','analyst',?,?)", (AT,AT))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO soc_event_receipts(tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,created_at) "
                "VALUES('acme','intrusion','only-contoso',?,?,?,?)", (AT,AT,DIGEST,AT))

    def test_detection_cannot_reference_event_in_another_tenant(self):
        self.db.execute(
            "INSERT INTO soc_event_receipts(tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,created_at) "
            "VALUES('contoso','only-contoso','siem',?,?,?,?)", (AT,AT,DIGEST,AT))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO soc_detections(tenant_id,detection_id,event_id,rule_id,rule_version,severity,created_at) "
                "VALUES('acme','intrusion','only-contoso','rule','v1','HIGH',?)", (AT,))

    def test_incident_owner_cannot_cross_tenant(self):
        self.db.execute(
            "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,created_at,updated_at) "
            "VALUES('contoso','foreign-analyst','idp','foreign','ANALYST',?,?)", (AT,AT))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "INSERT INTO soc_incidents(tenant_id,incident_id,title,severity,owner_id,created_at,updated_at) "
                "VALUES('acme','intrusion','Test','HIGH','foreign-analyst',?,?)", (AT,AT))

    def test_incident_cannot_link_detection_in_another_tenant(self):
        self.db.execute("INSERT INTO soc_detections(tenant_id,detection_id,event_id,rule_id,rule_version,severity,created_at) "
                        "VALUES('contoso','only-contoso','event','rule','v1','HIGH',?)",(AT,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO soc_incident_detections(tenant_id,incident_id,detection_id,linked_at) "
                            "VALUES('acme','incident','only-contoso',?)",(AT,))
        self.db.execute("INSERT INTO soc_incident_detections(tenant_id,incident_id,detection_id,linked_at) "
                        "VALUES('acme','incident','detection',?)",(AT,))

    def test_evidence_object_prefix_rejects_other_tenant_key(self):
        values=("acme","manifest","incident","soc/contoso/object.bin",DIGEST,"EVENT","analyst",AT,AT,AT)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO soc_evidence_manifests "
                            "(tenant_id,manifest_id,incident_id,object_key,artifact_sha256,evidence_kind,collector_id,collected_at,retention_until,created_at) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)", values)
        self.db.execute("INSERT INTO soc_evidence_manifests "
                        "(tenant_id,manifest_id,incident_id,object_key,artifact_sha256,evidence_kind,collector_id,collected_at,retention_until,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",("acme","manifest","incident","soc/acme/object.bin",DIGEST,"EVENT","analyst",AT,AT,AT))

    def test_evidence_key_rejects_traversal_empty_or_double_slash(self):
        for key in ("soc/acme/../contoso/object.bin", "soc/acme/", "soc/acme//object.bin"):
            with self.subTest(key=key), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO soc_evidence_manifests "
                                "(tenant_id,manifest_id,incident_id,object_key,artifact_sha256,evidence_kind,collector_id,collected_at,retention_until,created_at) "
                                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                                ("acme","test-object","incident",key,DIGEST,"EVENT","analyst",AT,AT,AT))

    def test_sha256_rejects_nonhex_and_wrong_length(self):
        for digest in ("g"*64,"AB"*32,"a"*63):
            with self.subTest(digest=digest), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO soc_event_receipts(tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,created_at) "
                                "VALUES('acme','another','siem',?,?,?,?)",(AT,AT,digest,AT))

    def test_audit_log_is_append_only_and_tenant_scoped(self):
        self.db.execute("INSERT INTO soc_audit_events(tenant_id,audit_id,actor_type,actor_id,action,resource_type,resource_id,outcome,request_id,event_at) "
                        "VALUES('acme','audit-1','ANALYST','analyst','VIEW','INCIDENT','incident','ALLOW','req-1',?)",(AT,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE soc_audit_events SET outcome='DENY' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_audit_events WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO soc_audit_events(tenant_id,audit_id,actor_type,actor_id,action,resource_type,resource_id,outcome,request_id,event_at) "
                            "VALUES('acme','audit-2','ANALYST','ghost','VIEW','INCIDENT','incident','DENY','req-2',?)",(AT,))

    def test_delete_restrict_preserves_incident_and_evidence_integrity(self):
        self.db.execute("INSERT INTO soc_evidence_manifests "
                        "(tenant_id,manifest_id,incident_id,object_key,artifact_sha256,evidence_kind,collector_id,collected_at,retention_until,created_at) "
                        "VALUES('acme','manifest','incident','soc/acme/object.bin',?,'EVENT','analyst',?,?,?)",(DIGEST,AT,AT,AT))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_incidents WHERE tenant_id='acme' AND incident_id='incident'")


if __name__ == '__main__':
    unittest.main()
