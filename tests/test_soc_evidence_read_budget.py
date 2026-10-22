"""Offline source-read D1 quota test using EXACT SQL exported by Node module.

No cloud access, customer telemetry, provider credentials or remote migration.
python3 -m unittest -v tests.test_soc_evidence_read_budget
"""
import datetime as dt
import sqlite3
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MIGRATIONS=[
    (ROOT/"migrations"/f"{i:04d}_{name}.sql").read_text(encoding="utf8")
    for i,name in [
        (9,"soc_tenant_control_plane"),(10,"soc_incident_audit_invariants"),
        (11,"soc_auth_session_authority"),(12,"soc_event_receipt_integrity"),
        (13,"soc_connector_key_lifecycle"),(14,"soc_detection_review_provenance"),
        (15,"soc_original_event_identity"),(16,"soc_evidence_read_budget"),
    ]
]
READ_SQL=subprocess.check_output([
    "node","-e",
    "process.stdout.write(require('./api/_lib/soc-evidence-read-budget').ADMIT_SQL)"
],cwd=ROOT,text=True)
NOW=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
TS=NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
WIN=(int(NOW.timestamp())//300)*300


class SourceEvidenceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for sql in MIGRATIONS:
            self.db.executescript(sql)
        for tenant in ("acme","contoso"):
            self.db.execute(
                "INSERT INTO soc_tenants(tenant_id,legal_name,status,data_region,retention_days,created_at,updated_at) "
                "VALUES(?,?,'ACTIVE','IN',30,?,?)",(tenant,tenant,TS,TS))
            self.db.execute(
                "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) "
                "VALUES(?,'analyst','https://idp.example',?,'TENANT_ADMIN','ACTIVE',?,?)",
                (tenant,tenant+'-analyst',TS,TS))
            for connector in ("siem","edr"):
                self.db.execute(
                    "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,state,created_by,created_at,updated_at) "
                    "VALUES (?,?,?,'metadata-only','APPROVED','analyst',?,?)",
                    (tenant,connector,connector.upper(),TS,TS))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def read(self,tenant="acme",connector="siem",window=WIN,
             epoch=None,limit=2):
        if epoch is None:
            epoch=window+5
        row=self.db.execute(
            READ_SQL,(window,epoch,tenant,connector,limit)
        ).fetchone()
        return None if row is None else row[0]

    def count(self,tenant="acme",connector="siem"):
        return self.db.execute(
            "SELECT consumed FROM soc_evidence_read_windows "
            "WHERE tenant_id=? AND connector_id=? AND window_start_epoch=?",
            (tenant,connector,WIN)
        ).fetchone()

    def test_atomically_enforces_two_reads_and_no_over_quota_write(self):
        self.assertEqual(self.read(),1)
        self.assertEqual(self.read(),2)
        self.assertIsNone(self.read())
        self.assertEqual(self.count(),(2,))

    def test_separate_tenant_and_connector_cannot_spend_another_budget(self):
        self.assertEqual(self.read(),1)
        self.assertEqual(self.read(connector="edr"),1)
        self.assertEqual(self.read(tenant="contoso"),1)
        self.assertEqual(self.count(),(1,))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_evidence_read_windows"
        ).fetchone()[0],3)

    def test_new_window_resets_capacity_while_retaining_ledger(self):
        self.assertEqual(self.read(),1)
        self.assertEqual(self.read(),2)
        self.assertIsNone(self.read())
        self.assertEqual(self.read(window=WIN+300,epoch=WIN+305),1)
        self.assertEqual(self.count(),(2,))

    def test_paused_or_revoked_connector_fails_even_in_existing_window(self):
        self.assertEqual(self.read(),1)
        self.db.execute(
            "UPDATE soc_connectors SET state='PAUSED' WHERE tenant_id='acme' AND connector_id='siem'")
        self.assertIsNone(self.read())
        self.assertEqual(self.count(),(1,))
        self.db.execute(
            "UPDATE soc_connectors SET state='REVOKED' WHERE tenant_id='acme' AND connector_id='siem'")
        self.assertIsNone(self.read(window=WIN+300,epoch=WIN+305))

    def test_suspended_tenant_fails_even_with_remaining_capacity(self):
        self.assertEqual(self.read(),1)
        self.db.execute("UPDATE soc_tenants SET status='SUSPENDED' WHERE tenant_id='acme'")
        self.assertIsNone(self.read())
        self.assertEqual(self.count(),(1,))

    def test_unknown_scope_never_creates_admission_window(self):
        self.assertIsNone(self.read(tenant="missing"))
        self.assertIsNone(self.read(connector="absent"))
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_evidence_read_windows"
        ).fetchone()[0],0)

    def test_database_rejects_unaligned_windows_and_future_epoch(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.read(window=WIN+1,epoch=WIN+5)
        with self.assertRaises(sqlite3.IntegrityError):
            self.read(window=WIN,epoch=WIN+301)
        self.assertIsNone(self.count())

    def test_single_atomic_sql_command_and_no_sensitive_ledger_columns(self):
        self.assertIn("ON CONFLICT(tenant_id,connector_id,window_start_epoch)",READ_SQL)
        self.assertIn("RETURNING consumed",READ_SQL)
        self.assertIn("t.status='ACTIVE'",READ_SQL)
        self.assertIn("c.state='APPROVED'",READ_SQL)
        cols={x[1] for x in self.db.execute(
            "PRAGMA table_info(soc_evidence_read_windows)"
        )}
        self.assertEqual(cols,{
            "tenant_id","connector_id","window_start_epoch",
            "consumed","last_admitted_epoch"
        })

    def test_no_default_telemetry_or_budget_rows_seeded(self):
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_evidence_read_windows"
        ).fetchone()[0],0)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM soc_event_receipts"
        ).fetchone()[0],0)

if __name__=="__main__":
    unittest.main()
