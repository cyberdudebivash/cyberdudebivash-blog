"""Source-only real SQLite regression for SOC detection human review.

Run: python3 -m unittest -v tests.test_soc_detection_review_provenance
No production D1, no customer event data, no HTTP, no made-up live incidents.
"""
import datetime
import sqlite3
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCHEMAS=[
 (ROOT/"migrations"/name).read_text(encoding="utf8")
 for name in (
  "0009_soc_tenant_control_plane.sql",
  "0010_soc_incident_audit_invariants.sql",
  "0012_soc_event_receipt_integrity.sql",
  "0013_soc_connector_key_lifecycle.sql",
  "0014_soc_detection_review_provenance.sql",
 )
]
NOW=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
AT=NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
START=int(NOW.timestamp())-60
EXP=int(NOW.timestamp())+3600
EVENT="evt_"+"a"*64
HASH="b"*64
ATTEST="c"*64
DETECTION="det_"+"d"*24
INCIDENT="inc_00000000-0000-4000-8000-000000000001"
NOTE="Reviewed and independently checked matching source evidence."


class DetectionReviewProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        for sql in SCHEMAS:
            self.db.executescript(sql)
        for t in ("acme","contoso"):
            self.db.execute(
                "INSERT INTO soc_tenants(tenant_id,legal_name,status,data_region,retention_days,created_at,updated_at) "
                "VALUES (?,?,'ACTIVE','IN',30,?,?)",(t,t,AT,AT))
            for who,role,status in [
                ("analyst","ANALYST","ACTIVE"),
                ("reader","READ_ONLY","ACTIVE"),
                ("revoked","ANALYST","REVOKED"),
            ]:
                self.db.execute(
                    "INSERT INTO soc_principals(tenant_id,principal_id,oidc_issuer,oidc_subject,role,status,created_at,updated_at) "
                    "VALUES(?,?, 'https://idp.example',?,?,?,?,?)",
                    (t,who,f"{t}-{who}",role,status,AT,AT))
            self.db.execute(
                "INSERT INTO soc_connectors(tenant_id,connector_id,type,authorized_scope,state,created_by,created_at,updated_at) "
                "VALUES(?,'edr','EDR','signed-metadata','APPROVED','analyst',?,?)",
                (t,AT,AT))
            # Key insertion must have an ACTIVE TENANT_ADMIN; promote analyst
            # only for local key enrollment, then restore analyst role.
            self.db.execute(
                "UPDATE soc_principals SET role='TENANT_ADMIN' WHERE tenant_id=? AND principal_id='analyst'",(t,))
            self.db.execute(
                "INSERT INTO soc_connector_signing_keys("
                "tenant_id,connector_id,key_id,valid_from_epoch,expires_epoch,"
                "created_by,changed_by,created_at,updated_at"
                ") VALUES (?,'edr','key-20261021',?,?, 'analyst','analyst',?,?)",
                (t,START,EXP,AT,AT))
            self.db.execute(
                "UPDATE soc_connector_signing_keys SET state='ACTIVE',changed_by='analyst',updated_at=? "
                "WHERE tenant_id=? AND connector_id='edr' AND key_id='key-20261021'",(AT,t))
            self.db.execute(
                "UPDATE soc_principals SET role='ANALYST' WHERE tenant_id=? AND principal_id='analyst'",(t,))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def event(self,tenant="acme",event_id=EVENT):
        self.db.execute(
            "INSERT INTO soc_event_receipts("
            "tenant_id,event_id,connector_id,source_event_at,received_at,digest_sha256,"
            "created_at,source_signed_at,attestation_sha256,signing_key_id"
            ") VALUES (?,?,'edr',?,?,?,?,?,?,'key-20261021')",
            (tenant,event_id,AT,AT,HASH,AT,AT,ATTEST))

    def candidate(self,tenant="acme",det=DETECTION,source=EVENT,
                  state="SOURCE_REPORTED",rule="rule.edr.signed",
                  version="v1",severity="HIGH"):
        self.db.execute(
            "INSERT INTO soc_detections(tenant_id,detection_id,event_id,rule_id,"
            "rule_version,severity,evidence_state,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (tenant,det,source,rule,version,severity,state,AT))

    def review(self,tenant="acme",det=DETECTION,state="ANALYST_VERIFIED",
               actor="analyst",req="review-2026102100001",digest=HASH,
               note=NOTE):
        return self.db.execute(
            "UPDATE soc_detections SET evidence_state=?,review_actor_id=?,"
            "review_request_id=?,review_note=?,reviewed_at=?,"
            "review_basis_sha256=?,review_version=review_version+1 "
            "WHERE tenant_id=? AND detection_id=? AND evidence_state='SOURCE_REPORTED' AND review_version=0",
            (state,actor,req,note,AT,digest,tenant,det))

    def create_incident(self,tenant="acme",id=INCIDENT,req="incident-20261021001"):
        self.db.execute(
            "INSERT INTO soc_incidents(tenant_id,incident_id,title,severity,"
            "audit_actor_id,audit_request_id,created_at,updated_at) "
            "VALUES(?,?,'Reviewed pilot finding','HIGH','analyst',?,?,?)",
            (tenant,id,req,AT,AT))

    def link(self,tenant="acme",id=INCIDENT,det=DETECTION,actor="analyst",
             req="link-2026102100000001"):
        self.db.execute(
            "INSERT INTO soc_incident_detections("
            "tenant_id,incident_id,detection_id,linked_at,linked_by,link_request_id) "
            "VALUES(?,?,?,?,?,?)",(tenant,id,det,AT,actor,req))

    def count(self,table,tenant="acme",where=""):
        return self.db.execute(
            "SELECT count(*) FROM "+table+" WHERE tenant_id=? "+where,(tenant,)
        ).fetchone()[0]

    def test_unverified_candidate_is_source_reported_with_atomic_system_audit(self):
        self.event()
        self.candidate()
        self.assertEqual(self.db.execute(
            "SELECT evidence_state,review_version,review_actor_id FROM soc_detections"
        ).fetchone(),("SOURCE_REPORTED",0,None))
        self.assertEqual(self.db.execute(
            "SELECT action,actor_type FROM soc_audit_events WHERE action='DETECTION_CANDIDATE_RECORDED'"
        ).fetchone(),("DETECTION_CANDIDATE_RECORDED","SYSTEM"))

    def test_candidate_cannot_skip_to_verified_without_an_authenticated_review(self):
        self.event()
        for state in ("ANALYST_VERIFIED","REJECTED"):
            with self.subTest(state=state),self.assertRaises(sqlite3.IntegrityError):
                self.candidate(state=state)
        self.assertEqual(self.count("soc_detections"),0)

    def test_candidate_requires_current_signed_event_and_approved_connector(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.candidate()
        self.event()
        self.db.execute(
            "UPDATE soc_connectors SET state='PAUSED' WHERE tenant_id='acme' AND connector_id='edr'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.candidate()
        self.assertEqual(self.count("soc_detections"),0)

    def test_duplicate_candidate_rule_and_version_cannot_clone_one_source(self):
        self.event()
        self.candidate()
        with self.assertRaises(sqlite3.IntegrityError):
            self.candidate(det="det_"+"e"*24)
        self.assertEqual(self.count("soc_detections"),1)

    def test_verified_review_requires_actor_rationale_and_matching_payload_digest(self):
        self.event()
        self.candidate()
        for kwargs in [
            {"actor":"reader"},{"actor":"revoked"},{"actor":"unknown"},
            {"note":"short"},{"digest":"d"*64},{"digest":None},{"req":"short"}
        ]:
            with self.subTest(kwargs=kwargs),self.assertRaises(sqlite3.IntegrityError):
                self.review(**kwargs)
        self.assertEqual(self.count("soc_audit_events",where="AND action='DETECTION_ANALYST_VERIFIED'"),0)
        self.review()
        self.assertEqual(self.db.execute(
            "SELECT evidence_state,review_version,review_actor_id,review_basis_sha256 "
            "FROM soc_detections WHERE tenant_id='acme'"
        ).fetchone(),("ANALYST_VERIFIED",1,"analyst",HASH))
        self.assertEqual(self.count("soc_audit_events",where="AND action='DETECTION_ANALYST_VERIFIED'"),1)

    def test_rejection_never_confers_verified_evidence(self):
        self.event()
        self.candidate()
        with self.assertRaises(sqlite3.IntegrityError):
            self.review(state="REJECTED")
        self.review(state="REJECTED",digest=None)
        self.assertEqual(self.db.execute(
            "SELECT evidence_state,review_basis_sha256 FROM soc_detections"
        ).fetchone(),("REJECTED",None))
        self.assertEqual(self.count("soc_audit_events",where="AND action='DETECTION_REJECTED'"),1)

    def test_review_cannot_be_rewritten_reversed_or_changed_across_tenant(self):
        self.event()
        self.candidate()
        self.review()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_detections SET evidence_state='REJECTED',review_version=2 "
                "WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_detections SET tenant_id='contoso',review_version=2 "
                "WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_detections WHERE tenant_id='acme'")

    def test_review_request_id_replay_is_atomic(self):
        self.event()
        self.candidate()
        self.candidate(det="det_"+"e"*24,rule="rule.edr.other")
        self.review()
        with self.assertRaises(sqlite3.IntegrityError):
            self.review(det="det_"+"e"*24)
        self.assertEqual(self.db.execute(
            "SELECT evidence_state FROM soc_detections WHERE detection_id=?",("det_"+"e"*24,)
        ).fetchone()[0],"SOURCE_REPORTED")

    def test_incident_cannot_link_an_unverified_or_rejected_candidate(self):
        self.event()
        self.candidate()
        self.create_incident()
        with self.assertRaises(sqlite3.IntegrityError):
            self.link()
        self.review(state="REJECTED",digest=None)
        with self.assertRaises(sqlite3.IntegrityError):
            self.link()
        self.assertEqual(self.count("soc_incident_detections"),0)

    def test_verified_detection_links_only_with_active_analyst_and_atomic_audit(self):
        self.event()
        self.candidate()
        self.review()
        self.create_incident()
        for actor in ("reader","revoked","unknown"):
            with self.subTest(actor=actor),self.assertRaises(sqlite3.IntegrityError):
                self.link(actor=actor)
        self.link()
        self.assertEqual(self.count("soc_incident_detections"),1)
        self.assertEqual(self.count("soc_audit_events",where="AND action='INCIDENT_DETECTION_LINKED'"),1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE soc_incident_detections SET linked_by='reader' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM soc_incident_detections WHERE tenant_id='acme'")

    def test_cross_tenant_incident_cannot_reference_another_tenants_detection(self):
        self.event()
        self.candidate()
        self.review()
        self.create_incident(tenant="contoso")
        with self.assertRaises(sqlite3.IntegrityError):
            self.link(tenant="contoso")
        self.assertEqual(self.count("soc_incident_detections",tenant="contoso"),0)

    def test_suspended_tenant_cannot_complete_review_or_link(self):
        self.event()
        self.candidate()
        self.create_incident()
        self.db.execute("UPDATE soc_tenants SET status='SUSPENDED' WHERE tenant_id='acme'")
        with self.assertRaises(sqlite3.IntegrityError):
            self.review()
        with self.assertRaises(sqlite3.IntegrityError):
            self.link()

    def test_review_audit_failure_rolls_back_entire_state_transition(self):
        self.event()
        self.candidate()
        self.db.execute("""
            CREATE TRIGGER test_deny_review_audit BEFORE INSERT ON soc_audit_events
            WHEN NEW.action='DETECTION_ANALYST_VERIFIED'
            BEGIN SELECT RAISE(ABORT,'forced audit failure'); END;
        """)
        with self.assertRaises(sqlite3.IntegrityError):
            self.review()
        self.assertEqual(self.db.execute(
            "SELECT evidence_state,review_version FROM soc_detections"
        ).fetchone(),("SOURCE_REPORTED",0))

    def test_link_audit_failure_rolls_back_incident_reference(self):
        self.event()
        self.candidate()
        self.review()
        self.create_incident()
        self.db.execute("""
            CREATE TRIGGER test_deny_link_audit BEFORE INSERT ON soc_audit_events
            WHEN NEW.action='INCIDENT_DETECTION_LINKED'
            BEGIN SELECT RAISE(ABORT,'forced link audit failure'); END;
        """)
        with self.assertRaises(sqlite3.IntegrityError):
            self.link()
        self.assertEqual(self.count("soc_incident_detections"),0)


if __name__=="__main__":
    unittest.main()
