"""AUD-10.2: scope-specific production claims require real egress assurance."""
from __future__ import annotations
import copy
from datetime import datetime, timezone
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import scoped_assessment as assess
from test_component_inventory import fixture

SHA="sha256:"+"a"*64

class ProtectedEgressGateTests(unittest.TestCase):
    def setUp(self):
        self.inventory=fixture()
        self.flow_id=self.inventory["flows"][0]["flow_id"]
        self.now=datetime(2026,10,9,23,0,0,tzinfo=timezone.utc)
        self.evidence={
            "provider_kind":"real-provider","result":"pass",
            "source_digest":self.inventory["source_digest"],
            "artifact_digest":self.inventory["artifact_digest"],
            "flow_id":self.flow_id,"verified_at":"2026-10-09T22:00:00Z",
            "valid_until":"2026-10-10T22:00:00Z",
            "covered_phases":["success","failure","crash","retry","analytics","background","user-action"],
            "egress_completeness_verified":True,"content_derivation_paths_tested":True,
            "recipient_key_isolation_tested":True,"metadata_egress_tested":True,
            "explicit_consent_scopes_tested":True,"provenance_reference":"authentic-source-review",
            "packet_capture_reference":"actual-outbound-trace",
            "egress_policy_digest":SHA,
            "flow_inventory_evidence_reference":"independent-flow-coverage",
            "negative_path_test_reference":"adversarial-export-scenarios",
        }

    def accepted(self,evidence=None,inventory=None):
        return assess.complete_protected_egress_assessment(
            self.evidence if evidence is None else evidence,
            self.inventory if inventory is None else inventory,
            self.flow_id,self.now
        )

    def test_reference_only_or_absent_evidence_never_qualifies(self):
        self.assertFalse(self.accepted({}))
        self.assertFalse(self.accepted({"provider_kind":"reference","result":"pass"}))

    def test_mock_adapter_record_can_model_all_fields_but_does_not_prove_real_provider(self):
        self.assertTrue(self.accepted())  # Synthetic trusted-adapter fixture, NOT a real audit.
        e=copy.deepcopy(self.evidence);e["provider_kind"]="mock"
        self.assertFalse(self.accepted(e))

    def test_incomplete_egress_phases_invalidate_evidence(self):
        for phase in self.evidence["covered_phases"]:
            with self.subTest(phase=phase):
                e=copy.deepcopy(self.evidence)
                e["covered_phases"].remove(phase)
                self.assertFalse(self.accepted(e))

    def test_false_completeness_and_untested_content_egress_fail(self):
        for key in (
            "egress_completeness_verified","content_derivation_paths_tested",
            "recipient_key_isolation_tested","metadata_egress_tested",
            "explicit_consent_scopes_tested",
        ):
            e=copy.deepcopy(self.evidence);e[key]=False
            self.assertFalse(self.accepted(e))

    def test_stale_source_artifact_and_flow_bindings_fail(self):
        for field in ("source_digest","artifact_digest"):
            e=copy.deepcopy(self.evidence);e[field]="sha256:"+"0"*64
            self.assertFalse(self.accepted(e))
        e=copy.deepcopy(self.evidence);e["flow_id"]="unrelated"
        self.assertFalse(self.accepted(e))

    def test_stale_timestamps_and_bad_policy_digest_fail(self):
        e=copy.deepcopy(self.evidence);e["valid_until"]="2026-10-08T22:00:00Z"
        self.assertFalse(self.accepted(e))
        e=copy.deepcopy(self.evidence);e["verified_at"]="2026-10-10T00:00:00Z"
        self.assertFalse(self.accepted(e))
        e=copy.deepcopy(self.evidence);e["egress_policy_digest"]="not-a-hash"
        self.assertFalse(self.accepted(e))

    def test_applicant_cannot_supply_trusted_egress_in_request(self):
        r={
            "schema_version":"0.2","assessment_id":"test-egress",
            "evaluated_at":"2026-10-09T23:00:00Z","policy":"production",
            "standard_lock":assess.standard_lock(),
            "inventory":self.inventory,"claims":[],
            "trusted_egress_evidence":self.evidence,"request_digest":"",
        }
        r["request_digest"]=assess.request_digest(r)
        self.assertEqual(assess.evaluate(r)["verdict"],"fail")
        self.assertIn("assessment request fields mismatch",assess.evaluate(r)["errors"])

    def test_protected_content_claim_without_egress_remains_indeterminate(self):
        from test_scoped_assessment import ScopedAssessmentTests
        t=ScopedAssessmentTests()
        r=t.messaging(t.request())
        r["policy"]="production"
        r["claims"]=[dict(t.claim(),profile_refs=["pairwise-pqxdh-triple-ratchet@0.1.0"],
                          evidence_refs=["claimed-test-evidence"])]
        r=t.bind(r)
        result=assess.evaluate(r,verified_evidence={"claimed-test-evidence":{"provider_kind":"mock"}})
        self.assertEqual(result["verdict"],"indeterminate")
        self.assertIn("protected egress assessment", " ".join(result["claims"][0]["reasons"]))


if __name__=="__main__":
    unittest.main()
