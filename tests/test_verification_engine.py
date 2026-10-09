import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import verification_engine as engine
from assurance_common import digest, load_json


class VerificationTests(unittest.TestCase):
    def pair(self,name="combined"):
        return (load_json(ROOT/f"fixtures/verification/policies/{name}.json"),
                load_json(ROOT/f"fixtures/verification/evidence/{name}.json"))

    def validate(self,p,e):
        return engine.validate_assessment(p,e,load_json(ROOT/"fixtures/profiles/development-catalog.json"))

    def reject(self,path,value):
        p,e=self.pair();node=e
        for key in path[:-1]:node=node[key]
        node[path[-1]]=value
        self.assertTrue(self.validate(p,e),(path,value))

    def test_all_assessment_profiles_and_negative_fixtures(self):
        for name in ("blackbox","whitebox","combined"):self.assertEqual(self.validate(*self.pair(name)),[])
        self.assertEqual(engine.validate_repository(ROOT,load_json(ROOT/"fixtures/profiles/development-catalog.json")),[])

    def test_missing_or_wrong_per_profile_methods(self):
        p,e=self.pair();e["suites"]=[s for s in e["suites"] if s["method"]!="fuzz"]
        self.assertTrue(any("missing per-profile" in x for x in self.validate(p,e)))
        self.reject(["suites",0,"profile_refs"],["unknown-profile@0.1.0"])
        self.reject(["tested_profile_refs"],["client-native-signed@0.1.0"])

    def test_exact_scope_and_authentication(self):
        self.reject(["suites",0,"source_digest"],"sha256:"+"0"*64)
        self.reject(["suites",0,"artifact_digest"],"sha256:"+"0"*64)
        self.reject(["policy_digest"],"sha256:"+"0"*64)
        self.reject(["assessment_authenticated"],False)

    def test_independent_assessors_and_suite_authority(self):
        self.reject(["assessor_ids"],["product-team"])
        self.reject(["suites",0,"assessor_id"],"other-lab")

    def test_failure_flakiness_and_counterexamples_block_release(self):
        for status in ("failed","skipped","flaky","cancelled"):self.reject(["suites",0,"status"],status)
        self.reject(["suites",0,"failure_count"],1)
        self.reject(["suites",0,"unresolved_counterexamples"],True)

    def test_fuzz_campaign_and_property_case_floors(self):
        for method,field,value in (("fuzz","test_cases",999),("fuzz","duration_seconds",59),("fuzz","corpus_digest",None),("property","test_cases",99)):
            p,e=self.pair();suite=next(s for s in e["suites"] if s["method"]==method);suite[field]=value
            self.assertTrue(self.validate(p,e))

    def test_protocol_model_spec_pin_and_proof_limits(self):
        p,e=self.pair();suite=next(s for s in e["suites"] if s["method"]=="protocol-model")
        suite["model"]["standard_version"]="other";self.assertTrue(self.validate(p,e))
        self.reject(["claims_full_formal_verification"],True)
        self.reject(["claims_no_unknown_vulnerabilities"],True)

    def test_coverage_of_required_threats_and_properties(self):
        for field in ("property_ids","threat_ids"):
            p,e=self.pair()
            for suite in e["suites"]:suite[field]=[]
            self.assertTrue(self.validate(p,e))
        self.reject(["suites",0,"property_ids"],["SP-UNKNOWN"])
        self.reject(["suites",0,"threat_ids"],["TM-UNKNOWN"])

    def test_profile_resolution_rejects_conflicts_and_illustrative_only_scope(self):
        p,e=self.pair();p["configuration"]["selected_profiles"].extend(["client-native-signed@0.1.0","client-web-hardened@0.1.0"])
        e["policy_digest"]=digest(p);self.assertTrue(self.validate(p,e))
        p,e=self.pair();p["configuration"]["selected_profiles"].remove("server-ciphertext-only@0.1.0")
        e["policy_digest"]=digest(p);self.assertTrue(self.validate(p,e))

    def test_blackbox_cannot_claim_internal_key_lifecycle_properties(self):
        p,e=self.pair("blackbox");p["configuration"]["selected_profiles"].append("pairwise-x3dh-double-ratchet@0.1.0")
        p["required_property_ids"].append("SP-FORWARD-SECRECY");e["policy_digest"]=digest(p)
        self.assertTrue(any("black-box-only" in x for x in self.validate(p,e)))

    def test_future_stale_duplicate_and_malformed_evidence(self):
        self.reject(["suites",0,"completed_at"],"2026-10-08T00:00:00Z")
        self.reject(["suites",0,"completed_at"],"2026-10-01T00:00:00Z")
        p,e=self.pair();e["suites"].append(copy.deepcopy(e["suites"][0]));self.assertTrue(self.validate(p,e))
        self.reject(["report_refs"],[])
        self.reject(["limitations_disclosed"],"true")


if __name__=="__main__":unittest.main()
