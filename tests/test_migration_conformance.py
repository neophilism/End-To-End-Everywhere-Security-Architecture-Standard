"""AUD-24: explicit legacy-byte migration and identity authority tests."""
import copy
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import migration_conformance as m
import canonical_serialization as canon


class MigrationContractTests(unittest.TestCase):
    def base(self):
        rec={
            "schema_version":"0.1",
            "source_standard_basis":"0.9.0-rc.1",
            "target_standard_basis":"0.9.0-rc.2-dev",
            "source_serialization_scheme":"legacy-python-ascii-v0",
            "target_serialization_scheme":"e2eesa-jcs-integer-v1",
            "source_artifact_digest":"sha256:"+"a"*64,
            "new_artifact_digest":"sha256:"+"b"*64,
            "migration_mode":"derive-new-record-preserve-history",
            "source_signed_bytes_preserved":True,
            "historical_signature_verified_on_original_bytes":True,
            "source_identity_root":"original-account-root",
            "target_identity_root":"original-account-root",
            "identity_authority_transition":"retained-root",
            "fresh_peer_comparison_required":False,
            "reenrollment_explicitly_authorized":False,
            "source_evidence_class":"historical-signed-artifact",
            "target_evidence_class":"unassessed-development-derived",
            "migration_test_report_digest":"sha256:"+"c"*64,
        }
        trust={"source_standard_basis":"0.9.0-rc.1",
               "source_artifact_digest":rec["source_artifact_digest"],
               "historical_verifier_report_digest":rec["migration_test_report_digest"],
               "approved_authority_transition_digest":None}
        return [rec,trust]

    def test_distinct_derived_artifact_is_not_new_signed_legacy_artifact(self):
        r=m.assess(*self.base())
        self.assertTrue(r["consistent"],r)
        self.assertFalse(r["cryptographically_verified"])
        self.assertFalse(r["legacy_signed_bytes_rewritten"])

    def test_original_historical_bytes_retained(self):
        obj={"name":"café","revision":4}
        legacy=canon.bytes_for_scheme(obj,scheme="legacy-python-ascii-v0")
        active=canon.bytes_for_scheme(obj,scheme=canon.SCHEME)
        self.assertNotEqual(legacy,active)
        self.assertIn(b"\\u00e9",legacy)
        self.assertIn("é".encode(),active)

    def test_unapproved_modes_and_versions_are_rejected(self):
        for field,value in (
            ("source_standard_basis","1.0.0"),
            ("target_standard_basis","1.0.0"),
            ("source_serialization_scheme",[]),
            ("target_serialization_scheme","legacy-python-ascii-v0"),
            ("migration_mode","rewrite-source"),
            ("source_signed_bytes_preserved",False),
            ("historical_signature_verified_on_original_bytes",False),
        ):
            with self.subTest(field=field):
                c=self.base();c[0][field]=value
                self.assertFalse(m.assess(*c)["consistent"])

    def test_history_only_creates_no_derived_artifact(self):
        c=self.base()
        c[0]["migration_mode"]="verify-historical-only"
        c[0]["new_artifact_digest"]=None
        c[0]["target_evidence_class"]="historical-verification-only"
        self.assertTrue(m.assess(*c)["consistent"])
        c[0]["new_artifact_digest"]="sha256:"+"1"*64
        self.assertFalse(m.assess(*c)["consistent"])

    def test_replacement_is_never_silent_verified_trust_transfer(self):
        c=self.base()
        c[0]["target_identity_root"]="different-account-root"
        self.assertFalse(m.assess(*c)["consistent"])
        c[0]["identity_authority_transition"]="replacement-identity"
        c[0]["fresh_peer_comparison_required"]=True
        c[0]["reenrollment_explicitly_authorized"]=True
        self.assertFalse(m.assess(*c)["consistent"])
        c[1]["approved_authority_transition_digest"]="sha256:"+"d"*64
        self.assertTrue(m.assess(*c)["consistent"])

    def test_external_verifier_and_scope_mismatch_fail(self):
        c=self.base()
        c[1]["historical_verifier_report_digest"]="sha256:"+"1"*64
        self.assertFalse(m.assess(*c)["consistent"])
        c=self.base()
        c[0]["target_evidence_class"]="certified-production"
        self.assertFalse(m.assess(*c)["consistent"])
        c=self.base()
        c[0]["new_artifact_digest"]=c[0]["source_artifact_digest"]
        self.assertFalse(m.assess(*c)["consistent"])

    def test_malformed_json_shape_and_flags_fail_closed(self):
        c=self.base();c[0]["migration_mode"]=[]
        self.assertFalse(m.assess(*c)["consistent"])
        c=self.base();c[0]["source_signed_bytes_preserved"]=1
        self.assertFalse(m.assess(*c)["consistent"])
        c=self.base();c[1]={}
        self.assertFalse(m.assess(*c)["consistent"])


if __name__=="__main__":
    unittest.main()
