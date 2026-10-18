"""AUD-18: construction-specific hybrid TLS lifecycle/claim tests."""
from __future__ import annotations
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import hybrid_construction_claims as h


class HybridClaimTests(unittest.TestCase):
    def load(self,path):
        return json.loads((ROOT/path).read_text(encoding="utf-8"))

    def args(self,group="X25519MLKEM768"):
        classical,pq=h.GROUPS[group]
        declaration={
            "schema_version":"0.1",
            "profile_ref":"transport-tls13-hybrid@0.1.0",
            "negotiated_group_id":group,
            "traditional_algorithm_id":classical,
            "pq_kem_algorithm_id":pq,
            "protocol_specification":"RFC 10024",
            "combiner_specification":"RFC 9954",
            "negotiated_tls_version":"TLS1.3",
            "hybrid_transcript_sha256":"sha256:"+"a"*64,
            "traditional_secret_integrated":True,
            "pq_secret_integrated":True,
            "downgrade_rejected":True,
            "claimed_property_id":"SP-PQ-CONFIDENTIALITY",
            "combiner_property_scope":"construction-specific-confidentiality",
        }
        trusted={
            "independently_verified_transcript_sha256":declaration["hybrid_transcript_sha256"],
            "independently_verified_group_id":group,
            "assessor_reference":"trusted-transcript-record",
        }
        return [declaration,trusted,self.load("registry/cryptographic-algorithms.json"),
                self.load("registry/transport-security.json")]

    def test_all_three_registered_rfc10024_groups(self):
        for group in h.GROUPS:
            with self.subTest(group=group):
                r=h.assess(*self.args(group))
                self.assertTrue(r["consistent"],r)
                self.assertFalse(r["cryptographically_verified"])
                self.assertFalse(r["certified"])

    def test_incompatible_algorithm_protocol_or_group(self):
        for field,value in (
            ("negotiated_group_id","X25519"),
            ("negotiated_group_id","X25519Kyber768Draft00"),
            ("profile_ref","transport-tls13-classical@0.1.0"),
            ("protocol_specification","draft"),
            ("combiner_specification","unreviewed-xor"),
            ("negotiated_tls_version","TLS1.2"),
            ("traditional_algorithm_id","ALG-HPKE-DHKEM-X25519-HKDF-SHA256"),
            ("pq_kem_algorithm_id","ALG-ML-KEM-512"),
        ):
            with self.subTest(field=field):
                a=self.args();a[0][field]=value
                self.assertFalse(h.assess(*a)["consistent"])

    def test_both_components_and_no_downgrade(self):
        for field in ("traditional_secret_integrated","pq_secret_integrated","downgrade_rejected"):
            a=self.args();a[0][field]=False
            self.assertFalse(h.assess(*a)["consistent"])

    def test_no_universal_hybrid_or_pq_authentication_overclaims(self):
        for key,value in (
            ("claimed_property_id","SP-PQ-AUTHENTICATION"),
            ("combiner_property_scope","all-security-properties"),
        ):
            a=self.args();a[0][key]=value
            self.assertFalse(h.assess(*a)["consistent"])

    def test_component_lifecycle_still_applies(self):
        a=self.args()
        next(x for x in a[2]["algorithms"] if x["id"]=="ALG-X25519")["status"]="prohibited"
        self.assertFalse(h.assess(*a)["consistent"])
        a=self.args()
        next(x for x in a[3]["groups"] if x["id"]=="X25519MLKEM768")["status"]="experimental"
        self.assertFalse(h.assess(*a)["consistent"])

    def test_independent_transcript_anchor_required(self):
        a=self.args();a[1]={}
        self.assertFalse(h.assess(*a)["consistent"])
        a=self.args();a[1]["independently_verified_transcript_sha256"]="sha256:"+"b"*64
        self.assertFalse(h.assess(*a)["consistent"])
        a=self.args();a[0]["claims_certified"]=True
        self.assertFalse(h.assess(*a)["consistent"])

    def test_malformed_untrusted_json_never_causes_dictionary_lookup_crashes(self):
        for key,value in (
            ("negotiated_group_id",[]),
            ("traditional_algorithm_id",{}),
            ("pq_kem_algorithm_id",[]),
            ("hybrid_transcript_sha256",{}),
        ):
            with self.subTest(key=key):
                a=self.args();a[0][key]=value
                self.assertFalse(h.assess(*a)["consistent"])


if __name__=="__main__":
    unittest.main()
