"""AUD-20.1: fail-closed certificate identity, CT, and ECH reference boundaries."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import pki_ech_policy as m


class TestPKIECH(unittest.TestCase):
    def case(self, public=True,ech=True):
        p={"schema_version":"0.1","service_name":"example.test",
           "trust_model":"public-web-pki" if public else "private-pki",
           "require_ct":public,"require_ech":ech,"allow_authenticated_ech_disable":False}
        e={"schema_version":"0.1","service_name":"example.test","tls_version":"TLS1.3",
           "certificate_chain_valid":True,"certificate_time_valid":True,
           "reference_identifier_valid":True,"common_name_fallback_used":False,
           "ct_applicable":public,"platform_ct_enforced":public,"platform_ct_valid":public,
           "ech_offered":True,"ech_accepted":True,"ech_rejected":False,
           "ech_rejection_authenticated_for_public_name":False,
           "ech_retry_authenticated_and_accepted":False,"plain_fallback_used":False,
           "dns_observable":True,"ip_observable":True,"timing_observable":True,
           "platform_observation_digest":"sha256:"+"a"*64}
        trust={"service_name":"example.test",
               "platform_observation_digest":e["platform_observation_digest"],
               "assessor_reference":"trusted-platform-validation"}
        return [p,e,trust]

    def test_baseline_is_only_consistency_not_cryptographic_proof(self):
        r=m.evaluate(*self.case())
        self.assertTrue(r["consistent"],r)
        self.assertTrue(r["ech_protection_supported"])
        self.assertFalse(r["fully_anonymous"])
        self.assertFalse(r["cryptographically_verified"])

    def test_separate_path_identity_ct_and_common_name(self):
        for field in ("certificate_chain_valid","certificate_time_valid",
                      "reference_identifier_valid","platform_ct_enforced","platform_ct_valid"):
            c=self.case();c[1][field]=False
            self.assertFalse(m.evaluate(*c)["consistent"],field)
        c=self.case();c[1]["common_name_fallback_used"]=True
        self.assertFalse(m.evaluate(*c)["consistent"])

    def test_private_pki_has_no_unrelated_public_ct_mandate(self):
        self.assertTrue(m.evaluate(*self.case(public=False))["consistent"])
        c=self.case(public=False);c[0]["require_ct"]=True
        self.assertFalse(m.evaluate(*c)["consistent"])

    def test_authentic_ech_disable_is_separate_from_required_ech(self):
        c=self.case();c[1]["ech_accepted"]=False;c[1]["ech_rejected"]=True
        c[1]["plain_fallback_used"]=True;c[1]["ech_rejection_authenticated_for_public_name"]=True
        self.assertFalse(m.evaluate(*c)["consistent"])
        c[0]["require_ech"]=False;c[0]["allow_authenticated_ech_disable"]=True
        r=m.evaluate(*c);self.assertTrue(r["consistent"],r)
        self.assertFalse(r["ech_protection_supported"])
        c[1]["ech_rejection_authenticated_for_public_name"]=False
        self.assertFalse(m.evaluate(*c)["consistent"])

    def test_retry_must_be_authentic_and_finally_accepted(self):
        c=self.case();c[1]["ech_retry_authenticated_and_accepted"]=True
        self.assertFalse(m.evaluate(*c)["consistent"])
        c[1]["ech_rejection_authenticated_for_public_name"]=True
        self.assertTrue(m.evaluate(*c)["consistent"])

    def test_observation_mismatch_and_malformed_json(self):
        c=self.case();c[2]["platform_observation_digest"]="sha256:"+"b"*64
        self.assertFalse(m.evaluate(*c)["consistent"])
        c=self.case();c[1]["certificate_chain_valid"]=[]
        self.assertFalse(m.evaluate(*c)["consistent"])
        c=self.case();c[0]["require_ech"]=1
        self.assertFalse(m.evaluate(*c)["consistent"])


if __name__=="__main__":
    unittest.main()
