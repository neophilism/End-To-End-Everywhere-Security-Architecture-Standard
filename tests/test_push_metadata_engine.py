"""AUD-17: wake-only, ciphertext, provider visibility, and response metadata."""
from __future__ import annotations
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import push_metadata_engine as p

HASH = "sha256:" + "a" * 64
TOKEN = "sha256:" + "b" * 64


class PushProviderPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "schema_version":"0.1","policy_id":"push-policy",
            "provider_id":"provider-fcm","app_scope_id":"private-messenger",
            "endpoint_recipient_id":"endpoint-alice",
            "endpoint_key_fingerprint":HASH,"encryption_profile_ref":"capsule-aead@0.1.0",
            "mode":"wake-only","allowed_outer_fields":["push-token","ttl"],
            "response_mode":"no-receipt","minimum_response_delay_seconds":0,
            "minimum_response_batch_size":0,
        }
        self.observation={
            "observation_id":"first-observation","provider_id":"provider-fcm",
            "app_scope_id":"private-messenger","token_digest":TOKEN,
            "mode":"wake-only","outer_fields":["push-token"],
            "payload_class":"empty","payload_length_bytes":0,
            "recipient_id":"endpoint-alice",
            "recipient_key_fingerprint":None,"encryption_profile_ref":None,
            "provider_can_decrypt":False,"send_epoch":100,
            "response_epoch":None,"batch_count":None,
        }

    def inspect(self, changes=None, policy=None):
        obs={**self.observation, **(changes or {})}
        return p.evaluate_observation(policy or self.policy,obs)

    def test_wake_only_payload_cannot_contain_content(self):
        self.assertTrue(self.inspect()["accepted"])
        for mod in (
            {"payload_class":"plaintext"},
            {"payload_class":"endpoint-ciphertext","payload_length_bytes":100},
            {"payload_length_bytes":1},
            {"recipient_key_fingerprint":HASH},
            {"encryption_profile_ref":"capsule-aead@0.1.0"},
        ):
            with self.subTest(mod=mod):
                self.assertEqual(self.inspect(mod)["reason"],"wake-only-must-carry-no-payload")

    def test_opaque_ciphertext_requires_verified_endpoint_key_not_provider_key(self):
        pol=copy.deepcopy(self.policy);pol["mode"]="opaque-encrypted-payload"
        obs={"mode":"opaque-encrypted-payload","payload_class":"endpoint-ciphertext",
             "payload_length_bytes":100,"recipient_key_fingerprint":HASH,
             "encryption_profile_ref":"capsule-aead@0.1.0"}
        result=self.inspect(obs,pol)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["provider_confidentiality_proved"])
        for mutation in (
            {"provider_can_decrypt":True},
            {"recipient_key_fingerprint":"sha256:"+"c"*64},
            {"payload_class":"plaintext"},
            {"encryption_profile_ref":"capsule-weaker@0.1.0"},
            {"payload_length_bytes":0},
        ):
            with self.subTest(mutation=mutation):
                self.assertEqual(self.inspect({**obs,**mutation},pol)["reason"],
                                 "provider-decryptable-or-unbound-ciphertext")

    def test_plaintext_relationship_identifier_not_outer_metadata(self):
        for field in ("sender-identity","recipient-identity","relationship-id","plaintext-preview"):
            result=self.inspect({"outer_fields":["push-token",field]})
            self.assertEqual(result["reason"],"undeclared-outer-metadata")
            pol=copy.deepcopy(self.policy)
            pol["allowed_outer_fields"].append(field)
            with self.assertRaises(ValueError):
                p.validate_policy(pol)

    def test_modes_cannot_be_downgraded(self):
        self.assertEqual(self.inspect({"mode":"opaque-encrypted-payload"})["reason"],"push-mode-downgrade")

    def test_provider_and_recipient_pin(self):
        self.assertEqual(self.inspect({"provider_id":"provider-other"})["reason"],"provider-or-app-scope-mismatch")
        self.assertEqual(self.inspect({"recipient_id":"endpoint-mallory"})["reason"],"wrong-endpoint-recipient")

    def test_silent_no_receipt_prevents_automatic_response(self):
        self.assertTrue(self.inspect()["accepted"])
        self.assertEqual(self.inspect({"response_epoch":120})["reason"],"automatic-response-forbidden")

    def test_delay_and_batch_do_not_establish_anonymity(self):
        pol=copy.deepcopy(self.policy);pol.update(response_mode="bounded-delay",minimum_response_delay_seconds=15)
        self.assertFalse(self.inspect({"response_epoch":105},pol)["accepted"])
        result=self.inspect({"response_epoch":125},pol)
        self.assertTrue(result["accepted"]);self.assertFalse(result["relationship_anonymity_proved"])
        pol.update(response_mode="batch",minimum_response_delay_seconds=0,minimum_response_batch_size=3)
        self.assertEqual(self.inspect({"response_epoch":125,"batch_count":2},pol)["reason"],
                         "insufficient-or-malformed-response-batch")
        result=self.inspect({"response_epoch":125,"batch_count":3},pol)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["relationship_anonymity_proved"])

    def test_replayed_event_and_cross_service_token_reuse(self):
        first=copy.deepcopy(self.observation)
        second={**first,"observation_id":"second-observation"}
        self.assertEqual(p.evaluate_observations([self.policy],[first,first])["results"][1]["reason"],
                         "replayed-observation-id")
        pol2={**self.policy,"provider_id":"provider-apns","app_scope_id":"different-application"}
        different={**second,"provider_id":"provider-apns","app_scope_id":"different-application"}
        report=p.evaluate_observations([self.policy,pol2],[first,different])
        self.assertFalse(report["accepted"])
        self.assertEqual(report["results"][1]["reason"],"cross-service-token-reuse")
        different["token_digest"]="sha256:"+"e"*64
        self.assertTrue(p.evaluate_observations([self.policy,pol2],[first,different])["accepted"])

    def test_no_confidentiality_or_anonymity_from_self_reported_evidence(self):
        result=p.evaluate_observations([self.policy],[self.observation])
        self.assertTrue(result["accepted"])
        self.assertFalse(result["provider_confidentiality_proved"])
        self.assertFalse(result["relationship_anonymity_proved"])
        self.assertIn("timing-and-global-observer-correlation-remain-possible",
                      result["results"][0]["limits"])

    def test_malformed_unrecognized_or_replayed_fields_fail(self):
        x=copy.deepcopy(self.observation)
        x["payload_exfiltration"]="secret"
        self.assertEqual(p.evaluate_observation(self.policy,x)["reason"],"invalid-observation")
        self.assertEqual(p.evaluate_observations([], [self.observation])["results"][0]["reason"],
                         "undeclared-provider-or-app")
        self.assertEqual(self.inspect({"provider_can_decrypt":True})["reason"],
                         "wake-only-provider-content-claim-invalid")


if __name__ == "__main__":
    unittest.main()
