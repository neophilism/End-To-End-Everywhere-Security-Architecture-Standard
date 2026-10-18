import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from push_observer_reference import assess_push_observation, response_policy

class PushObserverTests(unittest.TestCase):
    def setUp(self):
        self.base = {
            "mode": "wake-only",
            "declared_outer_fields": ["routing_token", "timestamp"],
            "actual_outer_fields": ["routing_token"],
            "encrypted_fields": [],
            "recipient_key_verified": False,
            "provider_can_decrypt": False,
            "plaintext_relationship_ids": False,
            "routing_token_reused_across_services": False,
            "response_correlation_tested": True,
            "provider_observed_timing": True,
        }

    def test_wake_only_is_not_encrypted_payload(self):
        self.assertTrue(assess_push_observation(self.base)["eligible"])
        self.assertEqual(assess_push_observation({**self.base, "encrypted_fields": ["message"]})["reason"],
                         "wake-only-cannot-carry-protected-payload")

    def test_no_plaintext_or_cross_service_token_reuse(self):
        for change in ({"plaintext_relationship_ids": True},
                       {"routing_token_reused_across_services": True},
                       {"actual_outer_fields": ["undeclared"]}):
            self.assertFalse(assess_push_observation({**self.base, **change})["eligible"])

    def test_encrypted_mode_cannot_be_readable_to_provider(self):
        v = {**self.base, "mode": "encrypted-payload",
             "encrypted_fields": ["content"], "recipient_key_verified": True}
        self.assertTrue(assess_push_observation(v)["eligible"])
        self.assertFalse(assess_push_observation({**v, "provider_can_decrypt": True})["eligible"])

    def test_jitter_never_proves_anonymity(self):
        self.assertEqual(response_policy(mode="delayed",delay_verified=True,
                          batching_verified=False,no_receipt_verified=False)["anonymity_proven"],False)
        self.assertFalse(response_policy(mode="batched",delay_verified=True,
                         batching_verified=False,no_receipt_verified=False)["reference_consistent"])

if __name__ == "__main__":
    unittest.main()
