import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from group_healing_reference import evaluate_group_healing, eligible_flow_assurance


class GroupHealingTests(unittest.TestCase):
    def setUp(self):
        self.good = {
            "group_profile": "group-mls-rfc9420@0.1.0",
            "accepted_epoch": 9, "compromise_epoch": 7,
            "applied_update_epoch": 9, "applied_commit_verified": True,
            "fresh_secret_contribution_verified": True,
            "stale_members_excluded": True, "sender_distribution_verified": True,
            "endpoint_still_compromised": False,
        }

    def test_reference_never_claims_endpoint_healing(self):
        decision = evaluate_group_healing(self.good)
        self.assertTrue(decision["reference_conditions_satisfied"])
        self.assertFalse(decision["healed"])

    def test_proposal_timer_and_stale_member_cannot_claim_healing(self):
        for changes in (
            {"applied_commit_verified": False},
            {"applied_update_epoch": 7},
            {"stale_members_excluded": False},
            {"fresh_secret_contribution_verified": False},
            {"endpoint_still_compromised": True},
        ):
            with self.subTest(changes=changes):
                decision = evaluate_group_healing({**self.good, **changes})
                self.assertFalse(decision["healed"])

    def test_group_claim_cannot_inherit_pairwise_pq(self):
        args = dict(pairwise_pq_verified=True, group_pq_verified=False,
                    media_pq_verified=False, attachment_pq_verified=False,
                    backup_pq_verified=False)
        self.assertTrue(eligible_flow_assurance("direct_message", **args)["pq_claim_supported"])
        for flow in ("group_message", "media", "attachment", "backup"):
            self.assertFalse(eligible_flow_assurance(flow, **args)["pq_claim_supported"])

    def test_sender_distribution_and_input_types_fail_closed(self):
        x = {**self.good, "group_profile": "group-sender-key-aead@0.1.0",
             "sender_distribution_verified": False}
        self.assertEqual(evaluate_group_healing(x)["reason"],
                         "sender-keys-not-redistributed-over-trusted-channels")
        self.assertEqual(evaluate_group_healing({**self.good, "accepted_epoch": True})["reason"],
                         "invalid-epoch")


if __name__ == "__main__":
    unittest.main()
