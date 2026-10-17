"""AUD-11: monotonic recovery attempt budget and hardware evidence boundaries."""
from __future__ import annotations

import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import recovery_attempt_budget as b

HASH = "sha256:" + "1" * 64
POLICY_HASH = "sha256:" + "2" * 64


class HardwareRecoveryAttemptBudgetTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "schema_version": "0.1", "policy_id": "recovery-policy",
            "budget_id": "recovery-budget",
            "secret_class": "user-chosen-low-entropy",
            "maximum_attempts": 2,
            "authority_mode": "single-hardware-counter",
            "hardware_id": "hsm-primary",
            "approved_code_measurement": HASH,
            "approved_policy_digest": POLICY_HASH,
            "replica_ids": ["hsm-a"],
            "authenticated_initiators": ["alice-device"],
            "reset_authority_ids": ["offline-recovery"],
        }
        self.state = b.new_budget_state(self.policy)
        self.head = b.state_digest(self.state, self.policy)

    def receipt(self, **changes):
        r = {
            "hardware_id": "hsm-primary",
            "code_measurement": HASH,
            "policy_digest": POLICY_HASH,
            "replica_id": "hsm-a",
            "epoch": self.state["epoch"],
            "counter": self.state["counter"],
            "attestation_evidence_ref": "verified-attestation",
        }
        r.update(changes)
        return r

    def request(self, **changes):
        q = {
            "operation": "guess",
            "initiator_id": "alice-device",
            "authentication_evidence_ref": "verified-device-signature",
            "replica_id": "hsm-a",
            "reset_authority_id": None,
            "reset_evidence_ref": None,
        }
        q.update(changes)
        return q

    def reserve(self, receipt_changes=None, request_changes=None, head=None):
        return b.reserve(self.policy, self.state, self.receipt(**(receipt_changes or {})),
                         self.request(**(request_changes or {})),
                         trusted_head=self.head if head is None else head)

    def apply(self, result):
        self.assertTrue(result["preconditions_met"], result)
        self.assertFalse(result["may_release_secret"])
        self.state = result["proposed_state"]
        self.head = result["proposed_head"]

    def test_reservation_increments_before_possible_guess(self):
        self.apply(self.reserve())
        self.assertEqual(self.state["counter"], 1)
        self.assertEqual(self.state["attempts_used"], 1)
        self.assertNotEqual(self.head, b.state_digest(b.new_budget_state(self.policy), self.policy))

    def test_exhaustion_blocks_even_authenticated_initiator(self):
        self.apply(self.reserve())
        self.apply(self.reserve())
        result = self.reserve()
        self.assertFalse(result["preconditions_met"])
        self.assertEqual(result["reason"], "recovery-budget-exhausted")

    def test_snapshot_restore_cannot_refresh_attempts(self):
        old = copy.deepcopy(self.state)
        self.apply(self.reserve())
        self.state = old
        result = self.reserve(head=self.head)
        self.assertEqual(result["reason"], "untrusted-or-rolled-back-counter-state")

    def test_malicious_service_bypass_is_not_authenticated(self):
        for change in (
            {"authentication_evidence_ref": None},
            {"authentication_evidence_ref": True},
            {"initiator_id": "frontend-service"},
        ):
            with self.subTest(change=change):
                self.assertEqual(self.reserve(request_changes=change)["reason"],
                                 "unauthenticated-attempt-initiation")
        self.assertEqual(self.state["counter"], 0)

    def test_changed_firmware_and_hardware_are_denied(self):
        for change in (
            {"code_measurement": "sha256:" + "f" * 64},
            {"policy_digest": "sha256:" + "f" * 64},
            {"hardware_id": "unknown-hardware"},
        ):
            with self.subTest(change=change):
                self.assertEqual(self.reserve(receipt_changes=change)["reason"],
                                 "hardware-or-measurement-mismatch")

    def test_attestation_boolean_is_not_evidence(self):
        self.assertEqual(self.reserve(receipt_changes={"attestation_evidence_ref": True})["reason"],
                         "no-externally-verifiable-attestation-reference")
        self.assertEqual(self.reserve(receipt_changes={"attestation_evidence_ref": None})["reason"],
                         "no-externally-verifiable-attestation-reference")

    def test_extra_replicas_cannot_reset_budget(self):
        self.assertEqual(self.reserve(receipt_changes={"replica_id": "hsm-b"},
                                      request_changes={"replica_id": "hsm-b"})["reason"],
                         "unregistered-hardware-replica")
        changed = copy.deepcopy(self.policy)
        changed["replica_ids"].append("hsm-b")
        with self.assertRaises(ValueError):
            b.validate_policy(changed)

    def test_shared_replica_policy_requires_trusted_global_counter(self):
        self.policy["authority_mode"] = "shared-monotonic-counter"
        self.policy["replica_ids"].append("hsm-b")
        self.state = b.new_budget_state(self.policy)
        self.head = b.state_digest(self.state, self.policy)
        self.apply(self.reserve())
        wrong = self.reserve(receipt_changes={"replica_id": "hsm-b", "counter": 0},
                             request_changes={"replica_id": "hsm-b"})
        self.assertEqual(wrong["reason"], "hardware-counter-or-epoch-mismatch")

    def test_wrong_attested_counter_and_epoch(self):
        self.assertEqual(self.reserve(receipt_changes={"counter": 2})["reason"],
                         "hardware-counter-or-epoch-mismatch")
        self.assertEqual(self.reserve(receipt_changes={"epoch": 5})["reason"],
                         "hardware-counter-or-epoch-mismatch")

    def test_reset_requires_separate_trusted_authority(self):
        self.apply(self.reserve())
        self.apply(self.reserve())
        self.assertEqual(self.reserve(request_changes={"operation": "reset"})["reason"],
                         "separate-reset-authority-required")
        result = self.reserve(request_changes={
            "operation": "reset", "reset_authority_id": "offline-recovery",
            "reset_evidence_ref": "offline-signed-authorization"
        })
        self.apply(result)
        self.assertEqual(self.state["epoch"], 1)
        self.assertEqual(self.state["attempts_used"], 0)
        self.assertEqual(self.state["counter"], 3)
        self.apply(self.reserve())
        self.assertEqual(self.state["counter"], 4)

    def test_no_reset_material_on_guess(self):
        self.assertEqual(self.reserve(request_changes={
            "reset_evidence_ref": "forged-authorization"
        })["reason"], "normal-guess-cannot-reset-counter")

    def test_policy_preserves_secret_class_and_explicit_bound(self):
        p = copy.deepcopy(self.policy)
        p["maximum_attempts"] = True
        with self.assertRaises(ValueError):
            b.validate_policy(p)
        p["maximum_attempts"] = 100000
        with self.assertRaises(ValueError):
            b.validate_policy(p)
        p = copy.deepcopy(self.policy)
        p["secret_class"] = "password-is-high-entropy"
        with self.assertRaises(ValueError):
            b.validate_policy(p)


if __name__ == "__main__":
    unittest.main()
