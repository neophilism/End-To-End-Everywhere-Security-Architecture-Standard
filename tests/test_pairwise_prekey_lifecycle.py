"""AUD-13 prekey operational bounds and precise PQ role security tests."""
from __future__ import annotations
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pairwise_prekey_lifecycle as k

DAY = 86400


class PrekeyLifecycleTests(unittest.TestCase):
    def policy(self, pq=True, kem="ALG-ML-KEM-768"):
        p = {
            "schema_version": "0.1", "policy_id": "default-prekey-lifecycle",
            "pairwise_profile_ref": "pairwise-pqxdh-double-ratchet@0.1.0" if pq
                else "pairwise-x3dh-double-ratchet@0.1.0",
            "pq_kem_algorithm_id": kem if pq else None,
            "pq_strength_policy": "recommended" if pq else "not-applicable",
            "strength_exception_reason": None,
            "recommended_signed_prekey_lifetime_seconds": 7 * DAY,
            "maximum_signed_prekey_lifetime_seconds": 30 * DAY,
            "private_key_deletion_grace_seconds": 3 * DAY,
            "clock_uncertainty_limit_seconds": 300,
            "minimum_one_time_prekey_stock": 4,
            "minimum_pq_one_time_prekey_stock": 4 if pq else 0,
        }
        return p

    def bundle(self, pq=True):
        return {
            "profile_ref": "pairwise-pqxdh-double-ratchet@0.1.0" if pq
                else "pairwise-x3dh-double-ratchet@0.1.0",
            "bundle_id": "signed-key-bundle", "authorized_recipient_id": "recipient-bob",
            "signature_evidence_ref": "actual-signature-validation-reference",
            "recipient_authorization_evidence_ref": "authenticated-identity-reference",
            "trusted_time_epoch": 1000 + DAY,
            "clock_uncertainty_seconds": 60,
            "signed_prekey_published_epoch": 1000,
            "signed_prekey_expires_epoch": 1000 + 7 * DAY,
            "signed_prekey_verified": True,
            "one_time_prekey_available": True, "one_time_prekey_consumed": True,
            "available_one_time_stock": 5,
            "pq_kem_algorithm_id": "ALG-ML-KEM-768" if pq else None,
            "pq_signed_prekey_present": pq, "pq_signed_prekey_verified": pq,
            "pq_one_time_prekey_available": pq, "pq_one_time_prekey_consumed": pq,
            "available_pq_one_time_stock": 5 if pq else 0,
            "last_resort_pq_prekey_used": False,
            "prior_signed_prekey_retired_epoch": None,
            "prior_private_key_deleted_epoch": None,
        }

    def test_all_pairwise_modes_keep_exact_classical_or_pq_role(self):
        p = self.policy(pq=False)
        self.assertTrue(k.evaluate_bundle(p, self.bundle(pq=False))["policy_consistent"])
        for ref in (
            "pairwise-pqxdh-double-ratchet@0.1.0",
            "pairwise-pqxdh-spqr@0.1.0",
            "pairwise-pqxdh-triple-ratchet@0.1.0",
        ):
            with self.subTest(ref=ref):
                p = self.policy()
                p["pairwise_profile_ref"] = ref
                b = self.bundle()
                b["profile_ref"] = ref
                result = k.evaluate_bundle(p, b)
                self.assertTrue(result["policy_consistent"], result)
                self.assertFalse(result["cryptographically_verified"])

    def test_classical_x3dh_no_pq_floor(self):
        p = self.policy(pq=False)
        self.assertIsNone(p["pq_kem_algorithm_id"])
        self.assertTrue(k.evaluate_bundle(p, self.bundle(False))["policy_consistent"])
        b = self.bundle(False)
        b["pq_kem_algorithm_id"] = "ALG-ML-KEM-768"
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "classical-profile-cannot-import-pq-evidence")

    def test_strength_exception_requires_named_constrained_choice(self):
        p = self.policy(kem="ALG-ML-KEM-512")
        with self.assertRaisesRegex(ValueError, "must match"):
            k.validate_policy(p)
        p["pq_strength_policy"] = "constrained-interop-exception"
        with self.assertRaisesRegex(ValueError, "case-specific"):
            k.validate_policy(p)
        p["strength_exception_reason"] = "Explicitly limited interoperability with a pinned legacy client."
        k.validate_policy(p)
        b = self.bundle()
        b["pq_kem_algorithm_id"] = "ALG-ML-KEM-512"
        self.assertTrue(k.evaluate_bundle(p,b)["policy_consistent"])

    def test_missing_pq_material_and_downgrades_block(self):
        p = self.policy()
        for key, val in (
            ("pq_kem_algorithm_id", None),
            ("pq_kem_algorithm_id", "ALG-ML-KEM-512"),
            ("pq_signed_prekey_present", False),
            ("pq_signed_prekey_verified", False),
        ):
            with self.subTest(key=key):
                b = self.bundle(); b[key] = val
                self.assertFalse(k.evaluate_bundle(p,b)["policy_consistent"])

    def test_signature_and_recipient_authorization_are_required(self):
        p = self.policy()
        for key, val in (
            ("signed_prekey_verified", False),
            ("signature_evidence_ref", None),
            ("recipient_authorization_evidence_ref", ""),
        ):
            b = self.bundle(); b[key] = val
            self.assertFalse(k.evaluate_bundle(p,b)["policy_consistent"])

    def test_expired_future_and_extended_bundles_fail(self):
        p = self.policy()
        b = self.bundle()
        b["trusted_time_epoch"] = b["signed_prekey_expires_epoch"]
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "future-or-expired-signed-prekey")
        b = self.bundle(); b["trusted_time_epoch"] = 900
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "future-or-expired-signed-prekey")
        b = self.bundle(); b["signed_prekey_expires_epoch"] = 1000 + 40 * DAY
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "signed-prekey-lifetime-exceeds-policy")

    def test_uncertain_clock_can_make_bundle_unusable(self):
        p = self.policy()
        b = self.bundle()
        b["clock_uncertainty_seconds"] = 500
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "clock-uncertainty-exceeds-policy")
        b = self.bundle()
        b["trusted_time_epoch"] = b["signed_prekey_expires_epoch"] - 30
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "future-or-expired-signed-prekey")

    def test_one_time_key_available_must_be_consumed(self):
        p = self.policy(); b = self.bundle()
        b["one_time_prekey_consumed"] = False
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "available-one-time-prekey-not-consumed")
        b = self.bundle(); b["pq_one_time_prekey_consumed"] = False
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "available-pq-one-time-prekey-not-consumed")

    def test_pq_last_resort_when_one_time_stock_depleted(self):
        p = self.policy(); b = self.bundle()
        b["pq_one_time_prekey_available"] = False
        b["pq_one_time_prekey_consumed"] = False
        b["available_pq_one_time_stock"] = 0
        b["last_resort_pq_prekey_used"] = True
        result = k.evaluate_bundle(p,b)
        self.assertTrue(result["policy_consistent"])
        self.assertTrue(result["pq_last_resort_used"])
        self.assertTrue(result["low_pq_one_time_stock"])
        b["last_resort_pq_prekey_used"] = False
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "pq-last-resort-selection-inconsistent")

    def test_bounded_old_private_key_retention(self):
        p = self.policy(); b = self.bundle()
        b["prior_signed_prekey_retired_epoch"] = 1000
        self.assertTrue(k.evaluate_bundle(p,b)["retained_private_key_warning"])
        b["trusted_time_epoch"] = 1000 + 5 * DAY
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "private-prekey-retained-past-grace")
        b["prior_private_key_deleted_epoch"] = 1000 + DAY
        self.assertTrue(k.evaluate_bundle(p,b)["policy_consistent"])
        b["prior_private_key_deleted_epoch"] = 1000 + 4 * DAY
        self.assertEqual(k.evaluate_bundle(p,b)["reason"], "invalid-or-late-private-prekey-deletion")

    def test_policy_durations_are_versioned_not_signal_mandate(self):
        p = self.policy()
        p["maximum_signed_prekey_lifetime_seconds"] = 35 * DAY
        with self.assertRaises(ValueError):
            k.validate_policy(p)
        p = self.policy(); p["recommended_signed_prekey_lifetime_seconds"] = 8 * DAY
        with self.assertRaises(ValueError):
            k.validate_policy(p)

    def test_bundle_declares_only_measured_reference_consistency(self):
        r = k.evaluate_bundle(self.policy(), self.bundle())
        self.assertTrue(r["policy_consistent"])
        self.assertFalse(r["cryptographically_verified"])
        self.assertIn("real-endpoint-evidence", r["assurance"])


if __name__ == "__main__":
    unittest.main()
