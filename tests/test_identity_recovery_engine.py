from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "identity_recovery_engine.py"

spec = importlib.util.spec_from_file_location("identity_recovery_engine", MODULE_PATH)
identity_recovery_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = identity_recovery_engine
spec.loader.exec_module(identity_recovery_engine)


class IdentityRecoveryEngineTests(unittest.TestCase):
    def load(self, name: str) -> dict:
        return json.loads((ROOT / "fixtures" / "identity-recovery" / name).read_text(encoding="utf-8"))

    def retained(self) -> tuple[dict, dict, dict]:
        return (
            self.load("retained-authority-policy.json"),
            self.load("trusted-transparency-state.json"),
            self.load("valid-retained-authority-event.json"),
        )

    def threshold(self) -> tuple[dict, dict, dict]:
        return (
            self.load("contact-threshold-policy.json"),
            self.load("trusted-local-state.json"),
            self.load("valid-contact-replacement-event.json"),
        )

    def test_retained_authority_recovery_is_state_bound(self) -> None:
        result = identity_recovery_engine.evaluate_recovery(*self.retained())
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["decision"], "recovered-identity")
        self.assertFalse(result["production_eligible"])
        self.assertEqual(result["peer_verification"], "reverification-required")
        self.assertEqual(result["group_membership"], "explicit-reenrollment-required")

    def test_threshold_contacts_create_replacement_not_continuity(self) -> None:
        result = identity_recovery_engine.evaluate_recovery(*self.threshold())
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["decision"], "replacement-identity")
        self.assertFalse(result["production_eligible"])

    def test_account_or_server_plus_delay_never_authorizes_recovery(self) -> None:
        policy, state, event = self.retained()
        event["verified_authorizers"] = [{
            "type": "server",
            "id": "account-service",
            "prior_state_hash": event["prior_state_hash"],
            "resulting_identity_id": event["resulting_identity_id"],
            "observed_history_epoch": event["observed_history_epoch"],
        }]
        event["account_delay_elapsed"] = True
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("not cryptographic recovery authority" in error for error in result["errors"]), result)

    def test_stale_state_and_concurrent_epoch_are_rejected(self) -> None:
        policy, state, event = self.retained()
        event["prior_state_hash"] = "sha256:" + "d" * 64
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("stale" in error for error in result["errors"]), result)

        policy, state, event = self.retained()
        event["observed_history_epoch"] -= 1
        event["verified_authorizers"][0]["observed_history_epoch"] -= 1
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("concurrent" in error for error in result["errors"]), result)

    def test_revoked_retained_authority_is_rejected(self) -> None:
        policy, state, event = self.retained()
        state["revoked_authority_ids"].append("offline-root-one")
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("was revoked" in error for error in result["errors"]), result)

    def test_contact_threshold_is_enforced(self) -> None:
        policy, state, event = self.threshold()
        event["verified_authorizers"] = event["verified_authorizers"][:1]
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("requires 2" in error for error in result["errors"]), result)

    def test_authorizer_must_bind_result_and_history(self) -> None:
        policy, state, event = self.threshold()
        event["verified_authorizers"][0]["resulting_identity_id"] = "different-replacement"
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("did not bind the resulting identity" in error for error in result["errors"]), result)

    def test_no_recovery_mode_fails_closed(self) -> None:
        _, state, event = self.threshold()
        policy = self.load("no-recovery-policy.json")
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("explicitly provides no recovery" in error for error in result["errors"]), result)

    def test_unknown_fields_and_transfer_claims_fail(self) -> None:
        policy, state, event = self.retained()
        policy["allow_peer_verification_transfer"] = True
        event["invented_authority"] = "support"
        result = identity_recovery_engine.evaluate_recovery(policy, state, event)
        self.assertFalse(result["valid"])
        self.assertTrue(any("peer verification transfer is prohibited" in error for error in result["errors"]), result)
        self.assertTrue(any("unknown fields" in error for error in result["errors"]), result)


if __name__ == "__main__":
    unittest.main()
