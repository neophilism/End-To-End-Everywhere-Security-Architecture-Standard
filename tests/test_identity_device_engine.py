from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "identity_device_engine.py"

spec = importlib.util.spec_from_file_location("identity_device_engine", MODULE_PATH)
identity_device_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = identity_device_engine
spec.loader.exec_module(identity_device_engine)


class IdentityDeviceEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def registry(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def transition(self, policy: str, state: str, event: str) -> list[str]:
        return identity_device_engine.validate_transition(
            self.load(f"fixtures/identity/policies/{policy}.json"),
            self.load(f"fixtures/identity/states/{state}.json"),
            self.load(f"fixtures/identity/{event}"),
            self.catalog(),
            self.registry(),
        )

    def test_three_identity_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "identity-architecture"
        }
        self.assertEqual(refs, {
            "identity-account-root@0.1.0",
            "identity-device-cross-signing@0.1.0",
            "identity-threshold-quorum@0.1.0",
        })

    def test_account_root_enrollment_passes(self) -> None:
        self.assertEqual(self.transition("account-root", "account-root", "valid/account-root-enroll.json"), [])

    def test_cross_signing_enrollment_and_rotation_pass(self) -> None:
        self.assertEqual(self.transition("cross-signing", "cross-signing", "valid/cross-sign-enroll.json"), [])
        self.assertEqual(self.transition("cross-signing", "cross-signing", "valid/cross-sign-rotate.json"), [])

    def test_threshold_majority_is_enforced(self) -> None:
        self.assertEqual(self.transition("threshold", "threshold", "valid/threshold-enroll.json"), [])
        errors = self.transition("threshold", "threshold", "invalid/insufficient-threshold.json")
        self.assertTrue(any("threshold quorum requires 2" in e for e in errors), errors)

    def test_server_only_authorization_is_rejected(self) -> None:
        errors = self.transition("cross-signing", "cross-signing", "invalid/server-only.json")
        self.assertTrue(any("server authorization is prohibited" in e for e in errors), errors)

    def test_stale_state_and_unknown_authorizer_are_rejected(self) -> None:
        errors = self.transition("cross-signing", "cross-signing", "invalid/stale-state-hash.json")
        self.assertTrue(any("previous_state_hash" in e for e in errors), errors)
        errors = self.transition("cross-signing", "cross-signing", "invalid/unknown-authorizer.json")
        self.assertTrue(any("not currently active" in e for e in errors), errors)

    def test_key_reuse_is_rejected(self) -> None:
        errors = self.transition("cross-signing", "cross-signing", "invalid/key-reuse.json")
        self.assertTrue(any("key reuse is prohibited" in e for e in errors), errors)

    def test_rotation_retires_old_keys(self) -> None:
        policy = self.load("fixtures/identity/policies/cross-signing.json")
        state = self.load("fixtures/identity/states/cross-signing.json")
        event = self.load("fixtures/identity/valid/cross-sign-rotate.json")
        next_state = identity_device_engine.apply_transition(policy, state, event, self.catalog(), self.registry())
        self.assertEqual(next_state["sequence"], 2)
        self.assertIn("device-a-sign-1", next_state["retired_key_ids"])
        self.assertIn("device-a-agree-1", next_state["retired_key_ids"])
        self.assertEqual(next_state["devices"][0]["key_generation"], 2)

    def test_last_device_cannot_be_ordinarily_revoked(self) -> None:
        policy = self.load("fixtures/identity/policies/cross-signing.json")
        state = self.load("fixtures/identity/states/cross-signing.json")
        event = {
            "schema_version":"0.1","event_id":"event-revoke-only-device",
            "identity_id":"alice","sequence":2,
            "previous_state_hash":identity_device_engine.state_hash(state),
            "event_type":"revoke","subject_device_id":"device-a",
            "verified_authorizers":[{"type":"device","id":"device-a"}]
        }
        errors = identity_device_engine.validate_transition(policy, state, event, self.catalog(), self.registry())
        self.assertTrue(any("last active device" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
