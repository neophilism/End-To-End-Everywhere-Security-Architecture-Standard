from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "key_verification_engine.py"

spec = importlib.util.spec_from_file_location("key_verification_engine", MODULE_PATH)
key_verification_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = key_verification_engine
spec.loader.exec_module(key_verification_engine)


class KeyVerificationEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/verification/policies/{name}.json")

    def snapshot(self, family: str, name: str) -> dict:
        return self.load(f"fixtures/verification/snapshots/{family}/{name}.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def record(self, policy_name: str, family: str) -> dict:
        return key_verification_engine.create_manual_record(
            record_id=f"record-{policy_name}",
            verification_method="qr",
            user_confirmed=True,
            policy=self.policy(policy_name),
            first_snapshot=self.snapshot(family, "alice"),
            second_snapshot=self.snapshot(family, "bob"),
            crypto_registry=self.crypto(),
            profile_catalog=self.catalog(),
        )

    def test_two_verification_profiles_are_registered(self) -> None:
        profiles = {
            f"{p['profile_id']}@{p['profile_version']}": p
            for p in self.catalog()["profiles"]
            if p["family_id"] == "key-verification"
        }
        self.assertEqual(
            set(profiles),
            {"verify-account-root@0.1.0", "verify-device-set@0.1.0"},
        )

    def test_valid_policies_pass(self) -> None:
        for name in ("account", "devices"):
            with self.subTest(name=name):
                self.assertEqual(
                    key_verification_engine.validate_policy(
                        self.policy(name), self.crypto(), self.catalog()
                    ),
                    [],
                )

    def test_subject_is_perspective_independent(self) -> None:
        policy = self.policy("devices")
        alice = self.snapshot("devices", "alice")
        bob = self.snapshot("devices", "bob")
        forward = key_verification_engine.subject_digest(policy, alice, bob)
        reverse = key_verification_engine.subject_digest(policy, bob, alice)
        self.assertEqual(forward, reverse)
        self.assertEqual(
            key_verification_engine.qr_payload(policy, alice, bob),
            key_verification_engine.qr_payload(policy, bob, alice),
        )

    def test_numeric_safety_number_is_sixty_digits(self) -> None:
        policy = self.policy("devices")
        digest = key_verification_engine.subject_digest(
            policy,
            self.snapshot("devices", "alice"),
            self.snapshot("devices", "bob"),
        )
        number = key_verification_engine.numeric_safety_number(digest)
        groups = number.split(" ")
        self.assertEqual(len(groups), 12)
        self.assertTrue(all(len(group) == 5 and group.isdigit() for group in groups))
        self.assertEqual(sum(len(group) for group in groups), 60)

    def test_numeric_and_qr_compare_same_subject(self) -> None:
        record = self.record("devices", "devices")
        self.assertTrue(
            key_verification_engine.compare_numeric(
                record, record["numeric_safety_number"]
            )
        )
        self.assertTrue(
            key_verification_engine.compare_qr(record, record["qr_payload"])
        )
        decoded = key_verification_engine.decode_qr_payload(record["qr_payload"])
        self.assertEqual(decoded["subject_digest_hex"], record["subject_digest_hex"])

    def test_manual_record_requires_explicit_confirmation(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit out-of-band user confirmation"):
            key_verification_engine.create_manual_record(
                record_id="record-no-confirm",
                verification_method="numeric",
                user_confirmed=False,
                policy=self.policy("devices"),
                first_snapshot=self.snapshot("devices", "alice"),
                second_snapshot=self.snapshot("devices", "bob"),
                crypto_registry=self.crypto(),
                profile_catalog=self.catalog(),
            )

    def test_account_root_device_addition_keeps_verification_valid(self) -> None:
        record = self.record("account", "account")
        status = key_verification_engine.verification_status(
            record,
            self.policy("account"),
            self.snapshot("account", "alice"),
            self.snapshot("account", "bob-device-added"),
            self.crypto(),
            self.catalog(),
        )
        self.assertEqual(status["status"], "verified")
        self.assertFalse(status["requires_manual_reverification"])

    def test_account_root_change_invalidates_verification(self) -> None:
        record = self.record("account", "account")
        status = key_verification_engine.verification_status(
            record,
            self.policy("account"),
            self.snapshot("account", "alice"),
            self.snapshot("account", "bob-root-changed"),
            self.crypto(),
            self.catalog(),
        )
        self.assertEqual(status["status"], "invalidated")
        self.assertTrue(status["requires_manual_reverification"])

    def test_device_addition_invalidates_device_set_verification(self) -> None:
        record = self.record("devices", "devices")
        status = key_verification_engine.verification_status(
            record,
            self.policy("devices"),
            self.snapshot("devices", "alice"),
            self.snapshot("devices", "bob-device-added"),
            self.crypto(),
            self.catalog(),
        )
        self.assertEqual(status["status"], "invalidated")
        self.assertTrue(status["requires_manual_reverification"])

    def test_device_key_rotation_invalidates_device_set_verification(self) -> None:
        record = self.record("devices", "devices")
        status = key_verification_engine.verification_status(
            record,
            self.policy("devices"),
            self.snapshot("devices", "alice"),
            self.snapshot("devices", "bob-key-rotated"),
            self.crypto(),
            self.catalog(),
        )
        self.assertEqual(status["status"], "invalidated")
        self.assertTrue(status["requires_manual_reverification"])

    def test_account_root_profile_rejects_non_root_identity_architecture(self) -> None:
        errors = key_verification_engine.validate_snapshot(
            self.snapshot("devices", "alice"),
            verification_profile_ref="verify-account-root@0.1.0",
        )
        self.assertTrue(
            any("requires identity-account-root@0.1.0" in e for e in errors),
            errors,
        )

    def test_qr_payload_rejects_tampering_and_unknown_fields(self) -> None:
        record = self.record("devices", "devices")
        payload = key_verification_engine.decode_qr_payload(record["qr_payload"])
        payload["unexpected"] = True
        encoded = __import__("base64").urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        tampered = "e2eesa-kv1:" + encoded
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            key_verification_engine.decode_qr_payload(tampered)
        self.assertFalse(key_verification_engine.compare_qr(record, tampered))

    def test_record_digest_tampering_is_rejected(self) -> None:
        record = self.record("devices", "devices")
        tampered = copy.deepcopy(record)
        tampered["subject_digest_hex"] = "00" + tampered["subject_digest_hex"][2:]
        errors = key_verification_engine.validate_record(
            tampered,
            self.policy("devices"),
            self.snapshot("devices", "alice"),
            self.snapshot("devices", "bob"),
            self.crypto(),
            self.catalog(),
        )
        self.assertTrue(any("subject has changed" in e for e in errors), errors)

    def test_projection_from_identity_state_uses_only_active_devices(self) -> None:
        state = self.load("fixtures/identity/states/threshold.json")
        state["devices"][1]["status"] = "revoked"
        snapshot = key_verification_engine.snapshot_from_identity_state(
            "identity-threshold-quorum@0.1.0", state
        )
        self.assertEqual(snapshot["identity_id"], "alice")
        self.assertIsNone(snapshot["account_root_key_fingerprint"])
        self.assertEqual(
            [device["device_id"] for device in snapshot["active_devices"]],
            ["device-a"],
        )


if __name__ == "__main__":
    unittest.main()
