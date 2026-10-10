from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "backup_recovery_engine.py"

spec = importlib.util.spec_from_file_location("backup_recovery_engine", MODULE_PATH)
backup_recovery_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = backup_recovery_engine
spec.loader.exec_module(backup_recovery_engine)


class BackupRecoveryEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/recovery/policies/{name}.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def test_argon2id_is_registered_as_recommended_kdf(self) -> None:
        algorithms = {
            item["id"]: item
            for item in self.crypto()["algorithms"]
        }
        argon = algorithms["ALG-ARGON2ID"]
        self.assertEqual(argon["category"], "kdf")
        self.assertEqual(argon["status"], "recommended")
        self.assertEqual(argon["specification"], "RFC 9106")

    def test_three_backup_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "backup-recovery"
        }
        self.assertEqual(
            refs,
            {
                "backup-none@0.1.0",
                "backup-user-secret@0.1.0",
                "backup-hardware-assisted@0.1.0",
            },
        )

    def test_valid_policies_pass(self) -> None:
        for name in ("none", "user", "user-passphrase", "hardware"):
            with self.subTest(name=name):
                self.assertEqual(
                    backup_recovery_engine.validate_policy(
                        self.policy(name), self.crypto(), self.catalog()
                    ),
                    [],
                )

    def test_weak_argon2_policy_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy("user"))
        policy["argon2_memory_kib"] = 32768
        errors = backup_recovery_engine.validate_policy(
            policy, self.crypto(), self.catalog()
        )
        self.assertTrue(any("Argon2id cost" in e for e in errors), errors)

    def test_generated_secret_requires_128_bits(self) -> None:
        policy = copy.deepcopy(self.policy("user"))
        policy["minimum_generated_secret_bits"] = 64
        errors = backup_recovery_engine.validate_policy(
            policy, self.crypto(), self.catalog()
        )
        self.assertTrue(any("at least 128 bits" in e for e in errors), errors)

    def test_no_backup_evidence_passes(self) -> None:
        self.assertEqual(
            backup_recovery_engine.validate_no_backup_evidence(
                self.policy("none"),
                self.load("fixtures/recovery/no-backup.json"),
            ),
            [],
        )

    def test_no_backup_profile_rejects_server_backup(self) -> None:
        evidence = self.load("fixtures/recovery/no-backup.json")
        evidence["server_backup_present"] = True
        errors = backup_recovery_engine.validate_no_backup_evidence(
            self.policy("none"), evidence
        )
        self.assertTrue(any("server_backup_present must be false" in e for e in errors), errors)

    def test_valid_user_and_hardware_envelopes_pass(self) -> None:
        self.assertEqual(
            backup_recovery_engine.validate_envelope(
                self.policy("user"),
                self.load("fixtures/recovery/user-envelope-gen1.json"),
                self.crypto(),
                self.catalog(),
            ),
            [],
        )
        self.assertEqual(
            backup_recovery_engine.validate_envelope(
                self.policy("hardware"),
                self.load("fixtures/recovery/hardware-envelope.json"),
                self.crypto(),
                self.catalog(),
            ),
            [],
        )

    def test_server_plaintext_or_key_access_is_rejected(self) -> None:
        envelope = self.load("fixtures/recovery/user-envelope-gen1.json")
        envelope["server_plaintext_access"] = True
        errors = backup_recovery_engine.validate_envelope(
            self.policy("user"), envelope, self.crypto(), self.catalog()
        )
        self.assertTrue(any("must not have backup plaintext" in e for e in errors), errors)

        envelope = self.load("fixtures/recovery/user-envelope-gen1.json")
        envelope["server_unwrapped_backup_key_access"] = True
        errors = backup_recovery_engine.validate_envelope(
            self.policy("user"), envelope, self.crypto(), self.catalog()
        )
        self.assertTrue(any("unwrapped backup data key" in e for e in errors), errors)

    def test_recovery_secret_must_not_be_uploaded(self) -> None:
        envelope = self.load("fixtures/recovery/user-envelope-gen1.json")
        envelope["recovery_secret_uploaded_to_server"] = True
        errors = backup_recovery_engine.validate_envelope(
            self.policy("user"), envelope, self.crypto(), self.catalog()
        )
        self.assertTrue(any("must never be uploaded" in e for e in errors), errors)

    def test_hardware_profile_requires_outer_wrap_nonexportable_key_and_attestation(self) -> None:
        for field, expected in (
            ("hardware_outer_wrap_present", False),
            ("hardware_key_non_exportable", False),
            ("hardware_attestation_verified", False),
        ):
            with self.subTest(field=field):
                envelope = self.load("fixtures/recovery/hardware-envelope.json")
                envelope[field] = expected
                errors = backup_recovery_engine.validate_envelope(
                    self.policy("hardware"), envelope, self.crypto(), self.catalog()
                )
                self.assertTrue(errors)

    def test_generation_transition_requires_fresh_key(self) -> None:
        first = self.load("fixtures/recovery/user-envelope-gen1.json")
        second = self.load("fixtures/recovery/user-envelope-gen2.json")
        self.assertEqual(
            backup_recovery_engine.validate_generation_transition(first, second),
            [],
        )
        second["backup_data_key_id"] = first["backup_data_key_id"]
        errors = backup_recovery_engine.validate_generation_transition(first, second)
        self.assertTrue(any("fresh backup data key" in e for e in errors), errors)

    def test_valid_recovery_evidence_passes(self) -> None:
        for policy_name, evidence_name in (
            ("user", "user-recovery"),
            ("hardware", "hardware-recovery"),
        ):
            with self.subTest(policy=policy_name):
                self.assertEqual(
                    backup_recovery_engine.validate_recovery(
                        self.policy(policy_name),
                        self.load(f"fixtures/recovery/{evidence_name}.json"),
                        self.crypto(),
                        self.catalog(),
                    ),
                    [],
                )

    def test_restore_requires_prior_device_authorization(self) -> None:
        evidence = self.load("fixtures/recovery/user-recovery.json")
        evidence["restoring_device_authorized"] = False
        errors = backup_recovery_engine.validate_recovery(
            self.policy("user"), evidence, self.crypto(), self.catalog()
        )
        self.assertTrue(any("must already be authorized" in e for e in errors), errors)

    def test_recovery_cannot_grant_device_authority(self) -> None:
        evidence = self.load("fixtures/recovery/user-recovery.json")
        evidence["recovery_granted_device_authority"] = True
        errors = backup_recovery_engine.validate_recovery(
            self.policy("user"), evidence, self.crypto(), self.catalog()
        )
        self.assertTrue(any("must not itself grant device authority" in e for e in errors), errors)

    def test_stale_backup_generation_is_rejected(self) -> None:
        evidence = self.load("fixtures/recovery/user-recovery.json")
        evidence["backup_generation"] = 1
        evidence["latest_known_generation"] = 2
        errors = backup_recovery_engine.validate_recovery(
            self.policy("user"), evidence, self.crypto(), self.catalog()
        )
        self.assertTrue(any("stale backup generation" in e for e in errors), errors)

    def test_hardware_recovery_requires_authenticated_rate_limited_release(self) -> None:
        for field in (
            "hardware_release_used",
            "hardware_release_authenticated",
            "hardware_release_rate_limited",
            "hardware_attestation_verified",
        ):
            with self.subTest(field=field):
                evidence = self.load("fixtures/recovery/hardware-recovery.json")
                evidence[field] = False
                errors = backup_recovery_engine.validate_recovery(
                    self.policy("hardware"), evidence, self.crypto(), self.catalog()
                )
                self.assertTrue(errors)

    def test_no_backup_profile_cannot_create_recovery_envelope(self) -> None:
        errors = backup_recovery_engine.validate_envelope(
            self.policy("none"),
            self.load("fixtures/recovery/user-envelope-gen1.json"),
            self.crypto(),
            self.catalog(),
        )
        self.assertTrue(any("must not create" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
