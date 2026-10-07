from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "secret_storage_engine.py"

spec = importlib.util.spec_from_file_location("secret_storage_engine", MODULE_PATH)
secret_storage_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secret_storage_engine
spec.loader.exec_module(secret_storage_engine)


class SecretStorageEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/secret-storage-mechanisms.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/secret-storage/policies/{name}.json")

    def state(self, name: str) -> dict:
        return self.load(f"fixtures/secret-storage/state/{name}.json")

    def validate_policy(self, name: str, policy: dict | None = None) -> list[str]:
        return secret_storage_engine.validate_policy(
            policy if policy is not None else self.policy(name),
            self.registry(),
            self.crypto(),
            self.catalog(),
        )

    def validate_state(self, name: str, evidence: dict | None = None) -> list[str]:
        return secret_storage_engine.validate_state(
            self.policy(name),
            evidence if evidence is not None else self.state(name),
            self.registry(),
            self.crypto(),
            self.catalog(),
        )

    def test_registry_pins_current_tpm_and_pkcs11_baselines(self) -> None:
        self.assertEqual(secret_storage_engine.validate_registry(self.registry()), [])
        mechanisms = {m["id"]: m for m in self.registry()["mechanisms"]}
        self.assertEqual(
            mechanisms["SECRET-TPM2-V185"]["specification"],
            "TCG TPM 2.0 Library Specification Version 185",
        )
        self.assertEqual(
            mechanisms["SECRET-PKCS11-3.2"]["specification"],
            "OASIS PKCS #11 Specification Version 3.2",
        )

    def test_four_storage_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "secret-storage"
        }
        self.assertEqual(refs, set(secret_storage_engine.PROFILE_CLASSES))

    def test_all_valid_policies_pass(self) -> None:
        for name in ("platform", "hardware", "token", "software"):
            with self.subTest(name=name):
                self.assertEqual(self.validate_policy(name), [])

    def test_hardware_profile_requires_hardware_isolation_and_attestation(self) -> None:
        policy = copy.deepcopy(self.policy("hardware"))
        policy["require_hardware_isolation"] = False
        errors = self.validate_policy("hardware", policy)
        self.assertTrue(any("requires hardware isolation" in e for e in errors), errors)

        policy = copy.deepcopy(self.policy("hardware"))
        policy["require_attestation"] = False
        errors = self.validate_policy("hardware", policy)
        self.assertTrue(any("requires attestation" in e for e in errors), errors)

    def test_profile_mechanism_class_must_match(self) -> None:
        policy = copy.deepcopy(self.policy("hardware"))
        policy["mechanism_id"] = "SECRET-OS-KEYSTORE"
        errors = self.validate_policy("hardware", policy)
        self.assertTrue(any("does not match profile class" in e for e in errors), errors)

    def test_external_token_requires_user_presence(self) -> None:
        policy = copy.deepcopy(self.policy("token"))
        policy["require_user_presence"] = False
        errors = self.validate_policy("token", policy)
        self.assertTrue(any("requires user presence" in e for e in errors), errors)

    def test_software_vault_requires_argon2id_and_cannot_claim_hardware(self) -> None:
        policy = copy.deepcopy(self.policy("software"))
        policy["software_kdf_algorithm_id"] = None
        errors = self.validate_policy("software", policy)
        self.assertTrue(any("requires ALG-ARGON2ID" in e for e in errors), errors)

        policy = copy.deepcopy(self.policy("software"))
        policy["require_hardware_isolation"] = True
        errors = self.validate_policy("software", policy)
        self.assertTrue(any("cannot require hardware isolation" in e for e in errors), errors)

    def test_weak_software_vault_argon2_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy("software"))
        policy["argon2_memory_kib"] = 32768
        errors = self.validate_policy("software", policy)
        self.assertTrue(any("Argon2id cost" in e for e in errors), errors)

    def test_rollback_claim_requires_independent_anchor(self) -> None:
        policy = copy.deepcopy(self.policy("platform"))
        policy["require_rollback_protection"] = True
        errors = self.validate_policy("platform", policy)
        self.assertTrue(any("requires an independent monotonic anchor" in e for e in errors), errors)

    def test_all_valid_state_evidence_passes(self) -> None:
        for name in ("platform", "hardware", "token", "software"):
            with self.subTest(name=name):
                self.assertEqual(self.validate_state(name), [])

    def test_hardware_state_requires_actual_nonexportable_hardware_key_and_attestation(self) -> None:
        for field in (
            "root_key_non_exportable",
            "root_key_hardware_isolated",
            "attestation_verified",
        ):
            with self.subTest(field=field):
                evidence = self.state("hardware")
                evidence[field] = False
                self.assertTrue(self.validate_state("hardware", evidence))

    def test_plaintext_export_and_raw_cloud_sync_are_rejected(self) -> None:
        for field in (
            "plaintext_secret_at_rest",
            "root_key_exported",
            "raw_root_key_cloud_synced",
        ):
            with self.subTest(field=field):
                evidence = self.state("platform")
                evidence[field] = True
                self.assertTrue(self.validate_state("platform", evidence))

    def test_vault_generation_must_advance_exactly_one(self) -> None:
        evidence = self.state("hardware")
        evidence["vault_generation"] = 3
        evidence["previous_vault_generation"] = 1
        errors = self.validate_state("hardware", evidence)
        self.assertTrue(any("advance by exactly one" in e for e in errors), errors)

    def test_rollback_anchor_must_advance_and_verify(self) -> None:
        evidence = self.state("hardware")
        evidence["rollback_anchor_value"] = 11
        errors = self.validate_state("hardware", evidence)
        self.assertTrue(any("must advance monotonically" in e for e in errors), errors)

        evidence = self.state("hardware")
        evidence["rollback_anchor_verified"] = False
        errors = self.validate_state("hardware", evidence)
        self.assertTrue(any("rollback anchor must verify" in e for e in errors), errors)

    def test_software_vault_cannot_fake_hardware_or_nonexportability(self) -> None:
        evidence = self.state("software")
        evidence["root_key_non_exportable"] = True
        errors = self.validate_state("software", evidence)
        self.assertTrue(any("must not claim root-key non-exportability" in e for e in errors), errors)

        evidence = self.state("software")
        evidence["root_key_hardware_isolated"] = True
        errors = self.validate_state("software", evidence)
        self.assertTrue(any("must not claim hardware isolation" in e for e in errors), errors)

    def test_software_vault_derivation_must_be_local(self) -> None:
        evidence = self.state("software")
        evidence["software_secret_supplied_locally"] = False
        errors = self.validate_state("software", evidence)
        self.assertTrue(any("must be supplied locally" in e for e in errors), errors)

        evidence = self.state("software")
        evidence["argon2_derived_locally"] = False
        errors = self.validate_state("software", evidence)
        self.assertTrue(any("must occur locally" in e for e in errors), errors)

    def test_valid_hardware_rotation_passes(self) -> None:
        event = self.load("fixtures/secret-storage/key-events/rotate-hardware.json")
        self.assertEqual(
            secret_storage_engine.validate_key_event(self.policy("hardware"), event),
            [],
        )

    def test_auth_policy_change_requires_real_rotation(self) -> None:
        event = self.load("fixtures/secret-storage/key-events/rotate-hardware.json")
        event["event_type"] = "create"
        event["old_key_id"] = None
        errors = secret_storage_engine.validate_key_event(self.policy("hardware"), event)
        self.assertTrue(any("requires key rotation" in e for e in errors), errors)

    def test_rotation_requires_rewrap_and_old_key_invalidation(self) -> None:
        event = self.load("fixtures/secret-storage/key-events/rotate-hardware.json")
        event["vault_rewrapped_under_new_key"] = False
        errors = secret_storage_engine.validate_key_event(self.policy("hardware"), event)
        self.assertTrue(any("requires vault rewrap" in e for e in errors), errors)

        event = self.load("fixtures/secret-storage/key-events/rotate-hardware.json")
        event["old_key_invalidated"] = False
        errors = secret_storage_engine.validate_key_event(self.policy("hardware"), event)
        self.assertTrue(any("old key invalidation" in e for e in errors), errors)

    def test_raw_root_key_must_never_exist_remotely(self) -> None:
        event = self.load("fixtures/secret-storage/key-events/rotate-hardware.json")
        event["remote_copy_of_raw_root_key_exists"] = True
        errors = secret_storage_engine.validate_key_event(self.policy("hardware"), event)
        self.assertTrue(any("must never exist remotely" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
