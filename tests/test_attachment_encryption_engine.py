from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "attachment_encryption_engine.py"

spec = importlib.util.spec_from_file_location("attachment_encryption_engine", MODULE_PATH)
attachment_encryption_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = attachment_encryption_engine
spec.loader.exec_module(attachment_encryption_engine)


class AttachmentEncryptionEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def policy(self) -> dict:
        return self.load("fixtures/attachments/policy.json")

    def manifest(self) -> dict:
        return self.load("fixtures/attachments/manifest.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def test_attachment_profile_is_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "attachment-encryption"
        }
        self.assertEqual(refs, {"attachment-chunked-aead@0.1.0"})

    def test_valid_policy_and_manifest_pass(self) -> None:
        self.assertEqual(
            attachment_encryption_engine.validate_policy(
                self.policy(), self.crypto(), self.catalog()
            ),
            [],
        )
        self.assertEqual(
            attachment_encryption_engine.validate_manifest(
                self.policy(), self.manifest(), self.crypto(), self.catalog()
            ),
            [],
        )

    def test_manifest_digest_is_canonical_and_exact(self) -> None:
        manifest = self.manifest()
        self.assertEqual(
            attachment_encryption_engine.manifest_context_digest(manifest),
            manifest["manifest_context_digest_hex"],
        )

    def test_manifest_tampering_changes_digest(self) -> None:
        manifest = self.manifest()
        manifest["filename"] = "substituted.pdf"
        errors = attachment_encryption_engine.validate_manifest(
            self.policy(), manifest, self.crypto(), self.catalog()
        )
        self.assertTrue(any("context digest" in e for e in errors), errors)

    def test_chunk_count_math_including_empty_file(self) -> None:
        self.assertEqual(
            attachment_encryption_engine.expected_chunk_count(2_500_000, 1_048_576),
            3,
        )
        self.assertEqual(
            attachment_encryption_engine.expected_chunk_count(0, 1_048_576),
            1,
        )

    def test_manifest_rejects_wrong_chunk_count(self) -> None:
        manifest = self.manifest()
        manifest["chunk_count"] = 2
        manifest["manifest_context_digest_hex"] = attachment_encryption_engine.manifest_context_digest(manifest)
        errors = attachment_encryption_engine.validate_manifest(
            self.policy(), manifest, self.crypto(), self.catalog()
        )
        self.assertTrue(any("chunk_count must equal" in e for e in errors), errors)

    def test_valid_first_and_final_chunks_pass(self) -> None:
        for name in ("chunk-zero", "chunk-final"):
            with self.subTest(name=name):
                evidence = self.load(f"fixtures/attachments/{name}.json")
                self.assertEqual(
                    attachment_encryption_engine.validate_chunk(
                        self.policy(), self.manifest(), evidence,
                        self.crypto(), self.catalog()
                    ),
                    [],
                )

    def test_final_chunk_length_is_exact(self) -> None:
        manifest = self.manifest()
        self.assertEqual(
            attachment_encryption_engine.expected_chunk_plaintext_length(manifest, 2),
            402848,
        )

    def test_nonce_is_exact_prefix_plus_counter(self) -> None:
        manifest = self.manifest()
        self.assertEqual(
            attachment_encryption_engine.expected_nonce_hex(manifest, 0),
            "a1b2c3d40000000000000000",
        )
        self.assertEqual(
            attachment_encryption_engine.expected_nonce_hex(manifest, 2),
            "a1b2c3d40000000000000002",
        )

    def test_nonce_tampering_is_rejected(self) -> None:
        evidence = self.load("fixtures/attachments/chunk-final.json")
        evidence["nonce_hex"] = "a1b2c3d40000000000000001"
        errors = attachment_encryption_engine.validate_chunk(
            self.policy(), self.manifest(), evidence, self.crypto(), self.catalog()
        )
        self.assertTrue(any("nonce does not equal" in e for e in errors), errors)

    def test_chunk_position_and_manifest_substitution_are_rejected(self) -> None:
        evidence = self.load("fixtures/attachments/chunk-zero.json")
        evidence["aad_chunk_index"] = 1
        errors = attachment_encryption_engine.validate_chunk(
            self.policy(), self.manifest(), evidence, self.crypto(), self.catalog()
        )
        self.assertTrue(any("AAD chunk index mismatch" in e for e in errors), errors)

        evidence = self.load("fixtures/attachments/chunk-zero.json")
        evidence["aad_manifest_context_digest_hex"] = "0" * 64
        errors = attachment_encryption_engine.validate_chunk(
            self.policy(), self.manifest(), evidence, self.crypto(), self.catalog()
        )
        self.assertTrue(any("AAD manifest digest mismatch" in e for e in errors), errors)

    def test_plaintext_cannot_be_released_before_authentication(self) -> None:
        evidence = self.load("fixtures/attachments/chunk-zero.json")
        evidence["plaintext_released_before_authentication"] = True
        errors = attachment_encryption_engine.validate_chunk(
            self.policy(), self.manifest(), evidence, self.crypto(), self.catalog()
        )
        self.assertTrue(
            any("plaintext_released_before_authentication must be false" in e for e in errors),
            errors,
        )

    def test_key_distribution_passes(self) -> None:
        evidence = self.load("fixtures/attachments/key-distribution.json")
        self.assertEqual(
            attachment_encryption_engine.validate_key_distribution(
                self.policy(), self.manifest(), evidence,
                self.crypto(), self.catalog()
            ),
            [],
        )

    def test_key_leak_reuse_and_unauthorized_history_share_are_rejected(self) -> None:
        for field in (
            "attachment_key_reused",
            "service_observed_attachment_key",
            "attachment_key_in_url",
            "attachment_key_in_storage_metadata",
            "automatic_history_share_to_new_group_members",
            "removed_member_received_new_attachment_key",
        ):
            with self.subTest(field=field):
                evidence = self.load("fixtures/attachments/key-distribution.json")
                evidence[field] = True
                errors = attachment_encryption_engine.validate_key_distribution(
                    self.policy(), self.manifest(), evidence,
                    self.crypto(), self.catalog()
                )
                self.assertTrue(errors)

    def test_manifest_must_be_inside_authenticated_e2ee_to_authorized_devices(self) -> None:
        for field in (
            "manifest_delivered_inside_authenticated_e2ee",
            "recipient_device_set_authorized",
            "attachment_key_fresh",
            "manifest_context_digest_matches",
        ):
            with self.subTest(field=field):
                evidence = self.load("fixtures/attachments/key-distribution.json")
                evidence[field] = False
                errors = attachment_encryption_engine.validate_key_distribution(
                    self.policy(), self.manifest(), evidence,
                    self.crypto(), self.catalog()
                )
                self.assertTrue(errors)

    def test_supported_256_bit_aead_alternatives_pass_policy(self) -> None:
        for algorithm in (
            "ALG-AES-256-GCM",
            "ALG-CHACHA20-POLY1305",
            "ALG-AES-256-GCM-SIV",
        ):
            with self.subTest(algorithm=algorithm):
                policy = copy.deepcopy(self.policy())
                policy["content_aead_algorithm_id"] = algorithm
                self.assertEqual(
                    attachment_encryption_engine.validate_policy(
                        policy, self.crypto(), self.catalog()
                    ),
                    [],
                )

    def test_aes128_attachment_profile_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy())
        policy["content_aead_algorithm_id"] = "ALG-AES-128-GCM"
        errors = attachment_encryption_engine.validate_policy(
            policy, self.crypto(), self.catalog()
        )
        self.assertTrue(any("unsupported attachment AEAD" in e for e in errors), errors)

    def test_valid_storage_deletion_evidence_passes(self) -> None:
        self.assertEqual(
            attachment_encryption_engine.validate_deletion(
                self.policy(), self.load("fixtures/attachments/deletion.json")
            ),
            [],
        )

    def test_remote_recall_and_remote_key_revocation_cannot_be_claimed(self) -> None:
        evidence = self.load("fixtures/attachments/deletion.json")
        evidence["remote_recipient_recall_guaranteed"] = True
        errors = attachment_encryption_engine.validate_deletion(self.policy(), evidence)
        self.assertTrue(any("global recipient recall" in e for e in errors), errors)

        evidence = self.load("fixtures/attachments/deletion.json")
        evidence["remote_recipient_key_revocation_possible"] = True
        errors = attachment_encryption_engine.validate_deletion(self.policy(), evidence)
        self.assertTrue(any("cannot be remotely revoked" in e for e in errors), errors)

    def test_storage_complete_requires_primary_and_replica_deletion(self) -> None:
        evidence = self.load("fixtures/attachments/deletion.json")
        evidence["replica_deletion_complete"] = False
        errors = attachment_encryption_engine.validate_deletion(self.policy(), evidence)
        self.assertTrue(any("replica deletion completion" in e for e in errors), errors)

    def test_sender_local_erasure_requires_local_key_and_plaintext_deletion(self) -> None:
        evidence = self.load("fixtures/attachments/deletion.json")
        evidence["deletion_status"] = "sender-local-erasure"
        evidence["sender_local_key_deleted"] = False
        evidence["sender_local_plaintext_deleted"] = False
        errors = attachment_encryption_engine.validate_deletion(self.policy(), evidence)
        self.assertTrue(any("local attachment key deletion" in e for e in errors), errors)
        self.assertTrue(any("local plaintext deletion" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
