from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "group_e2ee_engine.py"

spec = importlib.util.spec_from_file_location("group_e2ee_engine", MODULE_PATH)
group_e2ee_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = group_e2ee_engine
spec.loader.exec_module(group_e2ee_engine)


class GroupE2EEEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/group-protocols.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/group/policies/{name}.json")

    def membership(self, bucket: str, name: str) -> dict:
        return self.load(f"fixtures/group/membership/{bucket}/{name}.json")

    def message(self, bucket: str, name: str) -> dict:
        return self.load(f"fixtures/group/messages/{bucket}/{name}.json")

    def validate_policy(self, policy: dict) -> list[str]:
        return group_e2ee_engine.validate_policy(
            policy, self.registry(), self.crypto(), self.catalog()
        )

    def test_group_protocol_registry_is_valid(self) -> None:
        self.assertEqual(group_e2ee_engine.validate_protocol_registry(self.registry()), [])

    def test_three_group_profiles_are_registered(self) -> None:
        profiles = {
            f"{p['profile_id']}@{p['profile_version']}": p
            for p in self.catalog()["profiles"]
            if p["family_id"] == "group-e2ee"
        }
        self.assertEqual(set(profiles), set(group_e2ee_engine.PROFILE_BINDINGS))
        self.assertEqual(profiles["group-mls-rfc9420@0.1.0"]["status"], "recommended")
        self.assertNotIn(
            "SP-POST-COMPROMISE-SECURITY",
            profiles["group-sender-key-aead@0.1.0"]["security_properties"],
        )

    def test_all_valid_policies_pass(self) -> None:
        for name in ("mls", "sender", "pairwise"):
            with self.subTest(name=name):
                self.assertEqual(self.validate_policy(self.policy(name)), [])

    def test_mls_requires_registered_cipher_suite(self) -> None:
        policy = copy.deepcopy(self.policy("mls"))
        policy["mls_cipher_suite_id"] = "0xffff"
        errors = self.validate_policy(policy)
        self.assertTrue(any("registered mls_cipher_suite_id" in e for e in errors), errors)

    def test_sender_key_requires_registered_algorithms(self) -> None:
        policy = copy.deepcopy(self.policy("sender"))
        policy["sender_aead_algorithm_id"] = "ALG-SHA256"
        errors = self.validate_policy(policy)
        self.assertTrue(any("expected aead" in e for e in errors), errors)

    def test_all_valid_membership_events_pass(self) -> None:
        for name in ("mls", "sender", "pairwise"):
            with self.subTest(name=name):
                self.assertEqual(
                    group_e2ee_engine.validate_membership_event(
                        self.policy(name), self.membership("valid", name)
                    ),
                    [],
                )

    def test_server_membership_authorization_is_rejected(self) -> None:
        errors = group_e2ee_engine.validate_membership_event(
            self.policy("mls"), self.membership("invalid", "server-authorizer")
        )
        self.assertTrue(any("server-only membership authorization" in e for e in errors), errors)

    def test_epoch_must_advance_exactly_once(self) -> None:
        errors = group_e2ee_engine.validate_membership_event(
            self.policy("mls"), self.membership("invalid", "stale-epoch")
        )
        self.assertTrue(any("new_epoch must equal previous_epoch + 1" in e for e in errors), errors)

    def test_new_member_cannot_get_prior_epoch_access(self) -> None:
        errors = group_e2ee_engine.validate_membership_event(
            self.policy("mls"), self.membership("invalid", "new-member-history")
        )
        self.assertTrue(any("must not receive prior-epoch access" in e for e in errors), errors)

    def test_mls_requires_update_path_for_membership_change(self) -> None:
        errors = group_e2ee_engine.validate_membership_event(
            self.policy("mls"), self.membership("invalid", "mls-missing-update-path")
        )
        self.assertTrue(any("requires a fresh UpdatePath" in e for e in errors), errors)

    def test_sender_key_membership_change_requires_full_rotation(self) -> None:
        errors = group_e2ee_engine.validate_membership_event(
            self.policy("sender"), self.membership("invalid", "sender-not-rotated")
        )
        self.assertTrue(any("rotate every active sender key" in e for e in errors), errors)

    def test_pairwise_membership_change_updates_recipient_set(self) -> None:
        errors = group_e2ee_engine.validate_membership_event(
            self.policy("pairwise"),
            self.membership("invalid", "pairwise-recipient-set-not-updated"),
        )
        self.assertTrue(any("update its recipient set" in e for e in errors), errors)

    def test_all_valid_message_checkpoints_pass(self) -> None:
        for name in ("mls", "sender", "pairwise"):
            with self.subTest(name=name):
                self.assertEqual(
                    group_e2ee_engine.validate_message_checkpoint(
                        self.policy(name), self.message("valid", name)
                    ),
                    [],
                )

    def test_replay_and_nonmember_recipient_are_rejected(self) -> None:
        errors = group_e2ee_engine.validate_message_checkpoint(
            self.policy("mls"), self.message("invalid", "replay")
        )
        self.assertTrue(any("replayed group message" in e for e in errors), errors)
        errors = group_e2ee_engine.validate_message_checkpoint(
            self.policy("mls"), self.message("invalid", "nonmember-recipient")
        )
        self.assertTrue(any("recipients must equal" in e for e in errors), errors)

    def test_server_plaintext_access_is_rejected(self) -> None:
        errors = group_e2ee_engine.validate_message_checkpoint(
            self.policy("mls"), self.message("invalid", "server-plaintext")
        )
        self.assertTrue(any("must not have plaintext access" in e for e in errors), errors)

    def test_sender_message_key_deletion_and_bound_are_enforced(self) -> None:
        errors = group_e2ee_engine.validate_message_checkpoint(
            self.policy("sender"), self.message("invalid", "sender-key-not-deleted")
        )
        self.assertTrue(any("message key must be deleted" in e for e in errors), errors)
        errors = group_e2ee_engine.validate_message_checkpoint(
            self.policy("sender"), self.message("invalid", "sender-skipped-overflow")
        )
        self.assertTrue(any("exceed policy maximum" in e for e in errors), errors)

    def test_pairwise_fanout_requires_one_valid_ciphertext_per_recipient(self) -> None:
        errors = group_e2ee_engine.validate_message_checkpoint(
            self.policy("pairwise"), self.message("invalid", "pairwise-count-mismatch")
        )
        self.assertTrue(any("one ciphertext per recipient" in e for e in errors), errors)
        errors = group_e2ee_engine.validate_message_checkpoint(
            self.policy("pairwise"), self.message("invalid", "pairwise-session-invalid")
        )
        self.assertTrue(any("every pairwise recipient session must validate" in e for e in errors), errors)

    def test_full_valid_group_cases_pass(self) -> None:
        for name in ("mls", "sender", "pairwise"):
            with self.subTest(name=name):
                self.assertEqual(
                    group_e2ee_engine.validate_group_case(
                        self.policy(name),
                        self.membership("valid", name),
                        self.message("valid", name),
                        self.registry(),
                        self.crypto(),
                        self.catalog(),
                    ),
                    [],
                )


if __name__ == "__main__":
    unittest.main()
