from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "pairwise_session_engine.py"

spec = importlib.util.spec_from_file_location("pairwise_session_engine", MODULE_PATH)
pairwise_session_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = pairwise_session_engine
spec.loader.exec_module(pairwise_session_engine)


class PairwiseSessionEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def protocol_registry(self) -> dict:
        return self.load("registry/pairwise-protocols.json")

    def crypto_registry(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def profile_catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def property_ids(self) -> set[str]:
        data = self.load("registry/security-properties.json")
        return {item["id"] for item in data["properties"]}

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/pairwise/policies/{name}.json")

    def handshake(self, bucket: str, name: str) -> dict:
        return self.load(f"fixtures/pairwise/handshakes/{bucket}/{name}.json")

    def checkpoint(self, bucket: str, name: str) -> dict:
        return self.load(f"fixtures/pairwise/checkpoints/{bucket}/{name}.json")

    def validate_policy(self, policy: dict) -> list[str]:
        return pairwise_session_engine.validate_policy(
            policy,
            self.protocol_registry(),
            self.crypto_registry(),
            self.profile_catalog(),
        )

    def test_protocol_registry_is_valid(self) -> None:
        self.assertEqual(
            pairwise_session_engine.validate_protocol_registry(
                self.protocol_registry(),
                known_property_ids=self.property_ids(),
            ),
            [],
        )

    def test_all_four_complete_profiles_are_registered(self) -> None:
        profiles = {
            f"{p['profile_id']}@{p['profile_version']}": p
            for p in self.profile_catalog()["profiles"]
            if p["family_id"] == "pairwise-e2ee"
        }
        self.assertEqual(set(profiles), set(pairwise_session_engine.PROFILE_BINDINGS))
        self.assertEqual(
            profiles["pairwise-pqxdh-triple-ratchet@0.1.0"]["status"],
            "recommended",
        )

    def test_pq_profiles_do_not_claim_pq_authentication(self) -> None:
        for profile in self.profile_catalog()["profiles"]:
            if profile["family_id"] != "pairwise-e2ee":
                continue
            if profile["profile_id"].startswith("pairwise-pqxdh-"):
                self.assertNotIn("SP-PQ-AUTHENTICATION", profile["security_properties"])

    def test_valid_policies_pass(self) -> None:
        for name in ("classical", "pq-init", "spqr", "triple"):
            with self.subTest(name=name):
                self.assertEqual(self.validate_policy(self.policy(name)), [])

    def test_profile_protocol_binding_prevents_downgrade(self) -> None:
        policy = self.load("fixtures/pairwise/policies/invalid-triple-downgrade.json")
        errors = self.validate_policy(policy)
        self.assertTrue(any("ratchet_protocol_id does not match" in e for e in errors), errors)

    def test_classical_profile_rejects_pq_kem_field(self) -> None:
        policy = self.load("fixtures/pairwise/policies/invalid-classical-pq-kem.json")
        errors = self.validate_policy(policy)
        self.assertTrue(any("must set pq_kem_algorithm_id to null" in e for e in errors), errors)

    def test_all_valid_handshakes_pass(self) -> None:
        for name in ("classical", "pq-init", "spqr", "triple"):
            with self.subTest(name=name):
                self.assertEqual(
                    pairwise_session_engine.validate_handshake_evidence(
                        self.policy(name), self.handshake("valid", name)
                    ),
                    [],
                )

    def test_replayed_initial_message_is_rejected(self) -> None:
        errors = pairwise_session_engine.validate_handshake_evidence(
            self.policy("triple"), self.handshake("invalid", "replay")
        )
        self.assertTrue(any("replayed initial message" in e for e in errors), errors)

    def test_available_one_time_prekey_must_be_consumed(self) -> None:
        errors = pairwise_session_engine.validate_handshake_evidence(
            self.policy("triple"),
            self.handshake("invalid", "one-time-not-consumed"),
        )
        self.assertTrue(any("one-time prekey must be consumed" in e for e in errors), errors)

    def test_pq_signed_prekey_must_verify(self) -> None:
        errors = pairwise_session_engine.validate_handshake_evidence(
            self.policy("triple"),
            self.handshake("invalid", "pq-prekey-unverified"),
        )
        self.assertTrue(any("post-quantum signed prekey must be verified" in e for e in errors), errors)

    def test_classical_handshake_rejects_pq_fields(self) -> None:
        errors = pairwise_session_engine.validate_handshake_evidence(
            self.policy("classical"),
            self.handshake("invalid", "classical-pq-fields"),
        )
        self.assertTrue(any("must not include a PQ signed prekey" in e for e in errors), errors)

    def test_all_valid_message_checkpoints_pass(self) -> None:
        for name in ("classical", "pq-init", "spqr", "triple"):
            with self.subTest(name=name):
                self.assertEqual(
                    pairwise_session_engine.validate_message_checkpoint(
                        self.policy(name), self.checkpoint("valid", name)
                    ),
                    [],
                )

    def test_message_key_deletion_is_required(self) -> None:
        errors = pairwise_session_engine.validate_message_checkpoint(
            self.policy("triple"),
            self.checkpoint("invalid", "message-key-not-deleted"),
        )
        self.assertTrue(any("message key must be deleted" in e for e in errors), errors)

    def test_triple_ratchet_requires_pq_component(self) -> None:
        errors = pairwise_session_engine.validate_message_checkpoint(
            self.policy("triple"),
            self.checkpoint("invalid", "triple-pq-component-off"),
        )
        self.assertTrue(any("PQ ratchet component" in e for e in errors), errors)

    def test_skipped_key_bound_is_enforced(self) -> None:
        errors = pairwise_session_engine.validate_message_checkpoint(
            self.policy("triple"),
            self.checkpoint("invalid", "skipped-bound-exceeded"),
        )
        self.assertTrue(any("exceeds policy maximum" in e for e in errors), errors)

    def test_message_replay_is_rejected(self) -> None:
        errors = pairwise_session_engine.validate_message_checkpoint(
            self.policy("triple"),
            self.checkpoint("invalid", "replay"),
        )
        self.assertTrue(any("replayed ratchet message" in e for e in errors), errors)

    def test_policy_cannot_disable_security_invariants(self) -> None:
        policy = copy.deepcopy(self.policy("triple"))
        policy["require_message_key_deletion"] = False
        errors = self.validate_policy(policy)
        self.assertTrue(any("require_message_key_deletion" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
