from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "negotiation_engine.py"

spec = importlib.util.spec_from_file_location("negotiation_engine", MODULE_PATH)
negotiation_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = negotiation_engine
spec.loader.exec_module(negotiation_engine)


class NegotiationEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def policy(self) -> dict:
        return self.load("fixtures/negotiation/policy.json")

    def crypto_registry(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def profile_catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def validate(self, rel: str, **kwargs) -> list[str]:
        return negotiation_engine.validate_evidence(
            self.policy(),
            self.load(rel),
            self.crypto_registry(),
            self.profile_catalog(),
            **kwargs,
        )

    def test_policy_passes(self) -> None:
        self.assertEqual(
            negotiation_engine.validate_policy(
                self.policy(),
                self.crypto_registry(),
                self.profile_catalog(),
            ),
            [],
        )

    def test_baseline_negotiation_passes(self) -> None:
        self.assertEqual(self.validate("fixtures/negotiation/valid/baseline.json"), [])

    def test_registered_alternate_suite_interoperates(self) -> None:
        self.assertEqual(
            self.validate("fixtures/negotiation/valid/interoperability-alternate-suite.json"),
            [],
        )

    def test_highest_mutual_version_is_required(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/downgraded-version.json")
        self.assertTrue(any("highest mutually supported version" in error for error in errors))

    def test_minimum_version_floor_is_enforced(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/below-version-floor.json")
        self.assertTrue(any("below minimum" in error for error in errors))

    def test_unpinned_suite_is_rejected(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/unpinned-suite.json")
        self.assertTrue(any("suite not pinned by policy" in error for error in errors))

    def test_required_transcript_binding_is_enforced(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/missing-transcript-binding.json")
        self.assertTrue(any("authenticated transcript omits required fields" in error for error in errors))

    def test_automatic_fallback_is_rejected(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/fallback-retry.json")
        self.assertTrue(any("automatic weaker fallback retry is prohibited" in error for error in errors))

    def test_registry_pin_must_match(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/registry-mismatch.json")
        self.assertTrue(any("cryptographic_registry_version does not match pinned policy" in error for error in errors))

    def test_effective_profile_set_is_pinned(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/profile-mismatch.json")
        self.assertTrue(any("effective_profile_refs do not match pinned policy configuration" in error for error in errors))

    def test_freshness_values_must_differ(self) -> None:
        errors = self.validate("fixtures/negotiation/invalid/same-nonce.json")
        self.assertTrue(any("initiator and responder nonces must differ" in error for error in errors))

    def test_replay_cache_rejects_seen_nonce_pair(self) -> None:
        evidence = self.load("fixtures/negotiation/valid/baseline.json")
        pair = (evidence["initiator_nonce_hex"], evidence["responder_nonce_hex"])
        errors = negotiation_engine.validate_evidence(
            self.policy(),
            evidence,
            self.crypto_registry(),
            self.profile_catalog(),
            seen_nonce_pairs={pair},
        )
        self.assertTrue(any("replayed negotiation nonce pair" in error for error in errors))

    def test_policy_cannot_disable_highest_mutual_rule(self) -> None:
        policy = copy.deepcopy(self.policy())
        policy["require_highest_mutual_version"] = False
        errors = negotiation_engine.validate_policy(
            policy,
            self.crypto_registry(),
            self.profile_catalog(),
        )
        self.assertTrue(any("require_highest_mutual_version must be true" in error for error in errors))

    def test_policy_cannot_disable_no_fallback_rule(self) -> None:
        policy = copy.deepcopy(self.policy())
        policy["prohibit_fallback_retry"] = False
        errors = negotiation_engine.validate_policy(
            policy,
            self.crypto_registry(),
            self.profile_catalog(),
        )
        self.assertTrue(any("prohibit_fallback_retry must be true" in error for error in errors))

    def test_policy_cannot_remove_baseline_transcript_field(self) -> None:
        policy = copy.deepcopy(self.policy())
        policy["required_transcript_fields"].remove("selected_version")
        errors = negotiation_engine.validate_policy(
            policy,
            self.crypto_registry(),
            self.profile_catalog(),
        )
        self.assertTrue(any("omits mandatory downgrade-sensitive fields" in error for error in errors))

    def test_unknown_evidence_fields_fail_closed(self) -> None:
        evidence = self.load("fixtures/negotiation/valid/baseline.json")
        evidence["surprise"] = True
        errors = negotiation_engine.validate_evidence(
            self.policy(),
            evidence,
            self.crypto_registry(),
            self.profile_catalog(),
        )
        self.assertTrue(any("unknown fields" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
