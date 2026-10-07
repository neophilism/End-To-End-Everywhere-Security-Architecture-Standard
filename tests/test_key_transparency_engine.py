from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

kt_spec = importlib.util.spec_from_file_location(
    "key_transparency_engine", ROOT / "scripts" / "key_transparency_engine.py"
)
key_transparency_engine = importlib.util.module_from_spec(kt_spec)
assert kt_spec.loader is not None
sys.modules[kt_spec.name] = key_transparency_engine
kt_spec.loader.exec_module(key_transparency_engine)

kv_spec = importlib.util.spec_from_file_location(
    "key_verification_engine", ROOT / "scripts" / "key_verification_engine.py"
)
key_verification_engine = importlib.util.module_from_spec(kv_spec)
assert kv_spec.loader is not None
sys.modules[kv_spec.name] = key_verification_engine
kv_spec.loader.exec_module(key_verification_engine)


class KeyTransparencyEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/key-transparency-protocols.json")

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/transparency/policies/{name}.json")

    def evidence(self, name: str) -> dict:
        return self.load(f"fixtures/transparency/{name}.json")

    def checkpoint(self) -> dict:
        return self.load("fixtures/transparency/base-checkpoint.json")

    def expected_subject_digest(self) -> str:
        policy = self.load("fixtures/verification/policies/devices.json")
        alice = self.load("fixtures/verification/snapshots/devices/alice.json")
        bob = self.load("fixtures/verification/snapshots/devices/bob.json")
        return key_verification_engine.subject_digest(policy, alice, bob).hex()

    def validate(
        self,
        policy_name: str,
        evidence_name: str,
        previous: dict | None = None,
    ) -> list[str]:
        return key_transparency_engine.validate_evidence(
            self.policy(policy_name),
            self.evidence(evidence_name),
            self.registry(),
            self.catalog(),
            self.expected_subject_digest(),
            previous,
        )

    def test_protocol_registry_pins_current_ietf_drafts(self) -> None:
        self.assertEqual(
            key_transparency_engine.validate_protocol_registry(self.registry()),
            [],
        )
        protocol = self.registry()["protocols"][0]
        self.assertEqual(protocol["specification"], "draft-ietf-keytrans-protocol-05")
        self.assertEqual(
            protocol["architecture_specification"],
            "draft-ietf-keytrans-architecture-09",
        )
        self.assertEqual(protocol["status"], "provisional")

    def test_three_transparency_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "key-transparency"
        }
        self.assertEqual(refs, set(key_transparency_engine.PROFILE_BINDINGS))

    def test_all_three_policies_pass(self) -> None:
        for name in ("contact", "audit", "manager"):
            with self.subTest(name=name):
                self.assertEqual(
                    key_transparency_engine.validate_policy(
                        self.policy(name), self.registry(), self.catalog()
                    ),
                    [],
                )

    def test_fixture_digest_is_actual_pr11_subject_digest(self) -> None:
        expected = self.expected_subject_digest()
        self.assertEqual(
            expected,
            self.evidence("contact-first")["subject_digest_hex"],
        )

    def test_all_three_first_observation_cycles_pass(self) -> None:
        for policy_name, evidence_name in (
            ("contact", "contact-first"),
            ("audit", "audit-first"),
            ("manager", "manager-first"),
        ):
            with self.subTest(profile=policy_name):
                self.assertEqual(self.validate(policy_name, evidence_name), [])

    def test_contact_monitoring_obligation_is_enforced(self) -> None:
        errors = self.validate("contact", "invalid-contact-monitor-missed")
        self.assertTrue(
            any("contact monitoring was not completed" in e for e in errors),
            errors,
        )

    def test_subject_substitution_is_rejected(self) -> None:
        errors = self.validate("contact", "invalid-subject-mismatch")
        self.assertTrue(
            any("PR 11 verification subject" in e for e in errors),
            errors,
        )

    def test_auditor_threshold_and_lag_are_enforced(self) -> None:
        errors = self.validate("audit", "invalid-auditor-threshold")
        self.assertTrue(
            any("insufficient verified third-party auditor" in e for e in errors),
            errors,
        )
        errors = self.validate("audit", "invalid-auditor-lag")
        self.assertTrue(any("auditor lag exceeds" in e for e in errors), errors)

    def test_manager_requires_service_update_authentication(self) -> None:
        errors = self.validate("manager", "invalid-manager-update-signature")
        self.assertTrue(
            any("service update signature" in e for e in errors),
            errors,
        )
        evidence = self.evidence("manager-first")
        evidence["service_fork_detection_active"] = False
        errors = key_transparency_engine.validate_evidence(
            self.policy("manager"),
            evidence,
            self.registry(),
            self.catalog(),
            self.expected_subject_digest(),
        )
        self.assertTrue(
            any("service-side fork detection" in e for e in errors),
            errors,
        )

    def test_tree_head_freshness_is_enforced(self) -> None:
        errors = self.validate("contact", "invalid-stale-tree-head")
        self.assertTrue(any("max_behind_ms" in e for e in errors), errors)

    def test_valid_checkpoint_continuity_passes(self) -> None:
        self.assertEqual(
            self.validate("contact", "contact-next", self.checkpoint()),
            [],
        )

    def test_same_size_different_root_is_a_fork(self) -> None:
        errors = self.validate(
            "contact", "invalid-same-size-fork", self.checkpoint()
        )
        self.assertTrue(
            any("same tree_size with different root" in e for e in errors),
            errors,
        )

    def test_label_and_tree_rollbacks_are_rejected(self) -> None:
        errors = self.validate(
            "contact", "invalid-label-rollback", self.checkpoint()
        )
        self.assertTrue(any("label_version rollback" in e for e in errors), errors)

        evidence = self.evidence("contact-next")
        evidence["tree_size"] = 9
        errors = key_transparency_engine.validate_evidence(
            self.policy("contact"),
            evidence,
            self.registry(),
            self.catalog(),
            self.expected_subject_digest(),
            self.checkpoint(),
        )
        self.assertTrue(any("tree_size rollback" in e for e in errors), errors)

    def test_nonfirst_observation_requires_checkpoint(self) -> None:
        errors = self.validate("contact", "contact-next")
        self.assertTrue(
            any("requires previous checkpoint" in e for e in errors),
            errors,
        )

    def test_multi_party_threshold_must_be_majority(self) -> None:
        policy = copy.deepcopy(self.policy("audit"))
        policy["third_party_count"] = 3
        policy["third_party_threshold"] = 1
        errors = key_transparency_engine.validate_policy(
            policy, self.registry(), self.catalog()
        )
        self.assertTrue(any("at least a majority" in e for e in errors), errors)

    def test_checkpoint_projection(self) -> None:
        evidence = self.evidence("contact-next")
        checkpoint = key_transparency_engine.checkpoint_from_evidence(
            "primary-log", evidence
        )
        self.assertEqual(
            key_transparency_engine.validate_checkpoint(checkpoint),
            [],
        )
        self.assertEqual(checkpoint["tree_size"], 11)
        self.assertEqual(checkpoint["label_version"], 4)


if __name__ == "__main__":
    unittest.main()
