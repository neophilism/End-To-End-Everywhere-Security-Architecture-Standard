from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import formal_verification  # noqa: E402


class FormalVerificationTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def registry(self) -> dict:
        return self.load("registry/formal-verification.json")

    def property_ids(self) -> set[str]:
        return {x["id"] for x in self.load("registry/security-properties.json")["properties"]}

    def threat_ids(self) -> set[str]:
        return {x["id"] for x in self.load("registry/threat-model.json")["threats"]}

    def policy(self) -> dict:
        return self.load("fixtures/formal-verification/valid/policy.json")

    def evidence(self, policy: dict | None = None) -> dict:
        policy = policy or self.policy()
        evidence = self.load("fixtures/formal-verification/valid/evidence.json")
        evidence["configuration_digest"] = formal_verification.canonical_digest(policy["configuration"])
        return evidence

    def validate_policy(self, policy: dict) -> list[str]:
        return formal_verification.validate_policy(
            policy,
            self.registry(),
            self.catalog(),
            self.property_ids(),
            self.threat_ids(),
        )

    def validate_evidence(self, policy: dict, evidence: dict) -> list[str]:
        return formal_verification.validate_evidence(
            policy,
            evidence,
            self.registry(),
            self.catalog(),
            self.property_ids(),
            self.threat_ids(),
        )

    def test_registry_is_valid(self) -> None:
        self.assertEqual(
            formal_verification.validate_registry(self.registry(), self.catalog()),
            [],
        )

    def test_policy_is_valid(self) -> None:
        self.assertEqual(self.validate_policy(self.policy()), [])

    def test_evidence_is_valid(self) -> None:
        policy = self.policy()
        self.assertEqual(self.validate_evidence(policy, self.evidence(policy)), [])

    def test_unbounded_obligation_rejects_bounded_proof(self) -> None:
        policy = self.policy()
        evidence = self.evidence(policy)
        evidence["proofs"][0]["session_scope"] = "bounded"
        errors = self.validate_evidence(policy, evidence)
        self.assertTrue(any("formal obligation unsatisfied: protocol-secrecy" in e for e in errors))

    def test_unresolved_proof_obligation_fails(self) -> None:
        policy = self.policy()
        evidence = self.evidence(policy)
        evidence["proofs"][0]["unresolved_obligations"] = ["lemma-authentication"]
        errors = self.validate_evidence(policy, evidence)
        self.assertTrue(any("contains unresolved proof obligations" in e for e in errors))
        self.assertTrue(any("formal obligation unsatisfied: protocol-secrecy" in e for e in errors))

    def test_source_digest_mismatch_fails(self) -> None:
        policy = self.policy()
        evidence = self.evidence(policy)
        evidence["proofs"][0]["source_digest"] = "sha256:" + "9" * 64
        errors = self.validate_evidence(policy, evidence)
        self.assertTrue(any("source_digest does not match evidence source" in e for e in errors))

    def test_artifact_correspondence_is_required_when_policy_requests_it(self) -> None:
        policy = self.policy()
        evidence = self.evidence(policy)
        evidence["proofs"][1]["artifact_correspondence"] = "source-only"
        errors = self.validate_evidence(policy, evidence)
        self.assertTrue(any("formal obligation unsatisfied: implementation-refinement" in e for e in errors))

    def test_wrong_proof_kind_fails(self) -> None:
        policy = self.policy()
        evidence = self.evidence(policy)
        evidence["proofs"][0]["proof_kind"] = "computational"
        errors = self.validate_evidence(policy, evidence)
        self.assertTrue(any("proof_kind does not match formal profile" in e for e in errors))

    def test_stale_proof_fails_obligation(self) -> None:
        policy = self.policy()
        evidence = self.evidence(policy)
        evidence["proofs"][0]["completed_at"] = "2026-09-01T00:00:00Z"
        errors = self.validate_evidence(policy, evidence)
        self.assertTrue(any("formal obligation evidence is stale: protocol-secrecy" in e for e in errors))

    def test_policy_rejects_unknown_property(self) -> None:
        policy = self.policy()
        policy["obligations"][0]["property_ids"] = ["SP-NOT-REGISTERED"]
        errors = self.validate_policy(policy)
        self.assertTrue(any("unknown property_id" in e for e in errors))

    def test_policy_rejects_unknown_threat(self) -> None:
        policy = self.policy()
        policy["obligations"][0]["threat_ids"] = ["TM-NOT-REGISTERED"]
        errors = self.validate_policy(policy)
        self.assertTrue(any("unknown threat_id" in e for e in errors))

    def test_policy_requires_formal_profile_to_be_selected(self) -> None:
        policy = self.policy()
        policy["configuration"]["selected_profiles"] = [
            x for x in policy["configuration"]["selected_profiles"]
            if x != "formal-code-refinement@0.1.0"
        ]
        errors = self.validate_policy(policy)
        self.assertTrue(any("formal profile is not selected by configuration" in e for e in errors))

    def test_non_symbolic_profile_cannot_require_unbounded_sessions(self) -> None:
        policy = self.policy()
        policy["obligations"][1]["require_unbounded_sessions"] = True
        errors = self.validate_policy(policy)
        self.assertTrue(any("only meaningful for symbolic protocol proof" in e for e in errors))

    def test_non_refinement_profile_cannot_require_artifact_correspondence(self) -> None:
        policy = self.policy()
        policy["obligations"][0]["require_artifact_correspondence"] = True
        errors = self.validate_policy(policy)
        self.assertTrue(any("artifact correspondence requires code-refinement" in e for e in errors))

    def test_configuration_digest_is_bound(self) -> None:
        policy = self.policy()
        evidence = self.evidence(policy)
        evidence["configuration_digest"] = "sha256:" + "0" * 64
        errors = self.validate_evidence(policy, evidence)
        self.assertTrue(any("configuration_digest does not bind policy configuration" in e for e in errors))

    def test_registry_profile_must_exist_in_catalog(self) -> None:
        registry = copy.deepcopy(self.registry())
        registry["profiles"][0]["profile_ref"] = "formal-missing@0.1.0"
        errors = formal_verification.validate_registry(registry, self.catalog())
        self.assertTrue(any("absent from catalog" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
