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

import assurance_levels  # noqa: E402


class AssuranceLevelTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def registry(self) -> dict:
        return self.load("registry/assurance-levels.json")

    def property_ids(self) -> set[str]:
        return {x["id"] for x in self.load("registry/security-properties.json")["properties"]}

    def plan(self) -> dict:
        return self.load("fixtures/assurance/valid/a3-plan.json")

    def evaluate(self, plan: dict) -> dict:
        return assurance_levels.evaluate_plan(
            plan,
            self.registry(),
            self.catalog(),
            self.property_ids(),
        )

    def test_registry_is_monotonic_and_catalog_bound(self) -> None:
        self.assertEqual(
            assurance_levels.validate_registry(
                self.registry(), self.catalog(), self.property_ids()
            ),
            [],
        )

    def test_a3_plan_is_valid_and_derives_symbolic_requirement(self) -> None:
        result = self.evaluate(self.plan())
        self.assertTrue(result["valid"], result["errors"])
        self.assertIn("formal-symbolic-protocol@0.1.0", result["effective_profiles"])
        self.assertEqual(
            result["derived_formal_requirements"],
            [{
                "formal_profile_ref": "formal-symbolic-protocol@0.1.0",
                "kind": "symbolic",
                "property_ids": ["SP-CONFIDENTIALITY"],
            }],
        )

    def test_assurance_dependencies_are_auto_resolved(self) -> None:
        result = self.evaluate(self.plan())
        for ref in (
            "verification-combined@0.1.0",
            "development-ssdf-baseline@0.1.0",
            "supply-chain-attested-reproducible@0.1.0",
            "formal-symbolic-protocol@0.1.0",
        ):
            self.assertIn(ref, result["effective_profiles"])

    def a5_plan(self) -> dict:
        plan = self.plan()
        plan["plan_id"] = "example-a5-plan"
        plan["assurance_profile_ref"] = "assurance-a5-comprehensive-formal@0.1.0"
        plan["configuration"]["configuration_id"] = "example-a5-config"
        plan["configuration"]["selected_profiles"] = [
            "foundation-baseline@0.1.0",
            "example-choice-b@0.1.0",
            "assurance-a5-comprehensive-formal@0.1.0",
        ]
        plan["independent_assessor_ids"] = ["independent-assessor-one", "independent-assessor-two"]
        plan["computational_scope_property_ids"] = ["SP-CONFIDENTIALITY"]
        return plan

    def test_a5_derives_all_three_formal_proof_classes(self) -> None:
        result = self.evaluate(self.a5_plan())
        self.assertTrue(result["valid"], result["errors"])
        kinds = {item["kind"] for item in result["derived_formal_requirements"]}
        self.assertEqual(kinds, {"symbolic", "code-refinement", "computational"})

    def test_a5_requires_two_independent_assessors(self) -> None:
        plan = self.a5_plan()
        plan["independent_assessor_ids"] = ["independent-assessor-one"]
        result = self.evaluate(plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any("at least 2 independent assessors" in e for e in result["errors"]))

    def test_a5_requires_proof_scope_or_explicit_exemption(self) -> None:
        plan = self.a5_plan()
        plan["computational_scope_property_ids"] = []
        result = self.evaluate(plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any("require proof scope or explicit" in e for e in result["errors"]))

    def test_a5_standardized_construction_exemption_is_explicit(self) -> None:
        plan = self.a5_plan()
        plan["computational_scope_property_ids"] = []
        plan["computational_exemptions"] = [{
            "property_id": "SP-CONFIDENTIALITY",
            "rationale": "The assessed scope uses an unchanged standardized construction already covered by the cited specification and no product-specific cryptographic composition is claimed.",
            "standardized_construction_refs": ["example-standard-section-1"],
        }]
        result = self.evaluate(plan)
        self.assertTrue(result["valid"], result["errors"])
        kinds = {item["kind"] for item in result["derived_formal_requirements"]}
        self.assertNotIn("computational", kinds)

    def test_same_property_cannot_be_proof_scoped_and_exempted(self) -> None:
        plan = self.a5_plan()
        plan["computational_exemptions"] = [{
            "property_id": "SP-CONFIDENTIALITY",
            "rationale": "conflicting example",
            "standardized_construction_refs": ["example-standard"],
        }]
        result = self.evaluate(plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any("both proof-scoped and exempted" in e for e in result["errors"]))

    def test_unknown_claimed_property_fails(self) -> None:
        plan = self.plan()
        plan["claimed_property_ids"] = ["SP-NOT-REGISTERED"]
        result = self.evaluate(plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any("unknown claimed property_id" in e for e in result["errors"]))

    def test_property_not_provided_by_architecture_fails(self) -> None:
        plan = self.plan()
        plan["claimed_property_ids"] = ["SP-PQ-AUTHENTICATION"]
        result = self.evaluate(plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any("not provided by effective architecture" in e for e in result["errors"]))

    def test_assurance_profile_must_be_selected(self) -> None:
        plan = self.plan()
        plan["configuration"]["selected_profiles"] = [
            "foundation-baseline@0.1.0",
            "example-choice-b@0.1.0",
        ]
        result = self.evaluate(plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any("assurance profile is not selected" in e for e in result["errors"]))

    def test_two_assurance_levels_conflict_via_profile_engine(self) -> None:
        plan = self.plan()
        plan["configuration"]["selected_profiles"].append("assurance-a2-reviewed@0.1.0")
        result = self.evaluate(plan)
        self.assertFalse(result["valid"])
        self.assertTrue(any("assurance-level violates cardinality at-most-one" in e for e in result["errors"]))

    def test_registry_rejects_non_monotonic_profile_requirements(self) -> None:
        registry = copy.deepcopy(self.registry())
        registry["levels"][2]["required_profile_refs"] = ["formal-symbolic-protocol@0.1.0"]
        errors = assurance_levels.validate_registry(
            registry, self.catalog(), self.property_ids()
        )
        self.assertTrue(any("breaks monotonic required-profile inclusion" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
