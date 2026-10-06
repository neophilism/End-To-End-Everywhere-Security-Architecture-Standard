from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENGINE_PATH = ROOT / "scripts" / "profile_engine.py"

spec = importlib.util.spec_from_file_location("profile_engine", ENGINE_PATH)
profile_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(profile_engine)


class ProfileEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def property_ids(self) -> set[str]:
        registry = self.load("registry/security-properties.json")
        return {item["id"] for item in registry["properties"]}

    def resolve(self, config_rel: str):
        return profile_engine.resolve_configuration(
            self.catalog(),
            self.load(config_rel),
            known_property_ids=self.property_ids(),
        )

    def test_catalog_is_valid(self) -> None:
        self.assertEqual(
            profile_engine.validate_catalog(
                self.catalog(),
                known_property_ids=self.property_ids(),
            ),
            [],
        )

    def test_dependency_expansion_is_visible_and_deterministic(self) -> None:
        result = self.resolve("fixtures/configurations/valid/dependency-expansion.json")
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(
            result.auto_added_profiles,
            ["example-choice-a@0.1.0"],
        )
        self.assertEqual(
            result.effective_profiles,
            [
                "example-addon-requires-a@0.1.0",
                "example-choice-a@0.1.0",
                "foundation-baseline@0.1.0",
            ],
        )

    def test_alternate_architecture_choice_is_valid(self) -> None:
        result = self.resolve("fixtures/configurations/valid/alternate-choice.json")
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.auto_added_profiles, [])
        self.assertEqual(
            result.family_selections["example-architecture"],
            ["example-choice-b@0.1.0"],
        )

    def test_experimental_profile_requires_explicit_opt_in(self) -> None:
        invalid = self.resolve(
            "fixtures/configurations/invalid/experimental-without-opt-in.json"
        )
        self.assertFalse(invalid.valid)
        self.assertTrue(any("without explicit opt-in" in error for error in invalid.errors))

        valid = self.resolve("fixtures/configurations/valid/experimental-opt-in.json")
        self.assertTrue(valid.valid, valid.errors)
        self.assertTrue(any("experimental" in warning for warning in valid.warnings))

    def test_prohibited_profile_can_never_resolve(self) -> None:
        result = self.resolve("fixtures/configurations/invalid/prohibited.json")
        self.assertFalse(result.valid)
        self.assertTrue(any("prohibited profile selected" in error for error in result.errors))

    def test_missing_exactly_one_family_fails(self) -> None:
        result = self.resolve("fixtures/configurations/invalid/family-missing.json")
        self.assertFalse(result.valid)
        self.assertTrue(any("foundation violates cardinality exactly-one" in error for error in result.errors))

    def test_two_profiles_in_exactly_one_family_fail(self) -> None:
        result = self.resolve("fixtures/configurations/invalid/family-conflict.json")
        self.assertFalse(result.valid)
        self.assertTrue(any("example-architecture violates cardinality exactly-one" in error for error in result.errors))

    def test_one_sided_incompatibility_is_symmetric_at_resolution(self) -> None:
        result = self.resolve("fixtures/configurations/invalid/incompatible.json")
        self.assertFalse(result.valid)
        self.assertTrue(any("incompatible profiles selected" in error for error in result.errors))

    def test_conflicting_versions_fail_without_choosing_one(self) -> None:
        result = self.resolve("fixtures/configurations/invalid/conflicting-versions.json")
        self.assertFalse(result.valid)
        self.assertTrue(any("multiple versions selected for example-choice-a" in error for error in result.errors))

    def test_unknown_requested_profile_fails_closed(self) -> None:
        config = self.load("fixtures/configurations/valid/alternate-choice.json")
        config["selected_profiles"][1] = "not-in-catalog@1.0.0"
        result = profile_engine.resolve_configuration(
            self.catalog(),
            config,
            known_property_ids=self.property_ids(),
        )
        self.assertFalse(result.valid)
        self.assertTrue(any("unknown profiles" in error for error in result.errors))

    def test_standard_version_mismatch_fails(self) -> None:
        config = self.load("fixtures/configurations/valid/alternate-choice.json")
        config["standard_version"] = "9.9.9"
        result = profile_engine.resolve_configuration(
            self.catalog(),
            config,
            known_property_ids=self.property_ids(),
        )
        self.assertFalse(result.valid)
        self.assertTrue(any("does not match catalog" in error for error in result.errors))

    def test_floating_profile_reference_is_rejected(self) -> None:
        config = self.load("fixtures/configurations/valid/alternate-choice.json")
        config["selected_profiles"][1] = "example-choice-b@latest"
        errors = profile_engine.validate_configuration(config)
        self.assertTrue(any("exact and version-pinned" in error for error in errors))

    def test_prohibited_cannot_be_added_to_opt_in_list(self) -> None:
        config = self.load("fixtures/configurations/valid/alternate-choice.json")
        config["accepted_nondefault_statuses"] = ["prohibited"]
        errors = profile_engine.validate_configuration(config)
        self.assertTrue(any("invalid accepted_nondefault_statuses" in error for error in errors))

    def test_dependency_cycle_terminates_when_satisfiable(self) -> None:
        catalog = copy.deepcopy(self.catalog())
        by_ref = {
            profile_engine.profile_ref(profile): profile
            for profile in catalog["profiles"]
        }
        by_ref["example-choice-a@0.1.0"]["requires_profile_refs"] = [
            "example-addon-requires-a@0.1.0"
        ]
        config = self.load("fixtures/configurations/valid/alternate-choice.json")
        config["selected_profiles"][1] = "example-choice-a@0.1.0"
        result = profile_engine.resolve_configuration(
            catalog,
            config,
            known_property_ids=self.property_ids(),
        )
        self.assertTrue(result.valid, result.errors)
        self.assertIn("example-addon-requires-a@0.1.0", result.effective_profiles)

    def test_catalog_rejects_unknown_dependency(self) -> None:
        catalog = copy.deepcopy(self.catalog())
        catalog["profiles"][0]["requires_profile_refs"] = ["missing-profile@1.0.0"]
        errors = profile_engine.validate_catalog(
            catalog,
            known_property_ids=self.property_ids(),
        )
        self.assertTrue(any("unknown profile reference" in error for error in errors))

    def test_catalog_rejects_profile_family_migration_between_versions(self) -> None:
        catalog = copy.deepcopy(self.catalog())
        for profile in catalog["profiles"]:
            if profile_engine.profile_ref(profile) == "example-choice-a@0.2.0":
                profile["family_id"] = "example-addons"
        errors = profile_engine.validate_catalog(
            catalog,
            known_property_ids=self.property_ids(),
        )
        self.assertTrue(any("all versions of example-choice-a must remain in family" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
