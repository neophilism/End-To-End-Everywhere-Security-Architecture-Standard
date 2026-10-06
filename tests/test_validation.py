from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_repo.py"

spec = importlib.util.spec_from_file_location("validate_repo", MODULE_PATH)
validate_repo = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validate_repo)


class ProfileValidationTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def known_property_ids(self) -> set[str]:
        registry = self.load("registry/security-properties.json")
        return {item["id"] for item in registry["properties"]}

    def test_valid_fixture_passes(self) -> None:
        data = self.load("fixtures/profiles/valid/minimal-profile.json")
        self.assertEqual(
            validate_repo.validate_profile(data, known_property_ids=self.known_property_ids()),
            [],
        )

    def test_bad_status_fails(self) -> None:
        data = self.load("fixtures/profiles/invalid/bad-status.json")
        errors = validate_repo.validate_profile(data)
        self.assertTrue(any("invalid status" in error for error in errors))

    def test_bad_identifier_fails(self) -> None:
        data = self.load("fixtures/profiles/invalid/bad-id.json")
        errors = validate_repo.validate_profile(data)
        self.assertTrue(any("invalid profile_id" in error for error in errors))

    def test_unknown_fields_fail_closed(self) -> None:
        data = self.load("fixtures/profiles/valid/minimal-profile.json")
        data["surprise"] = True
        errors = validate_repo.validate_profile(data)
        self.assertTrue(any("unknown fields" in error for error in errors))

    def test_security_properties_must_be_array(self) -> None:
        data = self.load("fixtures/profiles/valid/minimal-profile.json")
        data["security_properties"] = "not-an-array"
        errors = validate_repo.validate_profile(data)
        self.assertTrue(any("security_properties" in error for error in errors))

    def test_duplicate_security_properties_fail(self) -> None:
        data = self.load("fixtures/profiles/valid/minimal-profile.json")
        data["security_properties"] = ["SP-CONFIDENTIALITY", "SP-CONFIDENTIALITY"]
        errors = validate_repo.validate_profile(data)
        self.assertTrue(any("security_properties" in error for error in errors))

    def test_unknown_security_property_fails_when_registry_is_in_scope(self) -> None:
        data = self.load("fixtures/profiles/valid/minimal-profile.json")
        data["security_properties"] = ["SP-NOT-REGISTERED"]
        errors = validate_repo.validate_profile(data, known_property_ids=self.known_property_ids())
        self.assertTrue(any("unknown security property id" in error for error in errors))


class TerminologyValidationTests(unittest.TestCase):
    def load_registry(self) -> dict:
        return json.loads((ROOT / "registry/terminology.json").read_text(encoding="utf-8"))

    def test_registry_passes(self) -> None:
        self.assertEqual(validate_repo.validate_terminology(self.load_registry()), [])

    def test_duplicate_ids_fail(self) -> None:
        data = self.load_registry()
        duplicate = copy.deepcopy(data["terms"][0])
        duplicate["term"] = "Different display label"
        data["terms"].append(duplicate)
        errors = validate_repo.validate_terminology(data)
        self.assertTrue(any("duplicate id" in error for error in errors))

    def test_duplicate_term_labels_fail_case_insensitively(self) -> None:
        data = self.load_registry()
        duplicate = copy.deepcopy(data["terms"][0])
        duplicate["id"] = "different-id"
        duplicate["term"] = data["terms"][0]["term"].swapcase()
        data["terms"].append(duplicate)
        errors = validate_repo.validate_terminology(data)
        self.assertTrue(any("duplicate term label" in error for error in errors))

    def test_invalid_term_id_fails(self) -> None:
        data = self.load_registry()
        data["terms"][0]["id"] = "Bad Term ID"
        errors = validate_repo.validate_terminology(data)
        self.assertTrue(any("invalid id" in error for error in errors))

    def test_empty_definition_fails(self) -> None:
        data = self.load_registry()
        data["terms"][0]["definition"] = "   "
        errors = validate_repo.validate_terminology(data)
        self.assertTrue(any("definition must be a non-empty string" in error for error in errors))

    def test_unknown_term_fields_fail_closed(self) -> None:
        data = self.load_registry()
        data["terms"][0]["surprise"] = True
        errors = validate_repo.validate_terminology(data)
        self.assertTrue(any("unknown fields" in error for error in errors))


class ThreatModelValidationTests(unittest.TestCase):
    def load_registry(self) -> dict:
        return json.loads((ROOT / "registry/threat-model.json").read_text(encoding="utf-8"))

    def test_registry_passes(self) -> None:
        self.assertEqual(validate_repo.validate_threat_model(self.load_registry()), [])

    def test_duplicate_threat_ids_fail(self) -> None:
        data = self.load_registry()
        duplicate = copy.deepcopy(data["threats"][0])
        duplicate["name"] = "Different threat name"
        data["threats"].append(duplicate)
        errors = validate_repo.validate_threat_model(data)
        self.assertTrue(any("duplicate threat id" in error for error in errors))

    def test_invalid_threat_category_fails(self) -> None:
        data = self.load_registry()
        data["threats"][0]["category"] = "mystery"
        errors = validate_repo.validate_threat_model(data)
        self.assertTrue(any("invalid category" in error for error in errors))

    def test_empty_capabilities_fail(self) -> None:
        data = self.load_registry()
        data["threats"][0]["capabilities"] = []
        errors = validate_repo.validate_threat_model(data)
        self.assertTrue(any("capabilities must" in error for error in errors))

    def test_missing_baseline_threat_fails(self) -> None:
        data = self.load_registry()
        data["threats"] = [t for t in data["threats"] if t["id"] != "TM-ENDPOINT-LIVE"]
        errors = validate_repo.validate_threat_model(data)
        self.assertTrue(any("missing baseline threat ids" in error for error in errors))

    def test_unknown_composite_reference_fails(self) -> None:
        data = self.load_registry()
        data["composite_scenarios"][0]["threat_ids"][0] = "TM-NOT-DEFINED"
        errors = validate_repo.validate_threat_model(data)
        self.assertTrue(any("unknown threat reference" in error for error in errors))

    def test_duplicate_composite_references_fail(self) -> None:
        data = self.load_registry()
        first = data["composite_scenarios"][0]["threat_ids"][0]
        data["composite_scenarios"][0]["threat_ids"] = [first, first]
        errors = validate_repo.validate_threat_model(data)
        self.assertTrue(any("threat_ids must be a unique array" in error for error in errors))

    def test_unknown_threat_fields_fail_closed(self) -> None:
        data = self.load_registry()
        data["threats"][0]["surprise"] = True
        errors = validate_repo.validate_threat_model(data)
        self.assertTrue(any("unknown fields" in error for error in errors))


class SecurityPropertyValidationTests(unittest.TestCase):
    def load_registry(self) -> dict:
        return json.loads((ROOT / "registry/security-properties.json").read_text(encoding="utf-8"))

    def test_registry_passes(self) -> None:
        self.assertEqual(validate_repo.validate_security_properties(self.load_registry()), [])

    def test_duplicate_property_ids_fail(self) -> None:
        data = self.load_registry()
        duplicate = copy.deepcopy(data["properties"][0])
        duplicate["name"] = "Different property name"
        data["properties"].append(duplicate)
        errors = validate_repo.validate_security_properties(data)
        self.assertTrue(any("duplicate property id" in error for error in errors))

    def test_invalid_property_category_fails(self) -> None:
        data = self.load_registry()
        data["properties"][0]["category"] = "magic"
        errors = validate_repo.validate_security_properties(data)
        self.assertTrue(any("invalid category" in error for error in errors))

    def test_unknown_claim_dimension_fails(self) -> None:
        data = self.load_registry()
        data["properties"][0]["required_claim_dimensions"].append("mystery-dimension")
        errors = validate_repo.validate_security_properties(data)
        self.assertTrue(any("unknown claim dimensions" in error for error in errors))

    def test_missing_baseline_property_fails(self) -> None:
        data = self.load_registry()
        data["properties"] = [
            item for item in data["properties"] if item["id"] != "SP-CONFIDENTIALITY"
        ]
        errors = validate_repo.validate_security_properties(data)
        self.assertTrue(any("missing baseline security property ids" in error for error in errors))


class SecurityClaimValidationTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registries(self) -> tuple[dict, dict]:
        return (
            self.load("registry/security-properties.json"),
            self.load("registry/threat-model.json"),
        )

    def validate(self, data: dict) -> list[str]:
        properties, threats = self.registries()
        return validate_repo.validate_security_claim(data, properties, threats)

    def test_confidentiality_fixture_passes(self) -> None:
        data = self.load("fixtures/security-claims/valid/confidentiality.json")
        self.assertEqual(self.validate(data), [])

    def test_post_compromise_security_fixture_passes(self) -> None:
        data = self.load("fixtures/security-claims/valid/post-compromise-security.json")
        self.assertEqual(self.validate(data), [])

    def test_unknown_property_fails(self) -> None:
        data = self.load("fixtures/security-claims/invalid/unknown-property.json")
        errors = self.validate(data)
        self.assertTrue(any("unknown property_id" in error for error in errors))

    def test_conditional_claim_requires_condition(self) -> None:
        data = self.load("fixtures/security-claims/invalid/conditional-without-condition.json")
        errors = self.validate(data)
        self.assertTrue(any("conditional claim must include" in error for error in errors))

    def test_property_specific_qualifiers_are_required(self) -> None:
        data = self.load("fixtures/security-claims/invalid/missing-required-qualifier.json")
        errors = self.validate(data)
        self.assertTrue(any("requires claim field: healing_event" in error for error in errors))
        self.assertTrue(any("requires claim field: exposure_window" in error for error in errors))

    def test_unknown_threat_reference_fails(self) -> None:
        data = self.load("fixtures/security-claims/valid/confidentiality.json")
        data["threat_ids"] = ["TM-NOT-DEFINED"]
        errors = self.validate(data)
        self.assertTrue(any("unknown threat reference" in error for error in errors))

    def test_unknown_composite_reference_fails(self) -> None:
        data = self.load("fixtures/security-claims/valid/confidentiality.json")
        data["composite_scenario_ids"] = ["CS-NOT-DEFINED"]
        errors = self.validate(data)
        self.assertTrue(any("unknown composite scenario reference" in error for error in errors))

    def test_assets_cannot_be_empty(self) -> None:
        data = self.load("fixtures/security-claims/valid/confidentiality.json")
        data["assets"] = []
        errors = self.validate(data)
        self.assertTrue(any("assets must be" in error for error in errors))

    def test_pcs_requires_post_healing_phase(self) -> None:
        data = self.load("fixtures/security-claims/valid/post-compromise-security.json")
        data["temporal_phases"] = ["post-compromise-pre-healing"]
        errors = self.validate(data)
        self.assertTrue(any("PCS claim must include post-healing" in error for error in errors))

    def test_post_quantum_confidentiality_requires_quantum_threat(self) -> None:
        data = self.load("fixtures/security-claims/valid/confidentiality.json")
        data["property_id"] = "SP-PQ-CONFIDENTIALITY"
        data["threat_ids"] = ["TM-NET-PASSIVE"]
        errors = self.validate(data)
        self.assertTrue(any("must cover a quantum threat" in error for error in errors))


class RepositoryValidationTests(unittest.TestCase):
    def test_repository_passes(self) -> None:
        self.assertEqual(validate_repo.validate_repository(ROOT), [])


if __name__ == "__main__":
    unittest.main()
