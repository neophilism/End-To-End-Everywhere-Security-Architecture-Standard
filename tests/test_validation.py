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

    def test_valid_fixture_passes(self) -> None:
        data = self.load("fixtures/profiles/valid/minimal-profile.json")
        self.assertEqual(validate_repo.validate_profile(data), [])

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
        data["security_properties"] = ["duplicate", "duplicate"]
        errors = validate_repo.validate_profile(data)
        self.assertTrue(any("security_properties" in error for error in errors))


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


class RepositoryValidationTests(unittest.TestCase):
    def test_repository_passes(self) -> None:
        self.assertEqual(validate_repo.validate_repository(ROOT), [])


if __name__ == "__main__":
    unittest.main()
