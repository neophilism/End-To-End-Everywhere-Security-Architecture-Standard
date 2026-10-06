from __future__ import annotations

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

    def test_repository_passes(self) -> None:
        self.assertEqual(validate_repo.validate_repository(ROOT), [])


if __name__ == "__main__":
    unittest.main()
