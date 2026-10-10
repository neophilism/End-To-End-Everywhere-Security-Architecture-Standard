"""Malformed JSON enum values must produce denials, never uncaught TypeError."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "identity_recovery_engine.py"
spec = importlib.util.spec_from_file_location("identity_recovery_malformed", MODULE_PATH)
assert spec is not None and spec.loader is not None
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class MalformedRecoveryInputTests(unittest.TestCase):
    def inputs(self) -> list[dict]:
        names = (
            "retained-authority-policy.json",
            "trusted-transparency-state.json",
            "valid-retained-authority-event.json",
        )
        return [
            json.loads((ROOT / "fixtures" / "identity-recovery" / name).read_text(encoding="utf-8"))
            for name in names
        ]

    def test_valid_fixture_still_recovers(self) -> None:
        result = engine.evaluate_recovery(*self.inputs())
        self.assertTrue(result["valid"], result)
        self.assertFalse(result["production_eligible"])

    def test_non_string_enum_values_fail_closed(self) -> None:
        fields = (
            (0, "mode"),
            (0, "trusted_history_source"),
            (1, "history_source"),
            (2, "operation"),
            (2, "authorizer-type"),
        )
        values = ([], {}, ["retained-authority"], {"type": "contact"}, None, True, 1)
        for index, field in fields:
            for value in values:
                with self.subTest(field=field, value=value):
                    inputs = self.inputs()
                    if field == "authorizer-type":
                        inputs[index]["verified_authorizers"][0]["type"] = copy.deepcopy(value)
                    else:
                        inputs[index][field] = copy.deepcopy(value)
                    result = engine.evaluate_recovery(*inputs)
                    self.assertFalse(result["valid"], result)
                    self.assertEqual(result["decision"], "invalid")
                    self.assertTrue(result["errors"])

    def test_cli_returns_structured_rejection_for_unhashable_mode(self) -> None:
        inputs = self.inputs()
        inputs[0]["mode"] = []
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for index, document in enumerate(inputs):
                path = Path(directory) / f"input-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                paths.append(str(path))
            completed = subprocess.run(
                [sys.executable, str(MODULE_PATH), *paths],
                capture_output=True, text=True, check=False, timeout=15,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        self.assertFalse(result["valid"])
        self.assertEqual(result["decision"], "invalid")
        self.assertIn("recovery policy: unsupported mode", result["errors"])


if __name__ == "__main__":
    unittest.main()
