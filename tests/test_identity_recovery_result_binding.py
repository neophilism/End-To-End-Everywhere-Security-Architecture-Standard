"""Caller-verified authorizers must commit to the exact proposed result state."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_recovery_result_binding", ROOT / "scripts" / "identity_recovery_engine.py"
)
assert spec is not None and spec.loader is not None
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class RecoveryResultBindingTests(unittest.TestCase):
    def inputs(self, threshold: bool = False) -> list[dict]:
        names = (
            ("contact-threshold-policy.json", "trusted-local-state.json", "valid-contact-replacement-event.json")
            if threshold else
            ("retained-authority-policy.json", "trusted-transparency-state.json", "valid-retained-authority-event.json")
        )
        return [json.loads((ROOT / "fixtures" / "identity-recovery" / name).read_text(encoding="utf-8")) for name in names]

    def test_substituted_event_result_state_is_denied_in_both_modes(self) -> None:
        for threshold in (False, True):
            with self.subTest(threshold=threshold):
                inputs = self.inputs(threshold)
                inputs[2]["resulting_state_hash"] = "sha256:" + "d" * 64
                result = engine.evaluate_recovery(*inputs)
                self.assertFalse(result["valid"], result)
                self.assertEqual(result["decision"], "denied")
                self.assertTrue(any("did not bind the resulting state" in error for error in result["errors"]), result)

    def test_each_contact_must_bind_the_same_result_state(self) -> None:
        inputs = self.inputs(True)
        inputs[2]["verified_authorizers"][0]["resulting_state_hash"] = "sha256:" + "d" * 64
        result = engine.evaluate_recovery(*inputs)
        self.assertFalse(result["valid"], result)
        self.assertTrue(any("requires 2" in error for error in result["errors"]), result)

    def test_missing_result_binding_is_not_inferred_from_event(self) -> None:
        inputs = self.inputs()
        inputs[2]["verified_authorizers"][0].pop("resulting_state_hash")
        result = engine.evaluate_recovery(*inputs)
        self.assertFalse(result["valid"], result)
        self.assertEqual(result["decision"], "invalid")

    def test_malformed_result_bindings_fail_validation(self) -> None:
        for value in (None, [], {}, True, "sha256:bad", "sha256:" + "A" * 64):
            with self.subTest(value=value):
                inputs = self.inputs()
                inputs[2]["verified_authorizers"][0]["resulting_state_hash"] = value
                result = engine.evaluate_recovery(*inputs)
                self.assertFalse(result["valid"], result)
                self.assertEqual(result["decision"], "invalid")

    def test_schema_requires_result_state_in_authorizer(self) -> None:
        schema = json.loads((ROOT / "schemas" / "identity-recovery-event.schema.json").read_text(encoding="utf-8"))
        authorizer = schema["$defs"]["authorizer"]
        self.assertIn("resulting_state_hash", authorizer["required"])
        self.assertEqual(authorizer["properties"]["resulting_state_hash"], schema["properties"]["resulting_state_hash"])


if __name__ == "__main__":
    unittest.main()
