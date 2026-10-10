"""AUD-09.1: persisted invalidation cannot silently resurrect verified trust."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "key_verification_invalidation", ROOT / "scripts" / "key_verification_engine.py"
)
assert spec is not None and spec.loader is not None
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


class PersistedInvalidationTests(unittest.TestCase):
    def load(self, path: str) -> dict:
        return json.loads((ROOT / path).read_text(encoding="utf-8"))

    def inputs(self, family: str, peer: str = "bob") -> tuple[dict, ...]:
        return (
            self.load(f"fixtures/verification/policies/{family}.json"),
            self.load(f"fixtures/verification/snapshots/{family}/alice.json"),
            self.load(f"fixtures/verification/snapshots/{family}/{peer}.json"),
            self.load("registry/cryptographic-algorithms.json"),
            self.load("fixtures/profiles/development-catalog.json"),
        )

    def record(self, family: str, record_id: str = "original-comparison") -> dict:
        policy, first, second, crypto, catalog = self.inputs(family)
        return engine.create_manual_record(
            record_id=record_id, verification_method="qr", user_confirmed=True,
            policy=policy, first_snapshot=first, second_snapshot=second,
            crypto_registry=crypto, profile_catalog=catalog,
        )

    def test_invalidated_record_stays_invalidated_with_matching_subject(self) -> None:
        for family in ("account", "devices"):
            with self.subTest(family=family):
                record = self.record(family)
                record["status"] = "invalidated"
                before = copy.deepcopy(record)
                self.assertEqual(engine.validate_record(record, *self.inputs(family)), [])
                status = engine.verification_status(record, *self.inputs(family))
                self.assertEqual(record, before)
                self.assertEqual(status["status"], "invalidated")
                self.assertTrue(status["requires_manual_reverification"])

    def test_return_to_old_subject_does_not_restore_invalidated_comparison(self) -> None:
        for family, changed in (("account", "bob-root-changed"), ("devices", "bob-key-rotated")):
            with self.subTest(family=family):
                record = self.record(family)
                status = engine.verification_status(record, *self.inputs(family, changed))
                self.assertEqual(status["status"], "invalidated")
                record["status"] = status["status"]  # Persist the accepted invalidation.
                returned = engine.verification_status(record, *self.inputs(family))
                self.assertEqual(returned["status"], "invalidated")
                self.assertTrue(returned["requires_manual_reverification"])

    def test_current_explicit_comparison_remains_verified(self) -> None:
        for family in ("account", "devices"):
            with self.subTest(family=family):
                record = self.record(family)
                status = engine.verification_status(record, *self.inputs(family))
                self.assertEqual(status["status"], "verified")
                self.assertFalse(status["requires_manual_reverification"])

    def test_fresh_explicit_comparison_can_create_new_verified_record(self) -> None:
        for family in ("account", "devices"):
            with self.subTest(family=family):
                old = self.record(family)
                old["status"] = "invalidated"
                fresh = self.record(family, "fresh-out-of-band-comparison")
                self.assertNotEqual(old["record_id"], fresh["record_id"])
                status = engine.verification_status(fresh, *self.inputs(family))
                self.assertEqual(status["status"], "verified")
                self.assertEqual(old["status"], "invalidated")

    def test_new_comparison_still_requires_explicit_confirmation(self) -> None:
        policy, first, second, crypto, catalog = self.inputs("devices")
        with self.assertRaisesRegex(ValueError, "explicit out-of-band"):
            engine.create_manual_record(
                record_id="silent-reset", verification_method="qr", user_confirmed=False,
                policy=policy, first_snapshot=first, second_snapshot=second,
                crypto_registry=crypto, profile_catalog=catalog,
            )

    def test_invalidated_malformed_record_is_not_treated_as_valid(self) -> None:
        record = self.record("devices")
        record["status"] = "invalidated"
        record["user_confirmed"] = False
        status = engine.verification_status(record, *self.inputs("devices"))
        self.assertEqual(status["status"], "invalid")
        self.assertTrue(status["errors"])

    def test_ordinary_authorized_device_addition_under_same_root_still_works(self) -> None:
        record = self.record("account")
        status = engine.verification_status(record, *self.inputs("account", "bob-device-added"))
        self.assertEqual(status["status"], "verified")
        self.assertFalse(status["requires_manual_reverification"])


if __name__ == "__main__":
    unittest.main()
