from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "crypto_registry.py"

spec = importlib.util.spec_from_file_location("crypto_registry", MODULE_PATH)
crypto_registry = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = crypto_registry
spec.loader.exec_module(crypto_registry)


class CryptographicRegistryTests(unittest.TestCase):
    def registry(self) -> dict:
        return json.loads((ROOT / "registry/cryptographic-algorithms.json").read_text(encoding="utf-8"))

    def test_registry_passes(self) -> None:
        self.assertEqual(crypto_registry.validate_registry(self.registry()), [])

    def test_duplicate_algorithm_id_fails(self) -> None:
        data = self.registry()
        duplicate = copy.deepcopy(data["algorithms"][0])
        duplicate["name"] = "Different name"
        data["algorithms"].append(duplicate)
        errors = crypto_registry.validate_registry(data)
        self.assertTrue(any("duplicate algorithm id" in error for error in errors))

    def test_unknown_algorithm_field_fails_closed(self) -> None:
        data = self.registry()
        data["algorithms"][0]["surprise"] = True
        errors = crypto_registry.validate_registry(data)
        self.assertTrue(any("unknown fields" in error for error in errors))

    def test_unknown_suite_algorithm_fails(self) -> None:
        data = self.registry()
        data["suites"][0]["algorithm_ids"][0] = "ALG-NOT-REGISTERED"
        errors = crypto_registry.validate_registry(data)
        self.assertTrue(any("unknown algorithm reference" in error for error in errors))

    def test_prohibited_algorithm_cannot_be_in_suite(self) -> None:
        data = self.registry()
        data["suites"][0]["algorithm_ids"].append("ALG-SHA1")
        errors = crypto_registry.validate_registry(data)
        self.assertTrue(any("suite references prohibited algorithm" in error for error in errors))

    def test_suite_cannot_overstate_component_status(self) -> None:
        data = self.registry()
        data["suites"][0]["algorithm_ids"][0] = "ALG-HPKE-DHKEM-P256-HKDF-SHA256"
        data["suites"][0]["status"] = "recommended"
        errors = crypto_registry.validate_registry(data)
        self.assertTrue(any("suite status is stronger" in error for error in errors))

    def test_prohibited_algorithm_requires_reason(self) -> None:
        data = self.registry()
        sha1 = next(item for item in data["algorithms"] if item["id"] == "ALG-SHA1")
        del sha1["status_reason"]
        errors = crypto_registry.validate_registry(data)
        self.assertTrue(any("prohibited algorithm requires status_reason" in error for error in errors))

    def test_baseline_requires_post_quantum_primitives(self) -> None:
        data = self.registry()
        data["algorithms"] = [item for item in data["algorithms"] if item["id"] != "ALG-ML-KEM-768"]
        errors = crypto_registry.validate_registry(data)
        self.assertTrue(any("missing baseline algorithm ids" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
