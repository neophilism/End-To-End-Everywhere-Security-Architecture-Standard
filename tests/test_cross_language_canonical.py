"""Cross-language golden-byte regression for the restricted E2EESA canonical model.

Tests independent Python and ECMAScript reference implementations; not protocol
interoperability, cryptographic security, or external-review certification.
"""
from __future__ import annotations
import json
import shutil
import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import canonical_serialization as pyref

JS = ROOT / "reference" / "canonicalization" / "canonical.mjs"


@unittest.skipUnless(shutil.which("node"), "Node.js unavailable: cross-language test unverified")
class CrossLanguageCanonicalTests(unittest.TestCase):
    def js_bytes(self, obj):
        payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        run = subprocess.run(["node", str(JS), "canonical"], input=payload,
                             capture_output=True, text=True, encoding="utf-8",
                             check=False, timeout=15)
        self.assertEqual(run.returncode, 0, run.stderr)
        return bytes.fromhex(run.stdout.strip())

    def test_unicode_key_order_and_arrays_match(self):
        values = [
            {"claim": "cafe\u0301", "n": 1, "events": [3, 1, 2]},
            {"\ue000": 1, "\U00010000": 2, "nested": {"z": [True, None], "a": "cafe"}},
            {"message": "line\nquote\"slash\\", "scope": ["alpha", "omega"]},
        ]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(pyref.canonical_bytes(value), self.js_bytes(value))

    def test_ordered_array_is_not_interpreted_as_set(self):
        a = {"events": ["one", "two"]}
        b = {"events": ["two", "one"]}
        self.assertNotEqual(pyref.canonical_bytes(a), pyref.canonical_bytes(b))
        self.assertEqual(self.js_bytes(a), pyref.canonical_bytes(a))
        self.assertEqual(self.js_bytes(b), pyref.canonical_bytes(b))

    def test_nested_integer_bounds_match(self):
        x = {"count": 9007199254740991}
        self.assertEqual(pyref.canonical_bytes(x), self.js_bytes(x))


if __name__ == "__main__":
    unittest.main()
