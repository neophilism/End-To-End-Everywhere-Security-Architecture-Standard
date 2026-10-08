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

import standards_crosswalk  # noqa: E402


class StandardsCrosswalkTests(unittest.TestCase):
    def load(self, rel):
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def catalog(self):
        return self.load("registry/external-standards.json")

    def rules(self):
        return self.load("registry/standards-crosswalk-rules.json")

    def test_catalog_and_rules_cover_every_current_spec_document(self):
        self.assertEqual(
            standards_crosswalk.validate(self.catalog(), self.rules(), ROOT),
            [],
        )

    def test_crosswalk_is_100_percent_complete(self):
        report = standards_crosswalk.build_report(ROOT, self.catalog(), self.rules())
        self.assertGreater(report["requirement_count"], 0)
        self.assertEqual(report["covered_requirement_count"], report["requirement_count"])
        self.assertEqual(report["coverage_percent_basis_points"], 10000)
        self.assertEqual(len(report["requirements"]), report["requirement_count"])

    def test_every_requirement_is_external_or_explicit_no_direct_analog(self):
        report = standards_crosswalk.build_report(ROOT, self.catalog(), self.rules())
        for item in report["requirements"]:
            with self.subTest(requirement=item["requirement_id"]):
                if item["coverage"] == "external-related":
                    self.assertTrue(item["relations"])
                    self.assertIsNone(item["no_direct_analog_reason"])
                else:
                    self.assertEqual(item["coverage"], "no-direct-analog")
                    self.assertEqual(item["relations"], [])
                    self.assertTrue(item["no_direct_analog_reason"])

    def test_requirement_ids_are_content_addressed(self):
        a = standards_crosswalk.extract_requirements_from_text(
            "spec/example.md", "A client MUST reject downgrade attempts."
        )[0]
        b = standards_crosswalk.extract_requirements_from_text(
            "spec/example.md", "A client MUST reject authenticated downgrade attempts."
        )[0]
        self.assertNotEqual(a["requirement_id"], b["requirement_id"])
        self.assertNotEqual(a["text_digest"], b["text_digest"])

    def test_code_fences_are_not_normative_requirements(self):
        text = "```text\nThe client MUST do example-only work.\n```\n\nThe client SHOULD fail closed."
        reqs = standards_crosswalk.extract_requirements_from_text("spec/example.md", text)
        self.assertEqual(len(reqs), 1)
        self.assertIn("SHOULD", reqs[0]["keywords"])

    def test_missing_document_rule_fails_closed(self):
        rules = copy.deepcopy(self.rules())
        removed = rules["rules"].pop()
        errors = standards_crosswalk.validate(self.catalog(), rules, ROOT)
        self.assertTrue(any(removed["document_path"] in error for error in errors))

    def test_unknown_external_standard_fails_closed(self):
        rules = copy.deepcopy(self.rules())
        target = next(item for item in rules["rules"] if item["relations"])
        target["relations"][0]["standard_id"] = "NOT-A-STANDARD"
        errors = standards_crosswalk.validate(self.catalog(), rules, ROOT)
        self.assertTrue(any("unknown standard" in error for error in errors))

    def test_no_direct_analog_requires_rationale(self):
        rules = copy.deepcopy(self.rules())
        target = next(item for item in rules["rules"] if not item["relations"])
        target["no_direct_analog_reason"] = None
        errors = standards_crosswalk.validate(self.catalog(), rules, ROOT)
        self.assertTrue(any("requires no-direct-analog rationale" in error for error in errors))

    def test_direct_and_contextual_are_only_relationship_types(self):
        allowed = {"direct", "contextual"}
        for rule in self.rules()["rules"]:
            for relation in rule["relations"]:
                self.assertIn(relation["relation"], allowed)

    def test_catalog_spans_required_external_ecosystems(self):
        organizations = {item["organization"] for item in self.catalog()["standards"]}
        self.assertTrue({"IETF","NIST","ISO/IEC","OASIS","W3C","OpenSSF","Linux Foundation","OWASP"} <= organizations)

    def test_report_digest_is_deterministic(self):
        one = standards_crosswalk.build_report(ROOT, self.catalog(), self.rules())
        two = standards_crosswalk.build_report(ROOT, self.catalog(), self.rules())
        self.assertEqual(one["report_digest"], two["report_digest"])
        self.assertEqual(one, two)


if __name__ == "__main__":
    unittest.main()
