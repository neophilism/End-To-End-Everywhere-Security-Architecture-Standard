from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/"scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0,str(SCRIPTS))

import security_rationale  # noqa: E402
import standards_crosswalk  # noqa: E402


class SecurityRationaleTests(unittest.TestCase):
    def load(self,rel):
        return json.loads((ROOT/rel).read_text(encoding="utf-8"))

    def inputs(self):
        return (
            self.load("registry/security-rationale-rules.json"),
            self.load("registry/threat-model.json"),
            self.load("registry/security-properties.json"),
            self.load("registry/external-standards.json"),
            self.load("registry/standards-crosswalk-rules.json"),
        )

    def report(self):
        return security_rationale.build_report(ROOT,*self.inputs())

    def test_rules_cover_every_current_spec_document(self):
        rules,threats,props,_,_=self.inputs()
        self.assertEqual(security_rationale.validate_rules(rules,ROOT,threats,props),[])

    def test_rationale_coverage_is_complete(self):
        report=self.report()
        self.assertGreater(report["requirement_count"],0)
        self.assertEqual(report["requirement_count"],report["rationale_count"])
        self.assertEqual(report["coverage_percent_basis_points"],10000)
        self.assertEqual(len(report["records"]),report["requirement_count"])

    def test_requirement_set_exactly_matches_pr46(self):
        rules,threats,props,standards,crosswalk_rules=self.inputs()
        rationale=security_rationale.build_report(ROOT,rules,threats,props,standards,crosswalk_rules)
        crosswalk=standards_crosswalk.build_report(ROOT,standards,crosswalk_rules)
        self.assertEqual(
            {x["requirement_id"] for x in rationale["records"]},
            {x["requirement_id"] for x in crosswalk["requirements"]},
        )

    def test_external_mapping_is_preserved_exactly(self):
        rules,threats,props,standards,crosswalk_rules=self.inputs()
        rationale=security_rationale.build_report(ROOT,rules,threats,props,standards,crosswalk_rules)
        crosswalk=standards_crosswalk.build_report(ROOT,standards,crosswalk_rules)
        by_id={x["requirement_id"]:x for x in crosswalk["requirements"]}
        for record in rationale["records"]:
            source=by_id[record["requirement_id"]]
            self.assertEqual(record["external_coverage"],source["coverage"])
            self.assertEqual(record["external_relations"],source["relations"])
            self.assertEqual(record["no_direct_analog_reason"],source["no_direct_analog_reason"])

    def test_every_record_has_security_context_and_evidence(self):
        for record in self.report()["records"]:
            with self.subTest(requirement=record["requirement_id"]):
                self.assertTrue(record["rationale"])
                self.assertTrue(record["security_property_ids"])
                self.assertTrue(record["evidence_expectations"])
                self.assertTrue(record["rationale_record_digest"].startswith("sha256:"))

    def test_unknown_threat_fails_closed(self):
        rules,threats,props,_,_=self.inputs()
        rules=copy.deepcopy(rules)
        rules["rules"][0]["threat_ids"].append("TM-NOT-REGISTERED")
        errors=security_rationale.validate_rules(rules,ROOT,threats,props)
        self.assertTrue(any("unknown threats" in e for e in errors))

    def test_unknown_property_fails_closed(self):
        rules,threats,props,_,_=self.inputs()
        rules=copy.deepcopy(rules)
        rules["rules"][0]["security_property_ids"].append("SP-NOT-REGISTERED")
        errors=security_rationale.validate_rules(rules,ROOT,threats,props)
        self.assertTrue(any("unknown security properties" in e for e in errors))

    def test_unknown_scenario_fails_closed(self):
        rules,threats,props,_,_=self.inputs()
        rules=copy.deepcopy(rules)
        rules["rules"][0]["composite_scenario_ids"].append("CS-NOT-REGISTERED")
        errors=security_rationale.validate_rules(rules,ROOT,threats,props)
        self.assertTrue(any("unknown composite scenarios" in e for e in errors))

    def test_empty_evidence_expectation_fails_closed(self):
        rules,threats,props,_,_=self.inputs()
        rules=copy.deepcopy(rules)
        rules["rules"][0]["evidence_expectations"]=[]
        errors=security_rationale.validate_rules(rules,ROOT,threats,props)
        self.assertTrue(any("evidence_expectations" in e for e in errors))

    def test_missing_document_rule_fails_closed(self):
        rules,threats,props,_,_=self.inputs()
        rules=copy.deepcopy(rules)
        removed=rules["rules"].pop()
        errors=security_rationale.validate_rules(rules,ROOT,threats,props)
        self.assertTrue(any(removed["document_path"] in e for e in errors))

    def test_record_digest_is_reproducible(self):
        one=self.report(); two=self.report()
        self.assertEqual(one,two)
        self.assertEqual(one["report_digest"],two["report_digest"])


if __name__=="__main__":
    unittest.main()
