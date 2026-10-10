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

import advisory_interoperability  # noqa: E402


class AdvisoryInteroperabilityTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def registry(self) -> dict:
        return self.load("registry/advisory-interoperability.json")

    def handling_registry(self) -> dict:
        return self.load("registry/vulnerability-handling.json")

    def disclosure_registry(self) -> dict:
        return self.load("registry/vulnerability-disclosure.json")

    def handling_policy(self) -> dict:
        return self.load("fixtures/vulnerability-handling/valid/policy.json")

    def disclosure_policy(self) -> dict:
        return self.load("fixtures/vulnerability-disclosure/valid/fixed-90-policy.json")

    def handling_case(self) -> dict:
        return self.load("fixtures/vulnerability-handling/valid/case.json")

    def advisory(self) -> dict:
        return self.load("fixtures/advisory-interoperability/valid/advisory.json")

    def bound_advisory(self) -> tuple[dict, dict]:
        case=self.handling_case()
        advisory=self.advisory()
        advisory["handling_case_digest"]=advisory_interoperability.canonical_digest(case)
        return advisory,case

    def validate(self, advisory: dict, case: dict | None=None) -> list[str]:
        kwargs={}
        if case is not None:
            kwargs={
                "handling_case":case,
                "handling_policy":self.handling_policy(),
                "disclosure_policy":self.disclosure_policy(),
                "handling_registry":self.handling_registry(),
                "disclosure_registry":self.disclosure_registry(),
            }
        return advisory_interoperability.validate_advisory(
            advisory,self.registry(),self.catalog(),**kwargs
        )

    def test_registry_is_valid(self) -> None:
        self.assertEqual(
            advisory_interoperability.validate_registry(self.registry(),self.catalog()),[]
        )

    def test_normalized_advisory_is_valid(self) -> None:
        self.assertEqual(self.validate(self.advisory()),[])

    def test_advisory_binds_valid_pr32_case(self) -> None:
        advisory,case=self.bound_advisory()
        self.assertEqual(self.validate(advisory,case),[])

    def test_handling_case_digest_substitution_fails(self) -> None:
        advisory,case=self.bound_advisory()
        advisory["handling_case_digest"]="sha256:"+"9"*64
        errors=self.validate(advisory,case)
        self.assertTrue(any("handling_case_digest does not match" in e for e in errors))

    def test_source_case_must_be_disclosure_ready_or_closed(self) -> None:
        advisory,case=self.bound_advisory()
        case["events"]=case["events"][:5]
        advisory["handling_case_digest"]=advisory_interoperability.canonical_digest(case)
        errors=self.validate(advisory,case)
        self.assertTrue(any("must be disclosure-ready or closed" in e for e in errors))

    def test_invalid_cve_fails(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["cve"]="CVE-bad"
        errors=self.validate(advisory)
        self.assertTrue(any("invalid CVE identifier" in e for e in errors))

    def test_invalid_cwe_fails(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["cwes"][0]["id"]="CWE-0"
        errors=self.validate(advisory)
        self.assertTrue(any("invalid CWE id" in e for e in errors))

    def test_product_status_conflict_fails(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["product_status"]["known_not_affected"]=[
            "CSAFPID-EXAMPLE-100"
        ]
        errors=self.validate(advisory)
        self.assertTrue(any("product status conflict" in e for e in errors))

    def test_fixed_product_requires_affected_lineage(self) -> None:
        advisory=self.advisory()
        advisory["products"][1]["product_line_id"]="different-product"
        errors=self.validate(advisory)
        self.assertTrue(any("has no known-affected product lineage" in e for e in errors))

    def test_remediation_cannot_reference_unknown_product(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["remediations"][0]["product_ids"]=["missing-product"]
        errors=self.validate(advisory)
        self.assertTrue(any("references unknown products" in e for e in errors))

    def test_cvss_score_and_severity_must_agree(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["cvss_v4"]["baseSeverity"]="LOW"
        errors=self.validate(advisory)
        self.assertTrue(any("CVSS baseSeverity contradicts baseScore" in e for e in errors))

    def test_current_epss_observation_must_identify_v5(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["epss"]["model"]="EPSS-v4"
        errors=self.validate(advisory)
        self.assertTrue(any("must identify EPSS-v5" in e for e in errors))

    def test_epss_probability_is_bounded(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["epss"]["probability"]=1.2
        errors=self.validate(advisory)
        self.assertTrue(any("EPSS probability must be 0..1" in e for e in errors))

    def test_listed_kev_requires_date_added(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["kev"]["status"]="listed"
        errors=self.validate(advisory)
        self.assertTrue(any("listed KEV observation requires date_added" in e for e in errors))

    def test_synthetic_combined_score_is_prohibited(self) -> None:
        advisory=self.advisory()
        advisory["vulnerabilities"][0]["priority"]["combined_score"]=9.9
        errors=self.validate(advisory)
        self.assertTrue(any("synthetic combined risk score is prohibited" in e for e in errors))

    def test_revision_history_must_bind_current_release(self) -> None:
        advisory=self.advisory()
        advisory["revision_history"][0]["date"]="2026-10-11T12:59:00Z"
        errors=self.validate(advisory)
        self.assertTrue(any("latest date must equal current_release_at" in e for e in errors))

    def test_csaf_20_export_preserves_scope_without_cvss_downconversion(self) -> None:
        advisory=self.advisory()
        doc=advisory_interoperability.export_csaf(
            advisory,"advisory-csaf-2-0-iso20153@0.1.0",
            self.registry(),self.catalog()
        )
        self.assertEqual(doc["document"]["csaf_version"],"2.0")
        self.assertEqual(
            doc["$schema"],
            "https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json"
        )
        helper=doc["product_tree"]["full_product_names"][0]["product_identification_helper"]
        self.assertIn("purl",helper)
        self.assertNotIn("purls",helper)
        vuln=doc["vulnerabilities"][0]
        self.assertNotIn("scores",vuln)
        self.assertNotIn("metrics",vuln)
        self.assertIn("cwe",vuln)
        self.assertEqual(
            advisory_interoperability.validate_export_scope(
                doc,advisory,"advisory-csaf-2-0-iso20153@0.1.0",self.registry()
            ),[]
        )

    def test_csaf_21_export_carries_native_cvss_v4_and_epss(self) -> None:
        advisory=self.advisory()
        doc=advisory_interoperability.export_csaf(
            advisory,"advisory-csaf-2-1-csd03@0.1.0",
            self.registry(),self.catalog()
        )
        self.assertEqual(doc["document"]["csaf_version"],"2.1")
        helper=doc["product_tree"]["full_product_names"][0]["product_identification_helper"]
        self.assertIn("purls",helper)
        self.assertNotIn("purl",helper)
        vuln=doc["vulnerabilities"][0]
        self.assertIn("cwes",vuln)
        contents=[metric["content"] for metric in vuln["metrics"]]
        self.assertTrue(any("cvss_v4" in content for content in contents))
        self.assertTrue(any("epss" in content for content in contents))
        self.assertEqual(
            advisory_interoperability.validate_export_scope(
                doc,advisory,"advisory-csaf-2-1-csd03@0.1.0",self.registry()
            ),[]
        )

    def test_csaf_export_scope_tamper_fails(self) -> None:
        advisory=self.advisory()
        doc=advisory_interoperability.export_csaf(
            advisory,"advisory-csaf-2-1-csd03@0.1.0",
            self.registry(),self.catalog()
        )
        doc["vulnerabilities"][0]["product_status"]["known_affected"]=[]
        errors=advisory_interoperability.validate_export_scope(
            doc,advisory,"advisory-csaf-2-1-csd03@0.1.0",self.registry()
        )
        self.assertTrue(any("product status known_affected differs" in e for e in errors))

    def test_csaf_remediation_scope_tamper_fails(self) -> None:
        advisory=self.advisory()
        doc=advisory_interoperability.export_csaf(
            advisory,"advisory-csaf-2-0-iso20153@0.1.0",
            self.registry(),self.catalog()
        )
        doc["vulnerabilities"][0]["remediations"][0]["product_ids"]=[
            "CSAFPID-EXAMPLE-101"
        ]
        errors=advisory_interoperability.validate_export_scope(
            doc,advisory,"advisory-csaf-2-0-iso20153@0.1.0",self.registry()
        )
        self.assertTrue(any("remediation scope differs" in e for e in errors))

    def test_external_csaf_validation_result_binds_exact_document(self) -> None:
        advisory=self.advisory()
        doc=advisory_interoperability.export_csaf(
            advisory,"advisory-csaf-2-0-iso20153@0.1.0",
            self.registry(),self.catalog()
        )
        result=self.load("fixtures/advisory-interoperability/valid/csaf-validation-result.json")
        result["document_digest"]=advisory_interoperability.canonical_digest(doc)
        errors=advisory_interoperability.validate_external_csaf_result(
            doc,"advisory-csaf-2-0-iso20153@0.1.0",result,self.registry()
        )
        self.assertEqual(errors,[])
        self.assertTrue(advisory_interoperability.csaf_validated(
            doc,"advisory-csaf-2-0-iso20153@0.1.0",result,self.registry()
        ))

    def test_external_validator_errors_prevent_validated_claim(self) -> None:
        advisory=self.advisory()
        doc=advisory_interoperability.export_csaf(
            advisory,"advisory-csaf-2-0-iso20153@0.1.0",
            self.registry(),self.catalog()
        )
        result=self.load("fixtures/advisory-interoperability/valid/csaf-validation-result.json")
        result["document_digest"]=advisory_interoperability.canonical_digest(doc)
        result["errors"]=["mandatory CSAF test failed"]
        errors=advisory_interoperability.validate_external_csaf_result(
            doc,"advisory-csaf-2-0-iso20153@0.1.0",result,self.registry()
        )
        self.assertTrue(any("validator reported errors" in e for e in errors))
        self.assertFalse(advisory_interoperability.csaf_validated(
            doc,"advisory-csaf-2-0-iso20153@0.1.0",result,self.registry()
        ))

    def test_external_validation_digest_substitution_fails(self) -> None:
        advisory=self.advisory()
        doc=advisory_interoperability.export_csaf(
            advisory,"advisory-csaf-2-0-iso20153@0.1.0",
            self.registry(),self.catalog()
        )
        result=self.load("fixtures/advisory-interoperability/valid/csaf-validation-result.json")
        result["document_digest"]="sha256:"+"9"*64
        errors=advisory_interoperability.validate_external_csaf_result(
            doc,"advisory-csaf-2-0-iso20153@0.1.0",result,self.registry()
        )
        self.assertTrue(any("document_digest mismatch" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
