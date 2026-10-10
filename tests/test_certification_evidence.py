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

import certification_evidence  # noqa: E402
import formal_verification  # noqa: E402


class CertificationEvidenceTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def plan(self) -> dict:
        return self.load("fixtures/assurance/valid/a3-plan.json")

    def registry(self) -> dict:
        return self.load("registry/certification-evidence.json")

    def assurance_registry(self) -> dict:
        return self.load("registry/assurance-levels.json")

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def property_ids(self) -> set[str]:
        return {x["id"] for x in self.load("registry/security-properties.json")["properties"]}

    def threat_ids(self) -> set[str]:
        return {x["id"] for x in self.load("registry/threat-model.json")["threats"]}

    def bundle(self, plan: dict | None = None) -> dict:
        plan = plan or self.plan()
        bundle = self.load("fixtures/certification-evidence/valid/a3-bundle.json")
        bundle["assurance_plan_digest"] = formal_verification.canonical_digest(plan)
        bundle["configuration_digest"] = formal_verification.canonical_digest(plan["configuration"])
        return bundle

    def validate(self, bundle: dict, plan: dict | None = None) -> list[str]:
        plan = plan or self.plan()
        return certification_evidence.validate_bundle(
            bundle,
            plan,
            self.registry(),
            self.assurance_registry(),
            self.catalog(),
            self.property_ids(),
            self.threat_ids(),
        )

    def test_registry_is_valid_and_monotonic(self) -> None:
        self.assertEqual(
            certification_evidence.validate_registry(
                self.registry(), self.assurance_registry()
            ),
            [],
        )

    def test_complete_a3_bundle_is_valid(self) -> None:
        plan = self.plan()
        self.assertEqual(self.validate(self.bundle(plan), plan), [])

    def test_plan_digest_mismatch_fails(self) -> None:
        bundle = self.bundle()
        bundle["assurance_plan_digest"] = "sha256:" + "9" * 64
        errors = self.validate(bundle)
        self.assertTrue(any("assurance_plan_digest mismatch" in e for e in errors))

    def test_effective_profile_substitution_fails(self) -> None:
        bundle = self.bundle()
        bundle["effective_profile_refs"] = [
            x for x in bundle["effective_profile_refs"]
            if x != "formal-symbolic-protocol@0.1.0"
        ]
        errors = self.validate(bundle)
        self.assertTrue(any("effective_profile_refs do not match" in e for e in errors))

    def test_missing_required_evidence_type_fails(self) -> None:
        bundle = self.bundle()
        bundle["evidence_items"] = [
            x for x in bundle["evidence_items"] if x["evidence_type"] != "sbom"
        ]
        errors = self.validate(bundle)
        self.assertTrue(any("missing required evidence types" in e and "sbom" in e for e in errors))

    def test_a3_requires_source_review_access(self) -> None:
        bundle = self.bundle()
        bundle["source_access"] = "none"
        errors = self.validate(bundle)
        self.assertTrue(any("below assurance minimum" in e for e in errors))

    def test_independent_evidence_cannot_be_vendor_issued(self) -> None:
        bundle = self.bundle()
        item = next(x for x in bundle["evidence_items"] if x["evidence_type"] == "independent-audit-report")
        item["issuer_role"] = "vendor"
        errors = self.validate(bundle)
        self.assertTrue(any("requires independent-assessor issuer role" in e for e in errors))

    def test_all_plan_assessors_need_independent_evidence_coverage(self) -> None:
        plan = self.plan()
        plan["independent_assessor_ids"] = ["independent-assessor-one", "independent-assessor-two"]
        bundle = self.bundle(plan)
        errors = self.validate(bundle, plan)
        self.assertTrue(any("lacks independent evidence from assessors" in e for e in errors))

    def test_missing_formal_evidence_linkage_fails(self) -> None:
        bundle = self.bundle()
        bundle["evidence_items"] = [
            x for x in bundle["evidence_items"] if x["evidence_type"] != "formal-evidence"
        ]
        errors = self.validate(bundle)
        self.assertTrue(any("missing formal-evidence linkage" in e for e in errors))

    def test_claim_requires_property_scoped_evidence(self) -> None:
        bundle = self.bundle()
        ids = set(bundle["claim_evidence"][0]["evidence_ids"])
        for item in bundle["evidence_items"]:
            if item["evidence_id"] in ids:
                item["property_ids"] = []
        errors = self.validate(bundle)
        self.assertTrue(any("no referenced evidence item scoped to property" in e for e in errors))

    def test_claim_unknown_evidence_reference_fails(self) -> None:
        bundle = self.bundle()
        bundle["claim_evidence"][0]["evidence_ids"].append("missing-evidence")
        errors = self.validate(bundle)
        self.assertTrue(any("references unknown evidence_ids" in e for e in errors))

    def test_future_dated_evidence_fails(self) -> None:
        bundle = self.bundle()
        bundle["evidence_items"][0]["observed_at"] = "2026-10-08T20:00:00Z"
        errors = self.validate(bundle)
        self.assertTrue(any("future-dated relative to bundle" in e for e in errors))

    def test_must_waiver_is_not_representable(self) -> None:
        bundle = self.bundle()
        bundle["exceptions"] = [{
            "exception_id": "bad-must-waiver",
            "exception_class": "should-deviation",
            "requirement_ref": "example-MUST-rule",
            "requirement_strength": "MUST",
            "rationale": "invalid example",
            "security_consequence": "invalid example",
            "approving_authority": "example",
            "issued_at": "2026-10-07T18:00:00Z",
            "expires_at": "2026-10-08T18:00:00Z",
            "remediation_plan": "invalid example"
        }]
        errors = self.validate(bundle)
        self.assertTrue(any("cannot waive MUST/MUST-NOT" in e for e in errors))

    def test_expired_exception_fails(self) -> None:
        bundle = self.bundle()
        bundle["exceptions"] = [{
            "exception_id": "expired-example",
            "exception_class": "profile-limitation",
            "requirement_ref": "example-profile-limit",
            "requirement_strength": "PROFILE-LIMITATION",
            "rationale": "example",
            "security_consequence": "example",
            "approving_authority": "example",
            "issued_at": "2026-10-05T18:00:00Z",
            "expires_at": "2026-10-06T18:00:00Z",
            "remediation_plan": "example"
        }]
        errors = self.validate(bundle)
        self.assertTrue(any("expired at bundle observation time" in e for e in errors))

    def test_valid_exception_requires_exception_record_evidence(self) -> None:
        bundle = self.bundle()
        bundle["exceptions"] = [{
            "exception_id": "valid-example",
            "exception_class": "profile-limitation",
            "requirement_ref": "example-profile-limit",
            "requirement_strength": "PROFILE-LIMITATION",
            "rationale": "example",
            "security_consequence": "claim is narrowed",
            "approving_authority": "example-review-board",
            "issued_at": "2026-10-07T18:00:00Z",
            "expires_at": "2026-10-08T18:00:00Z",
            "remediation_plan": "remove the limitation before renewal"
        }]
        errors = self.validate(bundle)
        self.assertTrue(any("requires an exception-record evidence item" in e for e in errors))

    def test_unknown_evidence_type_fails(self) -> None:
        bundle = self.bundle()
        bundle["evidence_items"][0]["evidence_type"] = "mystery-evidence"
        errors = self.validate(bundle)
        self.assertTrue(any("unknown evidence_type" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
