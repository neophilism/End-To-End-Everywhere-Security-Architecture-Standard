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

import conformance_engine  # noqa: E402
import deprecation_migration  # noqa: E402
import formal_verification  # noqa: E402


class ConformanceEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def inputs(self) -> dict[str, dict]:
        return {
            "conformance_registry":self.load("registry/conformance.json"),
            "catalog":self.load("fixtures/profiles/development-catalog.json"),
            "crypto":self.load("registry/cryptographic-algorithms.json"),
            "property_registry":self.load("registry/security-properties.json"),
            "threat_registry":self.load("registry/threat-model.json"),
            "assurance_registry":self.load("registry/assurance-levels.json"),
            "certification_registry":self.load("registry/certification-evidence.json"),
            "promotion_registry":self.load("registry/research-promotion.json"),
            "migration_registry":self.load("registry/deprecation-migration.json"),
        }

    def prepare(
        self,
        *,
        plan: dict | None=None,
        bundle: dict | None=None,
        request: dict | None=None,
        inputs: dict[str,dict] | None=None,
    ):
        inputs=copy.deepcopy(inputs or self.inputs())
        plan=copy.deepcopy(
            plan or self.load("fixtures/conformance/valid/production-assurance-plan.json")
        )
        bundle=copy.deepcopy(
            bundle or self.load("fixtures/conformance/valid/production-certification-bundle.json")
        )
        request=copy.deepcopy(
            request or self.load("fixtures/conformance/valid/production-request.json")
        )

        bundle["assurance_plan_digest"]=formal_verification.canonical_digest(plan)
        bundle["configuration_digest"]=formal_verification.canonical_digest(
            plan["configuration"]
        )
        request["assurance_plan_digest"]=formal_verification.canonical_digest(plan)
        request["certification_bundle_digest"]=conformance_engine.canonical_digest(bundle)
        request["configuration_digest"]=formal_verification.canonical_digest(
            plan["configuration"]
        )
        request["source_digest"]=bundle["source_digest"]
        request["artifact_digest"]=bundle["artifact_digest"]
        request["standard_version"]=inputs["catalog"]["standard_version"]
        request["input_digests"]=conformance_engine.evaluation_input_digests(**inputs)
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        return request,plan,bundle,inputs

    def evaluate(
        self,
        request: dict,
        plan: dict,
        bundle: dict,
        inputs: dict[str,dict],
        *,
        migration_plan: dict | None=None,
        migration_case: dict | None=None,
    ):
        return conformance_engine.evaluate_conformance(
            request,
            plan,
            bundle,
            **inputs,
            migration_plan=migration_plan,
            migration_case=migration_case,
        )

    def add_promotion_state(
        self,
        inputs: dict[str,dict],
        profile_ref: str,
        lifecycle_state: str,
        gate_profile_ref: str,
    ) -> None:
        inputs["promotion_registry"]["promoted_profiles"].append({
            "profile_ref":profile_ref,
            "research_entry_digest":"sha256:"+"1"*64,
            "lifecycle_state":lifecycle_state,
            "promotion_record_digest":"sha256:"+"2"*64,
            "effective_at":"2026-10-08T01:00:00Z",
            "gate_profile_ref":gate_profile_ref,
        })
        inputs["promotion_registry"]["promoted_profiles"].sort(
            key=lambda item:item["profile_ref"]
        )

    def candidate(self):
        request,plan,bundle,inputs=self.prepare()
        old="example-choice-b@0.1.0"
        new="example-choice-a@0.2.0"
        plan["configuration"]["selected_profiles"]=[
            new if ref==old else ref
            for ref in plan["configuration"]["selected_profiles"]
        ]
        plan["configuration"]["accepted_nondefault_statuses"]=["provisional"]
        if "SP-KEY-CONSISTENCY" not in plan["claimed_property_ids"]:
            plan["claimed_property_ids"].append("SP-KEY-CONSISTENCY")
            plan["claimed_property_ids"].sort()

        bundle["effective_profile_refs"]=[
            new if ref==old else ref
            for ref in bundle["effective_profile_refs"]
        ]
        bundle["effective_profile_refs"].sort()
        for item in bundle["evidence_items"]:
            if "SP-KEY-CONSISTENCY" not in item["property_ids"]:
                item["property_ids"].append("SP-KEY-CONSISTENCY")
                item["property_ids"].sort()
        bundle["claim_evidence"].append({
            "property_id":"SP-KEY-CONSISTENCY",
            "threat_ids":["TM-DIRECTORY"],
            "evidence_ids":[
                "evidence-04-verification-evidence",
                "evidence-05-independent-audit-report",
                "evidence-16-formal-evidence",
            ],
            "status":"supported",
            "limitations":["Example Candidate fixture only."],
        })
        bundle["claim_evidence"].sort(key=lambda item:item["property_id"])

        self.add_promotion_state(
            inputs,new,"candidate","promotion-candidate-baseline@0.1.0"
        )
        request["conformance_policy_ref"]="conformance-candidate-evaluation@0.1.0"
        request["assessment_id"]="example-candidate-evaluation"
        return self.prepare(plan=plan,bundle=bundle,request=request,inputs=inputs)

    def migration(self):
        request,plan,bundle,inputs=self.prepare()
        migration_plan=self.load(
            "fixtures/deprecation-migration/valid/emergency-plan.json"
        )
        migration_plan["plan_digest"]=deprecation_migration.compute_plan_digest(
            migration_plan
        )
        migration_case=self.load(
            "fixtures/deprecation-migration/valid/emergency-case.json"
        )
        migration_case["plan_digest"]=migration_plan["plan_digest"]
        migration_case["case_digest"]=deprecation_migration.compute_case_digest(
            migration_case
        )
        request["conformance_policy_ref"]="conformance-migration-only@0.1.0"
        request["assessment_id"]="example-migration-only-evaluation"
        request["evaluated_at"]="2026-10-20T00:00:00Z"
        request["migration_context"]={
            "plan_digest":migration_plan["plan_digest"],
            "case_digest":migration_case["case_digest"],
            "operation":"historical-read-verify",
            "material_created_at":"2026-10-01T00:00:00Z",
            "usage_evidence_digest":"sha256:"+"3"*64,
            "usage_reference":"https://example.org/product/evidence/aes128-historical-use",
        }
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        return request,plan,bundle,inputs,migration_plan,migration_case

    def test_conformance_registry_is_valid(self) -> None:
        inputs=self.inputs()
        self.assertEqual(
            conformance_engine.validate_registry(
                inputs["conformance_registry"],inputs["catalog"]
            ),[]
        )

    def test_full_coverage_production_conformance_passes(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"pass",result["reasons"])
        self.assertFalse(result["production_certification_eligible"])
        self.assertEqual(
            set(result["required_property_ids"]),
            {
                "SP-BUILD-PROVENANCE","SP-CONFIDENTIALITY",
                "SP-DOWNGRADE-RESISTANCE","SP-INTEGRITY",
                "SP-SOFTWARE-INTEGRITY",
            },
        )
        self.assertEqual(
            result["result_digest"],
            conformance_engine.compute_result_digest(result),
        )

    def test_result_is_deterministic(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        first=self.evaluate(request,plan,bundle,inputs)
        second=self.evaluate(
            copy.deepcopy(request),copy.deepcopy(plan),copy.deepcopy(bundle),
            copy.deepcopy(inputs),
        )
        self.assertEqual(first,second)

    def test_result_tamper_is_detected(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        expected=self.evaluate(request,plan,bundle,inputs)
        tampered=copy.deepcopy(expected)
        tampered["verdict"]="fail"
        errors=conformance_engine.validate_result(tampered,expected)
        self.assertTrue(any("result_digest" in e for e in errors))
        self.assertTrue(any("differs from deterministic" in e for e in errors))

    def test_request_digest_tamper_fails(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        request["request_digest"]="sha256:"+"9"*64
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="request-digest-mismatch"
            for reason in result["reasons"]
        ))

    def test_registry_substitution_fails_exact_digest_binding(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        inputs["conformance_registry"]["registry_version"]="0.1.1"
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="evaluation-basis-digest-mismatch"
            and "conformance_registry" in reason["message"]
            for reason in result["reasons"]
        ))

    def test_product_identity_substitution_fails(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        request["product_version"]="2.0.0"
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="product-identity-mismatch"
            for reason in result["reasons"]
        ))

    def test_artifact_identity_substitution_fails(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        request["artifact_digest"]="sha256:"+"9"*64
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="artifact-identity-mismatch"
            for reason in result["reasons"]
        ))

    def test_configuration_digest_substitution_fails(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        request["configuration_digest"]="sha256:"+"9"*64
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="configuration-digest-mismatch"
            for reason in result["reasons"]
        ))

    def test_future_certification_bundle_fails(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        request["evaluated_at"]="2026-10-07T19:59:59Z"
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="future-certification-evidence"
            for reason in result["reasons"]
        ))

    def test_family_scope_must_cover_every_catalog_family(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        request["family_scope"]=request["family_scope"][:-1]
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="family-scope-incomplete"
            for reason in result["reasons"]
        ))

    def test_selected_profile_family_cannot_be_not_applicable(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        entry=next(
            item for item in request["family_scope"]
            if item["family_id"]=="example-architecture"
        )
        entry["applicability"]="not-applicable"
        entry["rationale"]="Invalid adversarial test."
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="effective-profile-family-out-of-scope"
            for reason in result["reasons"]
        ))

    def test_in_scope_family_must_have_effective_profile(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        entry=next(
            item for item in request["family_scope"]
            if item["family_id"]=="key-verification"
        )
        entry["applicability"]="in-scope"
        entry["rationale"]=None
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="in-scope-family-unimplemented"
            and "key-verification" in reason["message"]
            for reason in result["reasons"]
        ))

    def test_exactly_one_family_cannot_be_declared_not_applicable(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        foundation=next(
            item for item in request["family_scope"]
            if item["family_id"]=="foundation"
        )
        foundation["applicability"]="not-applicable"
        foundation["rationale"]="Invalid adversarial test."
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="mandatory-family-out-of-scope"
            for reason in result["reasons"]
        ))

    def test_production_configuration_cannot_accept_nondefault_statuses(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        plan["configuration"]["accepted_nondefault_statuses"]=["provisional"]
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="nondefault-status-acceptance-not-permitted"
            for reason in result["reasons"]
        ))

    def test_promised_property_must_be_in_assurance_claims(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        plan["claimed_property_ids"].remove("SP-BUILD-PROVENANCE")
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="promised-property-not-assessed"
            for reason in result["reasons"]
        ))

    def test_conditional_required_property_is_indeterminate(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        record=next(
            item for item in bundle["claim_evidence"]
            if item["property_id"]=="SP-INTEGRITY"
        )
        record["status"]="conditional"
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"indeterminate",result["reasons"])
        self.assertFalse(result["production_certification_eligible"])
        self.assertEqual(result["conditional_property_ids"],["SP-INTEGRITY"])

    def test_not_supported_required_property_fails(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        record=next(
            item for item in bundle["claim_evidence"]
            if item["property_id"]=="SP-INTEGRITY"
        )
        record["status"]="not-supported"
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertIn("SP-INTEGRITY",result["not_supported_property_ids"])

    def test_required_promoted_profile_is_enforced_when_family_in_scope(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        self.add_promotion_state(
            inputs,
            "example-choice-a@0.1.0",
            "required",
            "promotion-required-operational-maturity@0.1.0",
        )
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="required-profile-not-selected"
            for reason in result["reasons"]
        ))

    def test_required_profile_does_not_force_not_applicable_family_into_scope(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        self.add_promotion_state(
            inputs,
            "verify-account-root@0.1.0",
            "required",
            "promotion-required-operational-maturity@0.1.0",
        )
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"pass",result["reasons"])
        self.assertIn(
            "verify-account-root@0.1.0",
            result["required_promoted_profile_refs"],
        )

    def test_candidate_evaluation_passes_but_is_not_production_certification(self) -> None:
        request,plan,bundle,inputs=self.candidate()
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"pass",result["reasons"])
        self.assertEqual(result["claim_scope"],"candidate-evaluation")
        self.assertFalse(result["production_certification_eligible"])

    def test_unpromoted_provisional_profile_cannot_use_candidate_policy(self) -> None:
        request,plan,bundle,inputs=self.candidate()
        inputs["promotion_registry"]["promoted_profiles"]=[]
        request,plan,bundle,inputs=self.prepare(
            plan=plan,bundle=bundle,request=request,inputs=inputs
        )
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="provisional-profile-not-candidate"
            for reason in result["reasons"]
        ))

    def test_candidate_configuration_cannot_claim_production_conformance(self) -> None:
        request,plan,bundle,inputs=self.candidate()
        request["conformance_policy_ref"]="conformance-production@0.1.0"
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        codes={reason["code"] for reason in result["reasons"]}
        self.assertIn("profile-status-not-permitted",codes)
        self.assertIn("nondefault-status-acceptance-not-permitted",codes)

    def test_migration_only_historical_operation_passes_without_production_label(self) -> None:
        request,plan,bundle,inputs,migration_plan,migration_case=self.migration()
        result=self.evaluate(
            request,plan,bundle,inputs,
            migration_plan=migration_plan,migration_case=migration_case
        )
        self.assertEqual(result["verdict"],"pass",result["reasons"])
        self.assertEqual(result["claim_scope"],"migration-only")
        self.assertFalse(result["production_certification_eligible"])

    def test_migration_operation_after_legacy_deadline_fails(self) -> None:
        request,plan,bundle,inputs,migration_plan,migration_case=self.migration()
        request["evaluated_at"]="2026-11-09T00:00:00Z"
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(
            request,plan,bundle,inputs,
            migration_plan=migration_plan,migration_case=migration_case
        )
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="migration-operation-not-allowed"
            for reason in result["reasons"]
        ))

    def test_migration_context_digest_substitution_fails(self) -> None:
        request,plan,bundle,inputs,migration_plan,migration_case=self.migration()
        request["migration_context"]["plan_digest"]="sha256:"+"9"*64
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(
            request,plan,bundle,inputs,
            migration_plan=migration_plan,migration_case=migration_case
        )
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="migration-plan-digest-mismatch"
            for reason in result["reasons"]
        ))

    def test_production_conformance_rejects_migration_context(self) -> None:
        request,plan,bundle,inputs,migration_plan,migration_case=self.migration()
        request["conformance_policy_ref"]="conformance-production@0.1.0"
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(
            request,plan,bundle,inputs,
            migration_plan=migration_plan,migration_case=migration_case
        )
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="migration-context-not-permitted"
            for reason in result["reasons"]
        ))

    def test_missing_migration_context_fails_migration_policy(self) -> None:
        request,plan,bundle,inputs=self.prepare()
        request["conformance_policy_ref"]="conformance-migration-only@0.1.0"
        request["request_digest"]=conformance_engine.compute_request_digest(request)
        result=self.evaluate(request,plan,bundle,inputs)
        self.assertEqual(result["verdict"],"fail")
        self.assertTrue(any(
            reason["code"]=="migration-context-required"
            for reason in result["reasons"]
        ))


if __name__ == "__main__":
    unittest.main()
