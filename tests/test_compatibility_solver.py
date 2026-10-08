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

import compatibility_solver  # noqa: E402
import profile_engine  # noqa: E402


class CompatibilitySolverTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def properties(self) -> dict:
        return self.load("registry/security-properties.json")

    def promotions(self) -> dict:
        return self.load("registry/research-promotion.json")

    def conformance(self) -> dict:
        return self.load("registry/conformance.json")

    def registry(self) -> dict:
        return self.load("registry/compatibility-solver.json")

    def request(self) -> dict:
        request=self.load(
            "fixtures/compatibility-solver/valid/identity-options-request.json"
        )
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        return request

    def solve(
        self,
        request: dict | None=None,
        *,
        registry: dict | None=None,
        catalog: dict | None=None,
        promotions: dict | None=None,
    ) -> dict:
        return compatibility_solver.solve(
            request or self.request(),
            solver_registry=registry or self.registry(),
            catalog=catalog or self.catalog(),
            property_registry=self.properties(),
            promotion_registry=promotions or self.promotions(),
            conformance_registry=self.conformance(),
        )

    def add_promotion(
        self,
        registry: dict,
        *,
        profile_ref: str,
        state: str,
        gate_profile_ref: str,
        suffix: str,
    ) -> None:
        registry["promoted_profiles"].append({
            "profile_ref":profile_ref,
            "research_entry_digest":"sha256:"+suffix*64,
            "lifecycle_state":state,
            "promotion_record_digest":"sha256:"+("f" if suffix!="f" else "e")*64,
            "effective_at":"2026-10-08T01:00:00Z",
            "gate_profile_ref":gate_profile_ref,
        })

    def test_registry_is_valid(self) -> None:
        self.assertEqual(
            compatibility_solver.validate_registry(self.registry()),[]
        )

    def test_identity_request_returns_all_three_serious_options(self) -> None:
        result=self.solve()
        self.assertEqual(result["status"],"solutions",result["diagnostics"])
        self.assertTrue(result["search_exhaustive"])
        self.assertEqual(result["total_solution_count"],3)
        self.assertEqual(result["returned_solution_count"],3)
        self.assertFalse(result["truncated"])

        identity_refs=set()
        for solution in result["solutions"]:
            refs=set(solution["effective_profile_refs"])
            self.assertIn("foundation-baseline@0.1.0",refs)
            self.assertIn("example-choice-b@0.1.0",refs)
            selected=[
                ref for ref in refs
                if ref.startswith("identity-")
            ]
            self.assertEqual(len(selected),1)
            identity_refs.add(selected[0])
            self.assertNotIn("verdict",solution)
            self.assertNotIn("production_certification_eligible",solution)

        self.assertEqual(identity_refs,{
            "identity-account-root@0.1.0",
            "identity-device-cross-signing@0.1.0",
            "identity-threshold-quorum@0.1.0",
        })

    def test_every_solution_resolves_through_pr2(self) -> None:
        result=self.solve()
        property_ids={
            item["id"] for item in self.properties()["properties"]
        }
        for solution in result["solutions"]:
            resolved=profile_engine.resolve_configuration(
                self.catalog(),
                solution["configuration"],
                known_property_ids=property_ids,
            )
            self.assertTrue(resolved.valid,resolved.errors)
            self.assertEqual(
                sorted(resolved.effective_profiles),
                solution["effective_profile_refs"],
            )

    def test_solution_order_and_result_are_deterministic(self) -> None:
        first=self.solve()
        second=self.solve()
        self.assertEqual(first,second)
        keys=[
            tuple(solution["effective_profile_refs"])
            for solution in first["solutions"]
        ]
        self.assertEqual(keys,sorted(keys))
        self.assertEqual(
            first["result_digest"],
            compatibility_solver.compute_result_digest(first),
        )

    def test_return_limit_does_not_hide_complete_solution_count(self) -> None:
        request=self.request()
        request["max_solutions"]=2
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"solutions")
        self.assertTrue(result["search_exhaustive"])
        self.assertEqual(result["total_solution_count"],3)
        self.assertEqual(result["returned_solution_count"],2)
        self.assertTrue(result["truncated"])

    def test_pinning_identity_profile_reduces_to_exact_solution(self) -> None:
        request=self.request()
        request["pinned_profile_refs"].append("identity-account-root@0.1.0")
        request["pinned_profile_refs"].sort()
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"solutions",result["diagnostics"])
        self.assertEqual(result["total_solution_count"],1)
        self.assertIn(
            "identity-account-root@0.1.0",
            result["solutions"][0]["effective_profile_refs"],
        )

    def test_exclusion_removes_option_without_ranking_remaining_options(self) -> None:
        request=self.request()
        request["excluded_profile_refs"]=["identity-threshold-quorum@0.1.0"]
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["total_solution_count"],2)
        for solution in result["solutions"]:
            self.assertNotIn(
                "identity-threshold-quorum@0.1.0",
                solution["effective_profile_refs"],
            )

    def test_pin_exclusion_collision_is_invalid_request(self) -> None:
        request=self.request()
        request["excluded_profile_refs"]=["example-choice-b@0.1.0"]
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"invalid-request")
        self.assertTrue(any(
            "both pinned and excluded" in item["message"]
            for item in result["diagnostics"]
        ))

    def test_exactly_one_family_cannot_be_forbidden(self) -> None:
        request=self.request()
        request["forbidden_family_ids"]=["foundation"]
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"invalid-request")
        self.assertTrue(any(
            "exactly-one family cannot be forbidden" in item["message"]
            for item in result["diagnostics"]
        ))

    def test_unknown_desired_property_is_invalid_request(self) -> None:
        request=self.request()
        request["desired_property_ids"]=["SP-NOT-REGISTERED"]
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"invalid-request")
        self.assertTrue(any(
            "unknown desired properties" in item["message"]
            for item in result["diagnostics"]
        ))

    def test_desired_property_is_covered_by_effective_architecture(self) -> None:
        request=self.request()
        request["desired_property_ids"]=["SP-PEER-AUTHENTICATION"]
        request["max_solutions"]=500
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertIn(result["status"],{"solutions","search-limit"})
        self.assertGreater(result["returned_solution_count"],0)
        for solution in result["solutions"]:
            self.assertIn(
                "SP-PEER-AUTHENTICATION",
                solution["effective_property_ids"],
            )

    def test_production_mode_rejects_provisional_pin(self) -> None:
        request=self.request()
        request["pinned_profile_refs"]=["example-choice-a@0.2.0"]
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"invalid-request")
        self.assertTrue(any(
            "not eligible in production mode" in item["message"]
            for item in result["diagnostics"]
        ))

    def test_candidate_mode_allows_exact_pr38_candidate_only(self) -> None:
        request=self.request()
        request["mode"]="candidate"
        request["pinned_profile_refs"]=["example-choice-a@0.2.0"]
        promotions=self.promotions()
        self.add_promotion(
            promotions,
            profile_ref="example-choice-a@0.2.0",
            state="candidate",
            gate_profile_ref="promotion-candidate-baseline@0.1.0",
            suffix="a",
        )
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request,promotions=promotions)
        self.assertEqual(result["status"],"solutions",result["diagnostics"])
        self.assertEqual(result["total_solution_count"],3)
        for solution in result["solutions"]:
            self.assertIn(
                "example-choice-a@0.2.0",
                solution["effective_profile_refs"],
            )
            self.assertEqual(
                solution["configuration"]["accepted_nondefault_statuses"],
                ["provisional"],
            )

    def test_candidate_mode_rejects_unpromoted_provisional_pin(self) -> None:
        request=self.request()
        request["mode"]="candidate"
        request["pinned_profile_refs"]=["example-choice-a@0.2.0"]
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"invalid-request")
        self.assertTrue(any(
            "not eligible in candidate mode" in item["message"]
            for item in result["diagnostics"]
        ))

    def test_required_promotion_for_in_scope_family_is_enforced(self) -> None:
        request=self.request()
        promotions=self.promotions()
        self.add_promotion(
            promotions,
            profile_ref="identity-threshold-quorum@0.1.0",
            state="required",
            gate_profile_ref="promotion-required-operational-maturity@0.1.0",
            suffix="b",
        )
        result=self.solve(request,promotions=promotions)
        self.assertEqual(result["status"],"solutions",result["diagnostics"])
        self.assertEqual(result["total_solution_count"],1)
        self.assertIn(
            "identity-threshold-quorum@0.1.0",
            result["solutions"][0]["effective_profile_refs"],
        )

    def test_excluded_required_promotion_makes_request_unsatisfiable(self) -> None:
        request=self.request()
        request["excluded_profile_refs"]=["identity-threshold-quorum@0.1.0"]
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        promotions=self.promotions()
        self.add_promotion(
            promotions,
            profile_ref="identity-threshold-quorum@0.1.0",
            state="required",
            gate_profile_ref="promotion-required-operational-maturity@0.1.0",
            suffix="c",
        )
        result=self.solve(request,promotions=promotions)
        self.assertEqual(result["status"],"unsatisfiable")
        self.assertTrue(result["search_exhaustive"])
        self.assertEqual(result["total_solution_count"],0)

    def test_required_profile_in_out_of_scope_family_is_not_forced(self) -> None:
        request=self.request()
        promotions=self.promotions()
        self.add_promotion(
            promotions,
            profile_ref="pairwise-x3dh-double-ratchet@0.1.0",
            state="required",
            gate_profile_ref="promotion-required-operational-maturity@0.1.0",
            suffix="d",
        )
        result=self.solve(request,promotions=promotions)
        self.assertEqual(result["status"],"solutions",result["diagnostics"])
        self.assertEqual(result["total_solution_count"],3)
        for solution in result["solutions"]:
            self.assertNotIn(
                "pairwise-x3dh-double-ratchet@0.1.0",
                solution["effective_profile_refs"],
            )

    def test_disabling_required_promotion_enforcement_preserves_options(self) -> None:
        request=self.request()
        request["enforce_required_promotions"]=False
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        promotions=self.promotions()
        self.add_promotion(
            promotions,
            profile_ref="identity-threshold-quorum@0.1.0",
            state="required",
            gate_profile_ref="promotion-required-operational-maturity@0.1.0",
            suffix="e",
        )
        result=self.solve(request,promotions=promotions)
        self.assertEqual(result["total_solution_count"],3)

    def test_search_budget_exhaustion_is_explicit(self) -> None:
        registry=self.registry()
        registry["maximum_search_states"]=1
        result=self.solve(registry=registry)
        self.assertEqual(result["status"],"search-limit")
        self.assertFalse(result["search_exhaustive"])
        self.assertIsNone(result["total_solution_count"])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["search_states_examined"],1)

    def test_migration_mode_allows_legacy_but_production_does_not(self) -> None:
        catalog=self.catalog()
        target=next(
            item for item in catalog["profiles"]
            if item["profile_id"]=="example-choice-b"
            and item["profile_version"]=="0.1.0"
        )
        target["status"]="legacy"

        production=self.request()
        production_result=self.solve(production,catalog=catalog)
        self.assertEqual(production_result["status"],"invalid-request")

        migration=self.request()
        migration["mode"]="migration"
        migration["request_digest"]=compatibility_solver.compute_request_digest(migration)
        migration_result=self.solve(migration,catalog=catalog)
        self.assertEqual(migration_result["status"],"solutions",migration_result["diagnostics"])
        for solution in migration_result["solutions"]:
            self.assertEqual(
                solution["configuration"]["accepted_nondefault_statuses"],
                ["deprecated","legacy"],
            )

    def test_experimental_profile_is_never_migration_eligible(self) -> None:
        request=self.request()
        request["mode"]="migration"
        request["pinned_profile_refs"].append(
            "example-experimental-addon@0.1.0"
        )
        request["pinned_profile_refs"].sort()
        request["request_digest"]=compatibility_solver.compute_request_digest(request)
        result=self.solve(request)
        self.assertEqual(result["status"],"invalid-request")
        self.assertTrue(any(
            "not eligible in migration mode" in item["message"]
            for item in result["diagnostics"]
        ))

    def test_request_digest_tamper_is_invalid_request(self) -> None:
        request=self.request()
        request["request_digest"]="sha256:"+"9"*64
        result=self.solve(request)
        self.assertEqual(result["status"],"invalid-request")
        self.assertTrue(any(
            "request_digest does not match" in item["message"]
            for item in result["diagnostics"]
        ))

    def test_result_tamper_is_detected(self) -> None:
        expected=self.solve()
        supplied=copy.deepcopy(expected)
        supplied["status"]="unsatisfiable"
        errors=compatibility_solver.validate_result(supplied,expected)
        self.assertTrue(any("result_digest" in error for error in errors))
        self.assertTrue(any("differs from deterministic" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
