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

import interoperability_suite  # noqa: E402


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


class InteroperabilitySuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog=load("profiles/catalog.json")
        cls.properties=load("registry/security-properties.json")
        cls.promotions=load("registry/research-promotion.json")
        cls.conformance=load("registry/conformance.json")
        cls.solver_registry=load("registry/compatibility-solver.json")
        cls.fixture_registry=load("registry/reference-fixtures.json")
        cls.fixture_manifest=load("fixtures/reference-architectures/manifest.json")
        cls.suite_registry=load("registry/interoperability-suite.json")
        cls.contract_manifest=load(
            "fixtures/interoperability/dependency-contracts.json"
        )
        cls.report=interoperability_suite.evaluate_suite(
            suite_registry=cls.suite_registry,
            contract_manifest=cls.contract_manifest,
            fixture_registry=cls.fixture_registry,
            fixture_manifest=cls.fixture_manifest,
            solver_registry=cls.solver_registry,
            catalog=cls.catalog,
            property_registry=cls.properties,
            promotion_registry=cls.promotions,
            conformance_registry=cls.conformance,
        )
        cls.by_pair={
            (item["profile_a"],item["profile_b"]):item
            for item in cls.report["pairs"]
        }

    def pair(self,a: str,b: str) -> dict:
        x,y=sorted((a,b))
        return self.by_pair[(x,y)]

    def test_registry_prohibits_wire_interoperability_inference(self) -> None:
        self.assertEqual(
            interoperability_suite.validate_registry(self.suite_registry),[]
        )
        self.assertEqual(
            self.suite_registry["wire_interoperability_inference"],
            "prohibited",
        )

    def test_dependency_contract_manifest_exactly_snapshots_catalog_edges(self) -> None:
        errors=interoperability_suite.validate_contract_manifest(
            self.contract_manifest,
            suite_registry=self.suite_registry,
            catalog=self.catalog,
            fixture_manifest=self.fixture_manifest,
        )
        self.assertEqual(errors,[])
        self.assertEqual(len(self.contract_manifest["contracts"]),21)

    def test_full_63_profile_matrix_executes_all_1953_pairs(self) -> None:
        self.assertEqual(self.report["production_profile_count"],63)
        self.assertEqual(self.report["pair_count"],63*62//2)
        self.assertEqual(self.report["pair_count"],1953)
        self.assertEqual(len(self.report["pairs"]),1953)
        self.assertEqual(self.report["errors"],[])
        self.assertGreater(self.report["search_states_examined"],0)
        self.assertEqual(
            self.report["report_digest"],
            interoperability_suite.compute_report_digest(self.report),
        )
        self.assertEqual(
            interoperability_suite.validate_report(self.report),[]
        )

    def test_primary_relationship_counts_cover_every_pair_exactly_once(self) -> None:
        total=(
            self.report["co_configurable_count"]
            + self.report["exclusive_alternative_count"]
            + self.report["explicitly_incompatible_count"]
            + self.report["dependency_compatible_count"]
            + self.report["contextually_incompatible_count"]
        )
        self.assertEqual(total,self.report["pair_count"])

    def test_every_declared_dependency_contract_is_co_configurable(self) -> None:
        for contract in self.contract_manifest["contracts"]:
            with self.subTest(contract=contract["contract_id"]):
                record=self.pair(
                    contract["consumer_profile_ref"],
                    contract["provider_profile_ref"],
                )
                self.assertTrue(record["co_configurable"])
                self.assertIn(
                    record["primary_relationship"],
                    {"dependency-compatible","co-configurable"},
                )
                self.assertTrue(record["dependency_directions"])

    def test_runtime_sframe_mls_dependency_is_compatible(self) -> None:
        record=self.pair(
            "media-sframe-mls@0.1.0",
            "group-mls-rfc9420@0.1.0",
        )
        self.assertEqual(record["primary_relationship"],"dependency-compatible")
        self.assertTrue(record["co_configurable"])
        self.assertTrue(record["dependency_directions"])
        self.assertIsNotNone(record["reference_solution_digest"])

    def test_same_family_identity_alternatives_do_not_coexist(self) -> None:
        record=self.pair(
            "identity-account-root@0.1.0",
            "identity-device-cross-signing@0.1.0",
        )
        self.assertTrue(record["same_family"])
        self.assertTrue(record["exclusive_family"])
        self.assertTrue(record["explicit_incompatibility"])
        self.assertFalse(record["co_configurable"])
        # Explicit incompatibility has priority over the more general family boundary.
        self.assertEqual(
            record["primary_relationship"],
            "explicitly-incompatible",
        )

    def test_exclusive_alternative_without_direct_incompatibility_is_classified_separately(self) -> None:
        record=self.pair(
            "example-choice-a@0.1.0",
            "example-choice-b@0.1.0",
        )
        self.assertTrue(record["exclusive_family"])
        self.assertFalse(record["explicit_incompatibility"])
        self.assertFalse(record["co_configurable"])
        self.assertEqual(
            record["primary_relationship"],
            "exclusive-alternative",
        )

    def test_transitive_conflict_is_contextual_not_fake_direct_incompatibility(self) -> None:
        record=self.pair(
            "example-addon-requires-a@0.1.0",
            "example-addon-conflicts-a@0.1.0",
        )
        self.assertFalse(record["exclusive_family"])
        self.assertFalse(record["explicit_incompatibility"])
        self.assertFalse(record["dependency_directions"])
        self.assertFalse(record["co_configurable"])
        self.assertEqual(
            record["primary_relationship"],
            "contextually-incompatible",
        )

    def test_ordinary_cross_family_pair_can_coexist(self) -> None:
        record=self.pair(
            "foundation-baseline@0.1.0",
            "identity-account-root@0.1.0",
        )
        self.assertTrue(record["co_configurable"])
        self.assertEqual(record["primary_relationship"],"co-configurable")

    def test_all_exclusive_pairs_are_non_co_configurable(self) -> None:
        for record in self.report["pairs"]:
            if record["exclusive_family"]:
                with self.subTest(
                    a=record["profile_a"],b=record["profile_b"]
                ):
                    self.assertFalse(record["co_configurable"])

    def test_all_explicit_incompatibilities_are_non_co_configurable(self) -> None:
        for record in self.report["pairs"]:
            if record["explicit_incompatibility"]:
                with self.subTest(
                    a=record["profile_a"],b=record["profile_b"]
                ):
                    self.assertFalse(record["co_configurable"])

    def test_all_dependency_pairs_are_co_configurable(self) -> None:
        for record in self.report["pairs"]:
            if record["dependency_directions"]:
                with self.subTest(
                    a=record["profile_a"],b=record["profile_b"]
                ):
                    self.assertTrue(record["co_configurable"])

    def test_pair_evaluation_is_symmetric(self) -> None:
        args=dict(
            catalog=self.catalog,
            solver_registry=self.solver_registry,
            property_registry=self.properties,
            promotion_registry=self.promotions,
            conformance_registry=self.conformance,
            maximum_pair_search_states=self.suite_registry[
                "maximum_pair_search_states"
            ],
        )
        forward,forward_errors,_=interoperability_suite.evaluate_pair(
            "media-sframe-mls@0.1.0",
            "group-mls-rfc9420@0.1.0",
            **args,
        )
        reverse,reverse_errors,_=interoperability_suite.evaluate_pair(
            "group-mls-rfc9420@0.1.0",
            "media-sframe-mls@0.1.0",
            **args,
        )
        self.assertEqual(forward_errors,[])
        self.assertEqual(reverse_errors,[])
        self.assertEqual(forward,reverse)

    def test_co_configurable_pair_records_are_content_addressed(self) -> None:
        for record in self.report["pairs"]:
            self.assertEqual(
                record["pair_digest"],
                interoperability_suite.compute_pair_digest(record),
            )
            self.assertEqual(
                interoperability_suite.validate_pair_record(record),[]
            )
            if record["co_configurable"]:
                self.assertIsNotNone(record["reference_solution_digest"])

    def test_lifecycle_negative_profiles_are_not_in_production_pair_corpus(self) -> None:
        refs={
            ref
            for record in self.report["pairs"]
            for ref in (record["profile_a"],record["profile_b"])
        }
        self.assertNotIn("example-choice-a@0.2.0",refs)
        self.assertNotIn("advisory-csaf-2-1-csd03@0.1.0",refs)
        self.assertNotIn("example-experimental-addon@0.1.0",refs)
        self.assertNotIn("example-prohibited-addon@0.1.0",refs)

    def test_missing_dependency_contract_is_detected(self) -> None:
        manifest=copy.deepcopy(self.contract_manifest)
        manifest["contracts"]=manifest["contracts"][:-1]
        errors=interoperability_suite.validate_contract_manifest(
            manifest,
            suite_registry=self.suite_registry,
            catalog=self.catalog,
            fixture_manifest=self.fixture_manifest,
        )
        self.assertTrue(any(
            "missing direct dependencies" in error for error in errors
        ))

    def test_stale_dependency_contract_is_detected(self) -> None:
        manifest=copy.deepcopy(self.contract_manifest)
        extra=copy.deepcopy(manifest["contracts"][0])
        extra["contract_id"]="requires-stale-edge"
        extra["consumer_profile_ref"]="foundation-baseline@0.1.0"
        extra["provider_profile_ref"]="identity-account-root@0.1.0"
        extra["interface_kind"]="resolver-composition"
        manifest["contracts"].append(extra)
        errors=interoperability_suite.validate_contract_manifest(
            manifest,
            suite_registry=self.suite_registry,
            catalog=self.catalog,
            fixture_manifest=self.fixture_manifest,
        )
        self.assertTrue(any(
            "stale edges" in error for error in errors
        ))

    def test_pair_search_limit_fails_closed(self) -> None:
        record,errors,_=interoperability_suite.evaluate_pair(
            "foundation-baseline@0.1.0",
            "identity-account-root@0.1.0",
            catalog=self.catalog,
            solver_registry=self.solver_registry,
            property_registry=self.properties,
            promotion_registry=self.promotions,
            conformance_registry=self.conformance,
            maximum_pair_search_states=1,
        )
        self.assertEqual(record["solver_status"],"search-limit")
        self.assertTrue(any(
            "not exhaustive" in error for error in errors
        ))

    def test_pair_digest_tamper_is_detected(self) -> None:
        record=copy.deepcopy(self.pair(
            "foundation-baseline@0.1.0",
            "identity-account-root@0.1.0",
        ))
        record["pair_digest"]="sha256:"+"9"*64
        self.assertTrue(any(
            "pair_digest" in error
            for error in interoperability_suite.validate_pair_record(record)
        ))

    def test_report_digest_tamper_is_detected(self) -> None:
        report=copy.deepcopy(self.report)
        report["report_digest"]="sha256:"+"9"*64
        self.assertTrue(any(
            "report_digest" in error
            for error in interoperability_suite.validate_report(report)
        ))


if __name__ == "__main__":
    unittest.main()
