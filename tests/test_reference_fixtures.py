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

import reference_fixtures  # noqa: E402


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


class ReferenceFixturesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load("fixtures/profiles/development-catalog.json")
        cls.properties = load("registry/security-properties.json")
        cls.promotions = load("registry/research-promotion.json")
        cls.conformance = load("registry/conformance.json")
        cls.solver_registry = load("registry/compatibility-solver.json")
        cls.fixture_registry = load("registry/reference-fixtures.json")
        cls.manifest = load("fixtures/reference-architectures/development-manifest.json")
        cls.report = reference_fixtures.evaluate_manifest(
            cls.manifest,
            fixture_registry=cls.fixture_registry,
            solver_registry=cls.solver_registry,
            catalog=cls.catalog,
            property_registry=cls.properties,
            promotion_registry=cls.promotions,
            conformance_registry=cls.conformance,
        )

    def entry(self, profile_ref: str) -> dict:
        return next(
            item for item in self.manifest["entries"]
            if item["profile_ref"] == profile_ref
        )

    def generate(
        self,
        entry: dict,
        *,
        catalog: dict | None = None,
        promotions: dict | None = None,
    ):
        return reference_fixtures.generate_case(
            entry,
            solver_registry=self.solver_registry,
            fixture_registry=self.fixture_registry,
            catalog=catalog or self.catalog,
            property_registry=self.properties,
            promotion_registry=promotions or self.promotions,
            conformance_registry=self.conformance,
        )

    def test_reference_fixture_registry_is_valid(self) -> None:
        self.assertEqual(
            reference_fixtures.validate_registry(self.fixture_registry), []
        )

    def test_manifest_covers_every_exact_catalog_profile_once(self) -> None:
        errors=reference_fixtures.validate_manifest(
            self.manifest,
            fixture_registry=self.fixture_registry,
            catalog=self.catalog,
            promotion_registry=self.promotions,
        )
        self.assertEqual(errors,[])
        catalog_refs={
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog["profiles"]
        }
        manifest_refs={
            item["profile_ref"] for item in self.manifest["entries"]
        }
        self.assertEqual(catalog_refs,manifest_refs)
        self.assertEqual(len(manifest_refs),67)

    def test_current_manifest_has_63_positive_and_4_negative_cases(self) -> None:
        dispositions=[
            item["disposition"] for item in self.manifest["entries"]
        ]
        self.assertEqual(dispositions.count("production-positive"),63)
        self.assertEqual(dispositions.count("candidate-positive"),0)
        self.assertEqual(dispositions.count("migration-positive"),0)
        self.assertEqual(sum(
            1 for item in dispositions
            if item in set(self.fixture_registry["negative_dispositions"])
        ),4)

    def test_entire_reference_corpus_executes_without_failure(self) -> None:
        self.assertEqual(self.report["errors"],[])
        self.assertEqual(self.report["catalog_profile_count"],67)
        self.assertEqual(self.report["manifest_entry_count"],67)
        self.assertEqual(self.report["passed_case_count"],67)
        self.assertEqual(self.report["failed_case_count"],0)
        self.assertEqual(self.report["production_positive_count"],63)
        self.assertEqual(self.report["negative_lifecycle_count"],4)
        self.assertEqual(
            self.report["family_coverage_count"],
            len(self.catalog["families"]),
        )
        self.assertEqual(len(self.report["case_digests"]),67)

    def test_reference_report_is_deterministic_and_content_addressed(self) -> None:
        second=reference_fixtures.evaluate_manifest(
            self.manifest,
            fixture_registry=self.fixture_registry,
            solver_registry=self.solver_registry,
            catalog=self.catalog,
            property_registry=self.properties,
            promotion_registry=self.promotions,
            conformance_registry=self.conformance,
        )
        self.assertEqual(self.report,second)
        self.assertEqual(
            self.report["report_digest"],
            reference_fixtures.compute_report_digest(self.report),
        )
        self.assertEqual(reference_fixtures.validate_report(self.report),[])

    def test_all_three_identity_architectures_have_positive_reference_cases(self) -> None:
        for ref in (
            "identity-account-root@0.1.0",
            "identity-device-cross-signing@0.1.0",
            "identity-threshold-quorum@0.1.0",
        ):
            with self.subTest(ref=ref):
                entry=self.entry(ref)
                self.assertEqual(entry["disposition"],"production-positive")
                case,errors=self.generate(entry)
                self.assertEqual(errors,[])
                self.assertIn(
                    ref,case["reference_solution"]["effective_profile_refs"]
                )
                self.assertEqual(reference_fixtures.validate_case(case),[])

    def test_every_positive_case_contains_its_exact_target(self) -> None:
        positives=set(self.fixture_registry["positive_dispositions"])
        for entry in self.manifest["entries"]:
            if entry["disposition"] not in positives:
                continue
            with self.subTest(ref=entry["profile_ref"]):
                case,errors=self.generate(entry)
                self.assertEqual(errors,[])
                self.assertIsNotNone(case["reference_solution"])
                self.assertIn(
                    entry["profile_ref"],
                    case["reference_solution"]["effective_profile_refs"],
                )

    def test_unpromoted_provisional_profiles_are_negative_fixtures(self) -> None:
        for ref in (
            "example-choice-a@0.2.0",
            "advisory-csaf-2-1-csd03@0.1.0",
        ):
            with self.subTest(ref=ref):
                entry=self.entry(ref)
                self.assertEqual(
                    entry["disposition"],
                    "unpromoted-provisional-negative",
                )
                case,errors=self.generate(entry)
                self.assertEqual(errors,[])
                self.assertIsNone(case["reference_solution"])

    def test_experimental_and_prohibited_profiles_are_explicit_negative_fixtures(self) -> None:
        checks={
            "example-experimental-addon@0.1.0":"experimental-negative",
            "example-prohibited-addon@0.1.0":"prohibited-negative",
        }
        for ref,disposition in checks.items():
            with self.subTest(ref=ref):
                entry=self.entry(ref)
                self.assertEqual(entry["disposition"],disposition)
                case,errors=self.generate(entry)
                self.assertEqual(errors,[])
                self.assertIsNone(case["reference_solution"])

    def test_missing_manifest_profile_fails_closed(self) -> None:
        manifest=copy.deepcopy(self.manifest)
        manifest["entries"]=manifest["entries"][:-1]
        errors=reference_fixtures.validate_manifest(
            manifest,
            fixture_registry=self.fixture_registry,
            catalog=self.catalog,
            promotion_registry=self.promotions,
        )
        self.assertTrue(any(
            "missing catalog profiles" in error for error in errors
        ))

    def test_stale_extra_manifest_profile_fails_closed(self) -> None:
        manifest=copy.deepcopy(self.manifest)
        extra=copy.deepcopy(manifest["entries"][0])
        extra["fixture_id"]="profile-stale-example"
        extra["profile_ref"]="stale-profile@0.1.0"
        manifest["entries"].append(extra)
        errors=reference_fixtures.validate_manifest(
            manifest,
            fixture_registry=self.fixture_registry,
            catalog=self.catalog,
            promotion_registry=self.promotions,
        )
        self.assertTrue(any(
            "stale" in error or "unknown" in error for error in errors
        ))

    def test_manifest_status_or_family_drift_is_detected(self) -> None:
        manifest=copy.deepcopy(self.manifest)
        entry=manifest["entries"][0]
        entry["profile_status"]="deprecated"
        entry["family_id"]="not-the-family"
        errors=reference_fixtures.validate_manifest(
            manifest,
            fixture_registry=self.fixture_registry,
            catalog=self.catalog,
            promotion_registry=self.promotions,
        )
        self.assertTrue(any("profile_status mismatch" in error for error in errors))
        self.assertTrue(any("family_id mismatch" in error for error in errors))

    def test_provisional_fixture_must_flip_to_candidate_positive_after_promotion(self) -> None:
        ref="example-choice-a@0.2.0"
        promotions=copy.deepcopy(self.promotions)
        promotions["promoted_profiles"].append({
            "profile_ref":ref,
            "research_entry_digest":"sha256:"+"a"*64,
            "lifecycle_state":"candidate",
            "promotion_record_digest":"sha256:"+"b"*64,
            "effective_at":"2026-10-08T01:00:00Z",
            "gate_profile_ref":"promotion-candidate-baseline@0.1.0",
        })

        stale=copy.deepcopy(self.manifest)
        errors=reference_fixtures.validate_manifest(
            stale,
            fixture_registry=self.fixture_registry,
            catalog=self.catalog,
            promotion_registry=promotions,
        )
        self.assertTrue(any(
            ref in error and "disposition mismatch" in error
            for error in errors
        ))

        entry=copy.deepcopy(self.entry(ref))
        entry.update({
            "disposition":"candidate-positive",
            "solver_mode":"candidate",
            "expected_solver_status":"solutions",
        })
        case,case_errors=self.generate(entry,promotions=promotions)
        self.assertEqual(case_errors,[])
        self.assertIn(
            ref,case["reference_solution"]["effective_profile_refs"]
        )

    def test_legacy_status_requires_migration_positive_fixture(self) -> None:
        ref="example-choice-b@0.1.0"
        catalog=copy.deepcopy(self.catalog)
        profile=next(
            item for item in catalog["profiles"]
            if f"{item['profile_id']}@{item['profile_version']}"==ref
        )
        profile["status"]="legacy"

        entry=copy.deepcopy(self.entry(ref))
        expected=reference_fixtures.expected_entry(profile,self.promotions)
        self.assertEqual(expected["disposition"],"migration-positive")
        entry.update({
            "profile_status":"legacy",
            "disposition":"migration-positive",
            "solver_mode":"migration",
            "expected_solver_status":"solutions",
        })
        case,errors=self.generate(entry,catalog=catalog)
        self.assertEqual(errors,[])
        self.assertIn(
            ref,case["reference_solution"]["effective_profile_refs"]
        )
        self.assertEqual(
            case["reference_solution"]["configuration"]["accepted_nondefault_statuses"],
            ["deprecated","legacy"],
        )

    def test_required_promotion_can_intentionally_break_conflicting_reference_case(self) -> None:
        promotions=copy.deepcopy(self.promotions)
        promotions["promoted_profiles"].append({
            "profile_ref":"identity-threshold-quorum@0.1.0",
            "research_entry_digest":"sha256:"+"c"*64,
            "lifecycle_state":"required",
            "promotion_record_digest":"sha256:"+"d"*64,
            "effective_at":"2026-10-08T01:00:00Z",
            "gate_profile_ref":"promotion-required-operational-maturity@0.1.0",
        })
        entry=self.entry("identity-account-root@0.1.0")
        _case,errors=self.generate(entry,promotions=promotions)
        self.assertTrue(errors)
        self.assertTrue(any(
            "expected solver status solutions" in error
            for error in errors
        ))

    def test_case_digest_tamper_is_detected(self) -> None:
        case,errors=self.generate(
            self.entry("identity-account-root@0.1.0")
        )
        self.assertEqual(errors,[])
        case["case_digest"]="sha256:"+"9"*64
        self.assertTrue(any(
            "case_digest" in error
            for error in reference_fixtures.validate_case(case)
        ))

    def test_report_digest_tamper_is_detected(self) -> None:
        report=copy.deepcopy(self.report)
        report["report_digest"]="sha256:"+"9"*64
        self.assertTrue(any(
            "report_digest" in error
            for error in reference_fixtures.validate_report(report)
        ))


if __name__ == "__main__":
    unittest.main()
