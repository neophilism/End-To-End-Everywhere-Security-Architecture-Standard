#!/usr/bin/env python3
"""Executable reference-fixture coverage for E2EESA PR 43."""

from __future__ import annotations

import canonical_serialization

import hashlib
import json
from typing import Any

import compatibility_solver
import profile_engine


def canonical_bytes(value: object) -> bytes:
    return canonical_serialization.canonical_bytes(value)


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def case_core(case: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in case.items() if k != "case_digest"}


def compute_case_digest(case: dict[str, Any]) -> str:
    return canonical_digest(case_core(case))


def report_core(report: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in report.items() if k != "report_digest"}


def compute_report_digest(report: dict[str, Any]) -> str:
    return canonical_digest(report_core(report))


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("reference fixtures registry schema_version must be 0.1")
    dispositions = registry.get("dispositions")
    positives = registry.get("positive_dispositions")
    negatives = registry.get("negative_dispositions")
    expected_positive = {
        "production-positive",
        "candidate-positive",
        "migration-positive",
    }
    expected_negative = {
        "unpromoted-provisional-negative",
        "experimental-negative",
        "prohibited-negative",
    }
    if not isinstance(dispositions, list) or len(dispositions) != len(set(dispositions)):
        errors.append("reference fixtures dispositions must be a unique array")
        dispositions = []
    if not isinstance(positives, list) or set(positives) != expected_positive:
        errors.append("reference fixtures positive_dispositions mismatch")
        positives = []
    if not isinstance(negatives, list) or set(negatives) != expected_negative:
        errors.append("reference fixtures negative_dispositions mismatch")
        negatives = []
    if set(dispositions) != expected_positive | expected_negative:
        errors.append("reference fixtures disposition universe mismatch")
    if registry.get("generated_case_version") != "0.1":
        errors.append("reference fixtures generated_case_version must be 0.1")
    return sorted(set(errors))


def _promoted_states(promotion_registry: dict[str, Any]) -> dict[str, str]:
    return {
        item.get("profile_ref"): item.get("lifecycle_state")
        for item in promotion_registry.get("promoted_profiles", [])
        if isinstance(item, dict)
        and isinstance(item.get("profile_ref"), str)
        and isinstance(item.get("lifecycle_state"), str)
    }


def expected_entry(
    profile: dict[str, Any],
    promotion_registry: dict[str, Any],
) -> dict[str, str]:
    ref = profile_engine.profile_ref(profile)
    status = profile.get("status")
    states = _promoted_states(promotion_registry)
    if status in {"recommended", "allowed"}:
        disposition = "production-positive"
        mode = "production"
        expected_status = "solutions"
    elif status == "provisional" and states.get(ref) == "candidate":
        disposition = "candidate-positive"
        mode = "candidate"
        expected_status = "solutions"
    elif status == "provisional":
        disposition = "unpromoted-provisional-negative"
        mode = "candidate"
        expected_status = "invalid-request"
    elif status in {"legacy", "deprecated"}:
        disposition = "migration-positive"
        mode = "migration"
        expected_status = "solutions"
    elif status == "experimental":
        disposition = "experimental-negative"
        mode = "candidate"
        expected_status = "invalid-request"
    elif status == "prohibited":
        disposition = "prohibited-negative"
        mode = "migration"
        expected_status = "invalid-request"
    else:
        raise ValueError(f"unsupported profile lifecycle status {status!r} for {ref}")
    return {
        "profile_ref": ref,
        "family_id": profile["family_id"],
        "profile_status": status,
        "disposition": disposition,
        "solver_mode": mode,
        "expected_solver_status": expected_status,
    }


def validate_manifest(
    manifest: dict[str, Any],
    *,
    fixture_registry: dict[str, Any],
    catalog: dict[str, Any],
    promotion_registry: dict[str, Any],
) -> list[str]:
    errors = validate_registry(fixture_registry)
    if manifest.get("schema_version") != "0.1":
        errors.append("reference fixture manifest schema_version must be 0.1")
    if manifest.get("standard_version") != catalog.get("standard_version"):
        errors.append("reference fixture manifest standard_version mismatch")

    profiles = {
        profile_engine.profile_ref(item): item
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    if manifest.get("catalog_profile_count") != len(profiles):
        errors.append("reference fixture manifest catalog_profile_count mismatch")

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        return sorted(set(errors + ["reference fixture manifest entries must be an array"]))

    by_ref: dict[str, dict[str, Any]] = {}
    fixture_ids: set[str] = set()
    for index, entry in enumerate(entries):
        prefix = f"reference fixture entries[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        fixture_id = entry.get("fixture_id")
        if not isinstance(fixture_id, str) or not fixture_id:
            errors.append(f"{prefix} fixture_id must be non-empty")
        elif fixture_id in fixture_ids:
            errors.append(f"{prefix} duplicate fixture_id {fixture_id}")
        else:
            fixture_ids.add(fixture_id)

        ref = entry.get("profile_ref")
        if not isinstance(ref, str) or not ref:
            errors.append(f"{prefix} profile_ref must be non-empty")
            continue
        if ref in by_ref:
            errors.append(f"{prefix} duplicate profile_ref {ref}")
            continue
        by_ref[ref] = entry
        profile = profiles.get(ref)
        if profile is None:
            errors.append(f"{prefix} stale/unknown profile_ref {ref}")
            continue
        expected = expected_entry(profile, promotion_registry)
        for field, value in expected.items():
            if entry.get(field) != value:
                errors.append(
                    f"{prefix} {field} mismatch for {ref}: "
                    f"{entry.get(field)!r} != {value!r}"
                )

    missing = sorted(set(profiles) - set(by_ref))
    extra = sorted(set(by_ref) - set(profiles))
    if missing:
        errors.append(
            "reference fixture manifest missing catalog profiles: " + ", ".join(missing)
        )
    if extra:
        errors.append(
            "reference fixture manifest contains stale profiles: " + ", ".join(extra)
        )

    positive = set(fixture_registry.get("positive_dispositions", []))
    production_families = {
        profile.get("family_id")
        for profile in profiles.values()
        if profile.get("status") in {"recommended", "allowed"}
    }
    positive_families = {
        entry.get("family_id")
        for entry in entries
        if isinstance(entry, dict) and entry.get("disposition") in positive
    }
    missing_families = sorted(production_families - positive_families)
    if missing_families:
        errors.append(
            "production-eligible families lack positive fixtures: "
            + ", ".join(missing_families)
        )

    return sorted(set(errors))


def fixture_request(
    entry: dict[str, Any],
    *,
    standard_version: str,
    solver_registry: dict[str, Any],
) -> dict[str, Any]:
    request = {
        "schema_version": "0.1",
        "request_id": "fixture-" + entry["fixture_id"],
        "standard_version": standard_version,
        "mode": entry["solver_mode"],
        "required_family_ids": [],
        "forbidden_family_ids": [],
        "desired_property_ids": [],
        "pinned_profile_refs": [entry["profile_ref"]],
        "excluded_profile_refs": [],
        "max_solutions": solver_registry["maximum_max_solutions"],
        "enforce_required_promotions": True,
        "request_digest": "",
    }
    request["request_digest"] = compatibility_solver.compute_request_digest(request)
    return request


def generate_case(
    entry: dict[str, Any],
    *,
    solver_registry: dict[str, Any],
    fixture_registry: dict[str, Any],
    catalog: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    request = fixture_request(
        entry,
        standard_version=catalog["standard_version"],
        solver_registry=solver_registry,
    )
    result = compatibility_solver.solve(
        request,
        solver_registry=solver_registry,
        catalog=catalog,
        property_registry=property_registry,
        promotion_registry=promotion_registry,
        conformance_registry=conformance_registry,
    )

    expected_status = entry["expected_solver_status"]
    if result.get("status") != expected_status:
        errors.append(
            f"{entry['profile_ref']}: expected solver status {expected_status}, "
            f"got {result.get('status')}"
        )

    positive = entry["disposition"] in set(
        fixture_registry.get("positive_dispositions", [])
    )
    reference_solution: dict[str, Any] | None = None
    if positive:
        if result.get("status") == "search-limit" or not result.get("search_exhaustive"):
            errors.append(
                f"{entry['profile_ref']}: positive fixture search was not exhaustive"
            )
        solutions = result.get("solutions")
        if not isinstance(solutions, list) or not solutions:
            errors.append(f"{entry['profile_ref']}: positive fixture has no solutions")
        else:
            target = entry["profile_ref"]
            for index, solution in enumerate(solutions):
                if target not in set(solution.get("effective_profile_refs", [])):
                    errors.append(
                        f"{entry['profile_ref']}: returned solution {index} omits target"
                    )
            reference_solution = solutions[0]
            configuration = reference_solution.get("configuration")
            if not isinstance(configuration, dict):
                errors.append(
                    f"{entry['profile_ref']}: reference solution lacks configuration"
                )
            else:
                property_ids = {
                    item.get("id")
                    for item in property_registry.get("properties", [])
                    if isinstance(item, dict) and isinstance(item.get("id"), str)
                }
                resolved = profile_engine.resolve_configuration(
                    catalog,
                    configuration,
                    known_property_ids=property_ids,
                )
                if not resolved.valid:
                    errors.append(
                        f"{entry['profile_ref']}: generated configuration fails PR 2: "
                        + " | ".join(resolved.errors)
                    )
                elif sorted(resolved.effective_profiles) != sorted(
                    reference_solution.get("effective_profile_refs", [])
                ):
                    errors.append(
                        f"{entry['profile_ref']}: PR 2 effective profile set differs "
                        "from reference solution"
                    )
    else:
        if result.get("status") == "solutions":
            errors.append(
                f"{entry['profile_ref']}: negative lifecycle fixture unexpectedly selectable"
            )
        if result.get("status") == "search-limit":
            errors.append(
                f"{entry['profile_ref']}: negative fixture reached search limit"
            )

    case = {
        "schema_version": fixture_registry.get("generated_case_version"),
        "fixture_id": entry["fixture_id"],
        "manifest_entry": dict(entry),
        "solver_request": request,
        "solver_result_digest": result.get("result_digest"),
        "reference_solution": reference_solution,
        "case_digest": "",
    }
    case["case_digest"] = compute_case_digest(case)
    return case, sorted(set(errors))


def evaluate_manifest(
    manifest: dict[str, Any],
    *,
    fixture_registry: dict[str, Any],
    solver_registry: dict[str, Any],
    catalog: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
) -> dict[str, Any]:
    errors = validate_manifest(
        manifest,
        fixture_registry=fixture_registry,
        catalog=catalog,
        promotion_registry=promotion_registry,
    )

    case_digests: dict[str, str] = {}
    passed = 0
    failed = 0
    if not errors:
        for entry in manifest["entries"]:
            case, case_errors = generate_case(
                entry,
                solver_registry=solver_registry,
                fixture_registry=fixture_registry,
                catalog=catalog,
                property_registry=property_registry,
                promotion_registry=promotion_registry,
                conformance_registry=conformance_registry,
            )
            case_digests[entry["fixture_id"]] = case["case_digest"]
            if case_errors:
                failed += 1
                errors.extend(case_errors)
            else:
                passed += 1

    entries = manifest.get("entries", [])
    dispositions = [
        entry.get("disposition")
        for entry in entries
        if isinstance(entry, dict)
    ]
    positive_set = set(fixture_registry.get("positive_dispositions", []))
    negative_set = set(fixture_registry.get("negative_dispositions", []))
    report = {
        "schema_version": "0.1",
        "standard_version": manifest.get("standard_version"),
        "catalog_profile_count": len(catalog.get("profiles", [])),
        "manifest_entry_count": len(entries) if isinstance(entries, list) else 0,
        "production_positive_count": dispositions.count("production-positive"),
        "candidate_positive_count": dispositions.count("candidate-positive"),
        "migration_positive_count": dispositions.count("migration-positive"),
        "negative_lifecycle_count": sum(
            1 for disposition in dispositions if disposition in negative_set
        ),
        "family_coverage_count": len({
            entry.get("family_id")
            for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("family_id"), str)
        }),
        "passed_case_count": passed,
        "failed_case_count": failed,
        "errors": sorted(set(errors)),
        "case_digests": dict(sorted(case_digests.items())),
        "report_digest": "",
    }
    report["report_digest"] = compute_report_digest(report)
    return report


def validate_case(case: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if case.get("schema_version") != "0.1":
        errors.append("reference fixture case schema_version must be 0.1")
    if case.get("case_digest") != compute_case_digest(case):
        errors.append("reference fixture case_digest does not match canonical case")
    return sorted(set(errors))


def validate_report(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if report.get("schema_version") != "0.1":
        errors.append("reference fixture report schema_version must be 0.1")
    if report.get("report_digest") != compute_report_digest(report):
        errors.append("reference fixture report_digest does not match canonical report")
    if report.get("failed_case_count") != len({
        error.split(":", 1)[0]
        for error in report.get("errors", [])
        if isinstance(error, str) and ":" in error
    }) and report.get("failed_case_count", 0) < 0:
        errors.append("reference fixture failed_case_count is invalid")
    return sorted(set(errors))
