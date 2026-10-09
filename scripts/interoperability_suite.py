#!/usr/bin/env python3
"""Cross-profile interoperability/compatibility suite for E2EESA PR 44."""

from __future__ import annotations

import canonical_serialization

import hashlib
import itertools
import json
from typing import Any

import compatibility_solver
import profile_engine
import reference_fixtures


def canonical_bytes(value: object) -> bytes:
    return canonical_serialization.canonical_bytes(value)


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def pair_core(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "pair_digest"}


def compute_pair_digest(record: dict[str, Any]) -> str:
    return canonical_digest(pair_core(record))


def report_core(report: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in report.items() if k != "report_digest"}


def compute_report_digest(report: dict[str, Any]) -> str:
    return canonical_digest(report_core(report))


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("interoperability suite registry schema_version must be 0.1")
    expected_kinds = {
        "runtime-profile-composition",
        "assurance-evidence-composition",
        "resolver-composition",
    }
    expected_relations = {
        "co-configurable",
        "exclusive-alternative",
        "explicitly-incompatible",
        "dependency-compatible",
        "contextually-incompatible",
    }
    kinds = registry.get("interface_kinds")
    relations = registry.get("pair_relationships")
    if (
        not isinstance(kinds, list)
        or len(kinds) != len(set(kinds))
        or set(kinds) != expected_kinds
    ):
        errors.append("interoperability suite interface_kinds mismatch")
    if (
        not isinstance(relations, list)
        or len(relations) != len(set(relations))
        or set(relations) != expected_relations
    ):
        errors.append("interoperability suite pair_relationships mismatch")
    if registry.get("wire_interoperability_inference") != "prohibited":
        errors.append("wire interoperability inference must be prohibited")
    maximum = registry.get("maximum_pair_search_states")
    if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 1:
        errors.append("maximum_pair_search_states must be positive integer")
    return sorted(set(errors))


def _production_refs(fixture_manifest: dict[str, Any]) -> list[str]:
    return sorted(
        entry["profile_ref"]
        for entry in fixture_manifest.get("entries", [])
        if isinstance(entry, dict)
        and entry.get("disposition") == "production-positive"
        and isinstance(entry.get("profile_ref"), str)
    )


def _expected_interface_kind(consumer: dict[str, Any]) -> str:
    family = consumer.get("family_id")
    if family == "assurance-level":
        return "assurance-evidence-composition"
    if family == "real-time-media":
        return "runtime-profile-composition"
    return "resolver-composition"


def _direct_dependency_edges(
    catalog: dict[str, Any],
    production_refs: set[str],
) -> set[tuple[str, str, str]]:
    profiles = {
        profile_engine.profile_ref(item): item
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    edges: set[tuple[str, str, str]] = set()
    for consumer_ref in sorted(production_refs):
        consumer = profiles.get(consumer_ref)
        if not isinstance(consumer, dict):
            continue
        kind = _expected_interface_kind(consumer)
        for provider_ref in consumer.get("requires_profile_refs", []):
            if provider_ref in production_refs:
                edges.add((consumer_ref, provider_ref, kind))
    return edges


def validate_contract_manifest(
    manifest: dict[str, Any],
    *,
    suite_registry: dict[str, Any],
    catalog: dict[str, Any],
    fixture_manifest: dict[str, Any],
) -> list[str]:
    errors = validate_registry(suite_registry)
    if manifest.get("schema_version") != "0.1":
        errors.append("interoperability contract manifest schema_version must be 0.1")
    if manifest.get("standard_version") != catalog.get("standard_version"):
        errors.append("interoperability contract manifest standard_version mismatch")

    production = set(_production_refs(fixture_manifest))
    profiles = {
        profile_engine.profile_ref(item): item
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    expected = _direct_dependency_edges(catalog, production)

    contracts = manifest.get("contracts")
    if not isinstance(contracts, list):
        return sorted(set(
            errors + ["interoperability contract manifest contracts must be an array"]
        ))

    actual: set[tuple[str, str, str]] = set()
    ids: set[str] = set()
    allowed_kinds = set(suite_registry.get("interface_kinds", []))
    for index, contract in enumerate(contracts):
        prefix = f"interoperability contracts[{index}]"
        if not isinstance(contract, dict):
            errors.append(f"{prefix} must be an object")
            continue
        contract_id = contract.get("contract_id")
        if not isinstance(contract_id, str) or not contract_id:
            errors.append(f"{prefix} contract_id must be non-empty")
        elif contract_id in ids:
            errors.append(f"{prefix} duplicate contract_id {contract_id}")
        else:
            ids.add(contract_id)

        consumer = contract.get("consumer_profile_ref")
        provider = contract.get("provider_profile_ref")
        kind = contract.get("interface_kind")
        if consumer not in production:
            errors.append(f"{prefix} consumer is not production-positive: {consumer}")
        if provider not in production:
            errors.append(f"{prefix} provider is not production-positive: {provider}")
        if kind not in allowed_kinds:
            errors.append(f"{prefix} invalid interface_kind {kind}")
        if contract.get("expected_relationship") != "co-configurable":
            errors.append(f"{prefix} expected_relationship must be co-configurable")
        if consumer in profiles and kind != _expected_interface_kind(profiles[consumer]):
            errors.append(f"{prefix} interface_kind does not match consumer family")
        if (
            isinstance(consumer, str)
            and isinstance(provider, str)
            and isinstance(kind, str)
        ):
            edge = (consumer, provider, kind)
            if edge in actual:
                errors.append(
                    f"{prefix} duplicate consumer/provider/interface contract {edge}"
                )
            actual.add(edge)

    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing:
        errors.append(
            "interoperability contracts missing direct dependencies: "
            + ", ".join(f"{a}->{b} ({k})" for a, b, k in missing)
        )
    if extra:
        errors.append(
            "interoperability contracts contain stale edges: "
            + ", ".join(f"{a}->{b} ({k})" for a, b, k in extra)
        )
    return sorted(set(errors))


def input_digests(
    *,
    catalog: dict[str, Any],
    fixture_manifest: dict[str, Any],
    solver_registry: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
    suite_registry: dict[str, Any],
    contract_manifest: dict[str, Any],
) -> dict[str, str]:
    return {
        "profile_catalog": canonical_digest(catalog),
        "reference_fixture_manifest": canonical_digest(fixture_manifest),
        "compatibility_solver_registry": canonical_digest(solver_registry),
        "security_properties_registry": canonical_digest(property_registry),
        "research_promotion_registry": canonical_digest(promotion_registry),
        "conformance_registry": canonical_digest(conformance_registry),
        "interoperability_suite_registry": canonical_digest(suite_registry),
        "interoperability_contract_manifest": canonical_digest(contract_manifest),
    }


def pair_request(
    profile_a: str,
    profile_b: str,
    *,
    standard_version: str,
) -> dict[str, Any]:
    a, b = sorted((profile_a, profile_b))
    seed = canonical_digest([a, b])[7:23]
    request = {
        "schema_version": "0.1",
        "request_id": "interop-" + seed,
        "standard_version": standard_version,
        "mode": "production",
        "required_family_ids": [],
        "forbidden_family_ids": [],
        "desired_property_ids": [],
        "pinned_profile_refs": [a, b],
        "excluded_profile_refs": [],
        "max_solutions": 1,
        "enforce_required_promotions": True,
        "request_digest": "",
    }
    request["request_digest"] = compatibility_solver.compute_request_digest(request)
    return request


def _pair_flags(
    a: str,
    b: str,
    *,
    profiles: dict[str, dict[str, Any]],
    families: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    pa = profiles[a]
    pb = profiles[b]
    same_family = pa.get("family_id") == pb.get("family_id")
    family = families.get(pa.get("family_id"), {}) if same_family else {}
    exclusive = bool(
        same_family
        and family.get("cardinality") in {"exactly-one", "at-most-one"}
    )
    explicit = bool(
        b in set(pa.get("incompatible_profile_refs", []))
        or a in set(pb.get("incompatible_profile_refs", []))
    )
    directions: list[str] = []
    if b in set(pa.get("requires_profile_refs", [])):
        directions.append("a-requires-b")
    if a in set(pb.get("requires_profile_refs", [])):
        directions.append("b-requires-a")
    return {
        "same_family": same_family,
        "exclusive_family": exclusive,
        "explicit_incompatibility": explicit,
        "dependency_directions": directions,
    }


def evaluate_pair(
    profile_a: str,
    profile_b: str,
    *,
    catalog: dict[str, Any],
    solver_registry: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
    maximum_pair_search_states: int,
) -> tuple[dict[str, Any], list[str], int]:
    a, b = sorted((profile_a, profile_b))
    errors: list[str] = []
    profiles = {
        profile_engine.profile_ref(item): item
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    families = {
        item.get("family_id"): item
        for item in catalog.get("families", [])
        if isinstance(item, dict)
    }
    if a == b:
        raise ValueError("interoperability pair requires two distinct profiles")
    if a not in profiles or b not in profiles:
        raise ValueError("interoperability pair references unknown profile")

    flags = _pair_flags(a, b, profiles=profiles, families=families)
    request = pair_request(a, b, standard_version=catalog["standard_version"])

    pair_solver_registry = json.loads(json.dumps(solver_registry))
    pair_solver_registry["maximum_search_states"] = min(
        pair_solver_registry["maximum_search_states"],
        maximum_pair_search_states,
    )
    result = compatibility_solver.solve(
        request,
        solver_registry=pair_solver_registry,
        catalog=catalog,
        property_registry=property_registry,
        promotion_registry=promotion_registry,
        conformance_registry=conformance_registry,
    )
    status = result.get("status")
    if status == "search-limit" or not result.get("search_exhaustive"):
        errors.append(f"{a} + {b}: interoperability search was not exhaustive")

    co_configurable = status == "solutions" and bool(result.get("solutions"))
    reference_solution_digest: str | None = None
    if co_configurable:
        solution = result["solutions"][0]
        effective = set(solution.get("effective_profile_refs", []))
        if a not in effective or b not in effective:
            errors.append(
                f"{a} + {b}: co-configurable solution omits one or both target profiles"
            )
        config = solution.get("configuration")
        if not isinstance(config, dict):
            errors.append(f"{a} + {b}: co-configurable solution lacks configuration")
        else:
            property_ids = {
                item.get("id")
                for item in property_registry.get("properties", [])
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            }
            resolved = profile_engine.resolve_configuration(
                catalog, config, known_property_ids=property_ids
            )
            if not resolved.valid:
                errors.append(
                    f"{a} + {b}: co-configurable solution fails PR 2: "
                    + " | ".join(resolved.errors)
                )
            elif sorted(resolved.effective_profiles) != sorted(
                solution.get("effective_profile_refs", [])
            ):
                errors.append(
                    f"{a} + {b}: PR 2 effective profiles differ from solver solution"
                )
        reference_solution_digest = solution.get("solution_digest")

    if flags["exclusive_family"] and co_configurable:
        errors.append(f"{a} + {b}: exclusive-family alternatives are co-configurable")
    if flags["explicit_incompatibility"] and co_configurable:
        errors.append(f"{a} + {b}: explicitly incompatible profiles are co-configurable")
    if flags["dependency_directions"] and not co_configurable:
        errors.append(f"{a} + {b}: declared dependency pair is not co-configurable")

    if flags["explicit_incompatibility"]:
        primary = "explicitly-incompatible"
    elif flags["exclusive_family"]:
        primary = "exclusive-alternative"
    elif flags["dependency_directions"]:
        primary = "dependency-compatible"
    elif co_configurable:
        primary = "co-configurable"
    else:
        primary = "contextually-incompatible"

    pair_seed = canonical_digest([a, b])[7:23]
    record = {
        "pair_id": "pair-" + pair_seed,
        "profile_a": a,
        "profile_b": b,
        "same_family": flags["same_family"],
        "exclusive_family": flags["exclusive_family"],
        "explicit_incompatibility": flags["explicit_incompatibility"],
        "dependency_directions": flags["dependency_directions"],
        "co_configurable": co_configurable,
        "solver_status": status,
        "solver_result_digest": result.get("result_digest"),
        "primary_relationship": primary,
        "reference_solution_digest": reference_solution_digest,
        "pair_digest": "",
    }
    record["pair_digest"] = compute_pair_digest(record)
    return record, sorted(set(errors)), int(result.get("search_states_examined", 0))


def evaluate_suite(
    *,
    suite_registry: dict[str, Any],
    contract_manifest: dict[str, Any],
    fixture_registry: dict[str, Any],
    fixture_manifest: dict[str, Any],
    solver_registry: dict[str, Any],
    catalog: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
) -> dict[str, Any]:
    errors = validate_registry(suite_registry)
    errors.extend(
        reference_fixtures.validate_manifest(
            fixture_manifest,
            fixture_registry=fixture_registry,
            catalog=catalog,
            promotion_registry=promotion_registry,
        )
    )
    errors.extend(
        validate_contract_manifest(
            contract_manifest,
            suite_registry=suite_registry,
            catalog=catalog,
            fixture_manifest=fixture_manifest,
        )
    )

    production = _production_refs(fixture_manifest)
    expected_pair_count = len(production) * (len(production) - 1) // 2
    pair_records: list[dict[str, Any]] = []
    search_states = 0
    if not errors:
        for a, b in itertools.combinations(production, 2):
            record, pair_errors, states = evaluate_pair(
                a,
                b,
                catalog=catalog,
                solver_registry=solver_registry,
                property_registry=property_registry,
                promotion_registry=promotion_registry,
                conformance_registry=conformance_registry,
                maximum_pair_search_states=suite_registry[
                    "maximum_pair_search_states"
                ],
            )
            pair_records.append(record)
            search_states += states
            errors.extend(pair_errors)

    if len(pair_records) not in {0, expected_pair_count}:
        errors.append(
            f"interoperability pair coverage mismatch: "
            f"{len(pair_records)} != {expected_pair_count}"
        )

    relationship_counts = {
        relation: 0 for relation in suite_registry.get("pair_relationships", [])
    }
    for record in pair_records:
        relationship = record.get("primary_relationship")
        if relationship in relationship_counts:
            relationship_counts[relationship] += 1

    report = {
        "schema_version": "0.1",
        "standard_version": catalog.get("standard_version"),
        "production_profile_count": len(production),
        "pair_count": len(pair_records),
        "co_configurable_count": relationship_counts.get("co-configurable", 0),
        "exclusive_alternative_count": relationship_counts.get(
            "exclusive-alternative", 0
        ),
        "explicitly_incompatible_count": relationship_counts.get(
            "explicitly-incompatible", 0
        ),
        "dependency_compatible_count": relationship_counts.get(
            "dependency-compatible", 0
        ),
        "contextually_incompatible_count": relationship_counts.get(
            "contextually-incompatible", 0
        ),
        "declared_contract_count": len(contract_manifest.get("contracts", [])),
        "search_states_examined": search_states,
        "input_digests": input_digests(
            catalog=catalog,
            fixture_manifest=fixture_manifest,
            solver_registry=solver_registry,
            property_registry=property_registry,
            promotion_registry=promotion_registry,
            conformance_registry=conformance_registry,
            suite_registry=suite_registry,
            contract_manifest=contract_manifest,
        ),
        "pairs": pair_records,
        "errors": sorted(set(errors)),
        "report_digest": "",
    }
    report["report_digest"] = compute_report_digest(report)
    return report


def validate_pair_record(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if record.get("pair_digest") != compute_pair_digest(record):
        errors.append("interoperability pair_digest does not match canonical record")
    if record.get("profile_a", "") >= record.get("profile_b", ""):
        errors.append("interoperability pair profiles must be canonical lexical order")
    return sorted(set(errors))


def validate_report(report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if report.get("schema_version") != "0.1":
        errors.append("interoperability report schema_version must be 0.1")
    if report.get("report_digest") != compute_report_digest(report):
        errors.append("interoperability report_digest does not match canonical report")
    pairs = report.get("pairs")
    if not isinstance(pairs, list):
        errors.append("interoperability report pairs must be an array")
        pairs = []
    for record in pairs:
        if isinstance(record, dict):
            errors.extend(validate_pair_record(record))
        else:
            errors.append("interoperability report contains non-object pair")
    counted = (
        report.get("co_configurable_count", 0)
        + report.get("exclusive_alternative_count", 0)
        + report.get("explicitly_incompatible_count", 0)
        + report.get("dependency_compatible_count", 0)
        + report.get("contextually_incompatible_count", 0)
    )
    if counted != report.get("pair_count"):
        errors.append("interoperability primary relationship counts do not sum to pair_count")
    return sorted(set(errors))
