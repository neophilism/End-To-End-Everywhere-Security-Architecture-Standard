#!/usr/bin/env python3
"""Deterministic E2EESA compatibility/configuration solver for PR 42."""

from __future__ import annotations

import hashlib
import itertools
import json
from typing import Any, Iterable

import conformance_engine
import profile_engine
import research_promotion


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def request_core(request: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in request.items() if k != "request_digest"}


def compute_request_digest(request: dict[str, Any]) -> str:
    return canonical_digest(request_core(request))


def solution_core(solution: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in solution.items() if k != "solution_digest"}


def compute_solution_digest(solution: dict[str, Any]) -> str:
    return canonical_digest(solution_core(solution))


def result_core(result: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in result.items() if k != "result_digest"}


def compute_result_digest(result: dict[str, Any]) -> str:
    return canonical_digest(result_core(result))


def _diagnostic(code: str, severity: str, message: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


def _unique_strings(value: object) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and bool(item) for item in value)
        and len(value) == len(set(value))
    )


def _mode_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["id"]: item
        for item in registry.get("modes", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("compatibility solver registry schema_version must be 0.1")

    modes = registry.get("modes")
    if not isinstance(modes, list) or len(modes) != 3:
        errors.append("compatibility solver registry must define exactly three modes")
        modes = []
    seen: set[str] = set()
    expected = {
        "production": (
            {"allowed", "recommended"},
            set(),
        ),
        "candidate": (
            {"allowed", "provisional", "recommended"},
            {"provisional"},
        ),
        "migration": (
            {"allowed", "deprecated", "legacy", "recommended"},
            {"deprecated", "legacy"},
        ),
    }
    for index, item in enumerate(modes):
        prefix = f"compatibility solver modes[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        mode_id = item.get("id")
        if mode_id not in expected:
            errors.append(f"{prefix} unknown mode {mode_id}")
            continue
        if mode_id in seen:
            errors.append(f"{prefix} duplicate mode {mode_id}")
        seen.add(mode_id)
        statuses = item.get("eligible_statuses")
        accepted = item.get("accepted_nondefault_statuses")
        if not _unique_strings(statuses) or set(statuses) != expected[mode_id][0]:
            errors.append(f"{prefix} eligible_statuses mismatch")
        if not _unique_strings(accepted) or set(accepted) != expected[mode_id][1]:
            errors.append(f"{prefix} accepted_nondefault_statuses mismatch")
        if isinstance(statuses, list) and (
            "experimental" in statuses or "prohibited" in statuses
        ):
            errors.append(f"{prefix} must never admit experimental/prohibited status")
    if seen != set(expected):
        errors.append("compatibility solver registry mode set mismatch")

    statuses = registry.get("result_statuses")
    if not _unique_strings(statuses) or set(statuses) != {
        "solutions", "unsatisfiable", "invalid-request", "search-limit"
    }:
        errors.append("compatibility solver result_statuses mismatch")

    default_max = registry.get("default_max_solutions")
    maximum_max = registry.get("maximum_max_solutions")
    maximum_states = registry.get("maximum_search_states")
    for name, value in (
        ("default_max_solutions", default_max),
        ("maximum_max_solutions", maximum_max),
        ("maximum_search_states", maximum_states),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append(f"compatibility solver {name} must be positive integer")
    if (
        isinstance(default_max, int)
        and isinstance(maximum_max, int)
        and default_max > maximum_max
    ):
        errors.append(
            "compatibility solver default_max_solutions exceeds maximum_max_solutions"
        )
    return sorted(set(errors))


def input_digests(
    *,
    catalog: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
    solver_registry: dict[str, Any],
) -> dict[str, str]:
    return {
        "profile_catalog": canonical_digest(catalog),
        "security_properties_registry": canonical_digest(property_registry),
        "research_promotion_registry": canonical_digest(promotion_registry),
        "conformance_registry": canonical_digest(conformance_registry),
        "compatibility_solver_registry": canonical_digest(solver_registry),
    }


def _basis_errors(
    *,
    catalog: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
    solver_registry: dict[str, Any],
) -> list[str]:
    property_ids = {
        item.get("id")
        for item in property_registry.get("properties", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    errors = [
        "profile catalog: " + error
        for error in profile_engine.validate_catalog(
            catalog, known_property_ids=property_ids
        )
    ]
    errors.extend(
        "research promotion registry: " + error
        for error in research_promotion.validate_registry(promotion_registry)
    )
    errors.extend(
        "conformance registry: " + error
        for error in conformance_engine.validate_registry(
            conformance_registry, catalog
        )
    )
    errors.extend(
        "compatibility solver registry: " + error
        for error in validate_registry(solver_registry)
    )

    catalog_refs = {
        profile_engine.profile_ref(item)
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    for item in promotion_registry.get("promoted_profiles", []):
        if not isinstance(item, dict):
            continue
        ref = item.get("profile_ref")
        if isinstance(ref, str) and ref not in catalog_refs:
            errors.append(
                f"research promotion registry references profile absent from catalog: {ref}"
            )
    return sorted(set(errors))


def _candidate_state_map(
    promotion_registry: dict[str, Any],
) -> dict[str, str]:
    return {
        item.get("profile_ref"): item.get("lifecycle_state")
        for item in promotion_registry.get("promoted_profiles", [])
        if isinstance(item, dict)
        and isinstance(item.get("profile_ref"), str)
        and isinstance(item.get("lifecycle_state"), str)
    }


def _eligible(
    ref: str,
    profile: dict[str, Any],
    *,
    mode: dict[str, Any],
    promoted_states: dict[str, str],
) -> bool:
    status = profile.get("status")
    if status not in set(mode.get("eligible_statuses", [])):
        return False
    if status in {"experimental", "prohibited"}:
        return False
    if status == "provisional":
        return (
            mode.get("id") == "candidate"
            and promoted_states.get(ref) == "candidate"
        )
    return True


def _request_errors(
    request: dict[str, Any],
    *,
    solver_registry: dict[str, Any],
    catalog: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "request_id",
        "standard_version",
        "mode",
        "required_family_ids",
        "forbidden_family_ids",
        "desired_property_ids",
        "pinned_profile_refs",
        "excluded_profile_refs",
        "max_solutions",
        "enforce_required_promotions",
        "request_digest",
    }
    missing = sorted(required - request.keys())
    extra = sorted(set(request) - required)
    if missing:
        errors.append("solver request missing fields: " + ", ".join(missing))
    if extra:
        errors.append("solver request unknown fields: " + ", ".join(extra))
    if request.get("schema_version") != "0.1":
        errors.append("solver request schema_version must be 0.1")
    for field in ("request_id", "standard_version", "mode"):
        if not isinstance(request.get(field), str) or not request[field]:
            errors.append(f"solver request {field} must be non-empty")

    if request.get("standard_version") != catalog.get("standard_version"):
        errors.append("solver request standard_version does not match catalog")

    modes = _mode_map(solver_registry)
    mode = modes.get(request.get("mode"))
    if mode is None:
        errors.append(f"solver request unknown mode {request.get('mode')}")

    list_fields = (
        "required_family_ids",
        "forbidden_family_ids",
        "desired_property_ids",
        "pinned_profile_refs",
        "excluded_profile_refs",
    )
    for field in list_fields:
        if not _unique_strings(request.get(field)):
            errors.append(f"solver request {field} must be a unique string array")

    max_solutions = request.get("max_solutions")
    maximum = solver_registry.get("maximum_max_solutions")
    if (
        not isinstance(max_solutions, int)
        or isinstance(max_solutions, bool)
        or max_solutions < 1
        or not isinstance(maximum, int)
        or max_solutions > maximum
    ):
        errors.append(
            f"solver request max_solutions must be integer 1..{maximum}"
        )
    if not isinstance(request.get("enforce_required_promotions"), bool):
        errors.append("solver request enforce_required_promotions must be boolean")

    if request.get("request_digest") != compute_request_digest(request):
        errors.append("solver request_digest does not match canonical request")

    families = {
        item.get("family_id"): item
        for item in catalog.get("families", [])
        if isinstance(item, dict) and isinstance(item.get("family_id"), str)
    }
    profiles = {
        profile_engine.profile_ref(item): item
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    property_ids = {
        item.get("id")
        for item in property_registry.get("properties", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    evidence_only = set(conformance_registry.get("evidence_only_families", []))
    promoted_states = _candidate_state_map(promotion_registry)

    required_families = set(request.get("required_family_ids", []))
    forbidden_families = set(request.get("forbidden_family_ids", []))
    desired = set(request.get("desired_property_ids", []))
    pins = set(request.get("pinned_profile_refs", []))
    excluded = set(request.get("excluded_profile_refs", []))

    unknown_required = sorted(required_families - set(families))
    unknown_forbidden = sorted(forbidden_families - set(families))
    unknown_properties = sorted(desired - property_ids)
    unknown_pins = sorted(pins - set(profiles))
    unknown_excluded = sorted(excluded - set(profiles))
    if unknown_required:
        errors.append("unknown required families: " + ", ".join(unknown_required))
    if unknown_forbidden:
        errors.append("unknown forbidden families: " + ", ".join(unknown_forbidden))
    if unknown_properties:
        errors.append("unknown desired properties: " + ", ".join(unknown_properties))
    if unknown_pins:
        errors.append("unknown pinned profiles: " + ", ".join(unknown_pins))
    if unknown_excluded:
        errors.append("unknown excluded profiles: " + ", ".join(unknown_excluded))

    overlap = sorted(required_families & forbidden_families)
    if overlap:
        errors.append(
            "families cannot be both required and forbidden: " + ", ".join(overlap)
        )
    overlap = sorted(pins & excluded)
    if overlap:
        errors.append(
            "profiles cannot be both pinned and excluded: " + ", ".join(overlap)
        )

    for family_id, family in families.items():
        if (
            family.get("cardinality") == "exactly-one"
            and family_id in forbidden_families
        ):
            errors.append(f"exactly-one family cannot be forbidden: {family_id}")

    pins_by_family: dict[str, list[str]] = {}
    pinned_profile_ids: dict[str, set[str]] = {}
    if mode is not None:
        for ref in sorted(pins & set(profiles)):
            profile = profiles[ref]
            family_id = profile.get("family_id")
            if family_id in forbidden_families:
                errors.append(
                    f"pinned profile belongs to forbidden family: {ref}"
                )
            if not _eligible(
                ref,
                profile,
                mode=mode,
                promoted_states=promoted_states,
            ):
                errors.append(
                    f"pinned profile is not eligible in {mode['id']} mode: {ref}"
                )
            pins_by_family.setdefault(family_id, []).append(ref)
            parsed = profile_engine.parse_profile_ref(ref)
            if parsed is not None:
                pinned_profile_ids.setdefault(parsed[0], set()).add(parsed[1])

        for family_id, refs in pins_by_family.items():
            cardinality = families.get(family_id, {}).get("cardinality")
            if cardinality in {"exactly-one", "at-most-one"} and len(refs) > 1:
                errors.append(
                    f"pinned profiles violate {cardinality} family {family_id}"
                )
        for profile_id, versions in pinned_profile_ids.items():
            if len(versions) > 1:
                errors.append(
                    f"multiple pinned versions for profile {profile_id}: "
                    + ", ".join(sorted(versions))
                )

        eligible_by_family: dict[str, list[str]] = {}
        for ref, profile in profiles.items():
            if ref in excluded:
                continue
            family_id = profile.get("family_id")
            if family_id in forbidden_families:
                continue
            if _eligible(
                ref,
                profile,
                mode=mode,
                promoted_states=promoted_states,
            ):
                eligible_by_family.setdefault(family_id, []).append(ref)

        mandatory = {
            family_id
            for family_id, family in families.items()
            if family.get("cardinality") == "exactly-one"
        } | required_families | set(pins_by_family)

        for family_id in sorted(mandatory & set(families)):
            if not eligible_by_family.get(family_id):
                errors.append(
                    f"required family has no eligible profiles in {mode['id']} mode: "
                    f"{family_id}"
                )

        for property_id in sorted(desired & property_ids):
            providers = [
                ref
                for ref, profile in profiles.items()
                if (
                    profile.get("family_id") not in evidence_only
                    and property_id in profile.get("security_properties", [])
                    and ref not in excluded
                    and profile.get("family_id") not in forbidden_families
                    and _eligible(
                        ref,
                        profile,
                        mode=mode,
                        promoted_states=promoted_states,
                    )
                )
            ]
            if not providers:
                errors.append(
                    f"desired property has no eligible architecture provider: {property_id}"
                )

    return sorted(set(errors))


def _subsets(values: list[str], *, allow_empty: bool) -> list[tuple[str, ...]]:
    result: list[tuple[str, ...]] = [()] if allow_empty else []
    start = 1
    for size in range(start, len(values) + 1):
        result.extend(itertools.combinations(values, size))
    return result


def _family_options(
    *,
    family_id: str,
    family: dict[str, Any],
    eligible_refs: list[str],
    pinned_refs: set[str],
    mandatory: bool,
) -> list[tuple[str, ...]]:
    refs = sorted(eligible_refs)
    pinned = sorted(pinned_refs)
    cardinality = family.get("cardinality")

    if cardinality in {"exactly-one", "at-most-one"}:
        if pinned:
            return [tuple(pinned)] if len(pinned) == 1 else []
        if mandatory:
            return [(ref,) for ref in refs]
        return [()] + [(ref,) for ref in refs]

    # many / one-or-more
    options = _subsets(refs, allow_empty=not mandatory)
    if pinned:
        pinned_set = set(pinned)
        options = [
            option for option in options
            if pinned_set.issubset(set(option))
        ]
    return options


def _architecture_properties(
    effective_refs: Iterable[str],
    profiles: dict[str, dict[str, Any]],
    evidence_only_families: set[str],
) -> set[str]:
    result: set[str] = set()
    for ref in effective_refs:
        profile = profiles.get(ref)
        if not isinstance(profile, dict):
            continue
        if profile.get("family_id") in evidence_only_families:
            continue
        result.update(
            item
            for item in profile.get("security_properties", [])
            if isinstance(item, str)
        )
    return result


def _make_solution(
    *,
    request: dict[str, Any],
    selected_refs: set[str],
    resolved: profile_engine.ResolutionResult,
    profiles: dict[str, dict[str, Any]],
    mode: dict[str, Any],
    evidence_only_families: set[str],
) -> dict[str, Any]:
    selected_sorted = sorted(selected_refs)
    effective = sorted(resolved.effective_profiles)
    auto_added = sorted(set(effective) - set(selected_sorted))
    selected_families = {
        profiles[ref]["family_id"]
        for ref in selected_sorted
        if ref in profiles
    }
    effective_families = {
        profiles[ref]["family_id"]
        for ref in effective
        if ref in profiles
    }
    auto_families = sorted(effective_families - selected_families)
    properties = sorted(
        _architecture_properties(effective, profiles, evidence_only_families)
    )
    config_seed = {
        "mode": request.get("mode"),
        "selected_profiles": selected_sorted,
        "accepted_nondefault_statuses": sorted(
            mode.get("accepted_nondefault_statuses", [])
        ),
    }
    config_id = "solver-" + canonical_digest(config_seed)[7:23]
    configuration = {
        "schema_version": "0.1",
        "configuration_id": config_id,
        "standard_version": request.get("standard_version"),
        "selected_profiles": selected_sorted,
        "accepted_nondefault_statuses": sorted(
            mode.get("accepted_nondefault_statuses", [])
        ),
        "notes": (
            "PR 42 compatible configuration proposal only; "
            "requires PR 40 conformance evaluation."
        ),
    }
    seed = {
        "configuration": configuration,
        "effective_profile_refs": effective,
    }
    solution_id = "solution-" + canonical_digest(seed)[7:23]
    solution = {
        "solution_id": solution_id,
        "configuration": configuration,
        "effective_profile_refs": effective,
        "auto_added_profile_refs": auto_added,
        "effective_property_ids": properties,
        "in_scope_family_ids": sorted(effective_families),
        "auto_added_family_ids": auto_families,
        "solution_digest": "",
    }
    solution["solution_digest"] = compute_solution_digest(solution)
    return solution


def solve(
    request: dict[str, Any],
    *,
    solver_registry: dict[str, Any],
    catalog: dict[str, Any],
    property_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
) -> dict[str, Any]:
    diagnostics: list[dict[str, str]] = []
    basis_errors = _basis_errors(
        catalog=catalog,
        property_registry=property_registry,
        promotion_registry=promotion_registry,
        conformance_registry=conformance_registry,
        solver_registry=solver_registry,
    )
    for error in basis_errors:
        diagnostics.append(
            _diagnostic("invalid-evaluation-basis", "error", error)
        )

    request_errors = _request_errors(
        request,
        solver_registry=solver_registry,
        catalog=catalog,
        property_registry=property_registry,
        promotion_registry=promotion_registry,
        conformance_registry=conformance_registry,
    )
    for error in request_errors:
        diagnostics.append(_diagnostic("invalid-request", "error", error))

    basis_digests = input_digests(
        catalog=catalog,
        property_registry=property_registry,
        promotion_registry=promotion_registry,
        conformance_registry=conformance_registry,
        solver_registry=solver_registry,
    )
    if basis_errors or request_errors:
        result = {
            "schema_version": "0.1",
            "request_id": request.get("request_id"),
            "request_digest": request.get("request_digest"),
            "status": "invalid-request",
            "mode": request.get("mode"),
            "standard_version": request.get("standard_version"),
            "search_exhaustive": True,
            "search_states_examined": 0,
            "total_solution_count": 0,
            "returned_solution_count": 0,
            "truncated": False,
            "input_digests": basis_digests,
            "solutions": [],
            "diagnostics": sorted(
                diagnostics, key=lambda item: (item["code"], item["message"])
            ),
            "result_digest": "",
        }
        result["result_digest"] = compute_result_digest(result)
        return result

    modes = _mode_map(solver_registry)
    mode = modes[request["mode"]]
    profiles = {
        profile_engine.profile_ref(item): item
        for item in catalog["profiles"]
        if isinstance(item, dict)
    }
    families = {
        item["family_id"]: item
        for item in catalog["families"]
        if isinstance(item, dict)
    }
    evidence_only = set(conformance_registry.get("evidence_only_families", []))
    promoted_states = _candidate_state_map(promotion_registry)
    excluded = set(request["excluded_profile_refs"])
    forbidden_families = set(request["forbidden_family_ids"])
    desired_properties = set(request["desired_property_ids"])
    pins = set(request["pinned_profile_refs"])

    eligible_by_family: dict[str, list[str]] = {}
    for ref, profile in profiles.items():
        family_id = profile.get("family_id")
        if ref in excluded or family_id in forbidden_families:
            continue
        if _eligible(
            ref,
            profile,
            mode=mode,
            promoted_states=promoted_states,
        ):
            eligible_by_family.setdefault(family_id, []).append(ref)
    for values in eligible_by_family.values():
        values.sort()

    pins_by_family: dict[str, set[str]] = {}
    for ref in pins:
        pins_by_family.setdefault(profiles[ref]["family_id"], set()).add(ref)

    mandatory_families = {
        family_id
        for family_id, family in families.items()
        if family.get("cardinality") == "exactly-one"
    }
    mandatory_families.update(request["required_family_ids"])
    mandatory_families.update(pins_by_family)

    provider_families: set[str] = set()
    for ref, profile in profiles.items():
        family_id = profile.get("family_id")
        if (
            family_id in evidence_only
            or family_id in forbidden_families
            or ref in excluded
            or not _eligible(
                ref,
                profile,
                mode=mode,
                promoted_states=promoted_states,
            )
        ):
            continue
        if desired_properties & set(profile.get("security_properties", [])):
            provider_families.add(family_id)

    search_families = sorted(mandatory_families | provider_families)
    options_by_family: list[tuple[str, list[tuple[str, ...]]]] = []
    for family_id in search_families:
        family = families[family_id]
        options = _family_options(
            family_id=family_id,
            family=family,
            eligible_refs=eligible_by_family.get(family_id, []),
            pinned_refs=pins_by_family.get(family_id, set()),
            mandatory=family_id in mandatory_families,
        )
        options_by_family.append((family_id, options))

    maximum_states = solver_registry["maximum_search_states"]
    states_examined = 0
    search_exhaustive = True
    rejection_samples: set[str] = set()
    solution_by_effective: dict[tuple[str, ...], dict[str, Any]] = {}

    required_states = {
        ref
        for ref, state in promoted_states.items()
        if state == "required"
    }

    def record_rejection(message: str) -> None:
        if len(rejection_samples) < 20:
            rejection_samples.add(message)

    def evaluate_selection(base_selected: set[str]) -> None:
        nonlocal states_examined, search_exhaustive
        if states_examined >= maximum_states:
            search_exhaustive = False
            return
        states_examined += 1

        selected = set(base_selected)
        for _ in range(len(families) + len(required_states) + 1):
            config = {
                "schema_version": "0.1",
                "configuration_id": "solver-probe",
                "standard_version": request["standard_version"],
                "selected_profiles": sorted(selected),
                "accepted_nondefault_statuses": sorted(
                    mode["accepted_nondefault_statuses"]
                ),
                "notes": "PR 42 compatibility solver probe.",
            }
            resolved = profile_engine.resolve_configuration(
                catalog,
                config,
                known_property_ids={
                    item.get("id")
                    for item in property_registry.get("properties", [])
                    if isinstance(item, dict)
                    and isinstance(item.get("id"), str)
                },
            )
            if not resolved.valid:
                record_rejection("resolver: " + " | ".join(resolved.errors[:3]))
                return

            effective = set(resolved.effective_profiles)
            if effective & excluded:
                record_rejection(
                    "excluded profile reached by dependency/selection: "
                    + ", ".join(sorted(effective & excluded))
                )
                return

            effective_families = {
                profiles[ref]["family_id"]
                for ref in effective
                if ref in profiles
            }
            blocked_families = effective_families & forbidden_families
            if blocked_families:
                record_rejection(
                    "forbidden family reached: "
                    + ", ".join(sorted(blocked_families))
                )
                return

            ineligible_effective = [
                ref
                for ref in effective
                if ref not in profiles
                or not _eligible(
                    ref,
                    profiles[ref],
                    mode=mode,
                    promoted_states=promoted_states,
                )
            ]
            if ineligible_effective:
                record_rejection(
                    "ineligible effective profiles: "
                    + ", ".join(sorted(ineligible_effective))
                )
                return

            missing_required: set[str] = set()
            if request["enforce_required_promotions"]:
                active_families = effective_families | mandatory_families
                for ref in required_states:
                    profile = profiles.get(ref)
                    if (
                        profile is not None
                        and profile.get("family_id") in active_families
                        and ref not in effective
                    ):
                        missing_required.add(ref)
            if missing_required:
                if missing_required & excluded:
                    record_rejection(
                        "Required promotion is excluded: "
                        + ", ".join(sorted(missing_required & excluded))
                    )
                    return
                for ref in missing_required:
                    profile = profiles.get(ref)
                    if profile is None:
                        record_rejection(f"Required promotion absent from catalog: {ref}")
                        return
                    if profile.get("family_id") in forbidden_families:
                        record_rejection(
                            f"Required promotion belongs to forbidden family: {ref}"
                        )
                        return
                    if not _eligible(
                        ref,
                        profile,
                        mode=mode,
                        promoted_states=promoted_states,
                    ):
                        record_rejection(
                            f"Required promotion is lifecycle-ineligible: {ref}"
                        )
                        return
                before = len(selected)
                selected.update(missing_required)
                if len(selected) == before:
                    record_rejection("Required-promotion closure could not progress")
                    return
                continue

            missing_mandatory = mandatory_families - effective_families
            if missing_mandatory:
                record_rejection(
                    "mandatory families absent after resolution: "
                    + ", ".join(sorted(missing_mandatory))
                )
                return

            architecture_properties = _architecture_properties(
                effective, profiles, evidence_only
            )
            missing_properties = desired_properties - architecture_properties
            if missing_properties:
                record_rejection(
                    "desired properties not covered: "
                    + ", ".join(sorted(missing_properties))
                )
                return

            solution = _make_solution(
                request=request,
                selected_refs=selected,
                resolved=resolved,
                profiles=profiles,
                mode=mode,
                evidence_only_families=evidence_only,
            )
            key = tuple(solution["effective_profile_refs"])
            prior = solution_by_effective.get(key)
            if prior is None:
                solution_by_effective[key] = solution
            else:
                prior_selected = tuple(prior["configuration"]["selected_profiles"])
                new_selected = tuple(solution["configuration"]["selected_profiles"])
                if new_selected < prior_selected:
                    solution_by_effective[key] = solution
            return

        record_rejection("Required-promotion closure exceeded deterministic bound")

    if any(not options for _, options in options_by_family):
        search_exhaustive = True
    else:
        option_lists = [options for _, options in options_by_family]
        for choice_tuple in itertools.product(*option_lists):
            if not search_exhaustive:
                break
            selected = set(pins)
            for option in choice_tuple:
                selected.update(option)
            evaluate_selection(selected)
            if not search_exhaustive:
                break

    all_solutions = sorted(
        solution_by_effective.values(),
        key=lambda item: (
            tuple(item["effective_profile_refs"]),
            tuple(item["configuration"]["selected_profiles"]),
        ),
    )

    for sample in sorted(rejection_samples):
        diagnostics.append(_diagnostic("candidate-rejected", "info", sample))

    if not search_exhaustive:
        status = "search-limit"
        total_solution_count: int | None = None
        truncated = True
    elif all_solutions:
        status = "solutions"
        total_solution_count = len(all_solutions)
        truncated = len(all_solutions) > request["max_solutions"]
    else:
        status = "unsatisfiable"
        total_solution_count = 0
        truncated = False

    returned = all_solutions[: request["max_solutions"]]
    result = {
        "schema_version": "0.1",
        "request_id": request["request_id"],
        "request_digest": request["request_digest"],
        "status": status,
        "mode": request["mode"],
        "standard_version": request["standard_version"],
        "search_exhaustive": search_exhaustive,
        "search_states_examined": states_examined,
        "total_solution_count": total_solution_count,
        "returned_solution_count": len(returned),
        "truncated": truncated,
        "input_digests": basis_digests,
        "solutions": returned,
        "diagnostics": sorted(
            diagnostics,
            key=lambda item: (item["severity"], item["code"], item["message"]),
        ),
        "result_digest": "",
    }
    result["result_digest"] = compute_result_digest(result)
    return result


def validate_result(
    result: dict[str, Any],
    expected: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if result.get("schema_version") != "0.1":
        errors.append("compatibility solver result schema_version must be 0.1")
    if result.get("result_digest") != compute_result_digest(result):
        errors.append("compatibility solver result_digest does not match canonical result")
    if canonical_bytes(result_core(result)) != canonical_bytes(result_core(expected)):
        errors.append(
            "compatibility solver result content differs from deterministic reevaluation"
        )
    return sorted(set(errors))
