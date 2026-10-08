#!/usr/bin/env python3
"""Assurance-level resolution for E2EESA PR 27."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import profile_engine


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return value


def _string_list(value: object, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (not nonempty or len(value) > 0)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
        and len(value) == len(set(value))
    )


def level_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["profile_ref"]: item
        for item in registry.get("levels", [])
        if isinstance(item, dict) and isinstance(item.get("profile_ref"), str)
    }


def validate_registry(
    registry: dict[str, Any],
    catalog: dict[str, Any],
    property_ids: set[str],
) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("assurance registry schema_version must be 0.1")

    levels = registry.get("levels")
    if not isinstance(levels, list) or not levels:
        return errors + ["assurance registry levels must be a non-empty array"]

    catalog_by_ref = {
        profile_engine.profile_ref(p): p
        for p in catalog.get("profiles", [])
        if isinstance(p, dict)
    }

    seen_refs: set[str] = set()
    seen_ordinals: set[int] = set()
    verification_rank = {
        "verification-blackbox@0.1.0": 1,
        "verification-whitebox@0.1.0": 2,
        "verification-combined@0.1.0": 3,
    }
    prior_nonverification_required: set[str] = set()
    prior_verification_rank = 0
    prior_symbolic: set[str] = set()
    prior_refinement: set[str] = set()
    prior_computational: set[str] = set()
    prior_assessors = 0

    ordered = sorted(levels, key=lambda x: x.get("ordinal", 0) if isinstance(x, dict) else 0)
    for index, level in enumerate(ordered, start=1):
        prefix = f"assurance registry level[{index}]"
        if not isinstance(level, dict):
            errors.append(f"{prefix} must be an object")
            continue
        ref = level.get("profile_ref")
        ordinal = level.get("ordinal")
        if not isinstance(ref, str):
            errors.append(f"{prefix} profile_ref must be a string")
            continue
        if ref in seen_refs:
            errors.append(f"{prefix} duplicate profile_ref {ref}")
        seen_refs.add(ref)

        if ordinal != index:
            errors.append(f"{prefix} ordinals must be consecutive starting at 1")
        if isinstance(ordinal, int):
            if ordinal in seen_ordinals:
                errors.append(f"{prefix} duplicate ordinal {ordinal}")
            seen_ordinals.add(ordinal)

        profile = catalog_by_ref.get(ref)
        if profile is None:
            errors.append(f"{prefix} profile absent from catalog: {ref}")
        elif profile.get("family_id") != "assurance-level":
            errors.append(f"{prefix} catalog profile is not assurance-level: {ref}")

        required = set(level.get("required_profile_refs", []))
        unknown_required = sorted(required - set(catalog_by_ref))
        if unknown_required:
            errors.append(f"{prefix} unknown required profiles: {', '.join(unknown_required)}")
        verification_refs = sorted(required & set(verification_rank))
        if len(verification_refs) != 1:
            errors.append(f"{prefix} must require exactly one security-verification profile")
            current_verification_rank = 0
        else:
            current_verification_rank = verification_rank[verification_refs[0]]
            if current_verification_rank < prior_verification_rank:
                errors.append(f"{prefix} breaks monotonic verification depth")
        nonverification_required = required - set(verification_rank)
        if not prior_nonverification_required.issubset(nonverification_required):
            errors.append(f"{prefix} breaks monotonic required-profile inclusion")
        if profile is not None and set(profile.get("requires_profile_refs", [])) != required:
            errors.append(f"{prefix} catalog dependencies do not match assurance registry")

        assessors = level.get("minimum_independent_assessors")
        if not isinstance(assessors, int) or isinstance(assessors, bool) or assessors < 1:
            errors.append(f"{prefix} invalid minimum_independent_assessors")
        elif assessors < prior_assessors:
            errors.append(f"{prefix} assessor floor must be monotonic")
        else:
            prior_assessors = assessors

        for field, prior in (
            ("symbolic_property_ids", prior_symbolic),
            ("refinement_property_ids", prior_refinement),
            ("computational_property_ids", prior_computational),
        ):
            values = level.get(field)
            if not _string_list(values):
                errors.append(f"{prefix} {field} must be a unique string array")
                current = set()
            else:
                current = set(values)
                unknown = sorted(current - property_ids)
                if unknown:
                    errors.append(f"{prefix} unknown properties in {field}: {', '.join(unknown)}")
                if not prior.issubset(current):
                    errors.append(f"{prefix} breaks monotonic {field} inclusion")
            if field == "symbolic_property_ids":
                prior_symbolic = current
            elif field == "refinement_property_ids":
                prior_refinement = current
            else:
                prior_computational = current

        prior_nonverification_required = nonverification_required
        prior_verification_rank = current_verification_rank

    return errors


def evaluate_plan(
    plan: dict[str, Any],
    registry: dict[str, Any],
    catalog: dict[str, Any],
    property_ids: set[str],
) -> dict[str, Any]:
    errors = validate_registry(registry, catalog, property_ids)
    result = {"valid": False, "errors": errors, "derived_formal_requirements": []}
    if errors:
        return result

    required = {
        "schema_version", "plan_id", "assurance_profile_ref", "product_id",
        "product_version", "platform", "configuration", "claimed_property_ids",
        "independent_assessor_ids", "computational_scope_property_ids",
        "computational_exemptions",
    }
    missing = sorted(required - plan.keys())
    if missing:
        result["errors"].append("assurance plan missing fields: " + ", ".join(missing))
        return result
    if plan.get("schema_version") != "0.1":
        result["errors"].append("assurance plan schema_version must be 0.1")

    levels = level_map(registry)
    level = levels.get(plan.get("assurance_profile_ref"))
    if level is None:
        result["errors"].append("unknown assurance_profile_ref")
        return result

    config = plan.get("configuration")
    if not isinstance(config, dict):
        result["errors"].append("assurance plan configuration must be an object")
        return result

    resolved = profile_engine.resolve_configuration(
        catalog,
        config,
        known_property_ids=property_ids,
    )
    if not resolved.valid:
        result["errors"].extend("configuration: " + e for e in resolved.errors)
        return result

    effective = set(resolved.effective_profiles)
    if level["profile_ref"] not in effective:
        result["errors"].append("assurance profile is not selected in effective configuration")

    missing_profiles = sorted(set(level["required_profile_refs"]) - effective)
    if missing_profiles:
        result["errors"].append("missing assurance-required profiles: " + ", ".join(missing_profiles))

    claimed = plan.get("claimed_property_ids")
    if not _string_list(claimed, nonempty=True):
        result["errors"].append("claimed_property_ids must be a unique non-empty array")
        claimed = []
    for property_id in claimed:
        if property_id not in property_ids:
            result["errors"].append(f"unknown claimed property_id {property_id}")

    catalog_by_ref = {
        profile_engine.profile_ref(p): p
        for p in catalog.get("profiles", [])
        if isinstance(p, dict)
    }
    evidence_only_families = {"assurance-level", "security-verification", "formal-verification"}
    architecture_properties = {
        prop
        for ref in effective
        if catalog_by_ref.get(ref, {}).get("family_id") not in evidence_only_families
        for prop in catalog_by_ref.get(ref, {}).get("security_properties", [])
    }
    unsupported = sorted(set(claimed) - architecture_properties)
    if unsupported:
        result["errors"].append(
            "claimed properties are not provided by effective architecture: " + ", ".join(unsupported)
        )

    assessors = plan.get("independent_assessor_ids")
    if not _string_list(assessors, nonempty=True):
        result["errors"].append("independent_assessor_ids must be unique and non-empty")
        assessors = []
    if len(assessors) < level["minimum_independent_assessors"]:
        result["errors"].append(
            f"assurance level requires at least {level['minimum_independent_assessors']} independent assessors"
        )

    formal_requirements: list[dict[str, Any]] = []
    claimed_set = set(claimed)
    mappings = [
        ("formal-symbolic-protocol@0.1.0", "symbolic", set(level["symbolic_property_ids"])),
        ("formal-code-refinement@0.1.0", "code-refinement", set(level["refinement_property_ids"])),
    ]
    for ref, kind, covered in mappings:
        applicable = sorted(claimed_set & covered)
        if applicable:
            if ref not in effective:
                result["errors"].append(f"required formal profile missing from effective configuration: {ref}")
            formal_requirements.append({
                "formal_profile_ref": ref,
                "kind": kind,
                "property_ids": applicable,
            })

    scope = plan.get("computational_scope_property_ids")
    if not _string_list(scope):
        result["errors"].append("computational_scope_property_ids must be a unique string array")
        scope = []
    exemptions = plan.get("computational_exemptions")
    if not isinstance(exemptions, list):
        result["errors"].append("computational_exemptions must be an array")
        exemptions = []

    exemption_map: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(exemptions):
        prefix = f"computational_exemptions[{index}]"
        if not isinstance(item, dict):
            result["errors"].append(f"{prefix} must be an object")
            continue
        property_id = item.get("property_id")
        if property_id in exemption_map:
            result["errors"].append(f"duplicate computational exemption for {property_id}")
        if not isinstance(property_id, str) or property_id not in property_ids:
            result["errors"].append(f"{prefix} unknown property_id")
            continue
        rationale = item.get("rationale")
        refs = item.get("standardized_construction_refs")
        if not isinstance(rationale, str) or not rationale.strip():
            result["errors"].append(f"{prefix} rationale must be non-empty")
        if not _string_list(refs, nonempty=True):
            result["errors"].append(f"{prefix} standardized_construction_refs must be non-empty")
        exemption_map[property_id] = item

    computational_candidates = claimed_set & set(level["computational_property_ids"])
    scope_set = set(scope)
    if not scope_set.issubset(computational_candidates):
        result["errors"].append("computational proof scope contains properties not applicable at this assurance level")
    overlap = scope_set & set(exemption_map)
    if overlap:
        result["errors"].append("computational property cannot be both proof-scoped and exempted: " + ", ".join(sorted(overlap)))
    missing_decisions = sorted(computational_candidates - scope_set - set(exemption_map))
    if missing_decisions:
        result["errors"].append(
            "A5 computational properties require proof scope or explicit standardized-construction exemption: "
            + ", ".join(missing_decisions)
        )
    irrelevant_exemptions = sorted(set(exemption_map) - computational_candidates)
    if irrelevant_exemptions:
        result["errors"].append(
            "computational exemptions are not applicable to claimed A5 properties: "
            + ", ".join(irrelevant_exemptions)
        )

    if scope_set:
        ref = "formal-computational-proof@0.1.0"
        if ref not in effective:
            result["errors"].append(f"required formal profile missing from effective configuration: {ref}")
        formal_requirements.append({
            "formal_profile_ref": ref,
            "kind": "computational",
            "property_ids": sorted(scope_set),
        })

    result["derived_formal_requirements"] = formal_requirements
    result["effective_profiles"] = resolved.effective_profiles
    result["valid"] = not result["errors"]
    return result
