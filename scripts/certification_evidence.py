#!/usr/bin/env python3
"""Certification evidence-bundle validation for E2EESA PR 28."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import assurance_levels
import formal_verification
import profile_engine

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_ACCESS_RANK = {
    "none": 0,
    "restricted-review": 1,
    "escrowed-source": 2,
    "full-source": 3,
}


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _string_list(value: object, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (not nonempty or len(value) > 0)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
        and len(value) == len(set(value))
    )


def validate_registry(
    registry: dict[str, Any],
    assurance_registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("certification evidence registry schema_version must be 0.1")

    evidence_types = registry.get("evidence_types")
    if not isinstance(evidence_types, list) or not evidence_types:
        return errors + ["certification evidence registry evidence_types must be non-empty"]

    known_types: set[str] = set()
    for index, item in enumerate(evidence_types):
        prefix = f"certification evidence registry evidence_types[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        name = item.get("type")
        if not isinstance(name, str) or not name:
            errors.append(f"{prefix} type must be non-empty")
        elif name in known_types:
            errors.append(f"{prefix} duplicate type {name}")
        else:
            known_types.add(name)
        if not isinstance(item.get("independence_required"), bool):
            errors.append(f"{prefix} independence_required must be boolean")

    assurance_refs = {
        item.get("profile_ref")
        for item in assurance_registry.get("levels", [])
        if isinstance(item, dict)
    }
    requirements = registry.get("assurance_requirements")
    if not isinstance(requirements, list) or not requirements:
        return errors + ["certification evidence registry assurance_requirements must be non-empty"]

    seen_refs: set[str] = set()
    previous_required: set[str] = set()
    for index, item in enumerate(requirements):
        prefix = f"certification evidence registry assurance_requirements[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        ref = item.get("assurance_profile_ref")
        if ref not in assurance_refs:
            errors.append(f"{prefix} unknown assurance_profile_ref {ref}")
        if ref in seen_refs:
            errors.append(f"{prefix} duplicate assurance_profile_ref {ref}")
        seen_refs.add(ref)

        required = item.get("required_evidence_types")
        if not _string_list(required, nonempty=True):
            errors.append(f"{prefix} required_evidence_types must be unique and non-empty")
            required_set: set[str] = set()
        else:
            required_set = set(required)
            unknown = sorted(required_set - known_types)
            if unknown:
                errors.append(f"{prefix} unknown evidence types: {', '.join(unknown)}")
            if not previous_required.issubset(required_set):
                errors.append(f"{prefix} breaks monotonic evidence-type inclusion")
        previous_required = required_set

        if item.get("minimum_source_access") not in SOURCE_ACCESS_RANK:
            errors.append(f"{prefix} invalid minimum_source_access")

    if seen_refs != assurance_refs:
        missing = sorted(assurance_refs - seen_refs)
        extra = sorted(seen_refs - assurance_refs)
        if missing:
            errors.append("certification evidence registry missing assurance refs: " + ", ".join(missing))
        if extra:
            errors.append("certification evidence registry has extra assurance refs: " + ", ".join(extra))

    return errors


def validate_bundle(
    bundle: dict[str, Any],
    assurance_plan: dict[str, Any],
    evidence_registry: dict[str, Any],
    assurance_registry: dict[str, Any],
    catalog: dict[str, Any],
    property_ids: set[str],
    threat_ids: set[str],
) -> list[str]:
    errors = validate_registry(evidence_registry, assurance_registry)

    assurance_result = assurance_levels.evaluate_plan(
        assurance_plan,
        assurance_registry,
        catalog,
        property_ids,
    )
    if not assurance_result["valid"]:
        return errors + ["assurance plan: " + e for e in assurance_result["errors"]]

    required_fields = {
        "schema_version","bundle_id","product_id","product_version","platform",
        "assurance_profile_ref","assurance_plan_digest","configuration_digest",
        "effective_profile_refs","source_digest","artifact_digest","source_access",
        "observed_at","evidence_items","claim_evidence","exceptions",
    }
    missing = sorted(required_fields - bundle.keys())
    if missing:
        return errors + ["certification bundle missing fields: " + ", ".join(missing)]

    if bundle.get("schema_version") != "0.1":
        errors.append("certification bundle schema_version must be 0.1")

    for field in ("product_id", "product_version", "platform"):
        if bundle.get(field) != assurance_plan.get(field):
            errors.append(f"certification bundle {field} does not match assurance plan")

    if bundle.get("assurance_profile_ref") != assurance_plan.get("assurance_profile_ref"):
        errors.append("certification bundle assurance_profile_ref does not match assurance plan")

    if bundle.get("assurance_plan_digest") != formal_verification.canonical_digest(assurance_plan):
        errors.append("certification bundle assurance_plan_digest mismatch")

    if bundle.get("configuration_digest") != formal_verification.canonical_digest(assurance_plan["configuration"]):
        errors.append("certification bundle configuration_digest mismatch")

    expected_profiles = sorted(assurance_result.get("effective_profiles", []))
    actual_profiles = bundle.get("effective_profile_refs")
    if not _string_list(actual_profiles, nonempty=True):
        errors.append("certification bundle effective_profile_refs must be unique and non-empty")
    elif sorted(actual_profiles) != expected_profiles:
        errors.append("certification bundle effective_profile_refs do not match resolved configuration")

    for field in ("source_digest", "artifact_digest"):
        value = bundle.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            errors.append(f"certification bundle {field} must be sha256")

    observed_at = _parse_time(bundle.get("observed_at"), "certification bundle observed_at", errors)

    requirement_map = {
        item["assurance_profile_ref"]: item
        for item in evidence_registry.get("assurance_requirements", [])
        if isinstance(item, dict) and isinstance(item.get("assurance_profile_ref"), str)
    }
    req = requirement_map.get(bundle.get("assurance_profile_ref"))
    if req is None:
        errors.append("no certification evidence requirements for assurance profile")
        return sorted(set(errors))

    source_access = bundle.get("source_access")
    if source_access not in SOURCE_ACCESS_RANK:
        errors.append("certification bundle has invalid source_access")
    elif SOURCE_ACCESS_RANK[source_access] < SOURCE_ACCESS_RANK[req["minimum_source_access"]]:
        errors.append(
            f"source access {source_access} is below assurance minimum {req['minimum_source_access']}"
        )

    type_meta = {
        item["type"]: item
        for item in evidence_registry.get("evidence_types", [])
        if isinstance(item, dict) and isinstance(item.get("type"), str)
    }

    items = bundle.get("evidence_items")
    if not isinstance(items, list) or not items:
        errors.append("certification bundle evidence_items must be non-empty")
        return sorted(set(errors))

    item_by_id: dict[str, dict[str, Any]] = {}
    types_present: set[str] = set()
    independent_assessor_coverage: set[str] = set()
    effective_set = set(expected_profiles)

    for index, item in enumerate(items):
        prefix = f"certification evidence_items[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue

        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            errors.append(f"{prefix} evidence_id must be non-empty")
        elif evidence_id in item_by_id:
            errors.append(f"{prefix} duplicate evidence_id {evidence_id}")
        else:
            item_by_id[evidence_id] = item

        evidence_type = item.get("evidence_type")
        meta = type_meta.get(evidence_type)
        if meta is None:
            errors.append(f"{prefix} unknown evidence_type {evidence_type}")
        else:
            types_present.add(evidence_type)
            if meta.get("independence_required"):
                if item.get("issuer_role") != "independent-assessor":
                    errors.append(f"{prefix} evidence type {evidence_type} requires independent-assessor issuer role")
                assessor_ids = item.get("assessor_ids")
                if not _string_list(assessor_ids, nonempty=True):
                    errors.append(f"{prefix} independent evidence requires assessor_ids")
                else:
                    independent_assessor_coverage.update(assessor_ids)

        digest = item.get("digest")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            errors.append(f"{prefix} digest must be sha256")

        profile_refs = item.get("profile_refs")
        if not _string_list(profile_refs):
            errors.append(f"{prefix} profile_refs must be a unique string array")
        else:
            unknown_profiles = sorted(set(profile_refs) - effective_set)
            if unknown_profiles:
                errors.append(f"{prefix} profile_refs outside certification scope: {', '.join(unknown_profiles)}")

        properties = item.get("property_ids")
        if not _string_list(properties):
            errors.append(f"{prefix} property_ids must be a unique string array")
        else:
            unknown_properties = sorted(set(properties) - property_ids)
            if unknown_properties:
                errors.append(f"{prefix} unknown property_ids: {', '.join(unknown_properties)}")

        threats = item.get("threat_ids")
        if not _string_list(threats):
            errors.append(f"{prefix} threat_ids must be a unique string array")
        else:
            unknown_threats = sorted(set(threats) - threat_ids)
            if unknown_threats:
                errors.append(f"{prefix} unknown threat_ids: {', '.join(unknown_threats)}")

        item_time = _parse_time(item.get("observed_at"), f"{prefix} observed_at", errors)
        if observed_at is not None and item_time is not None and item_time > observed_at:
            errors.append(f"{prefix} is future-dated relative to bundle")

        if not isinstance(item.get("reference"), str) or not item["reference"].strip():
            errors.append(f"{prefix} reference must be non-empty")
        if not _string_list(item.get("limitations", [])):
            errors.append(f"{prefix} limitations must be a unique string array")

    missing_types = sorted(set(req["required_evidence_types"]) - types_present)
    if missing_types:
        errors.append("certification bundle missing required evidence types: " + ", ".join(missing_types))

    plan_assessors = set(assurance_plan.get("independent_assessor_ids", []))
    missing_assessors = sorted(plan_assessors - independent_assessor_coverage)
    if missing_assessors:
        errors.append("certification bundle lacks independent evidence from assessors: " + ", ".join(missing_assessors))

    for formal_req in assurance_result.get("derived_formal_requirements", []):
        ref = formal_req["formal_profile_ref"]
        properties_needed = set(formal_req["property_ids"])
        policy_items = [
            item for item in items
            if isinstance(item, dict)
            and item.get("evidence_type") == "formal-policy"
            and ref in set(item.get("profile_refs", []))
        ]
        evidence_items = [
            item for item in items
            if isinstance(item, dict)
            and item.get("evidence_type") == "formal-evidence"
            and ref in set(item.get("profile_refs", []))
            and properties_needed.issubset(set(item.get("property_ids", [])))
        ]
        if not policy_items:
            errors.append(f"missing formal-policy linkage for {ref}")
        if not evidence_items:
            errors.append(f"missing formal-evidence linkage for {ref}: {', '.join(sorted(properties_needed))}")

    claim_records = bundle.get("claim_evidence")
    if not isinstance(claim_records, list) or not claim_records:
        errors.append("certification bundle claim_evidence must be non-empty")
        claim_records = []

    supported_claims: set[str] = set()
    for index, claim in enumerate(claim_records):
        prefix = f"claim_evidence[{index}]"
        if not isinstance(claim, dict):
            errors.append(f"{prefix} must be an object")
            continue
        property_id = claim.get("property_id")
        if property_id not in property_ids:
            errors.append(f"{prefix} unknown property_id {property_id}")
        threats = claim.get("threat_ids")
        if not _string_list(threats, nonempty=True):
            errors.append(f"{prefix} threat_ids must be unique and non-empty")
        else:
            unknown_threats = sorted(set(threats) - threat_ids)
            if unknown_threats:
                errors.append(f"{prefix} unknown threat_ids: {', '.join(unknown_threats)}")
        evidence_ids = claim.get("evidence_ids")
        if not _string_list(evidence_ids, nonempty=True):
            errors.append(f"{prefix} evidence_ids must be unique and non-empty")
            referenced_items = []
        else:
            unknown_items = sorted(set(evidence_ids) - set(item_by_id))
            if unknown_items:
                errors.append(f"{prefix} references unknown evidence_ids: {', '.join(unknown_items)}")
            referenced_items = [item_by_id[eid] for eid in evidence_ids if eid in item_by_id]

        status = claim.get("status")
        if status not in {"supported", "conditional", "not-supported"}:
            errors.append(f"{prefix} invalid status")
        elif status in {"supported", "conditional"} and isinstance(property_id, str):
            supported_claims.add(property_id)
            if not any(property_id in set(item.get("property_ids", [])) for item in referenced_items):
                errors.append(f"{prefix} has no referenced evidence item scoped to property {property_id}")

        if not _string_list(claim.get("limitations", [])):
            errors.append(f"{prefix} limitations must be a unique string array")

    plan_claims = set(assurance_plan.get("claimed_property_ids", []))
    missing_claims = sorted(plan_claims - supported_claims)
    if missing_claims:
        errors.append("certification bundle lacks supporting claim-evidence records for: " + ", ".join(missing_claims))

    exceptions = bundle.get("exceptions")
    if not isinstance(exceptions, list):
        errors.append("certification bundle exceptions must be an array")
        exceptions = []

    seen_exception_ids: set[str] = set()
    for index, exception in enumerate(exceptions):
        prefix = f"exceptions[{index}]"
        if not isinstance(exception, dict):
            errors.append(f"{prefix} must be an object")
            continue
        exception_id = exception.get("exception_id")
        if not isinstance(exception_id, str) or not exception_id:
            errors.append(f"{prefix} exception_id must be non-empty")
        elif exception_id in seen_exception_ids:
            errors.append(f"{prefix} duplicate exception_id {exception_id}")
        else:
            seen_exception_ids.add(exception_id)

        strength = exception.get("requirement_strength")
        if strength not in {"SHOULD", "SHOULD-NOT", "PROFILE-LIMITATION"}:
            errors.append(f"{prefix} requirement_strength cannot waive MUST/MUST-NOT requirements")

        issued = _parse_time(exception.get("issued_at"), f"{prefix} issued_at", errors)
        expires = _parse_time(exception.get("expires_at"), f"{prefix} expires_at", errors)
        if issued is not None and expires is not None and expires <= issued:
            errors.append(f"{prefix} expires_at must be after issued_at")
        if observed_at is not None and issued is not None and issued > observed_at:
            errors.append(f"{prefix} is issued after bundle observation time")
        if observed_at is not None and expires is not None and expires <= observed_at:
            errors.append(f"{prefix} is expired at bundle observation time")

        for field in ("requirement_ref","rationale","security_consequence","approving_authority","remediation_plan"):
            if not isinstance(exception.get(field), str) or not exception[field].strip():
                errors.append(f"{prefix} {field} must be non-empty")

        matching_exception_items = [
            item for item in items
            if isinstance(item, dict) and item.get("evidence_type") == "exception-record"
        ]
        if not matching_exception_items:
            errors.append(f"{prefix} requires an exception-record evidence item")

    return sorted(set(errors))
