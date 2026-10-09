#!/usr/bin/env python3
"""Integrated E2EESA conformance evaluator for PR 40."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

import assurance_levels
import certification_evidence
import crypto_registry
import deprecation_migration
import formal_verification
import profile_engine
import research_promotion

SHA256_PREFIX = "sha256:"
PROFILE_STATUS_SET = {
    "recommended","allowed","provisional","experimental","legacy","deprecated","prohibited"
}

INPUT_KEYS = (
    "profile_catalog",
    "cryptographic_registry",
    "security_properties_registry",
    "threat_model_registry",
    "assurance_levels_registry",
    "certification_evidence_registry",
    "research_promotion_registry",
    "deprecation_migration_registry",
    "conformance_registry",
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return SHA256_PREFIX + hashlib.sha256(canonical_bytes(value)).hexdigest()


def request_core(request: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in request.items() if key != "request_digest"}


def compute_request_digest(request: dict[str, Any]) -> str:
    return canonical_digest(request_core(request))


def result_core(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key != "result_digest"}


def compute_result_digest(result: dict[str, Any]) -> str:
    return canonical_digest(result_core(result))


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _policy_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["profile_ref"]: item
        for item in registry.get("policies", [])
        if isinstance(item, dict) and isinstance(item.get("profile_ref"), str)
    }


def validate_registry(
    registry: dict[str, Any],
    catalog: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("conformance registry schema_version must be 0.1")

    known_families = {
        item.get("family_id")
        for item in catalog.get("families", [])
        if isinstance(item, dict) and isinstance(item.get("family_id"), str)
    }
    evidence_only = registry.get("evidence_only_families")
    if not isinstance(evidence_only, list) or len(evidence_only) != len(set(evidence_only)):
        errors.append("conformance evidence_only_families must be a unique array")
        evidence_only = []
    unknown_evidence_families = sorted(set(evidence_only) - known_families)
    if unknown_evidence_families:
        errors.append(
            "conformance registry has unknown evidence-only families: "
            + ", ".join(unknown_evidence_families)
        )

    policies = registry.get("policies")
    if not isinstance(policies, list) or not policies:
        return errors + ["conformance registry policies must be non-empty"]

    seen_refs: set[str] = set()
    seen_scopes: set[str] = set()
    for index, policy in enumerate(policies):
        prefix = f"conformance policies[{index}]"
        if not isinstance(policy, dict):
            errors.append(f"{prefix} must be an object")
            continue
        ref = policy.get("profile_ref")
        if not isinstance(ref, str) or not ref:
            errors.append(f"{prefix} profile_ref must be non-empty")
        elif ref in seen_refs:
            errors.append(f"{prefix} duplicate profile_ref {ref}")
        else:
            seen_refs.add(ref)
        scope = policy.get("claim_scope")
        if scope not in {
            "production-conformance","candidate-evaluation","migration-only"
        }:
            errors.append(f"{prefix} invalid claim_scope {scope}")
        elif scope in seen_scopes:
            errors.append(f"{prefix} duplicate claim_scope {scope}")
        else:
            seen_scopes.add(scope)
        statuses = policy.get("allowed_profile_statuses")
        if (
            not isinstance(statuses, list)
            or not statuses
            or len(statuses) != len(set(statuses))
            or not set(statuses).issubset(PROFILE_STATUS_SET)
        ):
            errors.append(f"{prefix} allowed_profile_statuses are invalid")
        accepted = policy.get("allowed_accepted_nondefault_statuses")
        if (
            not isinstance(accepted, list)
            or len(accepted) != len(set(accepted))
            or not set(accepted).issubset(
                {"provisional","experimental","legacy","deprecated"}
            )
        ):
            errors.append(
                f"{prefix} allowed_accepted_nondefault_statuses are invalid"
            )
        for field in (
            "permits_candidate_profiles",
            "requires_migration_context",
            "production_certification_eligible",
            "enforce_required_promotions",
            "require_full_property_coverage",
        ):
            if not isinstance(policy.get(field), bool):
                errors.append(f"{prefix} {field} must be boolean")

    expected_scopes = {
        "production-conformance","candidate-evaluation","migration-only"
    }
    if seen_scopes != expected_scopes:
        errors.append("conformance registry must define all three claim scopes exactly once")

    by_scope = {
        item.get("claim_scope"): item
        for item in policies if isinstance(item, dict)
    }
    production = by_scope.get("production-conformance", {})
    if set(production.get("allowed_profile_statuses", [])) != {"recommended","allowed"}:
        errors.append("production conformance must allow only recommended/allowed profiles")
    if production.get("allowed_accepted_nondefault_statuses") != []:
        errors.append("production conformance must not accept non-default statuses")
    if production.get("production_certification_eligible") is not True:
        errors.append("production conformance must be certification eligible")

    candidate = by_scope.get("candidate-evaluation", {})
    if set(candidate.get("allowed_profile_statuses", [])) != {
        "recommended","allowed","provisional"
    }:
        errors.append("candidate evaluation profile status set is invalid")
    if set(candidate.get("allowed_accepted_nondefault_statuses", [])) != {"provisional"}:
        errors.append("candidate evaluation may accept only provisional status")
    if candidate.get("permits_candidate_profiles") is not True:
        errors.append("candidate evaluation must permit Candidate profiles")
    if candidate.get("production_certification_eligible") is not False:
        errors.append("candidate evaluation cannot be production certification eligible")

    migration = by_scope.get("migration-only", {})
    if set(migration.get("allowed_profile_statuses", [])) != {
        "recommended","allowed","legacy","deprecated"
    }:
        errors.append("migration-only profile status set is invalid")
    if set(migration.get("allowed_accepted_nondefault_statuses", [])) != {
        "legacy","deprecated"
    }:
        errors.append("migration-only may accept only legacy/deprecated statuses")
    if migration.get("requires_migration_context") is not True:
        errors.append("migration-only policy must require migration context")
    if migration.get("production_certification_eligible") is not False:
        errors.append("migration-only cannot be production certification eligible")

    return sorted(set(errors))


def evaluation_input_digests(
    *,
    catalog: dict[str, Any],
    crypto: dict[str, Any],
    property_registry: dict[str, Any],
    threat_registry: dict[str, Any],
    assurance_registry: dict[str, Any],
    certification_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    migration_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
) -> dict[str, str]:
    return {
        "profile_catalog": canonical_digest(catalog),
        "cryptographic_registry": canonical_digest(crypto),
        "security_properties_registry": canonical_digest(property_registry),
        "threat_model_registry": canonical_digest(threat_registry),
        "assurance_levels_registry": canonical_digest(assurance_registry),
        "certification_evidence_registry": canonical_digest(certification_registry),
        "research_promotion_registry": canonical_digest(promotion_registry),
        "deprecation_migration_registry": canonical_digest(migration_registry),
        "conformance_registry": canonical_digest(conformance_registry),
    }


def _reason(
    reasons: list[dict[str, str]],
    code: str,
    severity: str,
    message: str,
) -> None:
    reasons.append({"code": code, "severity": severity, "message": message})


def _basis_errors(
    *,
    catalog: dict[str, Any],
    crypto: dict[str, Any],
    property_registry: dict[str, Any],
    assurance_registry: dict[str, Any],
    certification_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    migration_registry: dict[str, Any],
    conformance_registry: dict[str, Any],
) -> list[str]:
    property_ids = {
        item.get("id")
        for item in property_registry.get("properties", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    errors: list[str] = []
    errors.extend(
        "profile catalog: " + error
        for error in profile_engine.validate_catalog(
            catalog, known_property_ids=property_ids
        )
    )
    errors.extend(
        "cryptographic registry: " + error
        for error in crypto_registry.validate_registry(crypto)
    )
    errors.extend(
        "assurance registry: " + error
        for error in assurance_levels.validate_registry(
            assurance_registry, catalog, property_ids
        )
    )
    errors.extend(
        "certification evidence registry: " + error
        for error in certification_evidence.validate_registry(
            certification_registry, assurance_registry
        )
    )
    errors.extend(
        "research promotion registry: " + error
        for error in research_promotion.validate_registry(promotion_registry)
    )
    errors.extend(
        "deprecation migration registry: " + error
        for error in deprecation_migration.validate_registry(migration_registry)
    )
    errors.extend(
        "conformance registry: " + error
        for error in validate_registry(conformance_registry, catalog)
    )
    return sorted(set(errors))


def evaluate_conformance(
    request: dict[str, Any],
    assurance_plan: dict[str, Any],
    certification_bundle: dict[str, Any],
    *,
    conformance_registry: dict[str, Any],
    catalog: dict[str, Any],
    crypto: dict[str, Any],
    property_registry: dict[str, Any],
    threat_registry: dict[str, Any],
    assurance_registry: dict[str, Any],
    certification_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    migration_registry: dict[str, Any],
    migration_plan: dict[str, Any] | None = None,
    migration_case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons: list[dict[str, str]] = []
    conditional_properties: set[str] = set()
    not_supported_properties: set[str] = set()
    required_promoted_refs: set[str] = set()
    required_properties: set[str] = set()
    effective_profiles: list[str] = []
    in_scope_families: set[str] = set()

    for error in _basis_errors(
        catalog=catalog,
        crypto=crypto,
        property_registry=property_registry,
        assurance_registry=assurance_registry,
        certification_registry=certification_registry,
        promotion_registry=promotion_registry,
        migration_registry=migration_registry,
        conformance_registry=conformance_registry,
    ):
        _reason(reasons, "invalid-evaluation-basis", "error", error)

    policy_ref = request.get("conformance_policy_ref")
    policy = _policy_map(conformance_registry).get(policy_ref)
    if policy is None:
        _reason(
            reasons,"unknown-conformance-policy","error",
            f"unknown conformance policy {policy_ref}"
        )
        policy = {
            "claim_scope":"production-conformance",
            "allowed_profile_statuses":[],
            "allowed_accepted_nondefault_statuses":[],
            "permits_candidate_profiles":False,
            "requires_migration_context":False,
            "production_certification_eligible":False,
            "enforce_required_promotions":False,
            "require_full_property_coverage":True,
        }

    expected_basis = evaluation_input_digests(
        catalog=catalog,
        crypto=crypto,
        property_registry=property_registry,
        threat_registry=threat_registry,
        assurance_registry=assurance_registry,
        certification_registry=certification_registry,
        promotion_registry=promotion_registry,
        migration_registry=migration_registry,
        conformance_registry=conformance_registry,
    )
    supplied_basis = request.get("input_digests")
    if not isinstance(supplied_basis, dict):
        _reason(reasons,"missing-input-digests","error","request input_digests must be an object")
        supplied_basis = {}
    for key in INPUT_KEYS:
        if supplied_basis.get(key) != expected_basis[key]:
            _reason(
                reasons,"evaluation-basis-digest-mismatch","error",
                f"input digest mismatch for {key}"
            )

    if request.get("request_digest") != compute_request_digest(request):
        _reason(
            reasons,"request-digest-mismatch","error",
            "request_digest does not match canonical conformance request"
        )

    standard_version = request.get("standard_version")
    if standard_version != catalog.get("standard_version"):
        _reason(
            reasons,"standard-version-mismatch","error",
            "request standard_version does not match profile catalog"
        )

    evaluated_errors: list[str] = []
    evaluated_at = _parse_time(
        request.get("evaluated_at"), "conformance evaluated_at", evaluated_errors
    )
    for error in evaluated_errors:
        _reason(reasons,"invalid-evaluation-time","error",error)

    for field in ("product_id","product_version","platform"):
        request_value = request.get(field)
        if assurance_plan.get(field) != request_value:
            _reason(
                reasons,"product-identity-mismatch","error",
                f"assurance plan {field} does not match request"
            )
        if certification_bundle.get(field) != request_value:
            _reason(
                reasons,"product-identity-mismatch","error",
                f"certification bundle {field} does not match request"
            )

    expected_plan_digest = formal_verification.canonical_digest(assurance_plan)
    expected_bundle_digest = canonical_digest(certification_bundle)
    expected_config_digest = formal_verification.canonical_digest(
        assurance_plan.get("configuration")
    )
    if request.get("assurance_plan_digest") != expected_plan_digest:
        _reason(
            reasons,"assurance-plan-digest-mismatch","error",
            "request assurance_plan_digest does not match assurance plan"
        )
    if request.get("certification_bundle_digest") != expected_bundle_digest:
        _reason(
            reasons,"certification-bundle-digest-mismatch","error",
            "request certification_bundle_digest does not match certification bundle"
        )
    if request.get("configuration_digest") != expected_config_digest:
        _reason(
            reasons,"configuration-digest-mismatch","error",
            "request configuration_digest does not match assurance-plan configuration"
        )
    if certification_bundle.get("configuration_digest") != expected_config_digest:
        _reason(
            reasons,"configuration-digest-mismatch","error",
            "certification bundle configuration_digest does not match assurance-plan configuration"
        )
    if certification_bundle.get("assurance_plan_digest") != expected_plan_digest:
        _reason(
            reasons,"assurance-plan-digest-mismatch","error",
            "certification bundle assurance_plan_digest does not match assurance plan"
        )
    for field in ("source_digest","artifact_digest"):
        if request.get(field) != certification_bundle.get(field):
            _reason(
                reasons,"artifact-identity-mismatch","error",
                f"request {field} does not match certification bundle"
            )

    property_ids = {
        item.get("id")
        for item in property_registry.get("properties", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    threat_ids = {
        item.get("id")
        for item in threat_registry.get("threats", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }

    assurance_result = assurance_levels.evaluate_plan(
        assurance_plan, assurance_registry, catalog, property_ids
    )
    if not assurance_result.get("valid"):
        for error in assurance_result.get("errors", []):
            _reason(reasons,"assurance-plan-invalid","error",error)
    else:
        effective_profiles = sorted(assurance_result.get("effective_profiles", []))

    bundle_errors = certification_evidence.validate_bundle(
        certification_bundle,
        assurance_plan,
        certification_registry,
        assurance_registry,
        catalog,
        property_ids,
        threat_ids,
    )
    for error in bundle_errors:
        _reason(reasons,"certification-evidence-invalid","error",error)

    observed_errors: list[str] = []
    observed_at = _parse_time(
        certification_bundle.get("observed_at"),
        "certification bundle observed_at",
        observed_errors,
    )
    for error in observed_errors:
        _reason(reasons,"certification-observation-time-invalid","error",error)
    if (
        evaluated_at is not None
        and observed_at is not None
        and observed_at > evaluated_at
    ):
        _reason(
            reasons,"future-certification-evidence","error",
            "certification bundle observation time is after conformance evaluation time"
        )

    config = assurance_plan.get("configuration")
    accepted_nondefault: set[str] = set()
    if isinstance(config, dict):
        accepted = config.get("accepted_nondefault_statuses")
        if isinstance(accepted, list):
            accepted_nondefault = {
                value for value in accepted if isinstance(value, str)
            }
    disallowed_accepted = sorted(
        accepted_nondefault
        - set(policy.get("allowed_accepted_nondefault_statuses", []))
    )
    if disallowed_accepted:
        _reason(
            reasons,"nondefault-status-acceptance-not-permitted","error",
            "configuration accepts statuses not permitted by conformance policy: "
            + ", ".join(disallowed_accepted)
        )

    catalog_by_ref = {
        profile_engine.profile_ref(item): item
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    effective_set = set(effective_profiles)
    for ref in effective_profiles:
        profile = catalog_by_ref.get(ref)
        if profile is None:
            _reason(
                reasons,"resolved-profile-missing","error",
                f"resolved profile {ref} is absent from catalog"
            )
            continue
        status = profile.get("status")
        if status not in set(policy.get("allowed_profile_statuses", [])):
            _reason(
                reasons,"profile-status-not-permitted","error",
                f"effective profile {ref} has status {status}, not permitted for {policy.get('claim_scope')}"
            )
        if status in {"experimental","prohibited"}:
            _reason(
                reasons,"nonconformant-profile-lifecycle","error",
                f"effective profile {ref} cannot receive a conformance pass with status {status}"
            )

    if effective_profiles:
        actual_bundle_profiles = certification_bundle.get("effective_profile_refs")
        if not isinstance(actual_bundle_profiles, list) or sorted(actual_bundle_profiles) != effective_profiles:
            _reason(
                reasons,"effective-profile-evidence-mismatch","error",
                "certification bundle effective_profile_refs differ from resolved configuration"
            )

    families = {
        item.get("family_id"): item
        for item in catalog.get("families", [])
        if isinstance(item, dict) and isinstance(item.get("family_id"), str)
    }
    scope_entries = request.get("family_scope")
    scope_map: dict[str, dict[str, Any]] = {}
    if not isinstance(scope_entries, list):
        _reason(
            reasons,"family-scope-invalid","error",
            "family_scope must be an array covering every catalog family"
        )
        scope_entries = []
    for index, item in enumerate(scope_entries):
        if not isinstance(item, dict):
            _reason(
                reasons,"family-scope-invalid","error",
                f"family_scope[{index}] must be an object"
            )
            continue
        family_id = item.get("family_id")
        if not isinstance(family_id, str) or family_id not in families:
            _reason(
                reasons,"family-scope-invalid","error",
                f"family_scope[{index}] references unknown family {family_id}"
            )
            continue
        if family_id in scope_map:
            _reason(
                reasons,"family-scope-invalid","error",
                f"family {family_id} appears more than once in family_scope"
            )
            continue
        applicability = item.get("applicability")
        rationale = item.get("rationale")
        if applicability not in {"in-scope","not-applicable"}:
            _reason(
                reasons,"family-scope-invalid","error",
                f"family {family_id} has invalid applicability {applicability}"
            )
        if applicability == "not-applicable":
            if not isinstance(rationale, str) or not rationale.strip():
                _reason(
                    reasons,"family-scope-rationale-missing","error",
                    f"not-applicable family {family_id} requires rationale"
                )
        elif rationale is not None and not isinstance(rationale, str):
            _reason(
                reasons,"family-scope-invalid","error",
                f"in-scope family {family_id} rationale must be null or string"
            )
        scope_map[family_id] = item
    missing_scope = sorted(set(families) - set(scope_map))
    if missing_scope:
        _reason(
            reasons,"family-scope-incomplete","error",
            "family_scope omits catalog families: " + ", ".join(missing_scope)
        )
    if set(scope_map) - set(families):
        _reason(
            reasons,"family-scope-invalid","error",
            "family_scope contains unknown families"
        )
    in_scope_families = {
        family_id
        for family_id, item in scope_map.items()
        if item.get("applicability") == "in-scope"
    }
    for family_id, family in families.items():
        if family.get("cardinality") == "exactly-one" and family_id not in in_scope_families:
            _reason(
                reasons,"mandatory-family-out-of-scope","error",
                f"exactly-one family {family_id} must be in scope"
            )

    profiles_by_family: dict[str, set[str]] = {}
    for ref in effective_profiles:
        family_id = catalog_by_ref.get(ref, {}).get("family_id")
        if isinstance(family_id, str):
            profiles_by_family.setdefault(family_id, set()).add(ref)
            if family_id not in in_scope_families:
                _reason(
                    reasons,"effective-profile-family-out-of-scope","error",
                    f"effective profile {ref} belongs to family {family_id} declared not applicable"
                )
    for family_id in sorted(in_scope_families):
        if not profiles_by_family.get(family_id):
            _reason(
                reasons,"in-scope-family-unimplemented","error",
                f"in-scope family {family_id} has no effective profile"
            )

    promoted_state_by_ref = {
        item.get("profile_ref"): item
        for item in promotion_registry.get("promoted_profiles", [])
        if isinstance(item, dict) and isinstance(item.get("profile_ref"), str)
    }
    if policy.get("permits_candidate_profiles"):
        for ref in effective_profiles:
            profile = catalog_by_ref.get(ref, {})
            if profile.get("status") != "provisional":
                continue
            state = promoted_state_by_ref.get(ref)
            if state is None or state.get("lifecycle_state") != "candidate":
                _reason(
                    reasons,"provisional-profile-not-candidate","error",
                    f"provisional effective profile {ref} lacks exact PR 38 Candidate state"
                )
    else:
        for ref in effective_profiles:
            if catalog_by_ref.get(ref, {}).get("status") == "provisional":
                _reason(
                    reasons,"candidate-profile-not-permitted","error",
                    f"provisional profile {ref} is not permitted under {policy.get('claim_scope')}"
                )

    if policy.get("enforce_required_promotions"):
        for ref, state in sorted(promoted_state_by_ref.items()):
            if state.get("lifecycle_state") != "required":
                continue
            required_promoted_refs.add(ref)
            profile = catalog_by_ref.get(ref)
            if profile is None:
                _reason(
                    reasons,"required-profile-missing-from-catalog","error",
                    f"Required promoted profile {ref} is absent from evaluated catalog"
                )
                continue
            family_id = profile.get("family_id")
            if family_id in in_scope_families and ref not in effective_set:
                _reason(
                    reasons,"required-profile-not-selected","error",
                    f"Required profile {ref} must be selected because family {family_id} is in scope"
                )

    evidence_only = set(conformance_registry.get("evidence_only_families", []))
    if policy.get("require_full_property_coverage"):
        for ref in effective_profiles:
            profile = catalog_by_ref.get(ref)
            if not isinstance(profile, dict):
                continue
            family_id = profile.get("family_id")
            if (
                family_id in in_scope_families
                and family_id not in evidence_only
            ):
                required_properties.update(
                    prop
                    for prop in profile.get("security_properties", [])
                    if isinstance(prop, str)
                )

    claimed = {
        prop
        for prop in assurance_plan.get("claimed_property_ids", [])
        if isinstance(prop, str)
    }
    missing_claims = sorted(required_properties - claimed)
    if missing_claims:
        _reason(
            reasons,"promised-property-not-assessed","error",
            "in-scope profiles promise properties absent from assurance plan: "
            + ", ".join(missing_claims)
        )

    claim_records_by_property: dict[str, list[dict[str, Any]]] = {}
    for item in certification_bundle.get("claim_evidence", []):
        if isinstance(item, dict) and isinstance(item.get("property_id"), str):
            claim_records_by_property.setdefault(item["property_id"], []).append(item)

    for property_id in sorted(required_properties):
        records = claim_records_by_property.get(property_id, [])
        if not records:
            _reason(
                reasons,"promised-property-evidence-missing","error",
                f"required security property {property_id} has no claim evidence"
            )
            continue
        statuses = {
            item.get("status") for item in records if isinstance(item.get("status"), str)
        }
        if "not-supported" in statuses:
            not_supported_properties.add(property_id)
            _reason(
                reasons,"promised-property-not-supported","error",
                f"required security property {property_id} is explicitly not supported"
            )
        elif "conditional" in statuses:
            conditional_properties.add(property_id)
            _reason(
                reasons,"promised-property-conditional","conditional",
                f"required security property {property_id} is conditional"
            )
        elif "supported" not in statuses:
            _reason(
                reasons,"promised-property-evidence-invalid","error",
                f"required security property {property_id} lacks supported claim evidence"
            )

    migration_context = request.get("migration_context")
    if policy.get("requires_migration_context"):
        if not isinstance(migration_context, dict):
            _reason(
                reasons,"migration-context-required","error",
                "migration-only conformance requires migration_context"
            )
        elif migration_plan is None or migration_case is None:
            _reason(
                reasons,"migration-artifacts-required","error",
                "migration-only conformance requires exact migration plan and case inputs"
            )
        else:
            if migration_context.get("plan_digest") != deprecation_migration.compute_plan_digest(migration_plan):
                _reason(
                    reasons,"migration-plan-digest-mismatch","error",
                    "migration_context plan_digest does not match migration plan"
                )
            if migration_context.get("case_digest") != deprecation_migration.compute_case_digest(migration_case):
                _reason(
                    reasons,"migration-case-digest-mismatch","error",
                    "migration_context case_digest does not match migration case"
                )
            if migration_case.get("plan_digest") != migration_plan.get("plan_digest"):
                _reason(
                    reasons,"migration-case-plan-mismatch","error",
                    "migration case does not bind supplied migration plan"
                )
            case_result = deprecation_migration.validate_case(
                migration_case,
                migration_plan,
                migration_registry,
                crypto,
                catalog,
                as_of=request.get("evaluated_at"),
            )
            for error in case_result.errors:
                _reason(reasons,"migration-case-invalid","error",error)
            for obligation in case_result.overdue:
                _reason(reasons,"migration-obligation-overdue","error",obligation)
            operation = migration_context.get("operation")
            material_created_at = migration_context.get("material_created_at")
            if operation not in {"historical-read-verify","migration-transform"}:
                _reason(
                    reasons,"migration-operation-invalid","error",
                    f"migration-only operation {operation} is not permitted"
                )
            else:
                try:
                    allowed = deprecation_migration.operation_allowed(
                        migration_plan,
                        migration_case,
                        operation=operation,
                        as_of=request["evaluated_at"],
                        material_created_at=material_created_at,
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    allowed = False
                    _reason(
                        reasons,"migration-operation-invalid","error",
                        f"migration operation could not be evaluated: {exc}"
                    )
                if not allowed:
                    _reason(
                        reasons,"migration-operation-not-allowed","error",
                        f"PR 39 does not allow {operation} for the bound material at evaluation time"
                    )
            usage_digest = migration_context.get("usage_evidence_digest")
            if (
                not isinstance(usage_digest, str)
                or not usage_digest.startswith("sha256:")
                or len(usage_digest) != 71
            ):
                _reason(
                    reasons,"migration-usage-evidence-invalid","error",
                    "migration usage evidence digest must be sha256"
                )
            if (
                not isinstance(migration_context.get("usage_reference"), str)
                or not migration_context["usage_reference"].strip()
            ):
                _reason(
                    reasons,"migration-usage-evidence-invalid","error",
                    "migration usage reference must be non-empty"
                )
    else:
        if migration_context is not None:
            _reason(
                reasons,"migration-context-not-permitted","error",
                f"{policy.get('claim_scope')} must not include migration_context"
            )
        if migration_plan is not None or migration_case is not None:
            _reason(
                reasons,"migration-artifacts-not-permitted","error",
                f"{policy.get('claim_scope')} must not supply migration plan/case"
            )

    error_reasons = [item for item in reasons if item["severity"] == "error"]
    conditional_reasons = [
        item for item in reasons if item["severity"] == "conditional"
    ]
    if error_reasons:
        verdict = "fail"
    elif conditional_reasons:
        verdict = "indeterminate"
    else:
        verdict = "pass"

    result = {
        "schema_version":"0.1",
        "assessment_id":request.get("assessment_id"),
        "request_digest":request.get("request_digest"),
        "conformance_policy_ref":policy_ref,
        "claim_scope":policy.get("claim_scope"),
        "verdict":verdict,
        # Legacy evaluation checks configuration/evidence consistency only.
        # It has no component inventory and cannot establish product eligibility.
        "production_certification_eligible":False,
        "product_id":request.get("product_id"),
        "product_version":request.get("product_version"),
        "platform":request.get("platform"),
        "evaluated_at":request.get("evaluated_at"),
        "effective_profile_refs":sorted(effective_profiles),
        "in_scope_family_ids":sorted(in_scope_families),
        "required_promoted_profile_refs":sorted(required_promoted_refs),
        "required_property_ids":sorted(required_properties),
        "conditional_property_ids":sorted(conditional_properties),
        "not_supported_property_ids":sorted(not_supported_properties),
        "input_digests":expected_basis,
        "reasons":sorted(
            reasons,
            key=lambda item:(item["severity"],item["code"],item["message"]),
        ),
        "result_digest":"",
    }
    result["result_digest"] = compute_result_digest(result)
    return result


def validate_result(
    result: dict[str, Any],
    expected: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if result.get("schema_version") != "0.1":
        errors.append("conformance result schema_version must be 0.1")
    if result.get("result_digest") != compute_result_digest(result):
        errors.append("conformance result_digest does not match canonical result")
    if canonical_bytes(result_core(result)) != canonical_bytes(result_core(expected)):
        errors.append("conformance result content differs from deterministic reevaluation")
    return sorted(set(errors))
