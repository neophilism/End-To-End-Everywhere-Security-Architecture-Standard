"""Validate method/profile/threat/property coverage of security assessments."""
from pathlib import Path
from assurance_common import (
    binding_errors, check_schema, load_json, profile_errors, required_false,
    required_true, timestamp, validate_fixture_set,
)
import profile_engine

ROOT = Path(__file__).resolve().parents[1]
PROFILE_METHODS = {
    "verification-blackbox@0.1.0": {"black-box", "property", "fuzz", "adversarial"},
    "verification-whitebox@0.1.0": {"white-box", "property", "fuzz", "adversarial", "protocol-model"},
    "verification-combined@0.1.0": {"black-box", "white-box", "property", "fuzz", "adversarial", "protocol-model"},
}
INTERNAL_PROPERTIES = {"SP-SOFTWARE-INTEGRITY", "SP-BUILD-PROVENANCE", "SP-FORWARD-SECRECY", "SP-POST-COMPROMISE-SECURITY"}


def resolve(policy, catalog, root):
    property_ids = {p["id"] for p in load_json(root / "registry/security-properties.json")["properties"]}
    return profile_engine.resolve_configuration(catalog, policy["configuration"], known_property_ids=property_ids)


def target_profiles(result, catalog):
    excluded = {"foundation", "example-architecture", "example-addons", "security-verification"}
    return {f"{p['profile_id']}@{p['profile_version']}" for p in catalog["profiles"]
            if p["family_id"] not in excluded and f"{p['profile_id']}@{p['profile_version']}" in result.effective_profiles}


def validate_policy(policy, catalog, *, root=ROOT):
    errors = check_schema(root, "verification-policy", policy)
    if errors:
        return errors
    errors.extend(profile_errors(policy["profile_ref"], "security-verification", catalog))
    if policy["profile_ref"] not in PROFILE_METHODS:
        return errors + ["unsupported verification profile"]
    result = resolve(policy, catalog, root)
    errors.extend(result.errors)
    if policy["profile_ref"] not in result.effective_profiles:
        errors.append("verification profile must be included in the assessed exact configuration")
    if not target_profiles(result, catalog):
        errors.append("verification: at least one real architecture profile is required")
    properties = {p["id"] for p in load_json(root / "registry/security-properties.json")["properties"]}
    threats = {t["id"] for t in load_json(root / "registry/threat-model.json")["threats"]}
    targets = target_profiles(result, catalog)
    provided = {prop for p in catalog["profiles"] if f"{p['profile_id']}@{p['profile_version']}" in targets for prop in p["security_properties"]}
    if not set(policy["required_property_ids"]).issubset(properties & provided):
        errors.append("verification: unknown or unprovided security-property claim")
    if not set(policy["required_threat_ids"]).issubset(threats):
        errors.append("verification: unknown threat identifiers")
    if policy["profile_ref"] == "verification-blackbox@0.1.0" and set(policy["required_property_ids"]) & INTERNAL_PROPERTIES:
        errors.append("black-box-only evidence cannot establish internal lifecycle/software properties")
    errors.extend(required_true(policy, ("require_independent_assessment", "require_no_unresolved_counterexamples")))
    return errors


def validate_assessment(policy, evidence, catalog, *, root=ROOT):
    errors = validate_policy(policy, catalog, root=root)
    errors.extend(check_schema(root, "verification-evidence", evidence))
    if errors:
        return errors
    errors.extend(binding_errors(policy, evidence))
    errors.extend(required_true(evidence, ("assessment_authenticated", "tools_and_corpora_pinned", "limitations_disclosed", "regressions_retained")))
    errors.extend(required_false(evidence, ("claims_no_unknown_vulnerabilities", "claims_full_formal_verification")))
    required_methods = PROFILE_METHODS[policy["profile_ref"]]
    resolved = resolve(policy, catalog, root)
    targets = target_profiles(resolved, catalog)
    if set(evidence["tested_profile_refs"]) != targets:
        errors.append("assessment: tested profile set does not equal the resolved architecture scope")
    assessors = set(evidence["assessor_ids"])
    if len(assessors) < policy["minimum_independent_assessors"] or assessors & set(evidence["source_author_ids"]):
        errors.append("assessment: independent assessor requirement not met")
    suite_ids = [s["suite_id"] for s in evidence["suites"]]
    if len(suite_ids) != len(set(suite_ids)):
        errors.append("assessment: duplicate suite IDs")
    covered_pairs, covered_properties, properties, threats = set(), set(), set(), set()
    profile_properties = {f"{p['profile_id']}@{p['profile_version']}":set(p["security_properties"]) for p in catalog["profiles"]}
    try:
        observed = timestamp(evidence["observed_at"])
        for suite in evidence["suites"]:
            if suite["assessor_id"] not in assessors:
                errors.append("suite: assessor is not authorized by this assessment")
            if suite["source_digest"] != evidence["source_digest"] or suite["artifact_digest"] != evidence["artifact_digest"]:
                errors.append("suite: exact source/artifact mismatch")
            if suite["status"] != "passed" or suite["failure_count"] or suite["unresolved_counterexamples"]:
                errors.append("suite: failed/skipped/flaky or unresolved counterexample evidence")
                continue
            if not set(suite["profile_refs"]).issubset(targets):
                errors.append("suite: unassessed architecture profile")
            if not set(suite["property_ids"]).issubset(policy["required_property_ids"]) or not set(suite["threat_ids"]).issubset(policy["required_threat_ids"]):
                errors.append("suite: property/threat coverage lies outside the declared assessment")
            provided = set().union(*(profile_properties.get(p,set()) for p in suite["profile_refs"]))
            if not set(suite["property_ids"]).issubset(provided):
                errors.append("suite: properties are not provided by its assessed profiles")
            at = timestamp(suite["completed_at"])
            if at > observed or (observed-at).total_seconds() > policy["maximum_evidence_age_hours"] * 3600:
                errors.append("suite: future or stale evidence")
            if suite["method"] == "fuzz":
                if suite["test_cases"] < policy["minimum_fuzz_inputs"] or suite["duration_seconds"] < policy["minimum_fuzz_duration_seconds"] or suite["corpus_digest"] is None:
                    errors.append("fuzz: insufficient campaign/corpus evidence")
            if suite["method"] == "property" and suite["test_cases"] < policy["minimum_property_cases"]:
                errors.append("property: insufficient generated-case evidence")
            if suite["method"] == "protocol-model":
                if suite["model"] is None or suite["model"]["standard_version"] != catalog["standard_version"]:
                    errors.append("protocol model: missing or wrong specification version")
            elif suite["model"] is not None:
                errors.append("model evidence must belong to a protocol-model suite")
            covered_pairs.update((p, suite["method"]) for p in suite["profile_refs"])
            covered_properties.update((p, prop) for p in suite["profile_refs"] for prop in suite["property_ids"] if prop in profile_properties.get(p,set()))
            properties.update(suite["property_ids"])
            threats.update(suite["threat_ids"])
    except ValueError as exc:
        errors.append(str(exc))
    missing = {(p,m) for p in targets for m in required_methods} - covered_pairs
    if missing:
        errors.append(f"assessment: missing per-profile method coverage: {sorted(missing)}")
    expected_properties = {(p, prop) for p in targets for prop in set(policy["required_property_ids"]) & profile_properties[p]}
    if expected_properties - covered_properties:
        errors.append("assessment: incomplete per-profile security-property coverage")
    if not set(policy["required_property_ids"]).issubset(properties) or not set(policy["required_threat_ids"]).issubset(threats):
        errors.append("assessment: incomplete security-property or threat coverage")
    return errors


def validate_repository(root, catalog):
    errors = []
    try:
        registry = load_json(root / "registry/security-verification.json")
        errors.extend(check_schema(root, "security-verification-registry", registry))
        mapping = {p["profile_ref"]:set(p["required_methods"]) for p in registry["profiles"]}
        if mapping != PROFILE_METHODS or len(registry["profiles"]) != len(PROFILE_METHODS):
            errors.append("verification registry: changed supported method requirements")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"verification registry: {exc}")
    return errors + validate_fixture_set(root, "verification", validate_assessment, catalog)
