"""Validate SSDF-aligned development/change-control evidence."""
from pathlib import Path
from assurance_common import (
    binding_errors, check_schema, load_json, profile_errors, required_true,
    timestamp, validate_fixture_set,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "development-ssdf-baseline@0.1.0"
CONTROLS = {
    "SD-REQUIREMENTS": "PO.1", "SD-OWNERS": "PO.2", "SD-TOOLS": "PO.3",
    "SD-RELEASE-GATES": "PO.4", "SD-ENVIRONMENT": "PO.5",
    "SD-SOURCE-ACCESS": "PS.1", "SD-RELEASE-AUTH": "PS.2", "SD-ARCHIVE": "PS.3",
    "SD-DESIGN": "PW.1", "SD-DESIGN-REVIEW": "PW.2", "SD-DEPENDENCIES": "PW.4",
    "SD-SECURE-CODE": "PW.5", "SD-BUILD-CONFIG": "PW.6", "SD-CODE-REVIEW": "PW.7",
    "SD-TESTING": "PW.8", "SD-DEFAULTS": "PW.9", "SD-INTAKE": "RV.1",
    "SD-REMEDIATION": "RV.2", "SD-ROOT-CAUSE": "RV.3",
}
GATES = {"unit-tests", "adversarial-tests", "fuzz", "secret-scan", "dependency-scan", "static-analysis"}


def validate_policy(policy, catalog, *, root=ROOT):
    errors = check_schema(root, "secure-development-policy", policy)
    if errors:
        return errors
    errors.extend(profile_errors(policy["profile_ref"], "secure-development", catalog))
    if policy["profile_ref"] != PROFILE:
        errors.append("unsupported development profile")
    if set(policy["required_control_ids"]) != set(CONTROLS):
        errors.append("development policy must retain every baseline control")
    if set(policy["required_gate_ids"]) != GATES:
        errors.append("development policy must retain all test/scanning gates")
    errors.extend(required_true(policy, ("require_independent_review", "require_critical_high_remediation")))
    return errors


def validate_release(policy, evidence, catalog, *, root=ROOT):
    errors = validate_policy(policy, catalog, root=root)
    errors.extend(check_schema(root, "secure-development-evidence", evidence))
    if errors:
        return errors
    errors.extend(binding_errors(policy, evidence))
    controls = {c["control_id"]: c for c in evidence["controls"]}
    if len(controls) != len(evidence["controls"]) or set(controls) != set(CONTROLS):
        errors.append("development controls: incomplete or duplicate coverage")
    for control in controls.values():
        if control["status"] != "satisfied":
            errors.append(f"{control['control_id']}: baseline controls cannot be omitted or waived")
    authors, reviewers = set(evidence["author_ids"]), set(evidence["reviewer_ids"])
    if authors & reviewers or len(reviewers) < policy["minimum_independent_reviewers"]:
        errors.append("review: insufficient independent reviewers or self-review")
    authorizers = set(evidence["release_authorizer_ids"])
    if len(authorizers) < 2 or not authorizers & reviewers:
        errors.append("release: two distinct authorizers including an independent reviewer are required")
    errors.extend(required_true(evidence, (
        "reviews_approved", "source_access_reviewed", "training_current",
        "isolated_build_environments", "release_archive_complete", "two_person_release_authorization",
        "threat_model_updated", "security_change_classification_reviewed",
    )))
    if evidence["cryptographic_change"] and not evidence["qualified_crypto_review"]:
        errors.append("cryptographic change requires qualified protocol/cryptographic review")
    if evidence["reviewed_source_digest"] != evidence["source_digest"]:
        errors.append("review: approval must bind the exact release source")
    gates = {g["gate_id"]: g for g in evidence["gates"]}
    if len(gates) != len(evidence["gates"]) or set(gates) != GATES:
        errors.append("release gates: missing, extra or duplicate gate evidence")
    try:
        observed = timestamp(evidence["observed_at"])
        for gate in gates.values():
            if gate["status"] != "passed" or gate["source_digest"] != evidence["source_digest"]:
                errors.append(f"{gate['gate_id']}: required gate did not pass on the exact source")
            at = timestamp(gate["completed_at"])
            if at > observed or (observed-at).total_seconds() > policy["max_check_age_hours"] * 3600:
                errors.append(f"{gate['gate_id']}: future or stale check")
        finding_ids = [f["finding_id"] for f in evidence["findings"]]
        if len(finding_ids) != len(set(finding_ids)):
            errors.append("findings: duplicate IDs")
        for finding in evidence["findings"]:
            status = finding["status"]
            if status == "open":
                errors.append("release cannot proceed with open security findings")
            elif status == "fixed":
                if finding["retest_report_ref"] is None or finding["remediation_source_digest"] != evidence["source_digest"]:
                    errors.append("fixed finding: retest must bind the current remediated source")
            elif status == "accepted":
                if finding["severity"] in {"critical", "high"}:
                    errors.append("critical/high findings cannot be waived for release")
                if finding["accepted_by"] not in reviewers or not finding["rationale"]:
                    errors.append("risk acceptance requires an independent reviewer and rationale")
                if finding["acceptance_expires_at"] is None or timestamp(finding["acceptance_expires_at"]) <= observed:
                    errors.append("risk acceptance is missing or expired")
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def validate_repository(root, catalog):
    errors = []
    try:
        registry = load_json(root / "registry/secure-development.json")
        errors.extend(check_schema(root, "secure-development-registry", registry))
        mapping = {c["control_id"]: c["ssdf_practice_id"] for c in registry["controls"]}
        if mapping != CONTROLS or len(registry["controls"]) != len(CONTROLS):
            errors.append("development registry: missing/changed SSDF practice coverage")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"development registry: {exc}")
    return errors + validate_fixture_set(root, "secure-development", validate_release, catalog)
