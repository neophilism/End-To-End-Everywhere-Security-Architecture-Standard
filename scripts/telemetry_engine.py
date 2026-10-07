"""Validate minimized diagnostic and bounded differential-privacy evidence."""
from pathlib import Path
from assurance_common import (
    binding_errors, check_schema, digest, load_json, profile_errors,
    required_false, required_true, timestamp, validate_fixture_set,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_MODES = {
    "telemetry-none@0.1.0": "none",
    "telemetry-minimized-diagnostics@0.1.0": "diagnostics",
    "telemetry-dp-aggregate@0.1.0": "dp-aggregate",
}


def validate_policy(policy, catalog, *, root=ROOT):
    errors = check_schema(root, "telemetry-policy", policy)
    if errors:
        return errors
    errors.extend(profile_errors(policy["profile_ref"], "telemetry", catalog))
    mode = PROFILE_MODES.get(policy["profile_ref"])
    if mode is None:
        errors.append("unknown telemetry architecture")
    if policy["enabled_by_default"]:
        errors.append("telemetry must be opt-in and disabled by default")
    if mode == "none" and (policy["retention_seconds"] != 0 or policy["allowed_event_codes"]):
        errors.append("no-export telemetry policy cannot retain or authorize exported events")
    if mode != "none" and not policy["require_explicit_consent"]:
        errors.append("exported telemetry requires explicit revocable consent")
    if mode != "dp-aggregate" and policy["lifetime_epsilon_micros"] != 0:
        errors.append("non-DP profiles cannot carry a differential privacy budget")
    if mode == "dp-aggregate" and policy["lifetime_epsilon_micros"] == 0:
        errors.append("DP profile requires a positive lifetime budget")
    return errors


def privacy_spend(releases):
    """Basic sequential composition for pure-DP releases, in integer units."""
    return sum(r["epsilon_micros"] for r in releases)


def validate_telemetry(policy, evidence, catalog, *, root=ROOT):
    errors = validate_policy(policy, catalog, root=root)
    errors.extend(check_schema(root, "telemetry-evidence", evidence))
    if errors:
        return errors
    errors.extend(binding_errors(policy, evidence))
    mode = PROFILE_MODES[policy["profile_ref"]]
    if evidence["mode"] != mode:
        errors.append("telemetry: profile/mode mismatch")
    errors.extend(required_true(evidence, (
        "no_plaintext_or_secrets", "no_personal_identifiers", "no_raw_crash_dumps",
        "withdrawal_honored", "privacy_controls_tested",
    )))
    errors.extend(required_false(evidence, ("stable_pseudonyms", "cross_product_joining", "claims_network_anonymity")))
    if mode == "none":
        if evidence["collector_enabled"] or evidence["events"] or evidence["dp"] is not None or evidence["max_durable_age_seconds"]:
            errors.append("no-export telemetry: no collection/export/DP release or durable retention")
        return errors
    errors.extend(required_true(evidence, ("consent_granted", "collector_enabled", "export_authenticated_encrypted", "ip_stripped_before_collection")))
    if evidence["max_durable_age_seconds"] > policy["retention_seconds"]:
        errors.append("telemetry: retention exceeds policy")
    if mode == "diagnostics":
        if evidence["dp"] is not None:
            errors.append("minimized diagnostics cannot claim differential privacy")
        for event in evidence["events"]:
            if event["event_code"] not in policy["allowed_event_codes"]:
                errors.append("diagnostics: event not authorized by policy")
        return errors
    if evidence["events"]:
        errors.append("DP aggregate: individual diagnostics cannot be exported alongside aggregates")
    dp = evidence["dp"]
    if dp is None:
        return errors + ["DP aggregate: mechanism/accountant evidence is required"]
    if dp["accounting_domain"] != policy["accounting_domain"]:
        errors.append("DP: accounting domain mismatch")
    errors.extend(required_true(dp, ("accountant_continuity_verified", "all_prior_releases_included", "randomness_independently_tested", "raw_inputs_access_controlled", "raw_inputs_purged")))
    errors.extend(required_false(dp, ("claims_collector_cannot_observe_inputs", "budget_reset_on_update")))
    if dp["ledger_digest"] != digest(dp["releases"]):
        errors.append("DP: ledger digest mismatch")
    if len(dp["releases"]) < dp["previous_release_count"]:
        errors.append("DP: ledger rollback")
    ids = [r["release_id"] for r in dp["releases"]]
    if len(ids) != len(set(ids)):
        errors.append("DP: duplicate release IDs (privacy budget cannot be spent twice invisibly)")
    if privacy_spend(dp["releases"]) > policy["lifetime_epsilon_micros"]:
        errors.append("DP: cumulative lifetime privacy budget exceeded")
    try:
        observed = timestamp(evidence["observed_at"])
        previous_time = None
        for release in dp["releases"]:
            at = timestamp(release["published_at"])
            if at > observed or (previous_time is not None and at < previous_time):
                errors.append("DP: future or out-of-order publication")
            previous_time = at
            if release["metric_id"] not in policy["allowed_event_codes"]:
                errors.append("DP: unapproved metric/query")
            if release["distinct_users"] < policy["minimum_cohort_size"]:
                errors.append("DP: cohort below policy minimum")
            if release["noise_scale_denominator"] != release["epsilon_micros"]:
                errors.append("DP: noise scale must equal sensitivity/epsilon")
            errors.extend(required_true(release, ("contributions_clipped", "distinct_user_count_verified", "fresh_noise", "noise_mechanism_verified")))
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def validate_repository(root, catalog):
    errors = []
    try:
        registry = load_json(root / "registry/telemetry.json")
        errors.extend(check_schema(root, "telemetry-registry", registry))
        if set(registry["profile_refs"]) != set(PROFILE_MODES):
            errors.append("telemetry registry: unsupported profile set")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"telemetry registry: {exc}")
    return errors + validate_fixture_set(root, "telemetry", validate_telemetry, catalog)
