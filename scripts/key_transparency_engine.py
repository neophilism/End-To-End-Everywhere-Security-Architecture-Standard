#!/usr/bin/env python3
"""Semantic validator for E2EESA Key Transparency evidence.

This module pins the current IETF Key Transparency drafts and validates that
cryptographically verified search/monitoring results satisfy the selected
deployment profile. It does not reimplement the draft's Merkle/prefix-tree,
VRF, commitment, or signature primitives; those booleans must be populated
only after cryptographic verification by the protocol implementation.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64,128}$")

PROFILE_BINDINGS = {
    "kt-contact-monitoring@0.1.0": "contact-monitoring",
    "kt-third-party-auditing@0.1.0": "third-party-auditing",
    "kt-third-party-management@0.1.0": "third-party-management",
}

REQUIRED_INVARIANTS = (
    "require_vrf_label_privacy",
    "require_value_commitments",
    "require_owner_monitoring",
    "require_fork_detection",
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _profile_index(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in catalog.get("profiles", []):
        if not isinstance(item, dict):
            continue
        pid = item.get("profile_id")
        version = item.get("profile_version")
        if isinstance(pid, str) and isinstance(version, str):
            result[f"{pid}@{version}"] = item
    return result


def _protocol_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("protocols", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _suite_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("cipher_suites", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def validate_protocol_registry(
    registry: dict[str, Any],
    source: str = "key transparency protocol registry",
) -> list[str]:
    errors: list[str] = []
    required_top = {
        "schema_version",
        "registry_version",
        "standard_version",
        "protocols",
        "cipher_suites",
    }
    extra = sorted(set(registry) - required_top)
    missing = sorted(required_top - registry.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if registry.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    protocols = registry.get("protocols")
    if not isinstance(protocols, list) or not protocols:
        errors.append(f"{source}: protocols must be a non-empty array")
        protocols = []
    by_id = _protocol_index(registry)
    protocol = by_id.get("KEYTRANS-IETF-05")
    if protocol is None:
        errors.append(f"{source}: missing KEYTRANS-IETF-05")
    else:
        if protocol.get("specification") != "draft-ietf-keytrans-protocol-05":
            errors.append(f"{source}: KEYTRANS-IETF-05 must pin draft-ietf-keytrans-protocol-05")
        if protocol.get("architecture_specification") != "draft-ietf-keytrans-architecture-09":
            errors.append(f"{source}: KEYTRANS-IETF-05 must pin draft-ietf-keytrans-architecture-09")
        if protocol.get("status") != "provisional":
            errors.append(f"{source}: active Internet-Draft protocol must remain provisional")

    suites = registry.get("cipher_suites")
    if not isinstance(suites, list) or not suites:
        errors.append(f"{source}: cipher_suites must be a non-empty array")
        suites = []
    suite_ids = [item.get("id") for item in suites if isinstance(item, dict)]
    if len(suite_ids) != len(set(suite_ids)):
        errors.append(f"{source}: cipher suite ids must be unique")
    for required_suite in ("0x0001", "0x0002"):
        if required_suite not in suite_ids:
            errors.append(f"{source}: missing required draft cipher suite {required_suite}")
    recommended = _suite_index(registry).get("0x0002")
    if recommended and recommended.get("status") != "recommended":
        errors.append(f"{source}: 0x0002 must be the recommended E2EESA 0.1 KT suite")
    return sorted(set(errors))


def validate_policy(
    policy: dict[str, Any],
    protocol_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "key transparency policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "profile_ref",
        "protocol_registry_version",
        "protocol_id",
        "cipher_suite_id",
        "deployment_mode",
        "max_ahead_ms",
        "max_behind_ms",
        "reasonable_monitoring_window_ms",
        "maximum_lifetime_ms",
        "require_vrf_label_privacy",
        "require_value_commitments",
        "require_owner_monitoring",
        "require_fork_detection",
        "require_checkpoint_persistence",
        "third_party_count",
        "third_party_threshold",
        "max_auditor_lag_ms",
        "require_service_update_signature",
    }
    allowed = required | {"notes"}
    extra = sorted(set(policy) - allowed)
    missing = sorted(required - policy.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if policy.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(policy.get("policy_id"), str) or not ID_RE.fullmatch(policy.get("policy_id", "")):
        errors.append(f"{source}: invalid policy_id")

    profile_ref = policy.get("profile_ref")
    expected_mode = PROFILE_BINDINGS.get(profile_ref)
    if expected_mode is None:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    else:
        profile = _profile_index(profile_catalog).get(profile_ref)
        if profile is None:
            errors.append(f"{source}: profile_ref not present in profile catalog")
        elif profile.get("family_id") != "key-transparency":
            errors.append(f"{source}: profile_ref must belong to key-transparency")
        if policy.get("deployment_mode") != expected_mode:
            errors.append(f"{source}: deployment_mode does not match selected profile")

    if policy.get("protocol_registry_version") != protocol_registry.get("registry_version"):
        errors.append(f"{source}: protocol_registry_version does not match registry")
    if policy.get("protocol_id") != "KEYTRANS-IETF-05":
        errors.append(f"{source}: protocol_id must be KEYTRANS-IETF-05")
    if policy.get("protocol_id") not in _protocol_index(protocol_registry):
        errors.append(f"{source}: protocol_id is not registered")
    suite = _suite_index(protocol_registry).get(policy.get("cipher_suite_id"))
    if suite is None:
        errors.append(f"{source}: cipher_suite_id is not registered")
    elif suite.get("status") == "prohibited":
        errors.append(f"{source}: selected cipher suite is prohibited")

    for field in REQUIRED_INVARIANTS:
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} is an E2EESA invariant and must be true")

    for field in ("max_ahead_ms", "max_behind_ms"):
        value = policy.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"{source}: {field} must be a non-negative integer")
    window = policy.get("reasonable_monitoring_window_ms")
    if not isinstance(window, int) or isinstance(window, bool) or window < 1:
        errors.append(f"{source}: reasonable_monitoring_window_ms must be positive")
    lifetime = policy.get("maximum_lifetime_ms")
    if lifetime is not None and (
        not isinstance(lifetime, int) or isinstance(lifetime, bool) or lifetime < 1
    ):
        errors.append(f"{source}: maximum_lifetime_ms must be null or positive")

    count = policy.get("third_party_count")
    threshold = policy.get("third_party_threshold")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        errors.append(f"{source}: third_party_count must be non-negative")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0:
        errors.append(f"{source}: third_party_threshold must be non-negative")

    if expected_mode == "contact-monitoring":
        if policy.get("require_checkpoint_persistence") is not True:
            errors.append(f"{source}: contact monitoring requires durable checkpoint persistence")
        if count != 0 or threshold != 0:
            errors.append(f"{source}: contact monitoring must not configure a third party")
        if policy.get("max_auditor_lag_ms") is not None:
            errors.append(f"{source}: contact monitoring must set max_auditor_lag_ms to null")
        if policy.get("require_service_update_signature") is not False:
            errors.append(f"{source}: contact monitoring must not require third-party-manager update signatures")

    if expected_mode in {"third-party-auditing", "third-party-management"}:
        if not isinstance(count, int) or count < 1:
            errors.append(f"{source}: third-party mode requires at least one independent third party")
        if not isinstance(threshold, int) or threshold < 1:
            errors.append(f"{source}: third-party mode requires a positive signature threshold")
        if isinstance(count, int) and count > 1 and isinstance(threshold, int):
            if threshold < count // 2 + 1:
                errors.append(f"{source}: multi-party threshold must be at least a majority")
        if isinstance(count, int) and isinstance(threshold, int) and threshold > count:
            errors.append(f"{source}: third_party_threshold cannot exceed third_party_count")

    if expected_mode == "third-party-auditing":
        if policy.get("require_checkpoint_persistence") is not True:
            errors.append(f"{source}: auditing profile requires durable checkpoint persistence")
        lag = policy.get("max_auditor_lag_ms")
        if not isinstance(lag, int) or isinstance(lag, bool) or lag < 0:
            errors.append(f"{source}: auditing profile requires non-negative max_auditor_lag_ms")
        if policy.get("require_service_update_signature") is not False:
            errors.append(f"{source}: auditing profile must not require manager-mode service update signatures")

    if expected_mode == "third-party-management":
        if policy.get("max_auditor_lag_ms") is not None:
            errors.append(f"{source}: management profile must set max_auditor_lag_ms to null")
        if policy.get("require_service_update_signature") is not True:
            errors.append(f"{source}: management profile requires service update signatures")

    return sorted(set(errors))


def validate_checkpoint(
    checkpoint: dict[str, Any],
    source: str = "key transparency checkpoint",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "log_id",
        "tree_size",
        "tree_root_hash",
        "tree_timestamp_ms",
        "subject_digest_hex",
        "label_version",
    }
    if set(checkpoint) != required:
        missing = sorted(required - checkpoint.keys())
        extra = sorted(set(checkpoint) - required)
        if missing:
            errors.append(f"{source}: missing fields: {', '.join(missing)}")
        if extra:
            errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if checkpoint.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(checkpoint.get("log_id"), str) or not ID_RE.fullmatch(checkpoint.get("log_id", "")):
        errors.append(f"{source}: invalid log_id")
    size = checkpoint.get("tree_size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        errors.append(f"{source}: tree_size must be positive")
    if not isinstance(checkpoint.get("tree_root_hash"), str) or not HEX64_RE.fullmatch(checkpoint.get("tree_root_hash", "")):
        errors.append(f"{source}: invalid tree_root_hash")
    timestamp = checkpoint.get("tree_timestamp_ms")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        errors.append(f"{source}: invalid tree_timestamp_ms")
    if not isinstance(checkpoint.get("subject_digest_hex"), str) or not DIGEST_RE.fullmatch(checkpoint.get("subject_digest_hex", "")):
        errors.append(f"{source}: invalid subject_digest_hex")
    version = checkpoint.get("label_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        errors.append(f"{source}: label_version must be non-negative")
    return sorted(set(errors))


def validate_evidence(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    protocol_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    expected_subject_digest_hex: str,
    previous_checkpoint: dict[str, Any] | None = None,
    source: str = "key transparency evidence",
) -> list[str]:
    errors = validate_policy(policy, protocol_registry, profile_catalog)
    if errors:
        return errors

    required = {
        "schema_version","evidence_id","profile_ref","protocol_id","cipher_suite_id",
        "subject_digest_hex","label_version","tree_size","tree_root_hash",
        "tree_timestamp_ms","observed_at_ms","tree_head_signature_verified",
        "vrf_proofs_verified","value_commitment_verified","search_proof_verified",
        "greatest_version_verified","subject_digest_matches_value","first_observation",
        "previous_tree_size","previous_tree_root_hash",
        "consistency_from_previous_verified","checkpoint_persisted",
        "owner_monitoring_verified","contact_monitor_required","contact_monitor_completed",
        "fork_check_channel","fork_check_completed","fork_detected","rollback_detected",
        "third_party_signatures_verified","auditor_lag_ms",
        "service_update_signature_verified","service_fork_detection_active",
    }
    extra = sorted(set(evidence) - required)
    missing = sorted(required - evidence.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return sorted(set(errors))

    if evidence.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(evidence.get("evidence_id"), str) or not ID_RE.fullmatch(evidence.get("evidence_id", "")):
        errors.append(f"{source}: invalid evidence_id")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("protocol_id") != policy.get("protocol_id"):
        errors.append(f"{source}: protocol_id does not match policy")
    if evidence.get("cipher_suite_id") != policy.get("cipher_suite_id"):
        errors.append(f"{source}: cipher_suite_id does not match policy")

    digest = evidence.get("subject_digest_hex")
    if digest != expected_subject_digest_hex:
        errors.append(f"{source}: subject digest does not match PR 11 verification subject")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        errors.append(f"{source}: invalid subject_digest_hex")

    for field in (
        "tree_head_signature_verified",
        "vrf_proofs_verified",
        "value_commitment_verified",
        "search_proof_verified",
        "greatest_version_verified",
        "subject_digest_matches_value",
        "owner_monitoring_verified",
        "fork_check_completed",
    ):
        if evidence.get(field) is not True:
            errors.append(f"{source}: {field} must be true")

    if evidence.get("fork_detected") is not False:
        errors.append(f"{source}: fork-detected view must not be accepted")
    if evidence.get("rollback_detected") is not False:
        errors.append(f"{source}: rollback-detected view must not be accepted")

    size = evidence.get("tree_size")
    version = evidence.get("label_version")
    timestamp = evidence.get("tree_timestamp_ms")
    observed = evidence.get("observed_at_ms")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        errors.append(f"{source}: tree_size must be positive")
    if not isinstance(version, int) or isinstance(version, bool) or version < 0:
        errors.append(f"{source}: label_version must be non-negative")
    if not isinstance(evidence.get("tree_root_hash"), str) or not HEX64_RE.fullmatch(evidence.get("tree_root_hash", "")):
        errors.append(f"{source}: invalid tree_root_hash")
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
        errors.append(f"{source}: invalid tree_timestamp_ms")
    if not isinstance(observed, int) or isinstance(observed, bool) or observed < 0:
        errors.append(f"{source}: invalid observed_at_ms")
    elif isinstance(timestamp, int):
        if timestamp > observed + policy["max_ahead_ms"]:
            errors.append(f"{source}: tree timestamp exceeds max_ahead_ms")
        if timestamp < observed - policy["max_behind_ms"]:
            errors.append(f"{source}: tree timestamp exceeds max_behind_ms")

    first = evidence.get("first_observation")
    if first is True:
        if previous_checkpoint is not None:
            errors.append(f"{source}: first_observation cannot supply previous checkpoint")
        if evidence.get("previous_tree_size") is not None or evidence.get("previous_tree_root_hash") is not None:
            errors.append(f"{source}: first observation must not claim previous tree state")
        if evidence.get("consistency_from_previous_verified") is not False:
            errors.append(f"{source}: first observation must not claim consistency from previous")
    elif first is False:
        if previous_checkpoint is None:
            errors.append(f"{source}: non-first observation requires previous checkpoint")
        else:
            errors.extend(validate_checkpoint(previous_checkpoint, "previous key transparency checkpoint"))
            previous_size = previous_checkpoint.get("tree_size")
            previous_root = previous_checkpoint.get("tree_root_hash")
            previous_version = previous_checkpoint.get("label_version")
            if evidence.get("previous_tree_size") != previous_size:
                errors.append(f"{source}: previous_tree_size does not match retained checkpoint")
            if evidence.get("previous_tree_root_hash") != previous_root:
                errors.append(f"{source}: previous_tree_root_hash does not match retained checkpoint")
            if isinstance(size, int) and isinstance(previous_size, int) and size < previous_size:
                errors.append(f"{source}: tree_size rollback detected")
            if size == previous_size and evidence.get("tree_root_hash") != previous_root:
                errors.append(f"{source}: same tree_size with different root indicates a fork")
            if isinstance(version, int) and isinstance(previous_version, int) and version < previous_version:
                errors.append(f"{source}: label_version rollback detected")
            if evidence.get("consistency_from_previous_verified") is not True:
                errors.append(f"{source}: non-first observation requires verified consistency proof")
    else:
        errors.append(f"{source}: first_observation must be boolean")

    if policy.get("require_checkpoint_persistence") is True and evidence.get("checkpoint_persisted") is not True:
        errors.append(f"{source}: selected profile requires checkpoint persistence")

    mode = policy["deployment_mode"]
    third_party_verified = evidence.get("third_party_signatures_verified")
    if not isinstance(third_party_verified, int) or isinstance(third_party_verified, bool) or third_party_verified < 0:
        errors.append(f"{source}: third_party_signatures_verified must be non-negative")

    if mode == "contact-monitoring":
        if evidence.get("fork_check_channel") not in {"anonymous-log", "peer-gossip", "multiple"}:
            errors.append(f"{source}: contact monitoring requires anonymous or peer fork checking")
        if evidence.get("contact_monitor_required") is True and evidence.get("contact_monitor_completed") is not True:
            errors.append(f"{source}: required contact monitoring was not completed")
        if third_party_verified != 0:
            errors.append(f"{source}: contact monitoring must not depend on third-party signatures")
        if evidence.get("auditor_lag_ms") is not None:
            errors.append(f"{source}: contact monitoring must not report auditor lag")
        if evidence.get("service_update_signature_verified") is not False:
            errors.append(f"{source}: contact monitoring must not report manager update signatures")
        if evidence.get("service_fork_detection_active") is not False:
            errors.append(f"{source}: contact monitoring must not report manager-mode service fork detection")

    if mode == "third-party-auditing":
        if evidence.get("fork_check_channel") not in {"third-party-auditor", "multiple"}:
            errors.append(f"{source}: auditing profile requires auditor-backed fork checking")
        if isinstance(third_party_verified, int) and third_party_verified < policy["third_party_threshold"]:
            errors.append(f"{source}: insufficient verified third-party auditor signatures")
        lag = evidence.get("auditor_lag_ms")
        if not isinstance(lag, int) or isinstance(lag, bool) or lag < 0:
            errors.append(f"{source}: auditing profile requires non-negative auditor_lag_ms")
        elif lag > policy["max_auditor_lag_ms"]:
            errors.append(f"{source}: auditor lag exceeds policy maximum")
        if evidence.get("service_update_signature_verified") is not False:
            errors.append(f"{source}: auditing profile must not report manager update signature")
        if evidence.get("service_fork_detection_active") is not False:
            errors.append(f"{source}: auditing profile must not report manager service fork detection")

    if mode == "third-party-management":
        if evidence.get("fork_check_channel") not in {"third-party-manager", "multiple"}:
            errors.append(f"{source}: management profile requires manager-backed fork checking")
        if isinstance(third_party_verified, int) and third_party_verified < policy["third_party_threshold"]:
            errors.append(f"{source}: insufficient verified third-party manager signatures")
        if evidence.get("auditor_lag_ms") is not None:
            errors.append(f"{source}: management profile must not report auditor lag")
        if evidence.get("service_update_signature_verified") is not True:
            errors.append(f"{source}: management profile requires verified service update signature")
        if evidence.get("service_fork_detection_active") is not True:
            errors.append(f"{source}: management profile requires service-side fork detection")

    return sorted(set(errors))


def checkpoint_from_evidence(log_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(log_id, str) or not ID_RE.fullmatch(log_id):
        raise ValueError("invalid log_id")
    return {
        "schema_version": "0.1",
        "log_id": log_id,
        "tree_size": evidence["tree_size"],
        "tree_root_hash": evidence["tree_root_hash"],
        "tree_timestamp_ms": evidence["tree_timestamp_ms"],
        "subject_digest_hex": evidence["subject_digest_hex"],
        "label_version": evidence["label_version"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate E2EESA Key Transparency evidence.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("protocol_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    parser.add_argument("expected_subject_digest_hex")
    parser.add_argument("--previous-checkpoint", type=Path)
    args = parser.parse_args()

    try:
        policy = load_json(args.policy)
        evidence = load_json(args.evidence)
        registry = load_json(args.protocol_registry)
        catalog = load_json(args.profile_catalog)
        previous = load_json(args.previous_checkpoint) if args.previous_checkpoint else None
        errors = validate_evidence(
            policy,
            evidence,
            registry,
            catalog,
            args.expected_subject_digest_hex,
            previous,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
