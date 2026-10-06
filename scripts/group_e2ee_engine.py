#!/usr/bin/env python3
"""Deterministic semantic validator for E2EESA group E2EE profiles.

This module validates architecture selection, membership transitions, and
message-level conformance evidence. It does not implement MLS, pairwise E2EE,
or sender-key cryptographic operations.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PROFILE_REF_RE = re.compile(
    r"^[a-z0-9]+(?:-[a-z0-9]+)*@[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$"
)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

ALL_STATUSES = {
    "recommended",
    "allowed",
    "provisional",
    "experimental",
    "legacy",
    "deprecated",
    "prohibited",
}

PROFILE_BINDINGS: dict[str, dict[str, str]] = {
    "group-mls-rfc9420@0.1.0": {
        "protocol_id": "GROUP-MLS-1-RFC9420",
        "architecture": "mls",
    },
    "group-sender-key-aead@0.1.0": {
        "protocol_id": "GROUP-SENDER-KEY-AEAD-1",
        "architecture": "sender-key",
    },
    "group-pairwise-fanout@0.1.0": {
        "protocol_id": "GROUP-PAIRWISE-FANOUT-1",
        "architecture": "pairwise-fanout",
    },
}

INVARIANT_POLICY_BOOLEANS = (
    "require_authenticated_membership_changes",
    "require_epoch_advance_on_membership_change",
    "require_removed_member_exclusion",
    "require_new_member_history_exclusion",
    "prohibit_server_membership_authorization",
    "require_device_revocation_rekey",
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _unique_string_list(value: Any, *, allow_empty: bool = True) -> bool:
    return (
        isinstance(value, list)
        and (allow_empty or bool(value))
        and all(_nonempty_string(item) for item in value)
        and len(value) == len(set(value))
    )


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


def _algorithm_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _protocol_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("protocols", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _mls_suite_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("mls_cipher_suites", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def validate_protocol_registry(
    registry: dict[str, Any],
    source: str = "group protocol registry",
) -> list[str]:
    errors: list[str] = []
    required_top = {
        "schema_version",
        "registry_version",
        "standard_version",
        "protocols",
        "mls_cipher_suites",
    }
    extra_top = sorted(set(registry) - required_top)
    missing_top = sorted(required_top - registry.keys())
    if extra_top:
        errors.append(f"{source}: unknown fields: {', '.join(extra_top)}")
    if missing_top:
        errors.append(f"{source}: missing fields: {', '.join(missing_top)}")

    if registry.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not _nonempty_string(registry.get("registry_version")):
        errors.append(f"{source}: registry_version must be non-empty")
    if not _nonempty_string(registry.get("standard_version")):
        errors.append(f"{source}: standard_version must be non-empty")

    protocols = registry.get("protocols")
    if not isinstance(protocols, list) or not protocols:
        errors.append(f"{source}: protocols must be a non-empty array")
        protocols = []

    required_protocol_fields = {
        "id",
        "name",
        "status",
        "architecture",
        "specification",
        "reference_uri",
        "security_notes",
    }
    protocol_ids: set[str] = set()
    for index, item in enumerate(protocols):
        prefix = f"{source}: protocols[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: protocol must be an object")
            continue
        extra = sorted(set(item) - required_protocol_fields)
        missing = sorted(required_protocol_fields - item.keys())
        if extra:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra)}")
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")
        protocol_id = item.get("id")
        if not isinstance(protocol_id, str) or not protocol_id.startswith("GROUP-"):
            errors.append(f"{prefix}: invalid protocol id")
        elif protocol_id in protocol_ids:
            errors.append(f"{prefix}: duplicate protocol id: {protocol_id}")
        else:
            protocol_ids.add(protocol_id)
        if item.get("status") not in ALL_STATUSES:
            errors.append(f"{prefix}: invalid status")
        if item.get("architecture") not in {
            "tree-group-key-agreement",
            "sender-key",
            "pairwise-fanout",
        }:
            errors.append(f"{prefix}: invalid architecture")
        for field in ("name", "specification", "reference_uri"):
            if not _nonempty_string(item.get(field)):
                errors.append(f"{prefix}: {field} must be non-empty")
        if not _unique_string_list(item.get("security_notes"), allow_empty=False):
            errors.append(f"{prefix}: security_notes must be a non-empty unique string array")

    required_protocols = {
        "GROUP-MLS-1-RFC9420",
        "GROUP-SENDER-KEY-AEAD-1",
        "GROUP-PAIRWISE-FANOUT-1",
    }
    missing_protocols = sorted(required_protocols - protocol_ids)
    if missing_protocols:
        errors.append(
            f"{source}: missing required protocols: {', '.join(missing_protocols)}"
        )

    suites = registry.get("mls_cipher_suites")
    if not isinstance(suites, list) or not suites:
        errors.append(f"{source}: mls_cipher_suites must be a non-empty array")
        suites = []

    suite_ids: set[str] = set()
    required_suite_fields = {"id", "name", "status", "specification", "reference_uri"}
    for index, item in enumerate(suites):
        prefix = f"{source}: mls_cipher_suites[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: suite must be an object")
            continue
        extra = sorted(set(item) - required_suite_fields)
        missing = sorted(required_suite_fields - item.keys())
        if extra:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra)}")
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")
        suite_id = item.get("id")
        if not isinstance(suite_id, str) or not re.fullmatch(r"0x[0-9A-Fa-f]{4}", suite_id):
            errors.append(f"{prefix}: invalid MLS cipher suite id")
        elif suite_id in suite_ids:
            errors.append(f"{prefix}: duplicate MLS cipher suite id: {suite_id}")
        else:
            suite_ids.add(suite_id)
        if item.get("status") not in ALL_STATUSES:
            errors.append(f"{prefix}: invalid status")

    if "0x0001" not in suite_ids:
        errors.append(f"{source}: MLS mandatory-to-implement suite 0x0001 must be registered")

    return sorted(set(errors))


def _validate_algorithm(
    algorithm_id: Any,
    *,
    category: str,
    algorithms: dict[str, dict[str, Any]],
    source: str,
) -> list[str]:
    if not _nonempty_string(algorithm_id):
        return [f"{source}: algorithm id must be a non-empty string"]
    algorithm = algorithms.get(algorithm_id)
    if algorithm is None:
        return [f"{source}: unknown algorithm id: {algorithm_id}"]
    errors: list[str] = []
    if algorithm.get("category") != category:
        errors.append(
            f"{source}: algorithm {algorithm_id} has category "
            f"{algorithm.get('category')}, expected {category}"
        )
    if algorithm.get("status") == "prohibited":
        errors.append(f"{source}: prohibited algorithm: {algorithm_id}")
    return errors


def validate_policy(
    policy: dict[str, Any],
    group_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "group policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "profile_ref",
        "protocol_registry_version",
        "protocol_id",
        "mls_cipher_suite_id",
        "pairwise_profile_ref",
        "sender_kdf_algorithm_id",
        "sender_aead_algorithm_id",
        "sender_signature_algorithm_id",
        "require_authenticated_membership_changes",
        "require_epoch_advance_on_membership_change",
        "require_removed_member_exclusion",
        "require_new_member_history_exclusion",
        "prohibit_server_membership_authorization",
        "require_device_revocation_rekey",
        "max_group_devices",
        "max_sender_skipped_message_keys",
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
    binding = PROFILE_BINDINGS.get(profile_ref)
    profile = _profile_index(profile_catalog).get(profile_ref)
    if binding is None:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    elif profile is None:
        errors.append(f"{source}: profile_ref is not present in profile catalog: {profile_ref}")
    elif profile.get("family_id") != "group-e2ee":
        errors.append(f"{source}: profile_ref must belong to group-e2ee")

    if policy.get("protocol_registry_version") != group_registry.get("registry_version"):
        errors.append(f"{source}: protocol_registry_version does not match group registry")

    if binding is not None and policy.get("protocol_id") != binding["protocol_id"]:
        errors.append(f"{source}: protocol_id does not match selected group profile")
    protocol = _protocol_index(group_registry).get(policy.get("protocol_id"))
    if protocol is None:
        errors.append(f"{source}: unknown protocol_id")
    elif protocol.get("status") == "prohibited":
        errors.append(f"{source}: selected group protocol is prohibited")

    for field in INVARIANT_POLICY_BOOLEANS:
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} is an E2EESA invariant and must be true")

    max_devices = policy.get("max_group_devices")
    if (
        not isinstance(max_devices, int)
        or isinstance(max_devices, bool)
        or max_devices < 2
    ):
        errors.append(f"{source}: max_group_devices must be an integer >= 2")

    architecture = binding["architecture"] if binding else None
    pairwise_ref = policy.get("pairwise_profile_ref")
    mls_suite = policy.get("mls_cipher_suite_id")
    sender_fields = (
        "sender_kdf_algorithm_id",
        "sender_aead_algorithm_id",
        "sender_signature_algorithm_id",
    )
    algorithms = _algorithm_index(crypto_registry)
    profiles = _profile_index(profile_catalog)

    if architecture == "mls":
        suite = _mls_suite_index(group_registry).get(mls_suite)
        if suite is None:
            errors.append(f"{source}: MLS profile requires a registered mls_cipher_suite_id")
        elif suite.get("status") == "prohibited":
            errors.append(f"{source}: selected MLS cipher suite is prohibited")
        if pairwise_ref is not None:
            errors.append(f"{source}: MLS profile must set pairwise_profile_ref to null")
        for field in sender_fields:
            if policy.get(field) is not None:
                errors.append(f"{source}: MLS profile must set {field} to null")
        if policy.get("max_sender_skipped_message_keys") is not None:
            errors.append(f"{source}: MLS profile must set max_sender_skipped_message_keys to null")

    if architecture in {"sender-key", "pairwise-fanout"}:
        if mls_suite is not None:
            errors.append(f"{source}: non-MLS profile must set mls_cipher_suite_id to null")
        pairwise_profile = profiles.get(pairwise_ref) if isinstance(pairwise_ref, str) else None
        if pairwise_profile is None or pairwise_profile.get("family_id") != "pairwise-e2ee":
            errors.append(f"{source}: profile requires a valid pairwise_profile_ref")
        elif pairwise_profile.get("status") == "prohibited":
            errors.append(f"{source}: pairwise_profile_ref is prohibited")

    if architecture == "sender-key":
        errors.extend(
            _validate_algorithm(
                policy.get("sender_kdf_algorithm_id"),
                category="kdf",
                algorithms=algorithms,
                source=f"{source}: sender_kdf_algorithm_id",
            )
        )
        errors.extend(
            _validate_algorithm(
                policy.get("sender_aead_algorithm_id"),
                category="aead",
                algorithms=algorithms,
                source=f"{source}: sender_aead_algorithm_id",
            )
        )
        errors.extend(
            _validate_algorithm(
                policy.get("sender_signature_algorithm_id"),
                category="signature",
                algorithms=algorithms,
                source=f"{source}: sender_signature_algorithm_id",
            )
        )
        skipped = policy.get("max_sender_skipped_message_keys")
        if (
            not isinstance(skipped, int)
            or isinstance(skipped, bool)
            or skipped < 0
        ):
            errors.append(
                f"{source}: sender-key profile requires non-negative max_sender_skipped_message_keys"
            )

    if architecture == "pairwise-fanout":
        for field in sender_fields:
            if policy.get(field) is not None:
                errors.append(f"{source}: pairwise fanout must set {field} to null")
        if policy.get("max_sender_skipped_message_keys") is not None:
            errors.append(
                f"{source}: pairwise fanout must set max_sender_skipped_message_keys to null"
            )

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")

    return sorted(set(errors))


def validate_membership_event(
    policy: dict[str, Any],
    event: dict[str, Any],
    source: str = "group membership event",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "event_id",
        "group_id",
        "profile_ref",
        "identity_state_hash",
        "previous_epoch",
        "new_epoch",
        "previous_member_device_ids",
        "added_member_device_ids",
        "removed_member_device_ids",
        "new_member_device_ids",
        "verified_membership_authorizers",
        "membership_transcript_authenticated",
        "future_content_rebound_to_new_membership",
        "added_members_prior_epoch_access",
        "removed_members_new_epoch_access",
        "mls_commit_authenticated",
        "mls_update_path_present",
        "mls_welcome_count",
        "mls_key_packages_single_use",
        "sender_keys_rotated_for_all_active_senders",
        "sender_key_distribution_covers_current_members",
        "pairwise_recipient_set_updated",
    }
    extra = sorted(set(event) - required)
    missing = sorted(required - event.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")

    if event.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("event_id", "group_id"):
        if not isinstance(event.get(field), str) or not ID_RE.fullmatch(event.get(field, "")):
            errors.append(f"{source}: invalid {field}")
    if event.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if not isinstance(event.get("identity_state_hash"), str) or not HASH_RE.fullmatch(event.get("identity_state_hash", "")):
        errors.append(f"{source}: invalid identity_state_hash")

    previous_epoch = event.get("previous_epoch")
    new_epoch = event.get("new_epoch")
    if (
        not isinstance(previous_epoch, int)
        or isinstance(previous_epoch, bool)
        or previous_epoch < 0
    ):
        errors.append(f"{source}: previous_epoch must be a non-negative integer")
    if (
        not isinstance(new_epoch, int)
        or isinstance(new_epoch, bool)
        or not isinstance(previous_epoch, int)
        or isinstance(previous_epoch, bool)
        or new_epoch != previous_epoch + 1
    ):
        errors.append(f"{source}: new_epoch must equal previous_epoch + 1")

    list_fields = (
        "previous_member_device_ids",
        "added_member_device_ids",
        "removed_member_device_ids",
        "new_member_device_ids",
    )
    for field in list_fields:
        allow_empty = field in {"added_member_device_ids", "removed_member_device_ids"}
        if not _unique_string_list(event.get(field), allow_empty=allow_empty):
            errors.append(f"{source}: {field} must be a unique string array")

    previous = set(event.get("previous_member_device_ids", []))
    added = set(event.get("added_member_device_ids", []))
    removed = set(event.get("removed_member_device_ids", []))
    new_members = set(event.get("new_member_device_ids", []))

    if not added and not removed:
        errors.append(f"{source}: membership transition must add or remove at least one device")
    if added & previous:
        errors.append(f"{source}: added devices must not already be members")
    if not removed <= previous:
        errors.append(f"{source}: removed devices must exist in previous membership")
    if added & removed:
        errors.append(f"{source}: a device cannot be both added and removed")
    expected_new = (previous - removed) | added
    if new_members != expected_new:
        errors.append(f"{source}: new_member_device_ids do not match add/remove transition")
    if not new_members:
        errors.append(f"{source}: group must retain at least one member")
    max_devices = policy.get("max_group_devices")
    if isinstance(max_devices, int) and len(new_members) > max_devices:
        errors.append(f"{source}: new membership exceeds max_group_devices")

    authorizers = event.get("verified_membership_authorizers")
    if not isinstance(authorizers, list) or not authorizers:
        errors.append(f"{source}: verified_membership_authorizers must be non-empty")
        authorizers = []
    seen: set[tuple[str, str]] = set()
    for index, authorizer in enumerate(authorizers):
        prefix = f"{source}: verified_membership_authorizers[{index}]"
        if not isinstance(authorizer, dict) or set(authorizer) != {"type", "id"}:
            errors.append(f"{prefix}: authorizer must contain exactly type and id")
            continue
        auth_type = authorizer.get("type")
        auth_id = authorizer.get("id")
        if auth_type not in {"device", "server"}:
            errors.append(f"{prefix}: invalid authorizer type")
        if not isinstance(auth_id, str) or not ID_RE.fullmatch(auth_id):
            errors.append(f"{prefix}: invalid authorizer id")
            continue
        marker = (auth_type, auth_id)
        if marker in seen:
            errors.append(f"{source}: duplicate membership authorizer")
        seen.add(marker)
        if auth_type == "server":
            errors.append(f"{source}: server-only membership authorization is prohibited")
        elif auth_id not in previous:
            errors.append(f"{source}: membership authorizer is not a previous member: {auth_id}")

    required_true = (
        "membership_transcript_authenticated",
        "future_content_rebound_to_new_membership",
    )
    for field in required_true:
        if event.get(field) is not True:
            errors.append(f"{source}: {field} must be true")
    if event.get("added_members_prior_epoch_access") is not False:
        errors.append(f"{source}: newly added devices must not receive prior-epoch access")
    if event.get("removed_members_new_epoch_access") is not False:
        errors.append(f"{source}: removed devices must not receive new-epoch access")

    architecture = PROFILE_BINDINGS.get(policy.get("profile_ref"), {}).get("architecture")
    if architecture == "mls":
        if event.get("mls_commit_authenticated") is not True:
            errors.append(f"{source}: MLS membership change requires authenticated Commit")
        if event.get("mls_update_path_present") is not True:
            errors.append(f"{source}: E2EESA MLS membership change requires a fresh UpdatePath")
        if event.get("mls_welcome_count") != len(added):
            errors.append(f"{source}: MLS Welcome count must equal added member count")
        if event.get("mls_key_packages_single_use") is not True:
            errors.append(f"{source}: MLS KeyPackages must be single-use")
        if event.get("sender_keys_rotated_for_all_active_senders") is not False:
            errors.append(f"{source}: MLS event must not claim sender-key rotation")
        if event.get("sender_key_distribution_covers_current_members") is not False:
            errors.append(f"{source}: MLS event must not claim sender-key distribution")
        if event.get("pairwise_recipient_set_updated") is not False:
            errors.append(f"{source}: MLS event must not claim pairwise fanout update")

    if architecture == "sender-key":
        if event.get("sender_keys_rotated_for_all_active_senders") is not True:
            errors.append(f"{source}: sender-key membership change must rotate every active sender key")
        if event.get("sender_key_distribution_covers_current_members") is not True:
            errors.append(f"{source}: sender-key redistribution must cover the complete new membership")
        if event.get("mls_commit_authenticated") is not False or event.get("mls_update_path_present") is not False:
            errors.append(f"{source}: sender-key event must not claim MLS commit/path processing")
        if event.get("mls_welcome_count") != 0:
            errors.append(f"{source}: sender-key event must set mls_welcome_count to 0")
        if event.get("pairwise_recipient_set_updated") is not False:
            errors.append(f"{source}: sender-key event must not claim pairwise-fanout membership update")

    if architecture == "pairwise-fanout":
        if event.get("pairwise_recipient_set_updated") is not True:
            errors.append(f"{source}: pairwise fanout must update its recipient set")
        if event.get("mls_commit_authenticated") is not False or event.get("mls_update_path_present") is not False:
            errors.append(f"{source}: pairwise fanout event must not claim MLS processing")
        if event.get("mls_welcome_count") != 0:
            errors.append(f"{source}: pairwise fanout event must set mls_welcome_count to 0")
        if event.get("sender_keys_rotated_for_all_active_senders") is not False:
            errors.append(f"{source}: pairwise fanout event must not claim sender-key rotation")
        if event.get("sender_key_distribution_covers_current_members") is not False:
            errors.append(f"{source}: pairwise fanout event must not claim sender-key distribution")

    return sorted(set(errors))


def validate_message_checkpoint(
    policy: dict[str, Any],
    checkpoint: dict[str, Any],
    source: str = "group message checkpoint",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "group_id",
        "profile_ref",
        "epoch",
        "message_id",
        "sender_device_id",
        "current_member_device_ids",
        "recipient_device_ids",
        "replay_status",
        "authenticated",
        "server_plaintext_access",
        "ciphertext_count",
        "mls_application_message",
        "sender_chain_advanced",
        "sender_message_key_deleted",
        "sender_signature_verified",
        "skipped_sender_message_keys_retained",
        "all_pairwise_sessions_valid",
    }
    extra = sorted(set(checkpoint) - required)
    missing = sorted(required - checkpoint.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")

    if checkpoint.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("group_id", "message_id", "sender_device_id"):
        if not isinstance(checkpoint.get(field), str) or not ID_RE.fullmatch(checkpoint.get(field, "")):
            errors.append(f"{source}: invalid {field}")
    if checkpoint.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")

    epoch = checkpoint.get("epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        errors.append(f"{source}: epoch must be a non-negative integer")

    members = checkpoint.get("current_member_device_ids")
    recipients = checkpoint.get("recipient_device_ids")
    if not _unique_string_list(members, allow_empty=False):
        errors.append(f"{source}: current_member_device_ids must be a unique non-empty string array")
        members = []
    if not _unique_string_list(recipients, allow_empty=False):
        errors.append(f"{source}: recipient_device_ids must be a unique non-empty string array")
        recipients = []

    member_set = set(members)
    sender = checkpoint.get("sender_device_id")
    if sender not in member_set:
        errors.append(f"{source}: sender must be a current member")
    expected_recipients = member_set - {sender}
    if set(recipients) != expected_recipients:
        errors.append(f"{source}: recipients must equal all current members except sender")
    max_devices = policy.get("max_group_devices")
    if isinstance(max_devices, int) and len(member_set) > max_devices:
        errors.append(f"{source}: current membership exceeds max_group_devices")

    if checkpoint.get("replay_status") != "fresh":
        errors.append(f"{source}: replayed group message must be rejected")
    if checkpoint.get("authenticated") is not True:
        errors.append(f"{source}: group message must authenticate successfully")
    if checkpoint.get("server_plaintext_access") is not False:
        errors.append(f"{source}: service must not have plaintext access")

    ciphertext_count = checkpoint.get("ciphertext_count")
    if (
        not isinstance(ciphertext_count, int)
        or isinstance(ciphertext_count, bool)
        or ciphertext_count < 1
    ):
        errors.append(f"{source}: ciphertext_count must be a positive integer")

    skipped = checkpoint.get("skipped_sender_message_keys_retained")
    if (
        not isinstance(skipped, int)
        or isinstance(skipped, bool)
        or skipped < 0
    ):
        errors.append(f"{source}: skipped_sender_message_keys_retained must be non-negative")

    architecture = PROFILE_BINDINGS.get(policy.get("profile_ref"), {}).get("architecture")
    if architecture == "mls":
        if ciphertext_count != 1:
            errors.append(f"{source}: MLS group message must use one group ciphertext")
        if checkpoint.get("mls_application_message") is not True:
            errors.append(f"{source}: MLS checkpoint must represent an MLS application message")
        if checkpoint.get("sender_chain_advanced") is not False:
            errors.append(f"{source}: MLS checkpoint must not claim sender-key chain advancement")
        if checkpoint.get("sender_message_key_deleted") is not False:
            errors.append(f"{source}: MLS checkpoint must not use sender-key deletion field")
        if checkpoint.get("sender_signature_verified") is not False:
            errors.append(f"{source}: MLS checkpoint must not use sender-key signature field")
        if skipped != 0:
            errors.append(f"{source}: MLS checkpoint must set skipped sender keys to 0")
        if checkpoint.get("all_pairwise_sessions_valid") is not False:
            errors.append(f"{source}: MLS checkpoint must not claim pairwise fanout")

    if architecture == "sender-key":
        if ciphertext_count != 1:
            errors.append(f"{source}: sender-key message must use one group ciphertext")
        if checkpoint.get("mls_application_message") is not False:
            errors.append(f"{source}: sender-key checkpoint must not claim MLS application framing")
        for field, label in (
            ("sender_chain_advanced", "sender chain must advance"),
            ("sender_message_key_deleted", "sender message key must be deleted"),
            ("sender_signature_verified", "sender signature must verify"),
        ):
            if checkpoint.get(field) is not True:
                errors.append(f"{source}: {label}")
        maximum = policy.get("max_sender_skipped_message_keys")
        if isinstance(maximum, int) and isinstance(skipped, int) and skipped > maximum:
            errors.append(f"{source}: skipped sender message keys exceed policy maximum")
        if checkpoint.get("all_pairwise_sessions_valid") is not False:
            errors.append(f"{source}: sender-key checkpoint must not claim pairwise fanout")

    if architecture == "pairwise-fanout":
        if ciphertext_count != len(expected_recipients):
            errors.append(
                f"{source}: pairwise fanout requires exactly one ciphertext per recipient"
            )
        if checkpoint.get("all_pairwise_sessions_valid") is not True:
            errors.append(f"{source}: every pairwise recipient session must validate")
        if checkpoint.get("mls_application_message") is not False:
            errors.append(f"{source}: pairwise fanout must not claim MLS application framing")
        if checkpoint.get("sender_chain_advanced") is not False:
            errors.append(f"{source}: pairwise fanout must not claim sender-key chain advancement")
        if checkpoint.get("sender_message_key_deleted") is not False:
            errors.append(f"{source}: pairwise fanout must not use sender-key deletion field")
        if checkpoint.get("sender_signature_verified") is not False:
            errors.append(f"{source}: pairwise fanout must not use sender-key signature field")
        if skipped != 0:
            errors.append(f"{source}: pairwise fanout must set skipped sender keys to 0")

    return sorted(set(errors))


def validate_group_case(
    policy: dict[str, Any],
    membership_event: dict[str, Any],
    checkpoint: dict[str, Any],
    group_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
) -> list[str]:
    errors = validate_policy(
        policy,
        group_registry,
        crypto_registry,
        profile_catalog,
    )
    if not errors:
        errors.extend(validate_membership_event(policy, membership_event))
        errors.extend(validate_message_checkpoint(policy, checkpoint))
        if membership_event.get("group_id") != checkpoint.get("group_id"):
            errors.append("group evidence: membership event and message group_id values differ")
        if membership_event.get("new_epoch") != checkpoint.get("epoch"):
            errors.append("group evidence: message checkpoint must use the membership event new_epoch")
        if set(membership_event.get("new_member_device_ids", [])) != set(
            checkpoint.get("current_member_device_ids", [])
        ):
            errors.append("group evidence: message membership does not match accepted new membership")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an E2EESA group E2EE evidence bundle.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("membership_event", type=Path)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("group_registry", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    args = parser.parse_args()

    try:
        errors = validate_group_case(
            load_json(args.policy),
            load_json(args.membership_event),
            load_json(args.checkpoint),
            load_json(args.group_registry),
            load_json(args.crypto_registry),
            load_json(args.profile_catalog),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
