#!/usr/bin/env python3
"""Semantic validator for E2EESA RFC 9605 real-time media profiles."""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PROFILE_MODES = {
    "media-sframe-sender-keys@0.1.0": "sender-keys",
    "media-sframe-mls@0.1.0": "mls",
}
ALLOWED_CONTROL_FAMILIES = {"pairwise-e2ee", "group-e2ee"}
RFC9605_SUITES = {"0x0001", "0x0002", "0x0003", "0x0004", "0x0005"}


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


def _suite_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("cipher_suites", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def validate_registry(
    registry: dict[str, Any],
    source: str = "real-time media registry",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version", "registry_version", "standard_version",
        "protocol", "cipher_suites", "pending_updates",
    }
    extra = sorted(set(registry) - required)
    missing = sorted(required - registry.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if registry.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    protocol = registry.get("protocol")
    if not isinstance(protocol, dict):
        errors.append(f"{source}: protocol must be an object")
    else:
        if protocol.get("id") != "SFRAME-RFC9605":
            errors.append(f"{source}: protocol id must be SFRAME-RFC9605")
        if protocol.get("specification") != "RFC 9605":
            errors.append(f"{source}: protocol must pin RFC 9605")

    suites = registry.get("cipher_suites")
    if not isinstance(suites, list):
        errors.append(f"{source}: cipher_suites must be an array")
        suites = []
    ids = [s.get("id") for s in suites if isinstance(s, dict)]
    if len(ids) != len(set(ids)):
        errors.append(f"{source}: duplicate cipher-suite identifiers")
    if set(ids) != RFC9605_SUITES:
        errors.append(f"{source}: registry must contain exactly RFC 9605 suites 0x0001-0x0005")

    by_id = _suite_index(registry)
    if by_id.get("0x0005", {}).get("status") != "recommended":
        errors.append(f"{source}: 0x0005 AES_256_GCM_SHA512_128 must be recommended")
    if by_id.get("0x0003", {}).get("status") != "prohibited":
        errors.append(f"{source}: 0x0003 32-bit-tag suite must be prohibited")
    for sid, expected_nt in {
        "0x0001": 10, "0x0002": 8, "0x0003": 4, "0x0004": 16, "0x0005": 16
    }.items():
        if by_id.get(sid, {}).get("nt") != expected_nt:
            errors.append(f"{source}: {sid} has incorrect RFC 9605 tag length")
    return sorted(set(errors))


def validate_policy(
    policy: dict[str, Any],
    registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "real-time media policy",
) -> list[str]:
    errors = validate_registry(registry)
    required = {
        "schema_version","policy_id","profile_ref","registry_version","protocol_id",
        "cipher_suite_id","key_management_mode","control_profile_ref",
        "require_hop_by_hop_transport_encryption","require_sfu_no_plaintext",
        "require_sfu_no_base_keys","require_unique_sender_key_space",
        "require_membership_rekey","require_replay_rejection",
        "require_persistent_ctr_before_encrypt","maximum_key_lifetime_seconds",
        "maximum_frames_per_sender_key","maximum_epoch_overlap",
        "mls_epoch_bits","allow_media_recording_bot",
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
    if not _valid_id(policy.get("policy_id")):
        errors.append(f"{source}: invalid policy_id")

    profile_ref = policy.get("profile_ref")
    mode = PROFILE_MODES.get(profile_ref)
    profiles = _profile_index(profile_catalog)
    profile = profiles.get(profile_ref)
    if mode is None:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    elif profile is None:
        errors.append(f"{source}: profile_ref not found in catalog")
    elif profile.get("family_id") != "real-time-media":
        errors.append(f"{source}: profile_ref must belong to real-time-media")

    if policy.get("registry_version") != registry.get("registry_version"):
        errors.append(f"{source}: registry_version does not match real-time-media registry")
    if policy.get("protocol_id") != "SFRAME-RFC9605":
        errors.append(f"{source}: protocol_id must be SFRAME-RFC9605")

    suite = _suite_index(registry).get(policy.get("cipher_suite_id"))
    if suite is None:
        errors.append(f"{source}: selected SFrame cipher suite is not registered")
    elif suite.get("status") == "prohibited":
        errors.append(f"{source}: selected SFrame cipher suite is prohibited")

    for field in (
        "require_hop_by_hop_transport_encryption",
        "require_sfu_no_plaintext",
        "require_sfu_no_base_keys",
        "require_unique_sender_key_space",
        "require_membership_rekey",
        "require_replay_rejection",
        "require_persistent_ctr_before_encrypt",
    ):
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} must be true")

    lifetime = policy.get("maximum_key_lifetime_seconds")
    if not isinstance(lifetime, int) or isinstance(lifetime, bool) or not 60 <= lifetime <= 86400:
        errors.append(f"{source}: maximum_key_lifetime_seconds must be 60..86400")
    frames = policy.get("maximum_frames_per_sender_key")
    if not isinstance(frames, int) or isinstance(frames, bool) or not 1 <= frames <= 4294967295:
        errors.append(f"{source}: maximum_frames_per_sender_key out of range")
    overlap = policy.get("maximum_epoch_overlap")
    if not isinstance(overlap, int) or isinstance(overlap, bool) or not 0 <= overlap <= 8:
        errors.append(f"{source}: maximum_epoch_overlap must be 0..8")
    if not isinstance(policy.get("allow_media_recording_bot"), bool):
        errors.append(f"{source}: allow_media_recording_bot must be boolean")

    control_ref = policy.get("control_profile_ref")
    control = profiles.get(control_ref)
    if control is None:
        errors.append(f"{source}: control_profile_ref not found in profile catalog")
    elif control.get("family_id") not in ALLOWED_CONTROL_FAMILIES:
        errors.append(f"{source}: control_profile_ref must be pairwise/group E2EE")

    if mode == "sender-keys":
        if policy.get("key_management_mode") != "sender-keys":
            errors.append(f"{source}: sender-key profile requires key_management_mode=sender-keys")
        if policy.get("mls_epoch_bits") is not None:
            errors.append(f"{source}: sender-key profile must set mls_epoch_bits to null")

    if mode == "mls":
        if policy.get("key_management_mode") != "mls":
            errors.append(f"{source}: MLS profile requires key_management_mode=mls")
        if control_ref != "group-mls-rfc9420@0.1.0":
            errors.append(f"{source}: MLS media profile requires group-mls-rfc9420@0.1.0 control")
        bits = policy.get("mls_epoch_bits")
        if not isinstance(bits, int) or isinstance(bits, bool) or not 4 <= bits <= 32:
            errors.append(f"{source}: MLS profile requires mls_epoch_bits 4..32")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return sorted(set(errors))


def validate_session(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "real-time media session evidence",
) -> list[str]:
    errors = validate_policy(policy, registry, profile_catalog)
    if errors:
        return errors

    required = {
        "schema_version","session_id","profile_ref","cipher_suite_id",
        "participant_device_ids","media_epoch","control_profile_ref",
        "hop_by_hop_transport_encryption_verified","sframe_e2ee_enabled",
        "sfu_present","sfu_observed_media_plaintext","sfu_observed_base_keys",
        "sfu_can_modify_media_without_detection","sfu_visible_metadata",
        "recording_bot_present","recording_bot_authorized_participant",
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
    if not _valid_id(evidence.get("session_id")):
        errors.append(f"{source}: invalid session_id")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("cipher_suite_id") != policy.get("cipher_suite_id"):
        errors.append(f"{source}: cipher_suite_id does not match policy")
    if evidence.get("control_profile_ref") != policy.get("control_profile_ref"):
        errors.append(f"{source}: control_profile_ref does not match policy")

    participants = evidence.get("participant_device_ids")
    if (
        not isinstance(participants, list)
        or len(participants) < 2
        or len(participants) != len(set(participants))
        or any(not _valid_id(x) for x in participants)
    ):
        errors.append(f"{source}: participant_device_ids must contain >=2 unique valid device ids")
    epoch = evidence.get("media_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        errors.append(f"{source}: media_epoch must be non-negative")

    if evidence.get("hop_by_hop_transport_encryption_verified") is not True:
        errors.append(f"{source}: hop-by-hop transport encryption must verify")
    if evidence.get("sframe_e2ee_enabled") is not True:
        errors.append(f"{source}: SFrame E2EE must be enabled")
    for field in (
        "sfu_observed_media_plaintext",
        "sfu_observed_base_keys",
        "sfu_can_modify_media_without_detection",
    ):
        if evidence.get(field) is not False:
            errors.append(f"{source}: {field} must be false")

    metadata = evidence.get("sfu_visible_metadata")
    allowed_metadata = {
        "kid","ctr","ssrc","codec","frame-size","packet-size","timing",
        "rtp-extensions","rtcp-feedback",
    }
    if not isinstance(metadata, list) or len(metadata) != len(set(metadata)):
        errors.append(f"{source}: sfu_visible_metadata must be a unique array")
    elif any(item not in allowed_metadata for item in metadata):
        errors.append(f"{source}: sfu_visible_metadata contains unsupported item")

    bot_present = evidence.get("recording_bot_present")
    bot_auth = evidence.get("recording_bot_authorized_participant")
    if not isinstance(bot_present, bool) or not isinstance(bot_auth, bool):
        errors.append(f"{source}: recording bot flags must be boolean")
    elif bot_present:
        if policy.get("allow_media_recording_bot") is not True:
            errors.append(f"{source}: recording bot is prohibited by policy")
        if bot_auth is not True:
            errors.append(f"{source}: recording bot must be an explicitly authorized participant")
    elif bot_auth is not False:
        errors.append(f"{source}: absent recording bot cannot be marked authorized")
    return sorted(set(errors))


def validate_membership_event(
    policy: dict[str, Any],
    event: dict[str, Any],
    registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "real-time media membership event",
) -> list[str]:
    errors = validate_policy(policy, registry, profile_catalog)
    if errors:
        return errors

    required = {
        "schema_version","event_id","session_id","profile_ref","event_type",
        "previous_media_epoch","new_media_epoch","changed_device_id",
        "previous_participant_device_ids","new_participant_device_ids",
        "identity_authorization_verified","keys_rotated_before_media_resume",
        "departed_devices_excluded_from_new_keys","new_joiner_received_prior_epoch_keys",
        "all_active_senders_rotated","new_sender_keys_distributed_over_e2ee",
        "mls_commit_authenticated","mls_epoch_advanced",
        "rejoining_device_reused_old_sender_key",
    }
    extra = sorted(set(event) - required)
    missing = sorted(required - event.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return sorted(set(errors))

    if event.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("event_id","session_id","changed_device_id"):
        if not _valid_id(event.get(field)):
            errors.append(f"{source}: invalid {field}")
    if event.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")

    prev_epoch = event.get("previous_media_epoch")
    new_epoch = event.get("new_media_epoch")
    if (
        not isinstance(prev_epoch, int) or isinstance(prev_epoch, bool) or prev_epoch < 0
        or not isinstance(new_epoch, int) or isinstance(new_epoch, bool)
        or new_epoch != prev_epoch + 1
    ):
        errors.append(f"{source}: membership change must advance media epoch by exactly one")

    previous = event.get("previous_participant_device_ids")
    current = event.get("new_participant_device_ids")
    if (
        not isinstance(previous, list) or not isinstance(current, list)
        or len(previous) != len(set(previous)) or len(current) != len(set(current))
        or any(not _valid_id(x) for x in previous + current)
    ):
        errors.append(f"{source}: participant lists must contain unique valid device ids")
        previous = previous if isinstance(previous, list) else []
        current = current if isinstance(current, list) else []

    changed = event.get("changed_device_id")
    kind = event.get("event_type")
    if kind in {"join","rejoin"}:
        if changed in previous or changed not in current:
            errors.append(f"{source}: join/rejoin device must be absent before and present after")
        if len(current) != len(previous) + 1:
            errors.append(f"{source}: join/rejoin must add exactly one participant")
    elif kind in {"leave","remove-compromised"}:
        if changed not in previous or changed in current:
            errors.append(f"{source}: leave/remove device must be present before and absent after")
        if len(current) != len(previous) - 1:
            errors.append(f"{source}: leave/remove must remove exactly one participant")
    else:
        errors.append(f"{source}: invalid event_type")

    for field in (
        "identity_authorization_verified",
        "keys_rotated_before_media_resume",
        "departed_devices_excluded_from_new_keys",
        "all_active_senders_rotated",
    ):
        if event.get(field) is not True:
            errors.append(f"{source}: {field} must be true")
    if event.get("new_joiner_received_prior_epoch_keys") is not False:
        errors.append(f"{source}: new/rejoining devices must not receive prior epoch media keys")
    if event.get("rejoining_device_reused_old_sender_key") is not False:
        errors.append(f"{source}: rejoining device must not reuse its old sender key")

    mode = PROFILE_MODES[policy["profile_ref"]]
    if mode == "sender-keys":
        if event.get("new_sender_keys_distributed_over_e2ee") is not True:
            errors.append(f"{source}: sender-key profile must distribute new sender keys over E2EE")
        if event.get("mls_commit_authenticated") is not False:
            errors.append(f"{source}: sender-key profile must not claim MLS commit")
        if event.get("mls_epoch_advanced") is not False:
            errors.append(f"{source}: sender-key profile must not claim MLS epoch advancement")

    if mode == "mls":
        if event.get("new_sender_keys_distributed_over_e2ee") is not False:
            errors.append(f"{source}: MLS profile derives keys and must not claim sender-key distribution")
        if event.get("mls_commit_authenticated") is not True:
            errors.append(f"{source}: MLS membership commit must authenticate")
        if event.get("mls_epoch_advanced") is not True:
            errors.append(f"{source}: MLS membership change must advance MLS epoch")
    return sorted(set(errors))


def mls_sender_bits(group_size: int) -> int:
    if group_size < 2:
        raise ValueError("group_size must be at least 2")
    return max(1, math.ceil(math.log2(group_size)))


def expected_mls_kid(
    *,
    epoch: int,
    sender_index: int,
    group_size: int,
    epoch_bits: int,
    context: int,
) -> int:
    if epoch < 0 or sender_index < 0 or context < 0:
        raise ValueError("epoch, sender_index, and context must be non-negative")
    if sender_index >= group_size:
        raise ValueError("sender_index outside group")
    if not 4 <= epoch_bits <= 32:
        raise ValueError("epoch_bits out of range")
    sender_bits = mls_sender_bits(group_size)
    available_context_bits = 64 - sender_bits - epoch_bits
    if available_context_bits < 0:
        raise ValueError("group size and epoch bits do not fit in 64-bit KID")
    if context >= (1 << available_context_bits):
        raise ValueError("context does not fit in KID")
    return (
        (context << (sender_bits + epoch_bits))
        + (sender_index << epoch_bits)
        + (epoch % (1 << epoch_bits))
    )


def validate_checkpoint(
    checkpoint: dict[str, Any],
    source: str = "real-time media sender checkpoint",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version","session_id","sender_device_id","media_epoch",
        "kid","max_ctr","base_key_fingerprint",
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
    for field in ("session_id","sender_device_id"):
        if not _valid_id(checkpoint.get(field)):
            errors.append(f"{source}: invalid {field}")
    for field in ("media_epoch","kid","max_ctr"):
        value = checkpoint.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"{source}: {field} must be non-negative")
    fp = checkpoint.get("base_key_fingerprint")
    if not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{64}", fp):
        errors.append(f"{source}: invalid base_key_fingerprint")
    return sorted(set(errors))


def validate_frame(
    policy: dict[str, Any],
    frame: dict[str, Any],
    registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    previous_checkpoint: dict[str, Any] | None = None,
    source: str = "real-time media frame evidence",
) -> list[str]:
    errors = validate_policy(policy, registry, profile_catalog)
    if errors:
        return errors
    required = {
        "schema_version","event_id","session_id","profile_ref","media_epoch",
        "sender_device_id","sender_index","group_size","mls_context",
        "kid","ctr","base_key_fingerprint","cipher_suite_id",
        "sender_authorized_for_epoch","base_key_reused_by_multiple_senders",
        "kid_ctr_previously_seen","sframe_authentication_verified",
        "replay_detected","plaintext_released_before_authentication",
        "sfu_observed_media_plaintext","sfu_observed_base_key",
        "hop_by_hop_transport_verified",
    }
    extra = sorted(set(frame) - required)
    missing = sorted(required - frame.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return sorted(set(errors))

    if frame.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("event_id","session_id","sender_device_id"):
        if not _valid_id(frame.get(field)):
            errors.append(f"{source}: invalid {field}")
    if frame.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if frame.get("cipher_suite_id") != policy.get("cipher_suite_id"):
        errors.append(f"{source}: cipher_suite_id does not match policy")

    for field in ("media_epoch","kid","ctr"):
        value = frame.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"{source}: {field} must be non-negative")
    fp = frame.get("base_key_fingerprint")
    if not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{64}", fp):
        errors.append(f"{source}: invalid base_key_fingerprint")

    for field in (
        "sender_authorized_for_epoch",
        "sframe_authentication_verified",
        "hop_by_hop_transport_verified",
    ):
        if frame.get(field) is not True:
            errors.append(f"{source}: {field} must be true")
    for field in (
        "base_key_reused_by_multiple_senders",
        "kid_ctr_previously_seen",
        "replay_detected",
        "plaintext_released_before_authentication",
        "sfu_observed_media_plaintext",
        "sfu_observed_base_key",
    ):
        if frame.get(field) is not False:
            errors.append(f"{source}: {field} must be false")

    mode = PROFILE_MODES[policy["profile_ref"]]
    if mode == "sender-keys":
        for field in ("sender_index","group_size","mls_context"):
            if frame.get(field) is not None:
                errors.append(f"{source}: sender-key frame must set {field} to null")

    if mode == "mls":
        sender_index = frame.get("sender_index")
        group_size = frame.get("group_size")
        context = frame.get("mls_context")
        if not isinstance(sender_index, int) or isinstance(sender_index, bool):
            errors.append(f"{source}: MLS frame requires sender_index")
        if not isinstance(group_size, int) or isinstance(group_size, bool) or group_size < 2:
            errors.append(f"{source}: MLS frame requires group_size >=2")
        if not isinstance(context, int) or isinstance(context, bool) or context < 0:
            errors.append(f"{source}: MLS frame requires non-negative mls_context")
        if (
            isinstance(sender_index, int) and not isinstance(sender_index, bool)
            and isinstance(group_size, int) and not isinstance(group_size, bool)
            and isinstance(context, int) and not isinstance(context, bool)
            and isinstance(frame.get("media_epoch"), int)
        ):
            try:
                expected = expected_mls_kid(
                    epoch=frame["media_epoch"],
                    sender_index=sender_index,
                    group_size=group_size,
                    epoch_bits=policy["mls_epoch_bits"],
                    context=context,
                )
                if frame.get("kid") != expected:
                    errors.append(f"{source}: KID does not match RFC 9605 MLS construction")
            except ValueError as exc:
                errors.append(f"{source}: invalid MLS KID inputs: {exc}")

    if previous_checkpoint is not None:
        cp_errors = validate_checkpoint(previous_checkpoint)
        if cp_errors:
            errors.extend(cp_errors)
        else:
            if frame.get("session_id") != previous_checkpoint.get("session_id"):
                errors.append(f"{source}: previous checkpoint session mismatch")
            if frame.get("sender_device_id") != previous_checkpoint.get("sender_device_id"):
                errors.append(f"{source}: previous checkpoint sender mismatch")
            epoch = frame.get("media_epoch")
            prev_epoch = previous_checkpoint.get("media_epoch")
            if isinstance(epoch, int) and epoch < prev_epoch:
                errors.append(f"{source}: media epoch rollback detected")
            if epoch == prev_epoch:
                if frame.get("kid") == previous_checkpoint.get("kid"):
                    if frame.get("ctr", -1) <= previous_checkpoint.get("max_ctr", -1):
                        errors.append(f"{source}: replay/CTR rollback within KID")
                    if frame.get("base_key_fingerprint") != previous_checkpoint.get("base_key_fingerprint"):
                        errors.append(f"{source}: same KID in same epoch changed base key")
                elif frame.get("base_key_fingerprint") == previous_checkpoint.get("base_key_fingerprint"):
                    errors.append(f"{source}: new KID must not reuse previous base key")
            elif isinstance(epoch, int) and epoch > prev_epoch:
                if frame.get("base_key_fingerprint") == previous_checkpoint.get("base_key_fingerprint"):
                    errors.append(f"{source}: new media epoch must rotate sender base key")
    return sorted(set(errors))


def checkpoint_from_frame(frame: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "0.1",
        "session_id": frame["session_id"],
        "sender_device_id": frame["sender_device_id"],
        "media_epoch": frame["media_epoch"],
        "kid": frame["kid"],
        "max_ctr": frame["ctr"],
        "base_key_fingerprint": frame["base_key_fingerprint"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate E2EESA SFrame media evidence.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    parser.add_argument("--session", type=Path)
    parser.add_argument("--membership", type=Path)
    parser.add_argument("--frame", type=Path)
    parser.add_argument("--previous-checkpoint", type=Path)
    args = parser.parse_args()
    try:
        policy = load_json(args.policy)
        registry = load_json(args.registry)
        catalog = load_json(args.profile_catalog)
        errors = validate_policy(policy, registry, catalog)
        if args.session:
            errors.extend(validate_session(policy, load_json(args.session), registry, catalog))
        if args.membership:
            errors.extend(validate_membership_event(policy, load_json(args.membership), registry, catalog))
        if args.frame:
            previous = load_json(args.previous_checkpoint) if args.previous_checkpoint else None
            errors.extend(validate_frame(policy, load_json(args.frame), registry, catalog, previous))
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    errors = sorted(set(errors))
    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
