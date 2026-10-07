#!/usr/bin/env python3
"""Semantic validator for E2EESA backup and recovery profiles.

This module validates backup/recovery policy, encrypted-envelope evidence, and
restore evidence. It does not implement Argon2id, HKDF, AEAD, or hardware
cryptography; conformance callers must populate evidence only after the
underlying cryptographic operations have been verified.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HEX_RE = re.compile(r"^[0-9a-f]+$")

PROFILE_MODES = {
    "backup-none@0.1.0": "none",
    "backup-user-secret@0.1.0": "user-secret",
    "backup-hardware-assisted@0.1.0": "hardware-assisted",
}

ARGON2_FIRST_RECOMMENDED_MEMORY_KIB = 2_097_152
ARGON2_FIRST_RECOMMENDED_ITERATIONS = 1
ARGON2_SECOND_RECOMMENDED_MEMORY_KIB = 65_536
ARGON2_SECOND_RECOMMENDED_ITERATIONS = 3

COMMON_POLICY_INVARIANTS = (
    "require_authorized_restoring_device",
    "require_manifest_authentication",
    "require_fresh_backup_key_per_generation",
    "require_generation_rollback_protection",
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _algorithm_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


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


def _validate_algorithm(
    algorithm_id: Any,
    *,
    expected_category: str,
    registry: dict[str, Any],
    source: str,
) -> list[str]:
    if not isinstance(algorithm_id, str) or not algorithm_id:
        return [f"{source}: algorithm id must be a non-empty string"]
    algorithm = _algorithm_index(registry).get(algorithm_id)
    if algorithm is None:
        return [f"{source}: unknown algorithm id: {algorithm_id}"]
    errors: list[str] = []
    if algorithm.get("category") != expected_category:
        errors.append(
            f"{source}: algorithm {algorithm_id} has category "
            f"{algorithm.get('category')}, expected {expected_category}"
        )
    if algorithm.get("status") == "prohibited":
        errors.append(f"{source}: prohibited algorithm: {algorithm_id}")
    return errors


def _argon2_cost_is_acceptable(policy: dict[str, Any]) -> bool:
    memory = policy.get("argon2_memory_kib")
    iterations = policy.get("argon2_iterations")
    if not isinstance(memory, int) or isinstance(memory, bool):
        return False
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        return False
    first = (
        memory >= ARGON2_FIRST_RECOMMENDED_MEMORY_KIB
        and iterations >= ARGON2_FIRST_RECOMMENDED_ITERATIONS
    )
    second = (
        memory >= ARGON2_SECOND_RECOMMENDED_MEMORY_KIB
        and iterations >= ARGON2_SECOND_RECOMMENDED_ITERATIONS
    )
    return first or second


def validate_policy(
    policy: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "backup recovery policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version","policy_id","profile_ref",
        "content_aead_algorithm_id","secret_kdf_algorithm_id","secret_hkdf_algorithm_id",
        "recovery_secret_type","minimum_generated_secret_bits",
        "argon2_version","argon2_memory_kib","argon2_iterations","argon2_parallelism",
        "argon2_salt_bytes","argon2_output_bytes",
        "hardware_assistance","hardware_wrap_aead_algorithm_id","hardware_module_assurance",
        "require_non_exportable_hardware_key","require_hardware_attestation",
        "require_hardware_rate_limiting","require_authorized_restoring_device",
        "require_manifest_authentication","require_fresh_backup_key_per_generation",
        "require_generation_rollback_protection","allow_server_plaintext",
        "allow_server_unwrapped_backup_key",
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
    mode = PROFILE_MODES.get(profile_ref)
    if mode is None:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    else:
        profile = _profile_index(profile_catalog).get(profile_ref)
        if profile is None:
            errors.append(f"{source}: profile_ref not present in profile catalog")
        elif profile.get("family_id") != "backup-recovery":
            errors.append(f"{source}: profile_ref must belong to backup-recovery")

    for field in COMMON_POLICY_INVARIANTS:
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} is an E2EESA invariant and must be true")
    if policy.get("allow_server_plaintext") is not False:
        errors.append(f"{source}: server plaintext access is prohibited")
    if policy.get("allow_server_unwrapped_backup_key") is not False:
        errors.append(f"{source}: server access to an unwrapped backup data key is prohibited")

    if mode == "none":
        for field in (
            "content_aead_algorithm_id","secret_kdf_algorithm_id","secret_hkdf_algorithm_id",
            "minimum_generated_secret_bits","argon2_version","argon2_memory_kib",
            "argon2_iterations","argon2_parallelism","argon2_salt_bytes",
            "argon2_output_bytes","hardware_wrap_aead_algorithm_id",
        ):
            if policy.get(field) is not None:
                errors.append(f"{source}: no-backup profile must set {field} to null")
        if policy.get("recovery_secret_type") != "none":
            errors.append(f"{source}: no-backup profile must set recovery_secret_type to none")
        if policy.get("hardware_assistance") is not False:
            errors.append(f"{source}: no-backup profile cannot enable hardware assistance")
        if policy.get("hardware_module_assurance") != "none":
            errors.append(f"{source}: no-backup profile must set hardware_module_assurance to none")
        for field in (
            "require_non_exportable_hardware_key",
            "require_hardware_attestation",
            "require_hardware_rate_limiting",
        ):
            if policy.get(field) is not False:
                errors.append(f"{source}: no-backup profile must set {field} to false")
        return sorted(set(errors))

    errors.extend(_validate_algorithm(
        policy.get("content_aead_algorithm_id"),
        expected_category="aead", registry=crypto_registry,
        source=f"{source}: content_aead_algorithm_id",
    ))
    errors.extend(_validate_algorithm(
        policy.get("secret_kdf_algorithm_id"),
        expected_category="kdf", registry=crypto_registry,
        source=f"{source}: secret_kdf_algorithm_id",
    ))
    errors.extend(_validate_algorithm(
        policy.get("secret_hkdf_algorithm_id"),
        expected_category="kdf", registry=crypto_registry,
        source=f"{source}: secret_hkdf_algorithm_id",
    ))
    if policy.get("secret_kdf_algorithm_id") != "ALG-ARGON2ID":
        errors.append(f"{source}: E2EESA 0.1 recovery profiles require ALG-ARGON2ID")
    if not str(policy.get("secret_hkdf_algorithm_id", "")).startswith("ALG-HKDF-"):
        errors.append(f"{source}: secret_hkdf_algorithm_id must select an HKDF profile")

    secret_type = policy.get("recovery_secret_type")
    if secret_type not in {"generated-high-entropy", "user-chosen-passphrase"}:
        errors.append(f"{source}: invalid recovery_secret_type")
    if secret_type == "generated-high-entropy":
        bits = policy.get("minimum_generated_secret_bits")
        if not isinstance(bits, int) or isinstance(bits, bool) or bits < 128:
            errors.append(f"{source}: generated recovery secret must require at least 128 bits")
    elif secret_type == "user-chosen-passphrase" and policy.get("minimum_generated_secret_bits") is not None:
        errors.append(f"{source}: passphrase mode must set minimum_generated_secret_bits to null")

    if policy.get("argon2_version") != "0x13":
        errors.append(f"{source}: Argon2 version must be 0x13")
    if not _argon2_cost_is_acceptable(policy):
        errors.append(
            f"{source}: Argon2id cost must meet RFC 9106 first recommendation "
            "(>=2 GiB, >=1 pass) or second recommendation (>=64 MiB, >=3 passes)"
        )
    parallelism = policy.get("argon2_parallelism")
    if not isinstance(parallelism, int) or isinstance(parallelism, bool) or parallelism < 1:
        errors.append(f"{source}: argon2_parallelism must be a positive integer")
    salt_bytes = policy.get("argon2_salt_bytes")
    if not isinstance(salt_bytes, int) or isinstance(salt_bytes, bool) or salt_bytes < 16:
        errors.append(f"{source}: Argon2 salt must be at least 16 bytes")
    output_bytes = policy.get("argon2_output_bytes")
    if not isinstance(output_bytes, int) or isinstance(output_bytes, bool) or output_bytes < 32:
        errors.append(f"{source}: Argon2 output must be at least 32 bytes")

    if mode == "user-secret":
        if policy.get("hardware_assistance") is not False:
            errors.append(f"{source}: user-secret profile must not enable hardware assistance")
        if policy.get("hardware_wrap_aead_algorithm_id") is not None:
            errors.append(f"{source}: user-secret profile must set hardware_wrap_aead_algorithm_id to null")
        if policy.get("hardware_module_assurance") != "none":
            errors.append(f"{source}: user-secret profile must set hardware_module_assurance to none")
        for field in (
            "require_non_exportable_hardware_key",
            "require_hardware_attestation",
            "require_hardware_rate_limiting",
        ):
            if policy.get(field) is not False:
                errors.append(f"{source}: user-secret profile must set {field} to false")

    if mode == "hardware-assisted":
        if policy.get("hardware_assistance") is not True:
            errors.append(f"{source}: hardware-assisted profile requires hardware_assistance")
        errors.extend(_validate_algorithm(
            policy.get("hardware_wrap_aead_algorithm_id"),
            expected_category="aead", registry=crypto_registry,
            source=f"{source}: hardware_wrap_aead_algorithm_id",
        ))
        if policy.get("hardware_module_assurance") == "none":
            errors.append(f"{source}: hardware-assisted profile requires declared hardware assurance")
        for field in (
            "require_non_exportable_hardware_key",
            "require_hardware_attestation",
            "require_hardware_rate_limiting",
        ):
            if policy.get(field) is not True:
                errors.append(f"{source}: hardware-assisted profile requires {field}=true")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return sorted(set(errors))


def validate_no_backup_evidence(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    source: str = "no-backup evidence",
) -> list[str]:
    errors: list[str] = []
    if policy.get("profile_ref") != "backup-none@0.1.0":
        return [f"{source}: policy is not the no-backup profile"]
    required = {
        "schema_version","profile_ref","identity_id",
        "recoverable_protected_content_outside_active_endpoints",
        "recoverable_content_key_material_outside_active_endpoints",
        "server_backup_present","server_can_recover_historical_plaintext",
        "authorized_device_to_device_transfer_permitted",
    }
    if set(evidence) != required:
        missing = sorted(required - evidence.keys())
        extra = sorted(set(evidence) - required)
        if missing:
            errors.append(f"{source}: missing fields: {', '.join(missing)}")
        if extra:
            errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if evidence.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if not isinstance(evidence.get("identity_id"), str) or not ID_RE.fullmatch(evidence.get("identity_id", "")):
        errors.append(f"{source}: invalid identity_id")
    for field in (
        "recoverable_protected_content_outside_active_endpoints",
        "recoverable_content_key_material_outside_active_endpoints",
        "server_backup_present","server_can_recover_historical_plaintext",
    ):
        if evidence.get(field) is not False:
            errors.append(f"{source}: {field} must be false")
    if not isinstance(evidence.get("authorized_device_to_device_transfer_permitted"), bool):
        errors.append(f"{source}: authorized_device_to_device_transfer_permitted must be boolean")
    return sorted(set(errors))


def validate_envelope(
    policy: dict[str, Any],
    envelope: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "backup envelope",
) -> list[str]:
    errors = validate_policy(policy, crypto_registry, profile_catalog)
    if errors:
        return errors
    mode = PROFILE_MODES[policy["profile_ref"]]
    if mode == "none":
        return [f"{source}: no-backup profile must not create a recoverable backup envelope"]

    required = {
        "schema_version","backup_id","identity_id","profile_ref","generation",
        "content_aead_algorithm_id","backup_data_key_id","backup_data_key_random_bits",
        "backup_data_key_reused","manifest_digest","manifest_authenticated",
        "manifest_binds_identity_and_generation","ciphertext_chunk_count",
        "server_plaintext_access","server_unwrapped_backup_key_access",
        "recovery_secret_uploaded_to_server","secret_kdf_algorithm_id",
        "secret_hkdf_algorithm_id","argon2_salt_hex","argon2_version",
        "argon2_memory_kib","argon2_iterations","argon2_parallelism","argon2_output_bytes",
        "inner_wrapped_backup_key_present","hardware_outer_wrap_present",
        "hardware_wrap_aead_algorithm_id","hardware_key_non_exportable",
        "hardware_attestation_verified",
    }
    extra = sorted(set(envelope) - required)
    missing = sorted(required - envelope.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return sorted(set(errors))

    if envelope.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("backup_id","identity_id","backup_data_key_id"):
        if not isinstance(envelope.get(field), str) or not ID_RE.fullmatch(envelope.get(field, "")):
            errors.append(f"{source}: invalid {field}")
    if envelope.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    generation = envelope.get("generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        errors.append(f"{source}: generation must be positive")
    if envelope.get("content_aead_algorithm_id") != policy.get("content_aead_algorithm_id"):
        errors.append(f"{source}: content AEAD does not match policy")
    if envelope.get("backup_data_key_random_bits", 0) < 256:
        errors.append(f"{source}: backup data key must contain at least 256 random bits")
    if envelope.get("backup_data_key_reused") is not False:
        errors.append(f"{source}: backup data key reuse is prohibited")
    if envelope.get("manifest_authenticated") is not True:
        errors.append(f"{source}: manifest must authenticate")
    if envelope.get("manifest_binds_identity_and_generation") is not True:
        errors.append(f"{source}: manifest must bind identity and backup generation")
    if not isinstance(envelope.get("manifest_digest"), str) or not HEX_RE.fullmatch(envelope.get("manifest_digest", "")):
        errors.append(f"{source}: invalid manifest_digest")
    if not isinstance(envelope.get("ciphertext_chunk_count"), int) or envelope.get("ciphertext_chunk_count") < 1:
        errors.append(f"{source}: ciphertext_chunk_count must be positive")
    if envelope.get("server_plaintext_access") is not False:
        errors.append(f"{source}: service must not have backup plaintext")
    if envelope.get("server_unwrapped_backup_key_access") is not False:
        errors.append(f"{source}: service must not have an unwrapped backup data key")
    if envelope.get("recovery_secret_uploaded_to_server") is not False:
        errors.append(f"{source}: recovery secret must never be uploaded to the service")
    if envelope.get("secret_kdf_algorithm_id") != policy.get("secret_kdf_algorithm_id"):
        errors.append(f"{source}: secret KDF does not match policy")
    if envelope.get("secret_hkdf_algorithm_id") != policy.get("secret_hkdf_algorithm_id"):
        errors.append(f"{source}: secret HKDF does not match policy")
    if envelope.get("argon2_version") != policy.get("argon2_version"):
        errors.append(f"{source}: Argon2 version does not match policy")
    for field in ("argon2_memory_kib","argon2_iterations","argon2_parallelism","argon2_output_bytes"):
        if envelope.get(field) != policy.get(field):
            errors.append(f"{source}: {field} does not match policy")
    salt = envelope.get("argon2_salt_hex")
    if not isinstance(salt, str) or not HEX_RE.fullmatch(salt) or len(salt) % 2:
        errors.append(f"{source}: invalid Argon2 salt")
    elif len(salt) // 2 < policy.get("argon2_salt_bytes", 16):
        errors.append(f"{source}: Argon2 salt is shorter than policy minimum")
    if envelope.get("inner_wrapped_backup_key_present") is not True:
        errors.append(f"{source}: user-secret inner wrapped backup key is required")

    if mode == "user-secret":
        if envelope.get("hardware_outer_wrap_present") is not False:
            errors.append(f"{source}: user-secret profile must not claim hardware outer wrapping")
        if envelope.get("hardware_wrap_aead_algorithm_id") is not None:
            errors.append(f"{source}: user-secret profile must set hardware wrap algorithm to null")
        if envelope.get("hardware_key_non_exportable") is not False:
            errors.append(f"{source}: user-secret profile must not claim a hardware key")
        if envelope.get("hardware_attestation_verified") is not False:
            errors.append(f"{source}: user-secret profile must not claim hardware attestation")

    if mode == "hardware-assisted":
        if envelope.get("hardware_outer_wrap_present") is not True:
            errors.append(f"{source}: hardware-assisted profile requires an outer hardware wrap")
        if envelope.get("hardware_wrap_aead_algorithm_id") != policy.get("hardware_wrap_aead_algorithm_id"):
            errors.append(f"{source}: hardware wrap AEAD does not match policy")
        if envelope.get("hardware_key_non_exportable") is not True:
            errors.append(f"{source}: hardware wrapping key must be non-exportable")
        if envelope.get("hardware_attestation_verified") is not True:
            errors.append(f"{source}: hardware attestation must verify")

    return sorted(set(errors))


def validate_generation_transition(
    previous: dict[str, Any],
    current: dict[str, Any],
    source: str = "backup generation transition",
) -> list[str]:
    errors: list[str] = []
    if current.get("identity_id") != previous.get("identity_id"):
        errors.append(f"{source}: identity_id changed between generations")
    if current.get("profile_ref") != previous.get("profile_ref"):
        errors.append(f"{source}: profile_ref changed between generations")
    prev_gen = previous.get("generation")
    cur_gen = current.get("generation")
    if not isinstance(prev_gen, int) or not isinstance(cur_gen, int) or cur_gen != prev_gen + 1:
        errors.append(f"{source}: generation must advance by exactly one")
    if current.get("backup_data_key_id") == previous.get("backup_data_key_id"):
        errors.append(f"{source}: each generation requires a fresh backup data key")
    return sorted(set(errors))


def validate_recovery(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "recovery evidence",
) -> list[str]:
    errors = validate_policy(policy, crypto_registry, profile_catalog)
    if errors:
        return errors
    mode = PROFILE_MODES[policy["profile_ref"]]
    if mode == "none":
        return [f"{source}: no-backup profile has no historical backup recovery operation"]

    required = {
        "schema_version","recovery_id","backup_id","profile_ref","restoring_device_id",
        "restoring_device_authorized","backup_generation","latest_known_generation",
        "manifest_authenticated","ciphertext_authentication_verified",
        "user_secret_supplied_locally","argon2_derived_locally",
        "hardware_release_used","hardware_release_authenticated",
        "hardware_release_rate_limited","hardware_attestation_verified",
        "service_plaintext_access","service_unwrapped_backup_key_access",
        "recovery_granted_device_authority","rollback_detected","recovery_success",
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
    for field in ("recovery_id","backup_id","restoring_device_id"):
        if not isinstance(evidence.get(field), str) or not ID_RE.fullmatch(evidence.get(field, "")):
            errors.append(f"{source}: invalid {field}")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("restoring_device_authorized") is not True:
        errors.append(f"{source}: restoring device must already be authorized by identity architecture")

    backup_generation = evidence.get("backup_generation")
    latest_generation = evidence.get("latest_known_generation")
    if (
        not isinstance(backup_generation, int) or isinstance(backup_generation, bool)
        or not isinstance(latest_generation, int) or isinstance(latest_generation, bool)
        or backup_generation < 1 or latest_generation < 1
    ):
        errors.append(f"{source}: backup/latest generation values must be positive integers")
    elif backup_generation < latest_generation:
        errors.append(f"{source}: stale backup generation is rejected by rollback protection")

    for field, label in (
        ("manifest_authenticated","backup manifest must authenticate"),
        ("ciphertext_authentication_verified","backup ciphertext must authenticate"),
        ("user_secret_supplied_locally","recovery secret must be supplied locally"),
        ("argon2_derived_locally","Argon2id recovery derivation must occur locally"),
    ):
        if evidence.get(field) is not True:
            errors.append(f"{source}: {label}")
    if evidence.get("service_plaintext_access") is not False:
        errors.append(f"{source}: service must not obtain restored plaintext")
    if evidence.get("service_unwrapped_backup_key_access") is not False:
        errors.append(f"{source}: service must not obtain unwrapped backup data key")
    if evidence.get("recovery_granted_device_authority") is not False:
        errors.append(f"{source}: recovery must not itself grant device authority")
    if evidence.get("rollback_detected") is not False:
        errors.append(f"{source}: detected rollback must fail recovery")
    if evidence.get("recovery_success") is not True:
        errors.append(f"{source}: recovery evidence must represent a successful recovery")

    if mode == "user-secret":
        for field in (
            "hardware_release_used","hardware_release_authenticated",
            "hardware_release_rate_limited","hardware_attestation_verified",
        ):
            if evidence.get(field) is not False:
                errors.append(f"{source}: user-secret profile must set {field}=false")

    if mode == "hardware-assisted":
        for field, label in (
            ("hardware_release_used","hardware release must be used"),
            ("hardware_release_authenticated","hardware release must authenticate"),
            ("hardware_release_rate_limited","hardware release must be rate limited"),
            ("hardware_attestation_verified","hardware attestation must verify"),
        ):
            if evidence.get(field) is not True:
                errors.append(f"{source}: {label}")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate E2EESA backup/recovery evidence.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    parser.add_argument("--envelope", type=Path)
    parser.add_argument("--recovery", type=Path)
    parser.add_argument("--no-backup", type=Path)
    args = parser.parse_args()

    try:
        policy = load_json(args.policy)
        crypto = load_json(args.crypto_registry)
        catalog = load_json(args.profile_catalog)
        errors = validate_policy(policy, crypto, catalog)
        if args.envelope:
            errors.extend(validate_envelope(policy, load_json(args.envelope), crypto, catalog))
        if args.recovery:
            errors.extend(validate_recovery(policy, load_json(args.recovery), crypto, catalog))
        if args.no_backup:
            errors.extend(validate_no_backup_evidence(policy, load_json(args.no_backup)))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    errors = sorted(set(errors))
    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
