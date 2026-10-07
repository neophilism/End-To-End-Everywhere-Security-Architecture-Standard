#!/usr/bin/env python3
"""Semantic validator for E2EESA secret-storage and hardware-protection profiles."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PROFILE_CLASSES = {
    "secret-platform-keystore@0.1.0": "platform-keystore",
    "secret-hardware-isolated@0.1.0": "hardware-isolated",
    "secret-external-token@0.1.0": "external-token",
    "secret-software-vault@0.1.0": "software-vault",
}
ALLOWED_VAULT_AEADS = {
    "ALG-AES-256-GCM",
    "ALG-CHACHA20-POLY1305",
    "ALG-AES-256-GCM-SIV",
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


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


def _mechanism_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("mechanisms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _algorithm_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def validate_registry(
    registry: dict[str, Any],
    source: str = "secret storage registry",
) -> list[str]:
    errors: list[str] = []
    required = {"schema_version", "registry_version", "standard_version", "mechanisms"}
    extra = sorted(set(registry) - required)
    missing = sorted(required - registry.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if registry.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    mechanisms = registry.get("mechanisms")
    if not isinstance(mechanisms, list) or not mechanisms:
        errors.append(f"{source}: mechanisms must be a non-empty array")
        mechanisms = []

    ids: list[str] = []
    for i, item in enumerate(mechanisms):
        prefix = f"{source}: mechanisms[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: mechanism must be an object")
            continue
        required_item = {
            "id","name","class","status","specification","reference_uri",
            "non_exportable_capable","hardware_isolation_capable",
            "attestation_capable","rollback_counter_capable","notes",
        }
        extra_item = sorted(set(item) - required_item)
        missing_item = sorted(required_item - item.keys())
        if extra_item:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra_item)}")
        if missing_item:
            errors.append(f"{prefix}: missing fields: {', '.join(missing_item)}")
        mid = item.get("id")
        if not isinstance(mid, str) or not mid.startswith("SECRET-"):
            errors.append(f"{prefix}: invalid mechanism id")
        else:
            ids.append(mid)
        if item.get("class") not in set(PROFILE_CLASSES.values()):
            errors.append(f"{prefix}: invalid mechanism class")
        if item.get("status") not in {
            "recommended","allowed","legacy","deprecated","prohibited","provisional"
        }:
            errors.append(f"{prefix}: invalid status")

    if len(ids) != len(set(ids)):
        errors.append(f"{source}: mechanism ids must be unique")

    by_id = _mechanism_index(registry)
    required_ids = {
        "SECRET-OS-KEYSTORE",
        "SECRET-APPLE-SECURE-ENCLAVE",
        "SECRET-ANDROID-TEE",
        "SECRET-ANDROID-STRONGBOX",
        "SECRET-TPM2-V185",
        "SECRET-PKCS11-3.2",
        "SECRET-SOFTWARE-VAULT",
    }
    missing_ids = sorted(required_ids - by_id.keys())
    if missing_ids:
        errors.append(f"{source}: missing required mechanisms: {', '.join(missing_ids)}")
    if by_id.get("SECRET-TPM2-V185", {}).get("specification") != "TCG TPM 2.0 Library Specification Version 185":
        errors.append(f"{source}: TPM mechanism must pin Version 185")
    if by_id.get("SECRET-PKCS11-3.2", {}).get("specification") != "OASIS PKCS #11 Specification Version 3.2":
        errors.append(f"{source}: external-token mechanism must pin PKCS #11 v3.2")
    return sorted(set(errors))


def _argon2_cost_acceptable(policy: dict[str, Any]) -> bool:
    memory = policy.get("argon2_memory_kib")
    iterations = policy.get("argon2_iterations")
    if not isinstance(memory, int) or isinstance(memory, bool):
        return False
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        return False
    return (
        (memory >= 2_097_152 and iterations >= 1)
        or (memory >= 65_536 and iterations >= 3)
    )


def validate_policy(
    policy: dict[str, Any],
    mechanism_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "secret storage policy",
) -> list[str]:
    errors = validate_registry(mechanism_registry)
    required = {
        "schema_version","policy_id","profile_ref","registry_version","mechanism_id",
        "vault_aead_algorithm_id","vault_key_bits","require_non_exportable_root_key",
        "require_hardware_isolation","require_attestation","require_key_use_authorization",
        "require_user_authentication","require_user_presence","rollback_anchor_mode",
        "require_rollback_protection","software_secret_type","software_kdf_algorithm_id",
        "minimum_generated_secret_bits","argon2_version","argon2_memory_kib",
        "argon2_iterations","argon2_parallelism","argon2_salt_bytes","argon2_output_bytes",
        "allow_plaintext_secret_at_rest","allow_root_key_export","allow_raw_root_key_cloud_sync",
        "require_key_rotation_on_auth_change","require_vault_generation_monotonicity",
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
    expected_class = PROFILE_CLASSES.get(profile_ref)
    profile = _profile_index(profile_catalog).get(profile_ref)
    if expected_class is None:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    elif profile is None:
        errors.append(f"{source}: profile_ref not found in profile catalog")
    elif profile.get("family_id") != "secret-storage":
        errors.append(f"{source}: profile_ref must belong to secret-storage")

    if policy.get("registry_version") != mechanism_registry.get("registry_version"):
        errors.append(f"{source}: registry_version does not match secret-storage registry")

    mechanism = _mechanism_index(mechanism_registry).get(policy.get("mechanism_id"))
    if mechanism is None:
        errors.append(f"{source}: mechanism_id not present in registry")
    elif expected_class is not None and mechanism.get("class") != expected_class:
        errors.append(
            f"{source}: mechanism class {mechanism.get('class')} does not match profile class {expected_class}"
        )
    elif mechanism.get("status") == "prohibited":
        errors.append(f"{source}: selected mechanism is prohibited")

    algorithms = _algorithm_index(crypto_registry)
    aead_id = policy.get("vault_aead_algorithm_id")
    if aead_id not in ALLOWED_VAULT_AEADS:
        errors.append(f"{source}: unsupported vault AEAD: {aead_id}")
    aead = algorithms.get(aead_id)
    if aead is None or aead.get("category") != "aead":
        errors.append(f"{source}: vault_aead_algorithm_id must reference a registered AEAD")
    elif aead.get("status") == "prohibited":
        errors.append(f"{source}: prohibited vault AEAD")
    if policy.get("vault_key_bits") != 256:
        errors.append(f"{source}: vault_key_bits must be 256")

    if policy.get("require_key_use_authorization") is not True:
        errors.append(f"{source}: require_key_use_authorization must be true")
    if policy.get("allow_plaintext_secret_at_rest") is not False:
        errors.append(f"{source}: plaintext secrets at rest are prohibited")
    if policy.get("allow_root_key_export") is not False:
        errors.append(f"{source}: root-key export is prohibited")
    if policy.get("allow_raw_root_key_cloud_sync") is not False:
        errors.append(f"{source}: raw root-key cloud sync is prohibited")
    if policy.get("require_key_rotation_on_auth_change") is not True:
        errors.append(f"{source}: authentication-policy changes must rotate/reprotect keying")
    if policy.get("require_vault_generation_monotonicity") is not True:
        errors.append(f"{source}: vault generation monotonicity is mandatory")

    anchor_mode = policy.get("rollback_anchor_mode")
    if anchor_mode not in {"none","hardware-monotonic","independent-witness"}:
        errors.append(f"{source}: invalid rollback_anchor_mode")
    if policy.get("require_rollback_protection") is True and anchor_mode == "none":
        errors.append(f"{source}: rollback protection requires an independent monotonic anchor")
    if policy.get("require_rollback_protection") is False and anchor_mode != "none":
        errors.append(f"{source}: rollback anchor must be none when rollback protection is not required")

    if expected_class in {"platform-keystore","hardware-isolated","external-token"}:
        if policy.get("require_non_exportable_root_key") is not True:
            errors.append(f"{source}: keystore/token profiles require a non-exportable root key")
        if policy.get("software_secret_type") != "none":
            errors.append(f"{source}: hardware/keystore profile must set software_secret_type to none")
        for field in (
            "software_kdf_algorithm_id","minimum_generated_secret_bits","argon2_version",
            "argon2_memory_kib","argon2_iterations","argon2_parallelism",
            "argon2_salt_bytes","argon2_output_bytes",
        ):
            if policy.get(field) is not None:
                errors.append(f"{source}: hardware/keystore profile must set {field} to null")

    if expected_class == "platform-keystore":
        if policy.get("require_hardware_isolation") is not False:
            errors.append(f"{source}: platform-keystore profile does not require hardware isolation")
        if policy.get("require_attestation") is not False:
            errors.append(f"{source}: platform-keystore profile does not require attestation")

    if expected_class == "hardware-isolated":
        if policy.get("require_hardware_isolation") is not True:
            errors.append(f"{source}: hardware-isolated profile requires hardware isolation")
        if policy.get("require_attestation") is not True:
            errors.append(f"{source}: hardware-isolated profile requires attestation/equivalent evidence")
        if mechanism is not None and mechanism.get("hardware_isolation_capable") is not True:
            errors.append(f"{source}: selected mechanism cannot satisfy hardware isolation")

    if expected_class == "external-token":
        if policy.get("require_hardware_isolation") is not True:
            errors.append(f"{source}: external-token profile requires hardware isolation")
        if policy.get("require_user_presence") is not True:
            errors.append(f"{source}: external-token profile requires user presence/PIN-equivalent authorization")

    if expected_class == "software-vault":
        if policy.get("require_non_exportable_root_key") is not False:
            errors.append(f"{source}: software-vault cannot claim root-key non-exportability")
        if policy.get("require_hardware_isolation") is not False:
            errors.append(f"{source}: software-vault cannot require hardware isolation")
        if policy.get("require_attestation") is not False:
            errors.append(f"{source}: software-vault cannot require hardware attestation")
        if policy.get("mechanism_id") != "SECRET-SOFTWARE-VAULT":
            errors.append(f"{source}: software-vault profile requires SECRET-SOFTWARE-VAULT")
        if policy.get("software_secret_type") not in {"generated-high-entropy","user-passphrase"}:
            errors.append(f"{source}: software-vault requires a local recovery/unlock secret")
        if policy.get("software_kdf_algorithm_id") != "ALG-ARGON2ID":
            errors.append(f"{source}: software-vault requires ALG-ARGON2ID")
        if policy.get("argon2_version") != "0x13":
            errors.append(f"{source}: software-vault requires Argon2 version 0x13")
        if not _argon2_cost_acceptable(policy):
            errors.append(f"{source}: software-vault Argon2id cost is below RFC 9106 recommendation floor")
        for field, minimum in (
            ("argon2_parallelism",1),("argon2_salt_bytes",16),("argon2_output_bytes",32)
        ):
            value = policy.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
                errors.append(f"{source}: {field} below minimum")
        if policy.get("software_secret_type") == "generated-high-entropy":
            bits = policy.get("minimum_generated_secret_bits")
            if not isinstance(bits, int) or isinstance(bits, bool) or bits < 128:
                errors.append(f"{source}: generated software-vault secret must contain at least 128 random bits")
        elif policy.get("minimum_generated_secret_bits") is not None:
            errors.append(f"{source}: passphrase software-vault must set minimum_generated_secret_bits to null")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return sorted(set(errors))


def validate_state(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    mechanism_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "secret storage state evidence",
) -> list[str]:
    errors = validate_policy(policy, mechanism_registry, crypto_registry, profile_catalog)
    if errors:
        return errors

    required = {
        "schema_version","evidence_id","profile_ref","mechanism_id","device_id","vault_id",
        "vault_generation","previous_vault_generation","vault_aead_algorithm_id",
        "root_key_non_exportable","root_key_hardware_isolated","attestation_verified",
        "key_use_authorization_verified","user_authentication_verified","user_presence_verified",
        "vault_authentication_verified","plaintext_secret_at_rest","root_key_exported",
        "raw_root_key_cloud_synced","rollback_anchor_mode","rollback_anchor_value",
        "previous_rollback_anchor_value","rollback_anchor_verified",
        "software_secret_supplied_locally","argon2_derived_locally",
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
    for field in ("evidence_id","device_id","vault_id"):
        if not _valid_id(evidence.get(field)):
            errors.append(f"{source}: invalid {field}")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("mechanism_id") != policy.get("mechanism_id"):
        errors.append(f"{source}: mechanism_id does not match policy")
    if evidence.get("vault_aead_algorithm_id") != policy.get("vault_aead_algorithm_id"):
        errors.append(f"{source}: vault AEAD does not match policy")

    generation = evidence.get("vault_generation")
    previous = evidence.get("previous_vault_generation")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        errors.append(f"{source}: vault_generation must be positive")
    if previous is not None:
        if not isinstance(previous, int) or isinstance(previous, bool) or previous < 1:
            errors.append(f"{source}: previous_vault_generation must be null or positive")
        elif generation != previous + 1:
            errors.append(f"{source}: vault generation must advance by exactly one")
    elif generation != 1:
        errors.append(f"{source}: first observed vault generation must be 1")

    if evidence.get("key_use_authorization_verified") is not True:
        errors.append(f"{source}: key-use authorization must verify")
    if policy.get("require_user_authentication") and evidence.get("user_authentication_verified") is not True:
        errors.append(f"{source}: user authentication required by policy")
    if not policy.get("require_user_authentication") and not isinstance(evidence.get("user_authentication_verified"), bool):
        errors.append(f"{source}: user_authentication_verified must be boolean")
    if policy.get("require_user_presence") and evidence.get("user_presence_verified") is not True:
        errors.append(f"{source}: user presence required by policy")
    if evidence.get("vault_authentication_verified") is not True:
        errors.append(f"{source}: encrypted vault authentication must verify")

    for field in ("plaintext_secret_at_rest","root_key_exported","raw_root_key_cloud_synced"):
        if evidence.get(field) is not False:
            errors.append(f"{source}: {field} must be false")

    if policy.get("require_non_exportable_root_key") and evidence.get("root_key_non_exportable") is not True:
        errors.append(f"{source}: root key must be non-exportable")
    if policy.get("require_hardware_isolation") and evidence.get("root_key_hardware_isolated") is not True:
        errors.append(f"{source}: root key must be hardware isolated")
    if not policy.get("require_hardware_isolation") and policy.get("profile_ref") == "secret-software-vault@0.1.0":
        if evidence.get("root_key_hardware_isolated") is not False:
            errors.append(f"{source}: software-vault must not claim hardware isolation")
    if policy.get("require_attestation") and evidence.get("attestation_verified") is not True:
        errors.append(f"{source}: required hardware attestation/equivalent evidence did not verify")

    anchor_mode = policy.get("rollback_anchor_mode")
    if evidence.get("rollback_anchor_mode") != anchor_mode:
        errors.append(f"{source}: rollback anchor mode does not match policy")
    anchor = evidence.get("rollback_anchor_value")
    prev_anchor = evidence.get("previous_rollback_anchor_value")
    if anchor_mode == "none":
        if anchor is not None or prev_anchor is not None:
            errors.append(f"{source}: no-anchor mode must use null anchor values")
        if evidence.get("rollback_anchor_verified") is not False:
            errors.append(f"{source}: no-anchor mode cannot claim rollback-anchor verification")
    else:
        if evidence.get("rollback_anchor_verified") is not True:
            errors.append(f"{source}: rollback anchor must verify")
        if not isinstance(anchor, int) or isinstance(anchor, bool) or anchor < 1:
            errors.append(f"{source}: rollback_anchor_value must be positive")
        if previous is None:
            if prev_anchor is not None:
                errors.append(f"{source}: first vault generation must not have previous rollback anchor")
        else:
            if not isinstance(prev_anchor, int) or isinstance(prev_anchor, bool) or prev_anchor < 1:
                errors.append(f"{source}: previous rollback anchor must be positive")
            elif isinstance(anchor, int) and anchor <= prev_anchor:
                errors.append(f"{source}: rollback anchor must advance monotonically")

    software = policy.get("profile_ref") == "secret-software-vault@0.1.0"
    if software:
        if evidence.get("root_key_non_exportable") is not False:
            errors.append(f"{source}: software-vault must not claim root-key non-exportability")
        if evidence.get("attestation_verified") is not False:
            errors.append(f"{source}: software-vault must not claim attestation")
        if evidence.get("software_secret_supplied_locally") is not True:
            errors.append(f"{source}: software-vault secret must be supplied locally")
        if evidence.get("argon2_derived_locally") is not True:
            errors.append(f"{source}: Argon2id vault derivation must occur locally")
    else:
        if evidence.get("software_secret_supplied_locally") is not False:
            errors.append(f"{source}: non-software profile must not claim software unlock secret")
        if evidence.get("argon2_derived_locally") is not False:
            errors.append(f"{source}: non-software profile must not claim Argon2 software derivation")
    return sorted(set(errors))


def validate_key_event(
    policy: dict[str, Any],
    event: dict[str, Any],
    source: str = "secret storage key event",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version","event_id","profile_ref","mechanism_id","device_id",
        "event_type","old_key_id","new_key_id","new_key_non_exportable",
        "new_key_hardware_isolated","old_key_invalidated","auth_policy_changed",
        "vault_rewrapped_under_new_key","remote_copy_of_raw_root_key_exists",
    }
    extra = sorted(set(event) - required)
    missing = sorted(required - event.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return errors

    if event.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("event_id","device_id"):
        if not _valid_id(event.get(field)):
            errors.append(f"{source}: invalid {field}")
    if event.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if event.get("mechanism_id") != policy.get("mechanism_id"):
        errors.append(f"{source}: mechanism_id does not match policy")
    if event.get("remote_copy_of_raw_root_key_exists") is not False:
        errors.append(f"{source}: raw root key must never exist remotely")

    kind = event.get("event_type")
    old_id = event.get("old_key_id")
    new_id = event.get("new_key_id")
    if kind == "create":
        if old_id is not None or not _valid_id(new_id):
            errors.append(f"{source}: create requires null old_key_id and valid new_key_id")
    elif kind == "rotate":
        if not _valid_id(old_id) or not _valid_id(new_id) or old_id == new_id:
            errors.append(f"{source}: rotate requires distinct valid old/new key ids")
        if event.get("old_key_invalidated") is not True:
            errors.append(f"{source}: rotation requires old key invalidation")
        if event.get("vault_rewrapped_under_new_key") is not True:
            errors.append(f"{source}: rotation requires vault rewrap under new key")
    elif kind in {"invalidate","delete"}:
        if not _valid_id(old_id) or new_id is not None:
            errors.append(f"{source}: invalidate/delete requires old key id and null new key id")
    else:
        errors.append(f"{source}: invalid event_type")

    if kind in {"create","rotate"}:
        if policy.get("require_non_exportable_root_key") and event.get("new_key_non_exportable") is not True:
            errors.append(f"{source}: new root key must be non-exportable")
        if policy.get("require_hardware_isolation") and event.get("new_key_hardware_isolated") is not True:
            errors.append(f"{source}: new root key must be hardware isolated")

    if event.get("auth_policy_changed") is True and policy.get("require_key_rotation_on_auth_change"):
        if kind != "rotate":
            errors.append(f"{source}: authentication-policy change requires key rotation")
        if event.get("old_key_invalidated") is not True:
            errors.append(f"{source}: authentication-policy change requires old key invalidation")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate E2EESA secret-storage evidence.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("mechanism_registry", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--key-event", type=Path)
    args = parser.parse_args()
    try:
        policy = load_json(args.policy)
        mechanisms = load_json(args.mechanism_registry)
        crypto = load_json(args.crypto_registry)
        catalog = load_json(args.profile_catalog)
        errors = validate_policy(policy, mechanisms, crypto, catalog)
        if args.state:
            errors.extend(validate_state(
                policy, load_json(args.state), mechanisms, crypto, catalog
            ))
        if args.key_event:
            errors.extend(validate_key_event(policy, load_json(args.key_event)))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    errors = sorted(set(errors))
    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
