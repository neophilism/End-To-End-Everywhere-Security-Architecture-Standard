"""Validate ciphertext-only service architecture and retention evidence."""
from pathlib import Path

from assurance_common import (
    binding_errors, check_schema, load_json, profile_errors, required_false,
    required_true, timestamp, validate_fixture_set,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "server-ciphertext-only@0.1.0"
SERVICE_KEY_PURPOSES = {"tls-authentication", "metadata-at-rest", "abuse-control"}


def validate_policy(policy, catalog, *, root=ROOT):
    errors = check_schema(root, "server-trust-policy", policy)
    if errors:
        return errors
    errors.extend(profile_errors(policy["profile_ref"], "server-trust", catalog))
    if policy["profile_ref"] != PROFILE:
        errors.append("unsupported server trust profile")
    errors.extend(required_true(policy, ("require_client_recipient_authorization", "require_no_application_key_access")))
    if not set(policy["allowed_service_key_purposes"]).issubset(SERVICE_KEY_PURPOSES):
        errors.append("service keys must be independent from application E2EE keys")
    return errors


def validate_deployment(policy, evidence, catalog, *, root=ROOT):
    errors = validate_policy(policy, catalog, root=root)
    errors.extend(check_schema(root, "server-deployment-evidence", evidence))
    if errors:
        return errors
    errors.extend(binding_errors(policy, evidence))
    components = {c["component_id"]: c for c in evidence["components"]}
    if len(components) != len(evidence["components"]):
        errors.append("server inventory: duplicate component IDs")
    if set(components) != set(evidence["assessed_component_ids"]):
        errors.append("server inventory: discovered and assessed components differ")
    for component in components.values():
        errors.extend(required_false(component, (
            "application_plaintext_access", "application_key_access",
            "backup_recovery_key_access", "can_authorize_e2ee_devices", "logs_application_content",
        )))
        errors.extend(required_true(component, ("metadata_at_rest_encrypted", "subprocessors_assessed")))
        if not set(component["metadata_fields"]).issubset(policy["allowed_metadata_fields"]):
            errors.append(f"{component['component_id']}: metadata exceeds the explicit allowlist")
        ids = [key["key_id"] for key in component["service_keys"]]
        if len(ids) != len(set(ids)):
            errors.append("server key inventory: duplicate keys")
        for key in component["service_keys"]:
            if key["purpose"] not in policy["allowed_service_key_purposes"]:
                errors.append("server key inventory: unauthorized key purpose")
            if key["shared_with_application_e2ee"]:
                errors.append("server key inventory: service key shared with application E2EE")
    errors.extend(required_true(evidence, ("client_envelope_validation", "storage_credentials_separate_from_e2ee", "compromise_test_completed")))
    try:
        observed = timestamp(evidence["observed_at"])
    except ValueError as exc:
        return errors + [str(exc)]
    object_ids = [o["object_id"] for o in evidence["objects"]]
    if len(set(object_ids)) != len(object_ids):
        errors.append("objects: duplicate object IDs")
    for item in evidence["objects"]:
        if item["component_id"] not in components:
            errors.append("object refers to an unassessed storage component")
        if set(item["recipient_device_ids"]) != set(item["authorized_device_ids"]):
            errors.append("object: recipient set must exactly match client-authorized devices")
        errors.extend(required_true(item, ("authenticated_envelope", "held_ciphertext_only", "derivatives_encrypted")))
        errors.extend(required_false(item, ("keys_in_locator", "plaintext_search_index")))
        try:
            created, expires = timestamp(item["created_at"]), timestamp(item["expires_at"])
            deleted = timestamp(item["deleted_at"]) if item["deleted_at"] is not None else None
            ttl = (expires - created).total_seconds()
            if created > observed or ttl <= 0 or ttl > policy["max_ciphertext_ttl_seconds"]:
                errors.append("object: invalid creation/expiration or excessive retention")
            if expires <= observed and deleted is None:
                errors.append("object: expired ciphertext must be purged")
            if deleted is not None and (deleted < created or deleted > expires or deleted > observed):
                errors.append("object: invalid or late deletion evidence")
        except ValueError as exc:
            errors.append(str(exc))
    return errors


def validate_repository(root, catalog):
    errors = []
    try:
        registry = load_json(root / "registry/server-trust-boundaries.json")
        errors.extend(check_schema(root, "server-trust-registry", registry))
        if set(registry["service_key_purposes"]) != SERVICE_KEY_PURPOSES:
            errors.append("server registry: changed service key separation rules")
        if registry["profile_ref"] != PROFILE:
            errors.append("server registry: unsupported profile")
        if set(registry["prohibited_server_holdings"]) != {
            "application-plaintext", "application-e2ee-keys", "backup-recovery-secrets", "device-authorization-roots"
        }:
            errors.append("server registry: required prohibited holdings were changed")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"server registry: {exc}")
    return errors + validate_fixture_set(root, "server-trust", validate_deployment, catalog)
