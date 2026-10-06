#!/usr/bin/env python3
"""Deterministic semantic validator for E2EESA pairwise E2EE profiles.

This module does not implement X3DH, PQXDH, Double Ratchet, SPQR, Triple
Ratchet, or ML-KEM Braid. It validates that a product configuration and
cryptographically verified conformance evidence obey the exact profile binding
and lifecycle invariants selected by E2EESA.
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
PROTO_ID_RE = re.compile(r"^PROTO-[A-Z0-9-]+$")
PROPERTY_ID_RE = re.compile(r"^SP-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

ALL_STATUSES = {
    "recommended",
    "allowed",
    "provisional",
    "experimental",
    "legacy",
    "deprecated",
    "prohibited",
}

PROFILE_BINDINGS: dict[str, dict[str, Any]] = {
    "pairwise-x3dh-double-ratchet@0.1.0": {
        "initialization_protocol_id": "PROTO-X3DH-R1",
        "ratchet_protocol_id": "PROTO-DOUBLE-RATCHET-R4",
        "pq_required": False,
        "ec_component": True,
        "pq_component": False,
    },
    "pairwise-pqxdh-double-ratchet@0.1.0": {
        "initialization_protocol_id": "PROTO-PQXDH-R3-2024",
        "ratchet_protocol_id": "PROTO-DOUBLE-RATCHET-R4",
        "pq_required": True,
        "ec_component": True,
        "pq_component": False,
    },
    "pairwise-pqxdh-spqr@0.1.0": {
        "initialization_protocol_id": "PROTO-PQXDH-R3-2024",
        "ratchet_protocol_id": "PROTO-SPQR-MLKEM-BRAID-R4",
        "pq_required": True,
        "ec_component": False,
        "pq_component": True,
    },
    "pairwise-pqxdh-triple-ratchet@0.1.0": {
        "initialization_protocol_id": "PROTO-PQXDH-R3-2024",
        "ratchet_protocol_id": "PROTO-TRIPLE-RATCHET-R4",
        "pq_required": True,
        "ec_component": True,
        "pq_component": True,
    },
}

INVARIANT_POLICY_BOOLEANS = (
    "require_identity_binding",
    "require_associated_data_identity_binding",
    "require_one_time_prekey_when_available",
    "require_replay_protection",
    "require_message_key_deletion",
    "require_old_ratchet_state_deletion",
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _unique_string_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(_nonempty_string(item) for item in value)
        and len(value) == len(set(value))
    )


def _protocol_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("protocols", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


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


def validate_protocol_registry(
    registry: dict[str, Any],
    *,
    known_property_ids: set[str] | None = None,
    source: str = "pairwise protocol registry",
) -> list[str]:
    errors: list[str] = []
    required_top = {"schema_version", "registry_version", "standard_version", "protocols"}
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

    ids: set[str] = set()
    required_protocols = {
        "PROTO-X3DH-R1": "initialization",
        "PROTO-PQXDH-R3-2024": "initialization",
        "PROTO-DOUBLE-RATCHET-R4": "ratchet",
        "PROTO-SPQR-MLKEM-BRAID-R4": "ratchet",
        "PROTO-TRIPLE-RATCHET-R4": "ratchet",
        "PROTO-SESAME-R2": "session-management",
    }

    required_fields = {
        "id",
        "name",
        "role",
        "status",
        "specification",
        "revision",
        "published_or_updated",
        "reference_uri",
        "quantum_characteristic",
        "security_properties",
        "constraints",
    }
    for index, protocol in enumerate(protocols):
        prefix = f"{source}: protocols[{index}]"
        if not isinstance(protocol, dict):
            errors.append(f"{prefix}: protocol must be an object")
            continue
        extra = sorted(set(protocol) - required_fields)
        missing = sorted(required_fields - protocol.keys())
        if extra:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra)}")
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")

        pid = protocol.get("id")
        if not isinstance(pid, str) or not PROTO_ID_RE.fullmatch(pid):
            errors.append(f"{prefix}: invalid protocol id")
        elif pid in ids:
            errors.append(f"{prefix}: duplicate protocol id: {pid}")
        else:
            ids.add(pid)

        if protocol.get("role") not in {"initialization", "ratchet", "session-management"}:
            errors.append(f"{prefix}: invalid role")
        if protocol.get("status") not in ALL_STATUSES:
            errors.append(f"{prefix}: invalid status")
        if protocol.get("quantum_characteristic") not in {
            "classical",
            "post-quantum",
            "hybrid",
            "protocol-agnostic",
        }:
            errors.append(f"{prefix}: invalid quantum_characteristic")

        for field in ("name", "specification", "revision", "published_or_updated", "reference_uri"):
            if not _nonempty_string(protocol.get(field)):
                errors.append(f"{prefix}: {field} must be non-empty")

        properties = protocol.get("security_properties")
        if not _unique_string_list(properties):
            errors.append(f"{prefix}: security_properties must be a unique string array")
        else:
            for property_id in properties:
                if not PROPERTY_ID_RE.fullmatch(property_id):
                    errors.append(f"{prefix}: invalid security property id: {property_id}")
                elif known_property_ids is not None and property_id not in known_property_ids:
                    errors.append(f"{prefix}: unknown security property id: {property_id}")

        constraints = protocol.get("constraints")
        if not _unique_string_list(constraints) or not constraints:
            errors.append(f"{prefix}: constraints must be a non-empty unique string array")

    by_id = _protocol_index(registry)
    for protocol_id, expected_role in required_protocols.items():
        protocol = by_id.get(protocol_id)
        if protocol is None:
            errors.append(f"{source}: missing required protocol: {protocol_id}")
        elif protocol.get("role") != expected_role:
            errors.append(
                f"{source}: {protocol_id} must have role {expected_role}"
            )

    pqxdh = by_id.get("PROTO-PQXDH-R3-2024")
    if pqxdh is not None and "SP-PQ-AUTHENTICATION" in pqxdh.get("security_properties", []):
        errors.append(
            f"{source}: current PQXDH profile must not claim SP-PQ-AUTHENTICATION"
        )

    return errors


def _validate_algorithm(
    algorithm_id: Any,
    *,
    expected_category: str,
    algorithms: dict[str, dict[str, Any]],
    source: str,
) -> list[str]:
    errors: list[str] = []
    if not _nonempty_string(algorithm_id):
        return [f"{source}: algorithm id must be a non-empty string"]
    algorithm = algorithms.get(algorithm_id)
    if algorithm is None:
        return [f"{source}: unknown algorithm id: {algorithm_id}"]
    if algorithm.get("category") != expected_category:
        errors.append(
            f"{source}: algorithm {algorithm_id} has category {algorithm.get('category')}, "
            f"expected {expected_category}"
        )
    if algorithm.get("status") == "prohibited":
        errors.append(f"{source}: prohibited algorithm: {algorithm_id}")
    return errors


def validate_policy(
    policy: dict[str, Any],
    protocol_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "pairwise policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "profile_ref",
        "protocol_registry_version",
        "initialization_protocol_id",
        "ratchet_protocol_id",
        "ec_algorithm_id",
        "pq_kem_algorithm_id",
        "kdf_algorithm_id",
        "aead_algorithm_id",
        "application_info",
        "require_identity_binding",
        "require_associated_data_identity_binding",
        "require_one_time_prekey_when_available",
        "require_replay_protection",
        "require_message_key_deletion",
        "require_old_ratchet_state_deletion",
        "max_skipped_message_keys",
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
    if binding is None:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    else:
        profile = _profile_index(profile_catalog).get(profile_ref)
        if profile is None:
            errors.append(f"{source}: profile_ref is not present in profile catalog: {profile_ref}")
        elif profile.get("family_id") != "pairwise-e2ee":
            errors.append(f"{source}: profile_ref must belong to pairwise-e2ee")
        elif (
            profile_ref != "pairwise-x3dh-double-ratchet@0.1.0"
            and "SP-PQ-AUTHENTICATION" in profile.get("security_properties", [])
        ):
            errors.append(
                f"{source}: current PQXDH-based profiles must not claim SP-PQ-AUTHENTICATION"
            )

    if policy.get("protocol_registry_version") != protocol_registry.get("registry_version"):
        errors.append(
            f"{source}: protocol_registry_version does not match registry"
        )

    protocol_index = _protocol_index(protocol_registry)
    if binding is not None:
        if policy.get("initialization_protocol_id") != binding["initialization_protocol_id"]:
            errors.append(
                f"{source}: initialization_protocol_id does not match selected profile"
            )
        if policy.get("ratchet_protocol_id") != binding["ratchet_protocol_id"]:
            errors.append(
                f"{source}: ratchet_protocol_id does not match selected profile"
            )

    init_protocol = protocol_index.get(policy.get("initialization_protocol_id"))
    if init_protocol is None:
        errors.append(f"{source}: unknown initialization_protocol_id")
    elif init_protocol.get("role") != "initialization":
        errors.append(f"{source}: initialization_protocol_id does not identify an initialization protocol")
    elif init_protocol.get("status") == "prohibited":
        errors.append(f"{source}: initialization protocol is prohibited")

    ratchet_protocol = protocol_index.get(policy.get("ratchet_protocol_id"))
    if ratchet_protocol is None:
        errors.append(f"{source}: unknown ratchet_protocol_id")
    elif ratchet_protocol.get("role") != "ratchet":
        errors.append(f"{source}: ratchet_protocol_id does not identify a ratchet protocol")
    elif ratchet_protocol.get("status") == "prohibited":
        errors.append(f"{source}: ratchet protocol is prohibited")

    for field in INVARIANT_POLICY_BOOLEANS:
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} is an E2EESA invariant and must be true")

    application_info = policy.get("application_info")
    if not isinstance(application_info, str) or len(application_info) < 8:
        errors.append(f"{source}: application_info must contain at least 8 characters")
    elif not application_info.isascii():
        errors.append(f"{source}: application_info must be ASCII")

    max_skipped = policy.get("max_skipped_message_keys")
    if (
        not isinstance(max_skipped, int)
        or isinstance(max_skipped, bool)
        or max_skipped < 0
    ):
        errors.append(f"{source}: max_skipped_message_keys must be a non-negative integer")

    algorithms = _algorithm_index(crypto_registry)
    errors.extend(
        _validate_algorithm(
            policy.get("ec_algorithm_id"),
            expected_category="key-agreement",
            algorithms=algorithms,
            source=f"{source}: ec_algorithm_id",
        )
    )
    if policy.get("ec_algorithm_id") != "ALG-X25519":
        errors.append(
            f"{source}: E2EESA pairwise profiles 0.1 currently pin ALG-X25519"
        )

    errors.extend(
        _validate_algorithm(
            policy.get("kdf_algorithm_id"),
            expected_category="kdf",
            algorithms=algorithms,
            source=f"{source}: kdf_algorithm_id",
        )
    )
    errors.extend(
        _validate_algorithm(
            policy.get("aead_algorithm_id"),
            expected_category="aead",
            algorithms=algorithms,
            source=f"{source}: aead_algorithm_id",
        )
    )

    pq_kem = policy.get("pq_kem_algorithm_id")
    if binding is not None and binding["pq_required"]:
        errors.extend(
            _validate_algorithm(
                pq_kem,
                expected_category="kem",
                algorithms=algorithms,
                source=f"{source}: pq_kem_algorithm_id",
            )
        )
        algorithm = algorithms.get(pq_kem) if isinstance(pq_kem, str) else None
        if algorithm is not None and algorithm.get("pq_characteristic") != "post-quantum":
            errors.append(f"{source}: pq_kem_algorithm_id must be post-quantum")
    elif binding is not None and pq_kem is not None:
        errors.append(
            f"{source}: classical pairwise profile must set pq_kem_algorithm_id to null"
        )

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")

    return sorted(set(errors))


def validate_handshake_evidence(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    source: str = "pairwise handshake evidence",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "session_id",
        "profile_ref",
        "protocol_registry_version",
        "initialization_protocol_id",
        "initiator_device_id",
        "responder_device_id",
        "initiator_identity_key_fingerprint",
        "responder_identity_key_fingerprint",
        "signed_prekey_id",
        "signed_prekey_signature_verified",
        "one_time_prekey_available",
        "one_time_prekey_id",
        "one_time_prekey_consumed",
        "pq_signed_prekey_id",
        "pq_signed_prekey_verified",
        "pq_one_time_prekey_available",
        "pq_one_time_prekey_id",
        "pq_one_time_prekey_consumed",
        "associated_data_binds_identities",
        "initial_ciphertext_authenticated",
        "initial_message_id",
        "replay_status",
        "ratchet_initialized",
        "responder_first_send_randomized",
    }
    extra = sorted(set(evidence) - required)
    missing = sorted(required - evidence.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")

    if evidence.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in (
        "session_id",
        "initiator_device_id",
        "responder_device_id",
        "signed_prekey_id",
        "initial_message_id",
    ):
        value = evidence.get(field)
        if not isinstance(value, str) or not ID_RE.fullmatch(value):
            errors.append(f"{source}: invalid {field}")

    if evidence.get("initiator_device_id") == evidence.get("responder_device_id"):
        errors.append(f"{source}: initiator and responder devices must differ")

    for field in (
        "initiator_identity_key_fingerprint",
        "responder_identity_key_fingerprint",
    ):
        value = evidence.get(field)
        if not isinstance(value, str) or not FINGERPRINT_RE.fullmatch(value):
            errors.append(f"{source}: invalid {field}")

    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("protocol_registry_version") != policy.get("protocol_registry_version"):
        errors.append(f"{source}: protocol_registry_version does not match policy")
    if evidence.get("initialization_protocol_id") != policy.get("initialization_protocol_id"):
        errors.append(f"{source}: initialization_protocol_id does not match policy")

    if evidence.get("signed_prekey_signature_verified") is not True:
        errors.append(f"{source}: signed prekey signature must be verified")

    if evidence.get("one_time_prekey_available") is True:
        if not _nonempty_string(evidence.get("one_time_prekey_id")):
            errors.append(f"{source}: available one-time prekey requires one_time_prekey_id")
        if evidence.get("one_time_prekey_consumed") is not True:
            errors.append(f"{source}: available one-time prekey must be consumed")
    else:
        if evidence.get("one_time_prekey_id") is not None:
            errors.append(f"{source}: absent one-time prekey must use null one_time_prekey_id")
        if evidence.get("one_time_prekey_consumed") is not False:
            errors.append(f"{source}: absent one-time prekey cannot be consumed")

    binding = PROFILE_BINDINGS.get(policy.get("profile_ref"))
    pq_required = bool(binding and binding["pq_required"])
    if pq_required:
        if not _nonempty_string(evidence.get("pq_signed_prekey_id")):
            errors.append(f"{source}: PQXDH requires pq_signed_prekey_id")
        if evidence.get("pq_signed_prekey_verified") is not True:
            errors.append(f"{source}: PQXDH post-quantum signed prekey must be verified")
        if evidence.get("pq_one_time_prekey_available") is True:
            if not _nonempty_string(evidence.get("pq_one_time_prekey_id")):
                errors.append(f"{source}: available PQ one-time prekey requires an id")
            if evidence.get("pq_one_time_prekey_consumed") is not True:
                errors.append(f"{source}: available PQ one-time prekey must be consumed")
        else:
            if evidence.get("pq_one_time_prekey_id") is not None:
                errors.append(f"{source}: absent PQ one-time prekey must use null id")
            if evidence.get("pq_one_time_prekey_consumed") is not False:
                errors.append(f"{source}: absent PQ one-time prekey cannot be consumed")
    else:
        if evidence.get("pq_signed_prekey_id") is not None:
            errors.append(f"{source}: X3DH profile must not include a PQ signed prekey")
        if evidence.get("pq_signed_prekey_verified") is not False:
            errors.append(f"{source}: X3DH profile must not report PQ signed-prekey verification")
        if evidence.get("pq_one_time_prekey_available") is not False:
            errors.append(f"{source}: X3DH profile must not report PQ one-time prekeys")
        if evidence.get("pq_one_time_prekey_id") is not None:
            errors.append(f"{source}: X3DH profile must set pq_one_time_prekey_id to null")
        if evidence.get("pq_one_time_prekey_consumed") is not False:
            errors.append(f"{source}: X3DH profile must not consume a PQ one-time prekey")

    for field, label in (
        ("associated_data_binds_identities", "associated data must bind both identities"),
        ("initial_ciphertext_authenticated", "initial ciphertext must authenticate successfully"),
        ("ratchet_initialized", "ratchet must initialize successfully"),
        ("responder_first_send_randomized", "responder first send must randomize post-handshake key material"),
    ):
        if evidence.get(field) is not True:
            errors.append(f"{source}: {label}")

    if evidence.get("replay_status") != "fresh":
        errors.append(f"{source}: replayed initial message must be rejected")

    return sorted(set(errors))


def validate_message_checkpoint(
    policy: dict[str, Any],
    checkpoint: dict[str, Any],
    source: str = "pairwise message checkpoint",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "session_id",
        "profile_ref",
        "ratchet_protocol_id",
        "message_id",
        "message_number",
        "replay_status",
        "associated_data_authenticated",
        "message_key_unique",
        "message_key_deleted",
        "superseded_key_material_deleted",
        "skipped_message_keys_retained",
        "ec_ratchet_component_active",
        "pq_ratchet_component_active",
    }
    extra = sorted(set(checkpoint) - required)
    missing = sorted(required - checkpoint.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")

    if checkpoint.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("session_id", "message_id"):
        value = checkpoint.get(field)
        if not isinstance(value, str) or not ID_RE.fullmatch(value):
            errors.append(f"{source}: invalid {field}")

    if checkpoint.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if checkpoint.get("ratchet_protocol_id") != policy.get("ratchet_protocol_id"):
        errors.append(f"{source}: ratchet_protocol_id does not match policy")

    number = checkpoint.get("message_number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 0:
        errors.append(f"{source}: message_number must be a non-negative integer")

    retained = checkpoint.get("skipped_message_keys_retained")
    if not isinstance(retained, int) or isinstance(retained, bool) or retained < 0:
        errors.append(f"{source}: skipped_message_keys_retained must be non-negative")
    elif isinstance(policy.get("max_skipped_message_keys"), int) and retained > policy["max_skipped_message_keys"]:
        errors.append(
            f"{source}: skipped message key retention exceeds policy maximum"
        )

    if checkpoint.get("replay_status") != "fresh":
        errors.append(f"{source}: replayed ratchet message must be rejected")
    for field, label in (
        ("associated_data_authenticated", "associated data must be authenticated"),
        ("message_key_unique", "message key must be unique to this message"),
        ("message_key_deleted", "message key must be deleted after use"),
        ("superseded_key_material_deleted", "superseded key material must be deleted"),
    ):
        if checkpoint.get(field) is not True:
            errors.append(f"{source}: {label}")

    binding = PROFILE_BINDINGS.get(policy.get("profile_ref"))
    if binding is not None:
        if checkpoint.get("ec_ratchet_component_active") is not binding["ec_component"]:
            errors.append(f"{source}: EC ratchet component does not match selected profile")
        if checkpoint.get("pq_ratchet_component_active") is not binding["pq_component"]:
            errors.append(f"{source}: PQ ratchet component does not match selected profile")

    return sorted(set(errors))


def validate_pairwise_case(
    policy: dict[str, Any],
    handshake: dict[str, Any],
    checkpoint: dict[str, Any],
    protocol_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    errors.extend(validate_policy(policy, protocol_registry, crypto_registry, profile_catalog))
    if not errors:
        errors.extend(validate_handshake_evidence(policy, handshake))
        errors.extend(validate_message_checkpoint(policy, checkpoint))
        if handshake.get("session_id") != checkpoint.get("session_id"):
            errors.append("pairwise evidence: handshake and checkpoint session_id values differ")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an E2EESA pairwise session evidence bundle.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("handshake", type=Path)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("protocol_registry", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    args = parser.parse_args()

    try:
        policy = load_json(args.policy)
        handshake = load_json(args.handshake)
        checkpoint = load_json(args.checkpoint)
        protocol_registry = load_json(args.protocol_registry)
        crypto_registry = load_json(args.crypto_registry)
        profile_catalog = load_json(args.profile_catalog)
        errors = validate_pairwise_case(
            policy,
            handshake,
            checkpoint,
            protocol_registry,
            crypto_registry,
            profile_catalog,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
