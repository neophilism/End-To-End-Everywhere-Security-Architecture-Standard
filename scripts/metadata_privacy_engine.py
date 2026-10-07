#!/usr/bin/env python3
"""Semantic validator for E2EESA metadata privacy profiles.

This module validates metadata-exposure and retention evidence. It does not
implement end-to-end encryption, sender-hidden envelopes, HPKE, or Oblivious
HTTP. Evidence booleans must only be populated after the corresponding
protocol operations and deployment properties have been verified.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

PROFILE_MODES = {
    "metadata-minimized@0.1.0": "minimized",
    "metadata-sender-hidden@0.1.0": "sender-hidden",
    "metadata-relay-partitioned@0.1.0": "relay-partitioned",
}

BASELINE_MAX_RETENTION_SECONDS = 86_400
SENDER_HIDDEN_MAX_RETENTION_SECONDS = 3_600
RELAY_MIN_PADDING_MULTIPLE_BYTES = 256

COMMON_POLICY_INVARIANTS = (
    "prohibit_durable_social_graph",
    "prohibit_content_derived_service_metadata",
    "prohibit_stable_cross_service_identifier",
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


def _algorithm_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _mechanism_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("mechanisms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def validate_protocol_registry(
    registry: dict[str, Any],
    source: str = "metadata privacy registry",
) -> list[str]:
    errors: list[str] = []
    required_top = {"schema_version", "registry_version", "standard_version", "mechanisms"}
    extra = sorted(set(registry) - required_top)
    missing = sorted(required_top - registry.keys())
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
    for index, item in enumerate(mechanisms):
        prefix = f"{source}: mechanisms[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: mechanism must be an object")
            continue
        required = {
            "id","name","status","mechanism_type","specification","reference_uri","notes"
        }
        extra_item = sorted(set(item) - required)
        missing_item = sorted(required - item.keys())
        if extra_item:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra_item)}")
        if missing_item:
            errors.append(f"{prefix}: missing fields: {', '.join(missing_item)}")
        mid = item.get("id")
        if not isinstance(mid, str) or not mid.startswith("META-"):
            errors.append(f"{prefix}: invalid mechanism id")
        else:
            ids.append(mid)
        if item.get("status") not in {
            "recommended","allowed","provisional","experimental",
            "legacy","deprecated","prohibited",
        }:
            errors.append(f"{prefix}: invalid status")
        if item.get("mechanism_type") not in {
            "minimization","sender-hiding","relay-partition",
            "configuration-privacy","architecture-guidance",
        }:
            errors.append(f"{prefix}: invalid mechanism_type")

    if len(ids) != len(set(ids)):
        errors.append(f"{source}: mechanism ids must be unique")

    by_id = _mechanism_index(registry)
    for required_id in (
        "META-MINIMIZATION-1",
        "META-SENDER-HIDDEN-1",
        "META-OHTTP-RFC9458",
        "META-OHTTP-DISCOVERY-RFC9540",
        "META-PRIVACY-PARTITION-RFC9614",
    ):
        if required_id not in by_id:
            errors.append(f"{source}: missing required mechanism: {required_id}")

    ohttp = by_id.get("META-OHTTP-RFC9458")
    if ohttp is not None and ohttp.get("specification") != "RFC 9458":
        errors.append(f"{source}: META-OHTTP-RFC9458 must pin RFC 9458")
    return sorted(set(errors))


def _validate_algorithm(
    algorithm_id: Any,
    *,
    category: str,
    crypto_registry: dict[str, Any],
    source: str,
) -> list[str]:
    if not isinstance(algorithm_id, str) or not algorithm_id:
        return [f"{source}: algorithm id must be a non-empty string"]
    algorithm = _algorithm_index(crypto_registry).get(algorithm_id)
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
    mechanism_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "metadata privacy policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version","policy_id","profile_ref","protocol_registry_version",
        "max_post_delivery_metadata_retention_seconds",
        "max_service_source_ip_retention_seconds",
        "max_relay_source_ip_retention_seconds",
        "prohibit_durable_social_graph","prohibit_content_derived_service_metadata",
        "prohibit_stable_cross_service_identifier",
        "sender_hidden_required","recipient_delivery_capability_required",
        "recipient_authenticates_sender_inside_e2ee",
        "relay_partition_required","ohttp_required",
        "require_independent_relay_gateway","require_authenticated_gateway_key_config",
        "require_nonpersonalized_gateway_key_config","require_no_identifying_relay_headers",
        "require_ohttp_replay_protection","ohttp_kem_algorithm_id",
        "ohttp_kdf_algorithm_id","ohttp_aead_algorithm_id",
        "request_padding_mode","minimum_padding_multiple_bytes",
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
        elif profile.get("family_id") != "metadata-privacy":
            errors.append(f"{source}: profile_ref must belong to metadata-privacy")

    if policy.get("protocol_registry_version") != mechanism_registry.get("registry_version"):
        errors.append(f"{source}: protocol_registry_version does not match registry")

    for field in COMMON_POLICY_INVARIANTS:
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} is an E2EESA invariant and must be true")

    for field in (
        "max_post_delivery_metadata_retention_seconds",
        "max_service_source_ip_retention_seconds",
    ):
        value = policy.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"{source}: {field} must be a non-negative integer")

    relay_retention = policy.get("max_relay_source_ip_retention_seconds")
    if relay_retention is not None and (
        not isinstance(relay_retention, int)
        or isinstance(relay_retention, bool)
        or relay_retention < 0
    ):
        errors.append(f"{source}: max_relay_source_ip_retention_seconds must be null or non-negative")

    if mode == "minimized":
        if policy.get("max_post_delivery_metadata_retention_seconds", BASELINE_MAX_RETENTION_SECONDS + 1) > BASELINE_MAX_RETENTION_SECONDS:
            errors.append(f"{source}: minimized profile post-delivery retention exceeds 24 hours")
        if policy.get("max_service_source_ip_retention_seconds", BASELINE_MAX_RETENTION_SECONDS + 1) > BASELINE_MAX_RETENTION_SECONDS:
            errors.append(f"{source}: minimized profile source-IP retention exceeds 24 hours")
        if relay_retention is not None:
            errors.append(f"{source}: minimized profile must set relay source-IP retention to null")
        for field in (
            "sender_hidden_required","recipient_delivery_capability_required",
            "recipient_authenticates_sender_inside_e2ee","relay_partition_required",
            "ohttp_required","require_independent_relay_gateway",
            "require_authenticated_gateway_key_config",
            "require_nonpersonalized_gateway_key_config",
            "require_no_identifying_relay_headers","require_ohttp_replay_protection",
        ):
            if policy.get(field) is not False:
                errors.append(f"{source}: minimized profile must set {field}=false")
        for field in ("ohttp_kem_algorithm_id","ohttp_kdf_algorithm_id","ohttp_aead_algorithm_id"):
            if policy.get(field) is not None:
                errors.append(f"{source}: minimized profile must set {field} to null")
        if policy.get("request_padding_mode") != "none":
            errors.append(f"{source}: minimized profile must set request_padding_mode to none")
        if policy.get("minimum_padding_multiple_bytes") is not None:
            errors.append(f"{source}: minimized profile must set minimum_padding_multiple_bytes to null")

    if mode == "sender-hidden":
        if policy.get("max_post_delivery_metadata_retention_seconds", SENDER_HIDDEN_MAX_RETENTION_SECONDS + 1) > SENDER_HIDDEN_MAX_RETENTION_SECONDS:
            errors.append(f"{source}: sender-hidden post-delivery retention exceeds one hour")
        if policy.get("max_service_source_ip_retention_seconds", SENDER_HIDDEN_MAX_RETENTION_SECONDS + 1) > SENDER_HIDDEN_MAX_RETENTION_SECONDS:
            errors.append(f"{source}: sender-hidden source-IP retention exceeds one hour")
        if relay_retention is not None:
            errors.append(f"{source}: sender-hidden profile must set relay source-IP retention to null")
        for field in (
            "sender_hidden_required","recipient_delivery_capability_required",
            "recipient_authenticates_sender_inside_e2ee",
        ):
            if policy.get(field) is not True:
                errors.append(f"{source}: sender-hidden profile requires {field}=true")
        for field in (
            "relay_partition_required","ohttp_required",
            "require_independent_relay_gateway","require_authenticated_gateway_key_config",
            "require_nonpersonalized_gateway_key_config",
            "require_no_identifying_relay_headers","require_ohttp_replay_protection",
        ):
            if policy.get(field) is not False:
                errors.append(f"{source}: sender-hidden profile must set {field}=false")
        for field in ("ohttp_kem_algorithm_id","ohttp_kdf_algorithm_id","ohttp_aead_algorithm_id"):
            if policy.get(field) is not None:
                errors.append(f"{source}: sender-hidden profile must set {field} to null")
        if policy.get("request_padding_mode") != "none":
            errors.append(f"{source}: sender-hidden profile must set request_padding_mode to none")
        if policy.get("minimum_padding_multiple_bytes") is not None:
            errors.append(f"{source}: sender-hidden profile must set minimum_padding_multiple_bytes to null")

    if mode == "relay-partitioned":
        if policy.get("max_post_delivery_metadata_retention_seconds", SENDER_HIDDEN_MAX_RETENTION_SECONDS + 1) > SENDER_HIDDEN_MAX_RETENTION_SECONDS:
            errors.append(f"{source}: relay-partitioned post-delivery retention exceeds one hour")
        if policy.get("max_service_source_ip_retention_seconds") != 0:
            errors.append(f"{source}: relay-partitioned service source-IP retention must be zero")
        if relay_retention != 0:
            errors.append(f"{source}: relay-partitioned relay source-IP retention must be zero after request completion")
        for field in (
            "sender_hidden_required","recipient_delivery_capability_required",
            "recipient_authenticates_sender_inside_e2ee","relay_partition_required",
            "ohttp_required","require_independent_relay_gateway",
            "require_authenticated_gateway_key_config",
            "require_nonpersonalized_gateway_key_config",
            "require_no_identifying_relay_headers","require_ohttp_replay_protection",
        ):
            if policy.get(field) is not True:
                errors.append(f"{source}: relay-partitioned profile requires {field}=true")
        errors.extend(_validate_algorithm(
            policy.get("ohttp_kem_algorithm_id"),
            category="kem", crypto_registry=crypto_registry,
            source=f"{source}: ohttp_kem_algorithm_id",
        ))
        errors.extend(_validate_algorithm(
            policy.get("ohttp_kdf_algorithm_id"),
            category="kdf", crypto_registry=crypto_registry,
            source=f"{source}: ohttp_kdf_algorithm_id",
        ))
        errors.extend(_validate_algorithm(
            policy.get("ohttp_aead_algorithm_id"),
            category="aead", crypto_registry=crypto_registry,
            source=f"{source}: ohttp_aead_algorithm_id",
        ))
        if policy.get("request_padding_mode") != "binary-http-padding":
            errors.append(f"{source}: relay-partitioned profile requires binary-http-padding")
        padding = policy.get("minimum_padding_multiple_bytes")
        if not isinstance(padding, int) or isinstance(padding, bool) or padding < RELAY_MIN_PADDING_MULTIPLE_BYTES:
            errors.append(f"{source}: relay-partitioned padding multiple must be at least 256 bytes")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return sorted(set(errors))


def validate_delivery_evidence(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    mechanism_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "metadata delivery evidence",
) -> list[str]:
    errors = validate_policy(
        policy, mechanism_registry, crypto_registry, profile_catalog
    )
    if errors:
        return errors

    required = {
        "schema_version","event_id","profile_ref","message_id",
        "e2ee_content_encryption_verified",
        "recipient_routing_identifier_visible_to_service",
        "sender_identity_visible_to_service","sender_identity_visible_to_recipient",
        "sender_credential_inside_e2ee_envelope","recipient_delivery_capability_verified",
        "durable_sender_recipient_mapping_written","content_derived_service_metadata_written",
        "stable_cross_service_identifier_attached",
        "post_delivery_metadata_retention_seconds",
        "service_observed_client_network_address","service_source_ip_retention_seconds",
        "relay_used","ohttp_encapsulated","gateway_key_config_authenticated",
        "gateway_key_config_personalized","relay_observed_client_network_address",
        "relay_source_ip_retention_seconds","relay_observed_application_plaintext",
        "gateway_observed_client_network_address","relay_added_identifying_headers",
        "relay_gateway_independent_operators","request_padding_applied",
        "padding_multiple_bytes","ohttp_replay_protection_enforced",
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
    for field in ("event_id","message_id"):
        if not isinstance(evidence.get(field), str) or not ID_RE.fullmatch(evidence.get(field, "")):
            errors.append(f"{source}: invalid {field}")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")

    if evidence.get("e2ee_content_encryption_verified") is not True:
        errors.append(f"{source}: end-to-end content encryption must remain verified")
    if evidence.get("recipient_routing_identifier_visible_to_service") is not True:
        errors.append(
            f"{source}: E2EESA 0.1 messaging metadata profiles assume the service sees the recipient routing identifier"
        )
    if evidence.get("sender_identity_visible_to_recipient") is not True:
        errors.append(f"{source}: recipient must authenticate the sender")

    for field, label in (
        ("durable_sender_recipient_mapping_written","durable sender-recipient mapping is prohibited"),
        ("content_derived_service_metadata_written","content-derived service metadata is prohibited"),
        ("stable_cross_service_identifier_attached","stable cross-service tracking identifier is prohibited"),
    ):
        if evidence.get(field) is not False:
            errors.append(f"{source}: {label}")

    post_retention = evidence.get("post_delivery_metadata_retention_seconds")
    if (
        not isinstance(post_retention, int)
        or isinstance(post_retention, bool)
        or post_retention < 0
        or post_retention > policy["max_post_delivery_metadata_retention_seconds"]
    ):
        errors.append(f"{source}: post-delivery metadata retention exceeds policy")
    source_retention = evidence.get("service_source_ip_retention_seconds")
    if (
        not isinstance(source_retention, int)
        or isinstance(source_retention, bool)
        or source_retention < 0
        or source_retention > policy["max_service_source_ip_retention_seconds"]
    ):
        errors.append(f"{source}: service source-IP retention exceeds policy")

    mode = PROFILE_MODES[policy["profile_ref"]]
    if mode == "minimized":
        if evidence.get("relay_used") is not False:
            errors.append(f"{source}: minimized fixture/profile must not claim relay use")
        if evidence.get("ohttp_encapsulated") is not False:
            errors.append(f"{source}: minimized profile must not claim OHTTP")
        if evidence.get("relay_source_ip_retention_seconds") is not None:
            errors.append(f"{source}: minimized profile must use null relay retention")

    if mode in {"sender-hidden","relay-partitioned"}:
        if evidence.get("sender_identity_visible_to_service") is not False:
            errors.append(f"{source}: sender-hidden profile must not expose sender identity to service")
        if evidence.get("sender_credential_inside_e2ee_envelope") is not True:
            errors.append(f"{source}: sender credential must remain inside recipient-decryptable envelope")
        if evidence.get("recipient_delivery_capability_verified") is not True:
            errors.append(f"{source}: recipient delivery capability must verify")

    if mode == "sender-hidden":
        if evidence.get("relay_used") is not False:
            errors.append(f"{source}: sender-hidden profile must not claim relay partition")
        if evidence.get("ohttp_encapsulated") is not False:
            errors.append(f"{source}: sender-hidden profile must not claim OHTTP")
        if evidence.get("relay_source_ip_retention_seconds") is not None:
            errors.append(f"{source}: sender-hidden profile must use null relay retention")

    if mode == "relay-partitioned":
        if evidence.get("service_observed_client_network_address") is not False:
            errors.append(f"{source}: messaging service must not observe client network address")
        if evidence.get("relay_used") is not True:
            errors.append(f"{source}: relay-partitioned profile requires relay use")
        if evidence.get("ohttp_encapsulated") is not True:
            errors.append(f"{source}: relay-partitioned profile requires OHTTP encapsulation")
        if evidence.get("gateway_key_config_authenticated") is not True:
            errors.append(f"{source}: OHTTP gateway key configuration must authenticate")
        if evidence.get("gateway_key_config_personalized") is not False:
            errors.append(f"{source}: personalized OHTTP key configuration is prohibited")
        relay_retention = evidence.get("relay_source_ip_retention_seconds")
        if (
            not isinstance(relay_retention, int)
            or isinstance(relay_retention, bool)
            or relay_retention < 0
            or relay_retention > policy["max_relay_source_ip_retention_seconds"]
        ):
            errors.append(f"{source}: relay source-IP retention exceeds policy")
        if evidence.get("relay_observed_application_plaintext") is not False:
            errors.append(f"{source}: relay must not observe application plaintext")
        if evidence.get("gateway_observed_client_network_address") is not False:
            errors.append(f"{source}: OHTTP gateway must not observe client network address")
        if evidence.get("relay_added_identifying_headers") is not False:
            errors.append(f"{source}: relay must not add client-identifying forwarding metadata")
        if evidence.get("relay_gateway_independent_operators") is not True:
            errors.append(f"{source}: relay and gateway/service must be independently operated")
        if evidence.get("request_padding_applied") is not True:
            errors.append(f"{source}: relay-partitioned profile requires request padding")
        padding = evidence.get("padding_multiple_bytes")
        if (
            not isinstance(padding, int)
            or isinstance(padding, bool)
            or padding < policy["minimum_padding_multiple_bytes"]
        ):
            errors.append(f"{source}: request padding is below policy minimum")
        if evidence.get("ohttp_replay_protection_enforced") is not True:
            errors.append(f"{source}: OHTTP application replay protection must be enforced")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate E2EESA metadata privacy evidence.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("mechanism_registry", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    args = parser.parse_args()
    try:
        errors = validate_delivery_evidence(
            load_json(args.policy),
            load_json(args.evidence),
            load_json(args.mechanism_registry),
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
