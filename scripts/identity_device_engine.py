#!/usr/bin/env python3
"""Deterministic E2EESA identity and device authorization evaluator.

The evaluator consumes *verified authorizer identities*. Cryptographic signature
verification is deliberately outside this module; a production caller MUST only
populate verified_authorizers after verifying signatures over the canonical
identity event payload with the applicable current key.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PROFILE_REF_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*@[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

IDENTITY_PROFILE_IDS = {
    "identity-account-root",
    "identity-device-cross-signing",
    "identity-threshold-quorum",
}
EVENT_TYPES = {"enroll", "rotate", "revoke"}
DEVICE_STATUSES = {"active", "revoked"}
AUTHORIZER_TYPES = {"device", "account-root", "server"}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _profile_id(profile_ref: str) -> str | None:
    if not isinstance(profile_ref, str) or not PROFILE_REF_RE.fullmatch(profile_ref):
        return None
    return profile_ref.split("@", 1)[0]


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _unique_string_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(_nonempty_string(item) for item in value)
        and len(value) == len(set(value))
    )


def canonical_state_bytes(state: dict[str, Any]) -> bytes:
    return json.dumps(
        state,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def state_hash(state: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_state_bytes(state)).hexdigest()


def _algorithm_index(crypto_registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in crypto_registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _profile_index(profile_catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in profile_catalog.get("profiles", []):
        if not isinstance(item, dict):
            continue
        pid = item.get("profile_id")
        version = item.get("profile_version")
        if isinstance(pid, str) and isinstance(version, str):
            result[f"{pid}@{version}"] = item
    return result


def _validate_key_descriptor(
    value: Any,
    *,
    source: str,
    expected_categories: set[str],
    algorithms: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return [f"{source}: key descriptor must be an object"]

    required = {"key_id", "algorithm_id", "public_key_fingerprint"}
    extra = sorted(set(value) - required)
    missing = sorted(required - value.keys())
    if extra:
        errors.append(f"{source}: unknown key fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing key fields: {', '.join(missing)}")

    key_id = value.get("key_id")
    if not isinstance(key_id, str) or not ID_RE.fullmatch(key_id):
        errors.append(f"{source}: invalid key_id")

    algorithm_id = value.get("algorithm_id")
    if not _nonempty_string(algorithm_id):
        errors.append(f"{source}: algorithm_id must be a non-empty string")
    else:
        algorithm = algorithms.get(algorithm_id)
        if algorithm is None:
            errors.append(f"{source}: unknown algorithm_id: {algorithm_id}")
        else:
            if algorithm.get("category") not in expected_categories:
                errors.append(
                    f"{source}: algorithm {algorithm_id} has category {algorithm.get('category')}, "
                    f"expected one of {', '.join(sorted(expected_categories))}"
                )
            if algorithm.get("status") == "prohibited":
                errors.append(f"{source}: prohibited algorithm_id: {algorithm_id}")

    fingerprint = value.get("public_key_fingerprint")
    if not isinstance(fingerprint, str) or not FINGERPRINT_RE.fullmatch(fingerprint):
        errors.append(f"{source}: public_key_fingerprint must be sha256:<64 lowercase hex>")

    return errors


def validate_policy(
    policy: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "identity policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "profile_ref",
        "require_state_hash_binding",
        "require_monotonic_sequence",
        "prohibit_server_authorization",
    }
    allowed = required | {"account_root_key_id", "notes"}
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
    profile_id = _profile_id(profile_ref) if isinstance(profile_ref, str) else None
    if profile_id not in IDENTITY_PROFILE_IDS:
        errors.append(f"{source}: unsupported identity profile_ref: {profile_ref}")
    else:
        catalog_profile = _profile_index(profile_catalog).get(profile_ref)
        if catalog_profile is None:
            errors.append(f"{source}: profile_ref is not present in the profile catalog: {profile_ref}")
        elif catalog_profile.get("family_id") != "identity-architecture":
            errors.append(f"{source}: profile_ref must belong to identity-architecture")

    for field in (
        "require_state_hash_binding",
        "require_monotonic_sequence",
        "prohibit_server_authorization",
    ):
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} is an E2EESA invariant and must be true")

    root_id = policy.get("account_root_key_id")
    if profile_id == "identity-account-root":
        if not isinstance(root_id, str) or not ID_RE.fullmatch(root_id):
            errors.append(f"{source}: identity-account-root requires a valid account_root_key_id")
    elif root_id is not None:
        errors.append(f"{source}: account_root_key_id is only valid for identity-account-root")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return errors


def validate_state(
    state: dict[str, Any],
    crypto_registry: dict[str, Any],
    source: str = "identity state",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "identity_id",
        "sequence",
        "account_root_key",
        "devices",
        "retired_key_ids",
    }
    extra = sorted(set(state) - required)
    missing = sorted(required - state.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")

    if state.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(state.get("identity_id"), str) or not ID_RE.fullmatch(state.get("identity_id", "")):
        errors.append(f"{source}: invalid identity_id")
    if not isinstance(state.get("sequence"), int) or isinstance(state.get("sequence"), bool) or state.get("sequence", -1) < 0:
        errors.append(f"{source}: sequence must be a non-negative integer")

    algorithms = _algorithm_index(crypto_registry)
    current_key_ids: list[str] = []
    current_fingerprints: list[str] = []

    root_key = state.get("account_root_key")
    if root_key is not None:
        errors.extend(
            _validate_key_descriptor(
                root_key,
                source=f"{source}: account_root_key",
                expected_categories={"signature"},
                algorithms=algorithms,
            )
        )
        if isinstance(root_key, dict):
            if isinstance(root_key.get("key_id"), str):
                current_key_ids.append(root_key["key_id"])
            if isinstance(root_key.get("public_key_fingerprint"), str):
                current_fingerprints.append(root_key["public_key_fingerprint"])

    devices = state.get("devices")
    if not isinstance(devices, list) or not devices:
        errors.append(f"{source}: devices must be a non-empty array")
        devices = []

    device_ids: list[str] = []
    for index, device in enumerate(devices):
        prefix = f"{source}: devices[{index}]"
        if not isinstance(device, dict):
            errors.append(f"{prefix}: device must be an object")
            continue
        required_device = {
            "device_id",
            "status",
            "key_generation",
            "signing_key",
            "agreement_key",
        }
        extra_device = sorted(set(device) - required_device)
        missing_device = sorted(required_device - device.keys())
        if extra_device:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra_device)}")
        if missing_device:
            errors.append(f"{prefix}: missing fields: {', '.join(missing_device)}")

        device_id = device.get("device_id")
        if not isinstance(device_id, str) or not ID_RE.fullmatch(device_id):
            errors.append(f"{prefix}: invalid device_id")
        else:
            device_ids.append(device_id)
        if device.get("status") not in DEVICE_STATUSES:
            errors.append(f"{prefix}: invalid status")
        generation = device.get("key_generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            errors.append(f"{prefix}: key_generation must be a positive integer")

        errors.extend(
            _validate_key_descriptor(
                device.get("signing_key"),
                source=f"{prefix}: signing_key",
                expected_categories={"signature"},
                algorithms=algorithms,
            )
        )
        errors.extend(
            _validate_key_descriptor(
                device.get("agreement_key"),
                source=f"{prefix}: agreement_key",
                expected_categories={"key-agreement", "kem"},
                algorithms=algorithms,
            )
        )
        for field in ("signing_key", "agreement_key"):
            key = device.get(field)
            if isinstance(key, dict):
                if isinstance(key.get("key_id"), str):
                    current_key_ids.append(key["key_id"])
                if isinstance(key.get("public_key_fingerprint"), str):
                    current_fingerprints.append(key["public_key_fingerprint"])

    if len(device_ids) != len(set(device_ids)):
        errors.append(f"{source}: device_id values must be unique and MUST NOT be reused")

    retired = state.get("retired_key_ids")
    if not _unique_string_list(retired):
        errors.append(f"{source}: retired_key_ids must be a unique string array")
        retired = []
    else:
        for key_id in retired:
            if not ID_RE.fullmatch(key_id):
                errors.append(f"{source}: invalid retired key id: {key_id}")

    if len(current_key_ids) != len(set(current_key_ids)):
        errors.append(f"{source}: current key_id values must be globally unique")
    if set(current_key_ids) & set(retired):
        errors.append(f"{source}: retired key ids must not be reused as current keys")
    if len(current_fingerprints) != len(set(current_fingerprints)):
        errors.append(f"{source}: current public-key fingerprints must be globally unique")

    if devices and not any(isinstance(d, dict) and d.get("status") == "active" for d in devices):
        errors.append(f"{source}: at least one active device is required")
    return errors


def validate_event(event: dict[str, Any], source: str = "identity event") -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "event_id",
        "identity_id",
        "sequence",
        "previous_state_hash",
        "event_type",
        "subject_device_id",
        "verified_authorizers",
    }
    conditional = {"new_key_generation", "new_signing_key", "new_agreement_key"}
    allowed = required | conditional
    extra = sorted(set(event) - allowed)
    missing = sorted(required - event.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")

    if event.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    for field in ("event_id", "identity_id", "subject_device_id"):
        if not isinstance(event.get(field), str) or not ID_RE.fullmatch(event.get(field, "")):
            errors.append(f"{source}: invalid {field}")
    if not isinstance(event.get("sequence"), int) or isinstance(event.get("sequence"), bool) or event.get("sequence", -1) < 1:
        errors.append(f"{source}: sequence must be a positive integer")
    previous_hash = event.get("previous_state_hash")
    if not isinstance(previous_hash, str) or not HASH_RE.fullmatch(previous_hash):
        errors.append(f"{source}: previous_state_hash must be 64 lowercase hex")

    event_type = event.get("event_type")
    if event_type not in EVENT_TYPES:
        errors.append(f"{source}: invalid event_type")

    authorizers = event.get("verified_authorizers")
    if not isinstance(authorizers, list) or not authorizers:
        errors.append(f"{source}: verified_authorizers must be a non-empty array")
        authorizers = []
    seen_authorizers: set[tuple[str, str]] = set()
    for index, authorizer in enumerate(authorizers):
        prefix = f"{source}: verified_authorizers[{index}]"
        if not isinstance(authorizer, dict):
            errors.append(f"{prefix}: authorizer must be an object")
            continue
        if set(authorizer) != {"type", "id"}:
            errors.append(f"{prefix}: authorizer fields must be exactly type and id")
        auth_type = authorizer.get("type")
        auth_id = authorizer.get("id")
        if auth_type not in AUTHORIZER_TYPES:
            errors.append(f"{prefix}: invalid authorizer type")
        if not isinstance(auth_id, str) or not ID_RE.fullmatch(auth_id):
            errors.append(f"{prefix}: invalid authorizer id")
        elif isinstance(auth_type, str):
            marker = (auth_type, auth_id)
            if marker in seen_authorizers:
                errors.append(f"{source}: verified_authorizers must be unique")
            seen_authorizers.add(marker)

    if event_type in {"enroll", "rotate"}:
        for field in conditional:
            if field not in event:
                errors.append(f"{source}: {event_type} event requires {field}")
        generation = event.get("new_key_generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            errors.append(f"{source}: new_key_generation must be a positive integer")
    elif event_type == "revoke":
        unexpected = sorted(field for field in conditional if field in event)
        if unexpected:
            errors.append(f"{source}: revoke event must not include: {', '.join(unexpected)}")

    return errors


def _active_devices(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        device["device_id"]: device
        for device in state.get("devices", [])
        if isinstance(device, dict)
        and isinstance(device.get("device_id"), str)
        and device.get("status") == "active"
    }


def _device_by_id(state: dict[str, Any], device_id: str) -> dict[str, Any] | None:
    for device in state.get("devices", []):
        if isinstance(device, dict) and device.get("device_id") == device_id:
            return device
    return None


def _current_and_retired_key_ids(state: dict[str, Any]) -> set[str]:
    result = set(state.get("retired_key_ids", []))
    root = state.get("account_root_key")
    if isinstance(root, dict) and isinstance(root.get("key_id"), str):
        result.add(root["key_id"])
    for device in state.get("devices", []):
        if not isinstance(device, dict):
            continue
        for field in ("signing_key", "agreement_key"):
            key = device.get(field)
            if isinstance(key, dict) and isinstance(key.get("key_id"), str):
                result.add(key["key_id"])
    return result


def _majority(count: int) -> int:
    return count // 2 + 1


def validate_transition(
    policy: dict[str, Any],
    state: dict[str, Any],
    event: dict[str, Any],
    profile_catalog: dict[str, Any],
    crypto_registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    errors.extend(validate_policy(policy, profile_catalog))
    errors.extend(validate_state(state, crypto_registry))
    errors.extend(validate_event(event))
    if errors:
        return errors

    if event["identity_id"] != state["identity_id"]:
        errors.append("identity event: identity_id does not match current state")
    if event["sequence"] != state["sequence"] + 1:
        errors.append("identity event: sequence must equal current state sequence + 1")
    if event["previous_state_hash"] != state_hash(state):
        errors.append("identity event: previous_state_hash does not bind the exact current state")

    profile_id = _profile_id(policy["profile_ref"])
    assert profile_id is not None
    active = _active_devices(state)
    subject_id = event["subject_device_id"]
    subject = _device_by_id(state, subject_id)

    if profile_id == "identity-account-root":
        root = state.get("account_root_key")
        if not isinstance(root, dict):
            errors.append("identity state: account-root profile requires account_root_key")
        elif root.get("key_id") != policy.get("account_root_key_id"):
            errors.append("identity state: account_root_key does not match policy account_root_key_id")
    elif state.get("account_root_key") is not None:
        errors.append("identity state: non-account-root profile must not rely on an account root key")

    authorizers = event["verified_authorizers"]
    if any(a.get("type") == "server" for a in authorizers):
        errors.append("identity event: server authorization is prohibited")

    event_type = event["event_type"]
    if event_type == "enroll":
        if subject is not None:
            errors.append("identity event: device_id reuse is prohibited")
        if event.get("new_key_generation") != 1:
            errors.append("identity event: newly enrolled device must start at key_generation 1")
    elif event_type == "rotate":
        if subject is None or subject.get("status") != "active":
            errors.append("identity event: rotate subject must be an active device")
        elif event.get("new_key_generation") != subject.get("key_generation", 0) + 1:
            errors.append("identity event: rotate must increment key_generation by exactly one")
    elif event_type == "revoke":
        if subject is None or subject.get("status") != "active":
            errors.append("identity event: revoke subject must be an active device")
        if len(active) <= 1:
            errors.append("identity event: ordinary device revocation must not remove the last active device; use the recovery architecture")

    algorithms = _algorithm_index(crypto_registry)
    if event_type in {"enroll", "rotate"}:
        errors.extend(
            _validate_key_descriptor(
                event.get("new_signing_key"),
                source="identity event: new_signing_key",
                expected_categories={"signature"},
                algorithms=algorithms,
            )
        )
        errors.extend(
            _validate_key_descriptor(
                event.get("new_agreement_key"),
                source="identity event: new_agreement_key",
                expected_categories={"key-agreement", "kem"},
                algorithms=algorithms,
            )
        )
        used_ids = _current_and_retired_key_ids(state)
        for field in ("new_signing_key", "new_agreement_key"):
            key = event.get(field)
            if isinstance(key, dict) and key.get("key_id") in used_ids:
                errors.append(f"identity event: key reuse is prohibited: {key.get('key_id')}")
        signing = event.get("new_signing_key")
        agreement = event.get("new_agreement_key")
        if isinstance(signing, dict) and isinstance(agreement, dict):
            if signing.get("key_id") == agreement.get("key_id"):
                errors.append("identity event: signing and agreement keys must use distinct key_id values")
            if signing.get("public_key_fingerprint") == agreement.get("public_key_fingerprint"):
                errors.append("identity event: signing and agreement keys must use distinct public keys")

    device_authorizers = [a["id"] for a in authorizers if a.get("type") == "device"]
    root_authorizers = [a["id"] for a in authorizers if a.get("type") == "account-root"]

    for signer in device_authorizers:
        if signer not in active:
            errors.append(f"identity event: authorizing device is not currently active: {signer}")

    if profile_id == "identity-account-root":
        expected_root = policy["account_root_key_id"]
        if expected_root not in root_authorizers:
            errors.append("identity event: account-root profile requires verified account-root authorization")
        if any(root != expected_root for root in root_authorizers):
            errors.append("identity event: unrecognized account-root authorizer")
    elif root_authorizers:
        errors.append("identity event: account-root authorization is not valid for the selected profile")

    if profile_id == "identity-device-cross-signing":
        if event_type == "enroll":
            eligible = set(active)
        elif event_type in {"rotate", "revoke"} and len(active) > 1:
            eligible = set(active) - {subject_id}
        else:
            eligible = set(active)
        valid = set(device_authorizers) & eligible
        if not valid:
            errors.append("identity event: cross-signing profile requires authorization by an eligible active device")

    if profile_id == "identity-threshold-quorum":
        if event_type == "revoke":
            eligible = set(active) - {subject_id}
        else:
            eligible = set(active)
        provided = set(device_authorizers)
        ineligible = sorted(provided - eligible)
        if ineligible:
            errors.append(
                "identity event: threshold authorization contains ineligible devices: "
                + ", ".join(ineligible)
            )
        required = _majority(len(eligible)) if eligible else 1
        if len(provided & eligible) < required:
            errors.append(
                f"identity event: threshold quorum requires {required} eligible device authorizer(s), "
                f"received {len(provided & eligible)}"
            )

    return sorted(set(errors))


def apply_transition(
    policy: dict[str, Any],
    state: dict[str, Any],
    event: dict[str, Any],
    profile_catalog: dict[str, Any],
    crypto_registry: dict[str, Any],
) -> dict[str, Any]:
    errors = validate_transition(policy, state, event, profile_catalog, crypto_registry)
    if errors:
        raise ValueError("; ".join(errors))

    result = copy.deepcopy(state)
    result["sequence"] = event["sequence"]
    event_type = event["event_type"]
    subject_id = event["subject_device_id"]

    if event_type == "enroll":
        result["devices"].append(
            {
                "device_id": subject_id,
                "status": "active",
                "key_generation": event["new_key_generation"],
                "signing_key": copy.deepcopy(event["new_signing_key"]),
                "agreement_key": copy.deepcopy(event["new_agreement_key"]),
            }
        )
    elif event_type == "rotate":
        device = _device_by_id(result, subject_id)
        assert device is not None
        result["retired_key_ids"].extend(
            [device["signing_key"]["key_id"], device["agreement_key"]["key_id"]]
        )
        result["retired_key_ids"] = sorted(set(result["retired_key_ids"]))
        device["key_generation"] = event["new_key_generation"]
        device["signing_key"] = copy.deepcopy(event["new_signing_key"])
        device["agreement_key"] = copy.deepcopy(event["new_agreement_key"])
    elif event_type == "revoke":
        device = _device_by_id(result, subject_id)
        assert device is not None
        device["status"] = "revoked"

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and apply an E2EESA identity-device transition.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("state", type=Path)
    parser.add_argument("event", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    args = parser.parse_args()

    try:
        policy = load_json(args.policy)
        state = load_json(args.state)
        event = load_json(args.event)
        profile_catalog = load_json(args.profile_catalog)
        crypto_registry = load_json(args.crypto_registry)
        errors = validate_transition(policy, state, event, profile_catalog, crypto_registry)
        if errors:
            print(json.dumps({"valid": False, "errors": errors}, indent=2, sort_keys=True))
            return 1
        next_state = apply_transition(policy, state, event, profile_catalog, crypto_registry)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    print(
        json.dumps(
            {"valid": True, "next_state": next_state, "next_state_hash": state_hash(next_state)},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
