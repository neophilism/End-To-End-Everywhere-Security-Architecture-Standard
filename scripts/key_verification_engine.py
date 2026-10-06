#!/usr/bin/env python3
"""Canonical E2EESA manual key-verification engine.

The engine derives one perspective-independent verification subject from two
authorized identity snapshots. The same subject digest is rendered as a
60-digit human-comparable safety number and a machine-scannable QR payload.

Manual verification authenticates the compared cryptographic subject. It does
not, by itself, prove a person's real-world identity.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PROFILE_REF_RE = re.compile(
    r"^[a-z0-9]+(?:-[a-z0-9]+)*@[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$"
)
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^[0-9a-f]+$")

VERIFICATION_PROFILES = {
    "verify-account-root@0.1.0": "account-root",
    "verify-device-set@0.1.0": "device-set",
}
HASH_ALGORITHMS = {
    "ALG-SHA256": "sha256",
    "ALG-SHA384": "sha384",
    "ALG-SHA512": "sha512",
}
DOMAIN = "E2EESA-KEY-VERIFICATION-v1"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


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
        profile_id = item.get("profile_id")
        version = item.get("profile_version")
        if isinstance(profile_id, str) and isinstance(version, str):
            result[f"{profile_id}@{version}"] = item
    return result


def snapshot_from_identity_state(
    identity_profile_ref: str,
    identity_state: dict[str, Any],
) -> dict[str, Any]:
    """Project PR 8 identity state into the verification snapshot format."""
    root = identity_state.get("account_root_key")
    root_fingerprint = (
        root.get("public_key_fingerprint")
        if isinstance(root, dict)
        else None
    )
    devices: list[dict[str, Any]] = []
    for device in identity_state.get("devices", []):
        if not isinstance(device, dict) or device.get("status") != "active":
            continue
        signing = device.get("signing_key")
        agreement = device.get("agreement_key")
        devices.append(
            {
                "device_id": device.get("device_id"),
                "key_generation": device.get("key_generation"),
                "signing_key_fingerprint": (
                    signing.get("public_key_fingerprint")
                    if isinstance(signing, dict)
                    else None
                ),
                "agreement_key_fingerprint": (
                    agreement.get("public_key_fingerprint")
                    if isinstance(agreement, dict)
                    else None
                ),
            }
        )
    return {
        "schema_version": "0.1",
        "identity_id": identity_state.get("identity_id"),
        "identity_profile_ref": identity_profile_ref,
        "account_root_key_fingerprint": root_fingerprint,
        "active_devices": devices,
    }


def validate_policy(
    policy: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "key verification policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "profile_ref",
        "hash_algorithm_id",
        "numeric_group_count",
        "numeric_group_width",
        "require_out_of_band_confirmation",
        "invalidate_on_subject_change",
        "block_silent_reverification",
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
    if profile_ref not in VERIFICATION_PROFILES:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    else:
        profile = _profile_index(profile_catalog).get(profile_ref)
        if profile is None:
            errors.append(f"{source}: profile_ref is not present in profile catalog")
        elif profile.get("family_id") != "key-verification":
            errors.append(f"{source}: profile_ref must belong to key-verification")

    algorithms = _algorithm_index(crypto_registry)
    hash_id = policy.get("hash_algorithm_id")
    if hash_id not in HASH_ALGORITHMS:
        errors.append(
            f"{source}: E2EESA 0.1 supports ALG-SHA256, ALG-SHA384, or ALG-SHA512 for verification digests"
        )
    algorithm = algorithms.get(hash_id) if isinstance(hash_id, str) else None
    if algorithm is None:
        errors.append(f"{source}: unknown hash_algorithm_id")
    else:
        if algorithm.get("category") != "hash":
            errors.append(f"{source}: hash_algorithm_id must reference a hash algorithm")
        if algorithm.get("status") == "prohibited":
            errors.append(f"{source}: prohibited hash_algorithm_id")

    if policy.get("numeric_group_count") != 12:
        errors.append(f"{source}: numeric_group_count must be 12")
    if policy.get("numeric_group_width") != 5:
        errors.append(f"{source}: numeric_group_width must be 5")

    for field in (
        "require_out_of_band_confirmation",
        "invalidate_on_subject_change",
        "block_silent_reverification",
    ):
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} is an E2EESA invariant and must be true")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return sorted(set(errors))


def validate_snapshot(
    snapshot: dict[str, Any],
    *,
    verification_profile_ref: str,
    source: str = "key verification snapshot",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "identity_id",
        "identity_profile_ref",
        "account_root_key_fingerprint",
        "active_devices",
    }
    extra = sorted(set(snapshot) - required)
    missing = sorted(required - snapshot.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")

    if snapshot.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    identity_id = snapshot.get("identity_id")
    if not isinstance(identity_id, str) or not ID_RE.fullmatch(identity_id):
        errors.append(f"{source}: invalid identity_id")

    identity_profile_ref = snapshot.get("identity_profile_ref")
    if not isinstance(identity_profile_ref, str) or not PROFILE_REF_RE.fullmatch(identity_profile_ref):
        errors.append(f"{source}: invalid identity_profile_ref")
    elif not identity_profile_ref.startswith("identity-"):
        errors.append(f"{source}: identity_profile_ref must reference an identity architecture")

    root = snapshot.get("account_root_key_fingerprint")
    if root is not None and (
        not isinstance(root, str) or not FINGERPRINT_RE.fullmatch(root)
    ):
        errors.append(f"{source}: invalid account_root_key_fingerprint")

    mode = VERIFICATION_PROFILES.get(verification_profile_ref)
    if mode == "account-root":
        if identity_profile_ref != "identity-account-root@0.1.0":
            errors.append(
                f"{source}: account-root verification requires identity-account-root@0.1.0"
            )
        if root is None:
            errors.append(f"{source}: account-root verification requires an account root fingerprint")

    devices = snapshot.get("active_devices")
    if not isinstance(devices, list) or not devices:
        errors.append(f"{source}: active_devices must be a non-empty array")
        devices = []

    device_ids: list[str] = []
    fingerprints: list[str] = []
    for index, device in enumerate(devices):
        prefix = f"{source}: active_devices[{index}]"
        if not isinstance(device, dict):
            errors.append(f"{prefix}: device must be an object")
            continue
        required_device = {
            "device_id",
            "key_generation",
            "signing_key_fingerprint",
            "agreement_key_fingerprint",
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

        generation = device.get("key_generation")
        if (
            not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 1
        ):
            errors.append(f"{prefix}: key_generation must be a positive integer")

        for field in ("signing_key_fingerprint", "agreement_key_fingerprint"):
            fingerprint = device.get(field)
            if not isinstance(fingerprint, str) or not FINGERPRINT_RE.fullmatch(fingerprint):
                errors.append(f"{prefix}: invalid {field}")
            else:
                fingerprints.append(fingerprint)

    if len(device_ids) != len(set(device_ids)):
        errors.append(f"{source}: active device ids must be unique")
    if len(fingerprints) != len(set(fingerprints)):
        errors.append(f"{source}: active device key fingerprints must be unique")

    return sorted(set(errors))


def _party_subject(
    snapshot: dict[str, Any],
    verification_profile_ref: str,
) -> dict[str, Any]:
    mode = VERIFICATION_PROFILES[verification_profile_ref]
    if mode == "account-root":
        return {
            "identity_id": snapshot["identity_id"],
            "account_root_key_fingerprint": snapshot["account_root_key_fingerprint"],
        }

    devices = sorted(
        (
            {
                "device_id": device["device_id"],
                "key_generation": device["key_generation"],
                "signing_key_fingerprint": device["signing_key_fingerprint"],
                "agreement_key_fingerprint": device["agreement_key_fingerprint"],
            }
            for device in snapshot["active_devices"]
        ),
        key=lambda item: item["device_id"],
    )
    return {
        "identity_id": snapshot["identity_id"],
        "active_devices": devices,
    }


def build_subject(
    policy: dict[str, Any],
    first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any],
) -> dict[str, Any]:
    profile_ref = policy["profile_ref"]
    first = _party_subject(first_snapshot, profile_ref)
    second = _party_subject(second_snapshot, profile_ref)
    if first["identity_id"] == second["identity_id"]:
        raise ValueError("verification parties must have distinct identity_id values")
    parties = sorted((first, second), key=lambda item: item["identity_id"])
    return {
        "domain": DOMAIN,
        "schema_version": "0.1",
        "profile_ref": profile_ref,
        "parties": parties,
    }


def subject_digest(
    policy: dict[str, Any],
    first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any],
) -> bytes:
    subject = build_subject(policy, first_snapshot, second_snapshot)
    hashlib_name = HASH_ALGORITHMS[policy["hash_algorithm_id"]]
    return hashlib.new(hashlib_name, _canonical_json(subject)).digest()


def numeric_safety_number(digest: bytes) -> str:
    """Render 192 digest bits as 12 zero-padded five-digit groups."""
    if len(digest) < 24:
        raise ValueError("verification digest must contain at least 24 bytes")
    groups = [
        f"{int.from_bytes(digest[index:index + 2], 'big'):05d}"
        for index in range(0, 24, 2)
    ]
    return " ".join(groups)


def qr_payload(
    policy: dict[str, Any],
    first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any],
) -> str:
    digest = subject_digest(policy, first_snapshot, second_snapshot)
    identities = sorted(
        [first_snapshot["identity_id"], second_snapshot["identity_id"]]
    )
    payload = {
        "v": 1,
        "profile_ref": policy["profile_ref"],
        "hash_algorithm_id": policy["hash_algorithm_id"],
        "party_identity_ids": identities,
        "subject_digest_hex": digest.hex(),
    }
    encoded = base64.urlsafe_b64encode(_canonical_json(payload)).decode("ascii").rstrip("=")
    return f"e2eesa-kv1:{encoded}"


def decode_qr_payload(value: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.startswith("e2eesa-kv1:"):
        raise ValueError("invalid E2EESA verification QR prefix")
    encoded = value.split(":", 1)[1]
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(encoded + padding)
        payload = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise ValueError("invalid E2EESA verification QR payload") from exc
    if not isinstance(payload, dict):
        raise ValueError("verification QR payload must decode to an object")
    required = {
        "v",
        "profile_ref",
        "hash_algorithm_id",
        "party_identity_ids",
        "subject_digest_hex",
    }
    if set(payload) != required:
        raise ValueError("verification QR payload has unexpected fields")
    if payload.get("v") != 1:
        raise ValueError("unsupported verification QR version")
    if payload.get("profile_ref") not in VERIFICATION_PROFILES:
        raise ValueError("unsupported verification QR profile")
    if payload.get("hash_algorithm_id") not in HASH_ALGORITHMS:
        raise ValueError("unsupported verification QR hash")
    identities = payload.get("party_identity_ids")
    if (
        not isinstance(identities, list)
        or len(identities) != 2
        or len(set(identities)) != 2
        or any(not isinstance(item, str) or not ID_RE.fullmatch(item) for item in identities)
        or identities != sorted(identities)
    ):
        raise ValueError("invalid verification QR party identities")
    digest_hex = payload.get("subject_digest_hex")
    if not isinstance(digest_hex, str) or not DIGEST_RE.fullmatch(digest_hex):
        raise ValueError("invalid verification QR digest")
    return payload


def validate_inputs(
    policy: dict[str, Any],
    first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
) -> list[str]:
    errors = validate_policy(policy, crypto_registry, profile_catalog)
    if errors:
        return errors
    errors.extend(
        validate_snapshot(
            first_snapshot,
            verification_profile_ref=policy["profile_ref"],
            source="first key verification snapshot",
        )
    )
    errors.extend(
        validate_snapshot(
            second_snapshot,
            verification_profile_ref=policy["profile_ref"],
            source="second key verification snapshot",
        )
    )
    if first_snapshot.get("identity_id") == second_snapshot.get("identity_id"):
        errors.append("key verification: parties must have distinct identity_id values")
    return sorted(set(errors))


def create_manual_record(
    *,
    record_id: str,
    verification_method: str,
    user_confirmed: bool,
    policy: dict[str, Any],
    first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
) -> dict[str, Any]:
    errors = validate_inputs(
        policy,
        first_snapshot,
        second_snapshot,
        crypto_registry,
        profile_catalog,
    )
    if errors:
        raise ValueError("; ".join(errors))
    if not isinstance(record_id, str) or not ID_RE.fullmatch(record_id):
        raise ValueError("invalid verification record_id")
    if verification_method not in {"numeric", "qr"}:
        raise ValueError("verification_method must be numeric or qr")
    if user_confirmed is not True:
        raise ValueError(
            "manual verification requires explicit out-of-band user confirmation"
        )

    digest = subject_digest(policy, first_snapshot, second_snapshot)
    return {
        "schema_version": "0.1",
        "record_id": record_id,
        "profile_ref": policy["profile_ref"],
        "hash_algorithm_id": policy["hash_algorithm_id"],
        "party_identity_ids": sorted(
            [first_snapshot["identity_id"], second_snapshot["identity_id"]]
        ),
        "subject_digest_hex": digest.hex(),
        "numeric_safety_number": numeric_safety_number(digest),
        "qr_payload": qr_payload(policy, first_snapshot, second_snapshot),
        "verification_method": verification_method,
        "user_confirmed": True,
        "status": "verified",
        "transparency_evidence_ref": None,
    }


def validate_record(
    record: dict[str, Any],
    policy: dict[str, Any],
    first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "key verification record",
) -> list[str]:
    errors = validate_inputs(
        policy,
        first_snapshot,
        second_snapshot,
        crypto_registry,
        profile_catalog,
    )
    required = {
        "schema_version",
        "record_id",
        "profile_ref",
        "hash_algorithm_id",
        "party_identity_ids",
        "subject_digest_hex",
        "numeric_safety_number",
        "qr_payload",
        "verification_method",
        "user_confirmed",
        "status",
        "transparency_evidence_ref",
    }
    extra = sorted(set(record) - required)
    missing = sorted(required - record.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return sorted(set(errors))

    if record.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(record.get("record_id"), str) or not ID_RE.fullmatch(record.get("record_id", "")):
        errors.append(f"{source}: invalid record_id")
    if record.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if record.get("hash_algorithm_id") != policy.get("hash_algorithm_id"):
        errors.append(f"{source}: hash_algorithm_id does not match policy")
    if record.get("verification_method") not in {"numeric", "qr"}:
        errors.append(f"{source}: invalid verification_method")
    if record.get("user_confirmed") is not True:
        errors.append(f"{source}: manual verification record requires user_confirmed=true")
    if record.get("status") not in {"verified", "invalidated"}:
        errors.append(f"{source}: invalid status")

    expected_ids = sorted(
        [first_snapshot["identity_id"], second_snapshot["identity_id"]]
    )
    if record.get("party_identity_ids") != expected_ids:
        errors.append(f"{source}: party_identity_ids do not match current verification parties")

    digest = subject_digest(policy, first_snapshot, second_snapshot)
    expected_hex = digest.hex()
    if record.get("subject_digest_hex") != expected_hex:
        errors.append(f"{source}: verified subject has changed")
    if record.get("numeric_safety_number") != numeric_safety_number(digest):
        errors.append(f"{source}: numeric safety number does not match current subject")
    if record.get("qr_payload") != qr_payload(policy, first_snapshot, second_snapshot):
        errors.append(f"{source}: QR payload does not match current subject")

    try:
        decoded = decode_qr_payload(record.get("qr_payload"))
        if decoded.get("subject_digest_hex") != record.get("subject_digest_hex"):
            errors.append(f"{source}: QR digest does not match record digest")
    except ValueError as exc:
        errors.append(f"{source}: {exc}")

    transparency_ref = record.get("transparency_evidence_ref")
    if transparency_ref is not None and (
        not isinstance(transparency_ref, str) or not ID_RE.fullmatch(transparency_ref)
    ):
        errors.append(f"{source}: invalid transparency_evidence_ref")

    return sorted(set(errors))


def verification_status(
    record: dict[str, Any],
    policy: dict[str, Any],
    first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
) -> dict[str, Any]:
    errors = validate_record(
        record,
        policy,
        first_snapshot,
        second_snapshot,
        crypto_registry,
        profile_catalog,
    )
    subject_changed = any(
        "subject has changed" in error
        or "does not match current subject" in error
        for error in errors
    )
    if subject_changed:
        return {
            "status": "invalidated",
            "requires_manual_reverification": True,
            "errors": errors,
        }
    if errors:
        return {
            "status": "invalid",
            "requires_manual_reverification": False,
            "errors": errors,
        }
    return {
        "status": "verified",
        "requires_manual_reverification": False,
        "errors": [],
    }


def compare_numeric(record: dict[str, Any], presented: str) -> bool:
    return (
        isinstance(presented, str)
        and presented == record.get("numeric_safety_number")
    )


def compare_qr(record: dict[str, Any], presented: str) -> bool:
    if not isinstance(presented, str):
        return False
    try:
        decoded = decode_qr_payload(presented)
        expected = decode_qr_payload(record.get("qr_payload"))
    except ValueError:
        return False
    return decoded == expected


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or validate an E2EESA manual key verification subject."
    )
    parser.add_argument("policy", type=Path)
    parser.add_argument("first_snapshot", type=Path)
    parser.add_argument("second_snapshot", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    args = parser.parse_args()

    try:
        policy = load_json(args.policy)
        first = load_json(args.first_snapshot)
        second = load_json(args.second_snapshot)
        crypto_registry = load_json(args.crypto_registry)
        profile_catalog = load_json(args.profile_catalog)
        errors = validate_inputs(
            policy, first, second, crypto_registry, profile_catalog
        )
        if errors:
            print(json.dumps({"valid": False, "errors": errors}, indent=2, sort_keys=True))
            return 1
        digest = subject_digest(policy, first, second)
        output = {
            "valid": True,
            "subject_digest_hex": digest.hex(),
            "numeric_safety_number": numeric_safety_number(digest),
            "qr_payload": qr_payload(policy, first, second),
        }
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
