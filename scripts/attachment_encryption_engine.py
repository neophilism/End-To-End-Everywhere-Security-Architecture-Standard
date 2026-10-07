#!/usr/bin/env python3
"""Semantic validator for E2EESA attachment/file encryption."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HEX_RE = re.compile(r"^[0-9a-f]+$")

PROFILE_REF = "attachment-chunked-aead@0.1.0"
ALLOWED_AEADS = {
    "ALG-AES-256-GCM",
    "ALG-CHACHA20-POLY1305",
    "ALG-AES-256-GCM-SIV",
}
HASHLIB_NAMES = {
    "ALG-SHA256": "sha256",
    "ALG-SHA384": "sha384",
    "ALG-SHA512": "sha512",
    "ALG-SHA3-256": "sha3_256",
    "ALG-SHA3-384": "sha3_384",
    "ALG-SHA3-512": "sha3_512",
}
HASH_HEX_LENGTHS = {
    "ALG-SHA256": 64,
    "ALG-SHA384": 96,
    "ALG-SHA512": 128,
    "ALG-SHA3-256": 64,
    "ALG-SHA3-384": 96,
    "ALG-SHA3-512": 128,
}
AEAD_TAG_BYTES = 16
MANIFEST_DOMAIN = "E2EESA-ATTACHMENT-MANIFEST-v1"


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


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def validate_policy(
    policy: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "attachment policy",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version","policy_id","profile_ref",
        "content_aead_algorithm_id","hash_algorithm_id",
        "attachment_key_bits","chunk_size_bytes","maximum_chunk_count",
        "nonce_prefix_bytes","nonce_counter_bytes",
        "require_fresh_attachment_key","require_e2ee_manifest_delivery",
        "require_manifest_authentication","require_chunk_aad_binding",
        "require_authorized_key_distribution","allow_key_in_url",
        "allow_key_in_storage_metadata","allow_server_plaintext",
        "allow_server_attachment_key","require_delete_api",
        "require_orphan_cleanup","require_no_global_recall_claim",
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
    if policy.get("profile_ref") != PROFILE_REF:
        errors.append(f"{source}: profile_ref must be {PROFILE_REF}")

    profile = _profile_index(profile_catalog).get(PROFILE_REF)
    if profile is None:
        errors.append(f"{source}: attachment profile is not present in profile catalog")
    elif profile.get("family_id") != "attachment-encryption":
        errors.append(f"{source}: attachment profile must belong to attachment-encryption")

    algorithms = _algorithm_index(crypto_registry)
    aead_id = policy.get("content_aead_algorithm_id")
    if aead_id not in ALLOWED_AEADS:
        errors.append(f"{source}: unsupported attachment AEAD: {aead_id}")
    aead = algorithms.get(aead_id)
    if aead is None:
        errors.append(f"{source}: attachment AEAD is not registered")
    else:
        if aead.get("category") != "aead":
            errors.append(f"{source}: content_aead_algorithm_id must reference an AEAD")
        if aead.get("status") == "prohibited":
            errors.append(f"{source}: prohibited attachment AEAD")

    hash_id = policy.get("hash_algorithm_id")
    if hash_id not in HASHLIB_NAMES:
        errors.append(f"{source}: unsupported hash_algorithm_id: {hash_id}")
    hash_alg = algorithms.get(hash_id)
    if hash_alg is None:
        errors.append(f"{source}: hash algorithm is not registered")
    else:
        if hash_alg.get("category") != "hash":
            errors.append(f"{source}: hash_algorithm_id must reference a hash")
        if hash_alg.get("status") == "prohibited":
            errors.append(f"{source}: prohibited hash algorithm")

    if policy.get("attachment_key_bits") != 256:
        errors.append(f"{source}: attachment_key_bits must be 256")
    chunk_size = policy.get("chunk_size_bytes")
    if (
        not isinstance(chunk_size, int)
        or isinstance(chunk_size, bool)
        or chunk_size < 65536
        or chunk_size > 8388608
    ):
        errors.append(f"{source}: chunk_size_bytes must be between 64 KiB and 8 MiB")
    max_chunks = policy.get("maximum_chunk_count")
    if (
        not isinstance(max_chunks, int)
        or isinstance(max_chunks, bool)
        or max_chunks < 1
        or max_chunks > 4294967295
    ):
        errors.append(f"{source}: maximum_chunk_count out of range")
    if policy.get("nonce_prefix_bytes") != 4:
        errors.append(f"{source}: nonce_prefix_bytes must be 4")
    if policy.get("nonce_counter_bytes") != 8:
        errors.append(f"{source}: nonce_counter_bytes must be 8")

    for field in (
        "require_fresh_attachment_key",
        "require_e2ee_manifest_delivery",
        "require_manifest_authentication",
        "require_chunk_aad_binding",
        "require_authorized_key_distribution",
        "require_delete_api",
        "require_orphan_cleanup",
        "require_no_global_recall_claim",
    ):
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} must be true")

    for field in (
        "allow_key_in_url",
        "allow_key_in_storage_metadata",
        "allow_server_plaintext",
        "allow_server_attachment_key",
    ):
        if policy.get(field) is not False:
            errors.append(f"{source}: {field} must be false")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return sorted(set(errors))


def manifest_context_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    excluded = {"attachment_master_key_hex", "manifest_context_digest_hex"}
    payload = {
        key: value
        for key, value in manifest.items()
        if key not in excluded
    }
    return {
        "domain": MANIFEST_DOMAIN,
        "manifest": payload,
    }


def manifest_context_digest(manifest: dict[str, Any]) -> str:
    hash_id = manifest["hash_algorithm_id"]
    name = HASHLIB_NAMES[hash_id]
    return hashlib.new(name, _canonical_json(manifest_context_payload(manifest))).hexdigest()


def expected_chunk_count(plaintext_size_bytes: int, chunk_size_bytes: int) -> int:
    if plaintext_size_bytes == 0:
        return 1
    return (plaintext_size_bytes + chunk_size_bytes - 1) // chunk_size_bytes


def expected_chunk_plaintext_length(manifest: dict[str, Any], chunk_index: int) -> int:
    count = manifest["chunk_count"]
    size = manifest["plaintext_size_bytes"]
    chunk_size = manifest["chunk_size_bytes"]
    if chunk_index < 0 or chunk_index >= count:
        raise ValueError("chunk index outside manifest")
    if count == 1:
        return size
    if chunk_index < count - 1:
        return chunk_size
    return size - chunk_size * (count - 1)


def expected_nonce_hex(manifest: dict[str, Any], chunk_index: int) -> str:
    if chunk_index < 0 or chunk_index >= 2**64:
        raise ValueError("chunk index cannot be encoded in 64-bit nonce counter")
    prefix = bytes.fromhex(manifest["nonce_prefix_hex"])
    if len(prefix) != 4:
        raise ValueError("nonce prefix must be exactly four bytes")
    return (prefix + chunk_index.to_bytes(8, "big")).hex()


def validate_manifest(
    policy: dict[str, Any],
    manifest: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "attachment manifest",
) -> list[str]:
    errors = validate_policy(policy, crypto_registry, profile_catalog)
    if errors:
        return errors

    required = {
        "schema_version","format_version","profile_ref","attachment_id",
        "parent_message_id","attachment_key_id","attachment_master_key_hex",
        "content_aead_algorithm_id","hash_algorithm_id","nonce_prefix_hex",
        "chunk_size_bytes","chunk_count","plaintext_size_bytes",
        "filename","media_type","whole_plaintext_hash_hex",
        "storage_object_id","manifest_context_digest_hex",
    }
    extra = sorted(set(manifest) - required)
    missing = sorted(required - manifest.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return sorted(set(errors))

    if manifest.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if manifest.get("format_version") != "attachment-v1":
        errors.append(f"{source}: unsupported format_version")
    if manifest.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    for field in ("attachment_id","parent_message_id","attachment_key_id","storage_object_id"):
        if not _valid_id(manifest.get(field)):
            errors.append(f"{source}: invalid {field}")

    key_hex = manifest.get("attachment_master_key_hex")
    if not isinstance(key_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", key_hex):
        errors.append(f"{source}: attachment master key must be exactly 256 bits")
    if manifest.get("content_aead_algorithm_id") != policy.get("content_aead_algorithm_id"):
        errors.append(f"{source}: content AEAD does not match policy")
    if manifest.get("hash_algorithm_id") != policy.get("hash_algorithm_id"):
        errors.append(f"{source}: hash algorithm does not match policy")

    prefix = manifest.get("nonce_prefix_hex")
    if not isinstance(prefix, str) or not re.fullmatch(r"[0-9a-f]{8}", prefix):
        errors.append(f"{source}: nonce prefix must be four bytes")

    if manifest.get("chunk_size_bytes") != policy.get("chunk_size_bytes"):
        errors.append(f"{source}: chunk size does not match policy")
    size = manifest.get("plaintext_size_bytes")
    count = manifest.get("chunk_count")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        errors.append(f"{source}: plaintext_size_bytes must be non-negative")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        errors.append(f"{source}: chunk_count must be positive")
    if isinstance(size, int) and size >= 0 and isinstance(count, int) and count >= 1:
        expected = expected_chunk_count(size, policy["chunk_size_bytes"])
        if count != expected:
            errors.append(f"{source}: chunk_count must equal ceil(size/chunk_size), with one chunk for an empty file")
        if count > policy["maximum_chunk_count"]:
            errors.append(f"{source}: chunk_count exceeds policy maximum")

    if not isinstance(manifest.get("filename"), str):
        errors.append(f"{source}: filename must be a string")
    if not isinstance(manifest.get("media_type"), str) or not manifest.get("media_type"):
        errors.append(f"{source}: media_type must be non-empty")

    hash_id = manifest.get("hash_algorithm_id")
    expected_hash_len = HASH_HEX_LENGTHS.get(hash_id)
    whole_hash = manifest.get("whole_plaintext_hash_hex")
    if (
        expected_hash_len is None
        or not isinstance(whole_hash, str)
        or not HEX_RE.fullmatch(whole_hash)
        or len(whole_hash) != expected_hash_len
    ):
        errors.append(f"{source}: whole_plaintext_hash_hex has wrong length or encoding")

    digest = manifest.get("manifest_context_digest_hex")
    if (
        expected_hash_len is None
        or not isinstance(digest, str)
        or not HEX_RE.fullmatch(digest)
        or len(digest) != expected_hash_len
    ):
        errors.append(f"{source}: manifest_context_digest_hex has wrong length or encoding")
    else:
        try:
            expected_digest = manifest_context_digest(manifest)
            if digest != expected_digest:
                errors.append(f"{source}: manifest context digest does not match canonical manifest context")
        except (KeyError, ValueError) as exc:
            errors.append(f"{source}: cannot compute manifest context digest: {exc}")

    return sorted(set(errors))


def validate_key_distribution(
    policy: dict[str, Any],
    manifest: dict[str, Any],
    evidence: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "attachment key distribution evidence",
) -> list[str]:
    errors = validate_manifest(policy, manifest, crypto_registry, profile_catalog)
    if errors:
        return errors
    required = {
        "schema_version","event_id","profile_ref","attachment_id",
        "parent_message_id","parent_message_e2ee_profile_ref",
        "recipient_count","manifest_delivered_inside_authenticated_e2ee",
        "recipient_device_set_authorized","attachment_key_fresh",
        "attachment_key_reused","service_observed_attachment_key",
        "attachment_key_in_url","attachment_key_in_storage_metadata",
        "automatic_history_share_to_new_group_members",
        "removed_member_received_new_attachment_key",
        "manifest_context_digest_matches",
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
    if not _valid_id(evidence.get("event_id")):
        errors.append(f"{source}: invalid event_id")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("attachment_id") != manifest.get("attachment_id"):
        errors.append(f"{source}: attachment_id does not match manifest")
    if evidence.get("parent_message_id") != manifest.get("parent_message_id"):
        errors.append(f"{source}: parent_message_id does not match manifest")

    e2ee_ref = evidence.get("parent_message_e2ee_profile_ref")
    if (
        not isinstance(e2ee_ref, str)
        or not re.fullmatch(
            r"(pairwise|group)-[a-z0-9-]+@[0-9]+.[0-9]+.[0-9]+(?:-[0-9A-Za-z.-]+)?",
            e2ee_ref,
        )
    ):
        errors.append(f"{source}: parent message must reference a pairwise/group E2EE profile")

    count = evidence.get("recipient_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        errors.append(f"{source}: recipient_count must be positive")
    for field in (
        "manifest_delivered_inside_authenticated_e2ee",
        "recipient_device_set_authorized",
        "attachment_key_fresh",
        "manifest_context_digest_matches",
    ):
        if evidence.get(field) is not True:
            errors.append(f"{source}: {field} must be true")
    for field in (
        "attachment_key_reused",
        "service_observed_attachment_key",
        "attachment_key_in_url",
        "attachment_key_in_storage_metadata",
        "automatic_history_share_to_new_group_members",
        "removed_member_received_new_attachment_key",
    ):
        if evidence.get(field) is not False:
            errors.append(f"{source}: {field} must be false")
    return sorted(set(errors))


def validate_chunk(
    policy: dict[str, Any],
    manifest: dict[str, Any],
    evidence: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "attachment chunk evidence",
) -> list[str]:
    errors = validate_manifest(policy, manifest, crypto_registry, profile_catalog)
    if errors:
        return errors
    required = {
        "schema_version","event_id","profile_ref","attachment_id",
        "chunk_index","chunk_count","plaintext_length_bytes",
        "ciphertext_length_bytes","nonce_hex",
        "aad_attachment_id","aad_manifest_context_digest_hex",
        "aad_chunk_index","aad_chunk_count","aad_plaintext_length_bytes",
        "aead_verified","plaintext_released_before_authentication",
        "storage_service_plaintext_access","service_observed_attachment_key",
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
    if not _valid_id(evidence.get("event_id")):
        errors.append(f"{source}: invalid event_id")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("attachment_id") != manifest.get("attachment_id"):
        errors.append(f"{source}: attachment_id does not match manifest")

    index = evidence.get("chunk_index")
    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or index < 0
        or index >= manifest["chunk_count"]
    ):
        errors.append(f"{source}: chunk_index outside manifest")
        return sorted(set(errors))

    if evidence.get("chunk_count") != manifest.get("chunk_count"):
        errors.append(f"{source}: chunk_count does not match manifest")
    expected_plain = expected_chunk_plaintext_length(manifest, index)
    if evidence.get("plaintext_length_bytes") != expected_plain:
        errors.append(f"{source}: plaintext length does not match manifest position")
    if evidence.get("ciphertext_length_bytes") != expected_plain + AEAD_TAG_BYTES:
        errors.append(f"{source}: ciphertext length must equal plaintext plus 16-byte tag")

    expected_nonce = expected_nonce_hex(manifest, index)
    if evidence.get("nonce_hex") != expected_nonce:
        errors.append(f"{source}: nonce does not equal nonce_prefix || uint64_be(chunk_index)")

    if evidence.get("aad_attachment_id") != manifest.get("attachment_id"):
        errors.append(f"{source}: AAD attachment id mismatch")
    if evidence.get("aad_manifest_context_digest_hex") != manifest.get("manifest_context_digest_hex"):
        errors.append(f"{source}: AAD manifest digest mismatch")
    if evidence.get("aad_chunk_index") != index:
        errors.append(f"{source}: AAD chunk index mismatch")
    if evidence.get("aad_chunk_count") != manifest.get("chunk_count"):
        errors.append(f"{source}: AAD chunk count mismatch")
    if evidence.get("aad_plaintext_length_bytes") != expected_plain:
        errors.append(f"{source}: AAD plaintext length mismatch")

    if evidence.get("aead_verified") is not True:
        errors.append(f"{source}: AEAD authentication must verify before plaintext use")
    for field in (
        "plaintext_released_before_authentication",
        "storage_service_plaintext_access",
        "service_observed_attachment_key",
    ):
        if evidence.get(field) is not False:
            errors.append(f"{source}: {field} must be false")
    return sorted(set(errors))


def validate_deletion(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    source: str = "attachment deletion evidence",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version","deletion_id","profile_ref","attachment_id",
        "deletion_status","storage_delete_requested","primary_storage_deleted",
        "replica_delete_requested","replica_deletion_complete",
        "documented_replica_retention_seconds",
        "sender_local_key_deleted","sender_local_plaintext_deleted",
        "remote_recipient_recall_guaranteed",
        "remote_recipient_key_revocation_possible",
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
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    for field in ("deletion_id","attachment_id"):
        if not _valid_id(evidence.get(field)):
            errors.append(f"{source}: invalid {field}")
    if evidence.get("remote_recipient_recall_guaranteed") is not False:
        errors.append(f"{source}: global recipient recall cannot be guaranteed after key/plaintext delivery")
    if evidence.get("remote_recipient_key_revocation_possible") is not False:
        errors.append(f"{source}: already delivered attachment keys cannot be remotely revoked")

    retention = evidence.get("documented_replica_retention_seconds")
    if not isinstance(retention, int) or isinstance(retention, bool) or retention < 0:
        errors.append(f"{source}: documented_replica_retention_seconds must be non-negative")

    status = evidence.get("deletion_status")
    if status not in {"requested","storage-complete","sender-local-erasure"}:
        errors.append(f"{source}: invalid deletion_status")
    if status in {"requested","storage-complete","sender-local-erasure"}:
        if evidence.get("storage_delete_requested") is not True:
            errors.append(f"{source}: deletion operation must request storage deletion")
        if evidence.get("replica_delete_requested") is not True:
            errors.append(f"{source}: deletion operation must request replica/cache deletion")
    if status == "storage-complete":
        if evidence.get("primary_storage_deleted") is not True:
            errors.append(f"{source}: storage-complete requires primary storage deletion")
        if evidence.get("replica_deletion_complete") is not True:
            errors.append(f"{source}: storage-complete requires replica deletion completion")
    if status == "sender-local-erasure":
        if evidence.get("sender_local_key_deleted") is not True:
            errors.append(f"{source}: sender-local-erasure requires local attachment key deletion")
        if evidence.get("sender_local_plaintext_deleted") is not True:
            errors.append(f"{source}: sender-local-erasure requires local plaintext deletion")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate E2EESA attachment encryption evidence.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    parser.add_argument("--key-distribution", type=Path)
    parser.add_argument("--chunk", type=Path)
    parser.add_argument("--deletion", type=Path)
    args = parser.parse_args()

    try:
        policy = load_json(args.policy)
        manifest = load_json(args.manifest)
        crypto = load_json(args.crypto_registry)
        catalog = load_json(args.profile_catalog)
        errors = validate_manifest(policy, manifest, crypto, catalog)
        if args.key_distribution:
            errors.extend(validate_key_distribution(
                policy, manifest, load_json(args.key_distribution), crypto, catalog
            ))
        if args.chunk:
            errors.extend(validate_chunk(
                policy, manifest, load_json(args.chunk), crypto, catalog
            ))
        if args.deletion:
            errors.extend(validate_deletion(policy, load_json(args.deletion)))
    except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    errors = sorted(set(errors))
    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
