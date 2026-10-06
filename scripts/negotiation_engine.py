#!/usr/bin/env python3
"""Fail-closed negotiation and downgrade validation for E2EESA."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import profile_engine

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
VERSION_RE = re.compile(r"^[0-9A-Za-z]+(?:[._-][0-9A-Za-z]+)*$")
HEX_RE = re.compile(r"^[0-9a-f]+$")

BASELINE_TRANSCRIPT_FIELDS = {
    "policy_id",
    "protocol_id",
    "cryptographic_registry_version",
    "initiator_offered_versions",
    "responder_supported_versions",
    "initiator_offered_suites",
    "responder_supported_suites",
    "selected_version",
    "selected_suite_id",
    "effective_profile_refs",
    "initiator_nonce_hex",
    "responder_nonce_hex",
}


def _string_list(value: Any, *, min_items: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
        and len(value) == len(set(value))
    )


def _suite_map(crypto_registry: dict) -> dict[str, dict]:
    suites = crypto_registry.get("suites")
    if not isinstance(suites, list):
        return {}
    return {
        suite["id"]: suite
        for suite in suites
        if isinstance(suite, dict) and isinstance(suite.get("id"), str)
    }


def _profile_refs(profile_catalog: dict) -> set[str]:
    profiles = profile_catalog.get("profiles")
    if not isinstance(profiles, list):
        return set()
    refs: set[str] = set()
    for profile in profiles:
        if isinstance(profile, dict):
            try:
                refs.add(profile_engine.profile_ref(profile))
            except (KeyError, TypeError):
                pass
    return refs


def validate_policy(
    policy: dict,
    crypto_registry: dict,
    profile_catalog: dict,
    source: str = "<negotiation-policy>",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "protocol_id",
        "protocol_versions",
        "minimum_protocol_version",
        "cryptographic_registry_version",
        "permitted_suite_ids",
        "effective_profile_refs",
        "required_transcript_fields",
        "require_highest_mutual_version",
        "prohibit_fallback_retry",
        "nonce_bytes",
    }
    extras = sorted(set(policy) - required)
    missing = sorted(required - policy.keys())
    if missing:
        errors.append(f"{source}: missing required fields: {', '.join(missing)}")
    if extras:
        errors.append(f"{source}: unknown fields: {', '.join(extras)}")

    if policy.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    for field in ("policy_id", "protocol_id"):
        value = policy.get(field)
        if not isinstance(value, str) or not ID_RE.fullmatch(value):
            errors.append(f"{source}: invalid {field}")

    versions = policy.get("protocol_versions")
    if not _string_list(versions, min_items=1):
        errors.append(f"{source}: protocol_versions must be an ordered unique non-empty string array")
        versions = []
    else:
        for version in versions:
            if not VERSION_RE.fullmatch(version):
                errors.append(f"{source}: malformed protocol version: {version}")

    minimum = policy.get("minimum_protocol_version")
    if not isinstance(minimum, str) or minimum not in versions:
        errors.append(f"{source}: minimum_protocol_version must appear in protocol_versions")

    registry_version = crypto_registry.get("registry_version")
    if policy.get("cryptographic_registry_version") != registry_version:
        errors.append(
            f"{source}: cryptographic_registry_version must exactly match registry version {registry_version}"
        )

    suites = _suite_map(crypto_registry)
    permitted = policy.get("permitted_suite_ids")
    if not _string_list(permitted, min_items=1):
        errors.append(f"{source}: permitted_suite_ids must be a unique non-empty string array")
        permitted = []
    else:
        for suite_id in permitted:
            suite = suites.get(suite_id)
            if suite is None:
                errors.append(f"{source}: unknown suite id: {suite_id}")
                continue
            if suite.get("status") not in {"recommended", "allowed"}:
                errors.append(
                    f"{source}: suite {suite_id} has non-production lifecycle status {suite.get('status')}"
                )

    known_profiles = _profile_refs(profile_catalog)
    effective_profiles = policy.get("effective_profile_refs")
    if not _string_list(effective_profiles, min_items=1):
        errors.append(f"{source}: effective_profile_refs must be a unique non-empty string array")
    else:
        for ref in effective_profiles:
            if profile_engine.parse_profile_ref(ref) is None:
                errors.append(f"{source}: malformed exact profile reference: {ref}")
            elif ref not in known_profiles:
                errors.append(f"{source}: unknown profile reference: {ref}")

    transcript_fields = policy.get("required_transcript_fields")
    if not _string_list(transcript_fields, min_items=1):
        errors.append(f"{source}: required_transcript_fields must be a unique non-empty string array")
    elif not BASELINE_TRANSCRIPT_FIELDS.issubset(set(transcript_fields)):
        missing_fields = sorted(BASELINE_TRANSCRIPT_FIELDS - set(transcript_fields))
        errors.append(
            f"{source}: required_transcript_fields omits mandatory downgrade-sensitive fields: "
            + ", ".join(missing_fields)
        )

    if policy.get("require_highest_mutual_version") is not True:
        errors.append(f"{source}: require_highest_mutual_version must be true")
    if policy.get("prohibit_fallback_retry") is not True:
        errors.append(f"{source}: prohibit_fallback_retry must be true")

    nonce_bytes = policy.get("nonce_bytes")
    if not isinstance(nonce_bytes, int) or isinstance(nonce_bytes, bool) or not 16 <= nonce_bytes <= 64:
        errors.append(f"{source}: nonce_bytes must be an integer from 16 through 64")

    return errors


def validate_evidence(
    policy: dict,
    evidence: dict,
    crypto_registry: dict,
    profile_catalog: dict,
    source: str = "<negotiation-evidence>",
    *,
    seen_nonce_pairs: set[tuple[str, str]] | None = None,
) -> list[str]:
    errors = validate_policy(policy, crypto_registry, profile_catalog, f"{source}: policy")
    required = {
        "schema_version",
        "policy_id",
        "protocol_id",
        "cryptographic_registry_version",
        "initiator_offered_versions",
        "responder_supported_versions",
        "initiator_offered_suites",
        "responder_supported_suites",
        "selected_version",
        "selected_suite_id",
        "effective_profile_refs",
        "transcript_bound_fields",
        "authenticated_transcript",
        "initiator_nonce_hex",
        "responder_nonce_hex",
        "fallback_retry",
    }
    missing = sorted(required - evidence.keys())
    extras = sorted(set(evidence) - required)
    if missing:
        errors.append(f"{source}: missing required fields: {', '.join(missing)}")
    if extras:
        errors.append(f"{source}: unknown fields: {', '.join(extras)}")

    if evidence.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    for field in ("policy_id", "protocol_id", "cryptographic_registry_version"):
        if evidence.get(field) != policy.get(field):
            errors.append(f"{source}: {field} does not match pinned policy value")

    policy_versions = policy.get("protocol_versions", [])
    version_rank = {version: index for index, version in enumerate(policy_versions)}
    minimum = policy.get("minimum_protocol_version")

    for field in ("initiator_offered_versions", "responder_supported_versions"):
        values = evidence.get(field)
        if not _string_list(values, min_items=1):
            errors.append(f"{source}: {field} must be a unique non-empty string array")
            continue
        for version in values:
            if version not in version_rank:
                errors.append(f"{source}: {field} contains unrecognized protocol version: {version}")

    initiator_versions = evidence.get("initiator_offered_versions")
    responder_versions = evidence.get("responder_supported_versions")
    selected_version = evidence.get("selected_version")

    if isinstance(initiator_versions, list) and isinstance(responder_versions, list):
        common = [
            version
            for version in policy_versions
            if version in initiator_versions and version in responder_versions
        ]
        if not common:
            errors.append(f"{source}: no mutually supported protocol version")
        elif selected_version != common[-1]:
            errors.append(
                f"{source}: selected_version must be highest mutually supported version {common[-1]}"
            )

    if selected_version not in version_rank:
        errors.append(f"{source}: selected_version is not recognized by policy")
    elif minimum in version_rank and version_rank[selected_version] < version_rank[minimum]:
        errors.append(
            f"{source}: selected_version {selected_version} is below minimum {minimum}"
        )

    suites = _suite_map(crypto_registry)
    permitted = set(policy.get("permitted_suite_ids", []))
    for field in ("initiator_offered_suites", "responder_supported_suites"):
        values = evidence.get(field)
        if not _string_list(values, min_items=1):
            errors.append(f"{source}: {field} must be a unique non-empty string array")
            continue
        for suite_id in values:
            if suite_id not in suites:
                errors.append(f"{source}: {field} contains unknown suite id: {suite_id}")
            if suite_id not in permitted:
                errors.append(f"{source}: {field} contains suite not pinned by policy: {suite_id}")

    initiator_suites = evidence.get("initiator_offered_suites")
    responder_suites = evidence.get("responder_supported_suites")
    selected_suite = evidence.get("selected_suite_id")
    if selected_suite not in permitted:
        errors.append(f"{source}: selected_suite_id is not pinned by policy")
    if selected_suite not in suites:
        errors.append(f"{source}: selected_suite_id is not registered")
    if isinstance(initiator_suites, list) and selected_suite not in initiator_suites:
        errors.append(f"{source}: selected_suite_id was not offered by initiator")
    if isinstance(responder_suites, list) and selected_suite not in responder_suites:
        errors.append(f"{source}: selected_suite_id is not supported by responder")

    expected_profiles = policy.get("effective_profile_refs")
    if evidence.get("effective_profile_refs") != expected_profiles:
        errors.append(f"{source}: effective_profile_refs do not match pinned policy configuration")

    bound = evidence.get("transcript_bound_fields")
    required_bound = set(policy.get("required_transcript_fields", []))
    if not _string_list(bound, min_items=1):
        errors.append(f"{source}: transcript_bound_fields must be a unique non-empty string array")
    elif not required_bound.issubset(set(bound)):
        missing_bound = sorted(required_bound - set(bound))
        errors.append(
            f"{source}: authenticated transcript omits required fields: " + ", ".join(missing_bound)
        )

    if evidence.get("authenticated_transcript") is not True:
        errors.append(f"{source}: negotiation transcript must be authenticated before protected traffic")
    if evidence.get("fallback_retry") is not False:
        errors.append(f"{source}: automatic weaker fallback retry is prohibited")

    nonce_bytes = policy.get("nonce_bytes")
    nonce_values: list[str] = []
    for field in ("initiator_nonce_hex", "responder_nonce_hex"):
        value = evidence.get(field)
        if (
            not isinstance(value, str)
            or not isinstance(nonce_bytes, int)
            or len(value) != nonce_bytes * 2
            or not HEX_RE.fullmatch(value)
        ):
            errors.append(f"{source}: {field} must encode exactly {nonce_bytes} bytes as lowercase hex")
        else:
            nonce_values.append(value)

    if len(nonce_values) == 2:
        pair = (nonce_values[0], nonce_values[1])
        if pair[0] == pair[1]:
            errors.append(f"{source}: initiator and responder nonces must differ")
        if seen_nonce_pairs is not None and pair in seen_nonce_pairs:
            errors.append(f"{source}: replayed negotiation nonce pair")

    return errors
