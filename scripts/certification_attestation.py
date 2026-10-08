#!/usr/bin/env python3
"""Signed certification attestation semantics for E2EESA PR 30."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable

import certification_evidence
import certification_lifecycle
import formal_verification

SignatureVerifier = Callable[[dict[str, Any], bytes, str, dict[str, Any]], list[dict[str, str]]]


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be a UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _reject_noncanonical_types(value: object, path: str, errors: list[str]) -> None:
    if isinstance(value, float):
        errors.append(f"{path}: floating-point values are not permitted")
        return
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            errors.append(f"{path}: Unicode surrogate code points are not permitted")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_noncanonical_types(item, f"{path}[{index}]", errors)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                errors.append(f"{path}: object keys must be strings")
                continue
            _reject_noncanonical_types(key, f"{path}.<key>", errors)
            _reject_noncanonical_types(item, f"{path}.{key}", errors)
        return
    if value is None or isinstance(value, (bool, int)):
        return
    errors.append(f"{path}: unsupported canonical JSON type {type(value).__name__}")


def normalize_attestation_payload(payload: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(payload)
    if isinstance(value.get("effective_profile_refs"), list):
        value["effective_profile_refs"] = sorted(value["effective_profile_refs"])
    claims = value.get("claims")
    if isinstance(claims, list):
        for claim in claims:
            if isinstance(claim, dict):
                if isinstance(claim.get("threat_ids"), list):
                    claim["threat_ids"] = sorted(claim["threat_ids"])
                if isinstance(claim.get("limitations"), list):
                    claim["limitations"] = sorted(claim["limitations"])
        value["claims"] = sorted(
            claims,
            key=lambda item: (
                item.get("property_id", "") if isinstance(item, dict) else "",
                item.get("status", "") if isinstance(item, dict) else "",
                json.dumps(item.get("threat_ids", []), sort_keys=True) if isinstance(item, dict) else "",
                json.dumps(item.get("limitations", []), sort_keys=True) if isinstance(item, dict) else "",
            ),
        )
    return value


def canonical_payload_bytes(payload: dict[str, Any], *, attestation: bool = True) -> bytes:
    errors: list[str] = []
    _reject_noncanonical_types(payload, "payload", errors)
    if errors:
        raise ValueError("; ".join(errors))
    value = normalize_attestation_payload(payload) if attestation else copy.deepcopy(payload)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def payload_digest(payload: dict[str, Any], *, attestation: bool = True) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_payload_bytes(payload, attestation=attestation)
    ).hexdigest()


def _prefix_case(case: dict[str, Any], event_id: str) -> dict[str, Any] | None:
    events = case.get("events")
    if not isinstance(events, list):
        return None
    prefix: list[dict[str, Any]] = []
    found = False
    for event in events:
        prefix.append(copy.deepcopy(event))
        if isinstance(event, dict) and event.get("event_id") == event_id:
            found = True
            break
    if not found:
        return None
    result = copy.deepcopy(case)
    result["events"] = prefix
    return result


def _crypto_algorithms(crypto_registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["id"]: item
        for item in crypto_registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def validate_attestation_registry(
    registry: dict[str, Any],
    crypto_registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("attestation registry schema_version must be 0.1")
    formats = registry.get("envelope_formats")
    if not isinstance(formats, list) or not formats:
        errors.append("attestation registry envelope_formats must be non-empty")
        formats = []
    format_ids: set[str] = set()
    for index, item in enumerate(formats):
        prefix = f"attestation registry envelope_formats[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        format_id = item.get("id")
        if not isinstance(format_id, str) or not format_id:
            errors.append(f"{prefix} id must be non-empty")
        elif format_id in format_ids:
            errors.append(f"{prefix} duplicate id {format_id}")
        else:
            format_ids.add(format_id)
        if not isinstance(item.get("multiple_signatures_per_envelope"), bool):
            errors.append(f"{prefix} multiple_signatures_per_envelope must be boolean")

    algorithms = _crypto_algorithms(crypto_registry)
    ids = registry.get("algorithm_ids")
    if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)):
        errors.append("attestation registry algorithm_ids must be unique and non-empty")
        ids = []
    for algorithm_id in ids:
        algorithm = algorithms.get(algorithm_id)
        if algorithm is None:
            errors.append(f"attestation registry unknown algorithm {algorithm_id}")
        elif algorithm.get("category") != "signature":
            errors.append(f"attestation registry algorithm is not a signature: {algorithm_id}")
        elif algorithm.get("status") not in {"recommended", "allowed"}:
            errors.append(f"attestation registry algorithm not permitted for new issuance: {algorithm_id}")

    classes: set[str] = set()
    for index, item in enumerate(registry.get("signature_policies", [])):
        prefix = f"attestation registry signature_policies[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        policy_class = item.get("policy_class")
        if not isinstance(policy_class, str) or not policy_class:
            errors.append(f"{prefix} policy_class must be non-empty")
        elif policy_class in classes:
            errors.append(f"{prefix} duplicate policy_class {policy_class}")
        else:
            classes.add(policy_class)
        for field in (
            "minimum_signatures",
            "minimum_classical_signatures",
            "minimum_post_quantum_signatures",
        ):
            value = item.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append(f"{prefix} {field} must be a non-negative integer")
    return errors


def validate_signing_policy(
    policy: dict[str, Any],
    registry: dict[str, Any],
    crypto_registry: dict[str, Any],
) -> list[str]:
    errors = validate_attestation_registry(registry, crypto_registry)
    if policy.get("schema_version") != "0.1":
        errors.append("signing policy schema_version must be 0.1")

    classes = {
        item["policy_class"]: item
        for item in registry.get("signature_policies", [])
        if isinstance(item, dict) and isinstance(item.get("policy_class"), str)
    }
    if policy.get("policy_class") not in classes:
        errors.append("signing policy has unknown policy_class")

    format_ids = {
        item["id"]
        for item in registry.get("envelope_formats", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    formats = policy.get("allowed_envelope_formats")
    if not isinstance(formats, list) or not formats or len(formats) != len(set(formats)):
        errors.append("signing policy allowed_envelope_formats must be unique and non-empty")
        formats = []
    unknown_formats = sorted(set(formats) - format_ids)
    if unknown_formats:
        errors.append("signing policy unknown envelope formats: " + ", ".join(unknown_formats))

    trusted_keys = policy.get("trusted_keys")
    if not isinstance(trusted_keys, list) or not trusted_keys:
        return errors + ["signing policy trusted_keys must be non-empty"]

    algorithms = _crypto_algorithms(crypto_registry)
    allowed_algorithms = set(registry.get("algorithm_ids", []))
    seen_keys: set[str] = set()
    usable_classes: set[str] = set()

    for index, key in enumerate(trusted_keys):
        prefix = f"signing policy trusted_keys[{index}]"
        if not isinstance(key, dict):
            errors.append(f"{prefix} must be an object")
            continue
        key_id = key.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            errors.append(f"{prefix} key_id must be non-empty")
        elif key_id in seen_keys:
            errors.append(f"{prefix} duplicate key_id {key_id}")
        else:
            seen_keys.add(key_id)

        algorithm_id = key.get("algorithm_id")
        algorithm = algorithms.get(algorithm_id)
        if algorithm_id not in allowed_algorithms or algorithm is None:
            errors.append(f"{prefix} algorithm is not allowed for certification signing: {algorithm_id}")
        elif algorithm.get("category") != "signature":
            errors.append(f"{prefix} algorithm is not a signature")
        else:
            pq = algorithm.get("pq_characteristic")
            if pq == "classical":
                usable_classes.add("classical")
            elif pq == "post-quantum":
                usable_classes.add("post-quantum")

        valid_from = _parse_time(key.get("valid_from"), f"{prefix} valid_from", errors)
        valid_until = _parse_time(key.get("valid_until"), f"{prefix} valid_until", errors)
        status_effective = _parse_time(
            key.get("status_effective_at"), f"{prefix} status_effective_at", errors
        )
        if valid_from is not None and valid_until is not None and valid_until <= valid_from:
            errors.append(f"{prefix} valid_until must be after valid_from")
        if status_effective is not None and valid_from is not None and status_effective < valid_from:
            errors.append(f"{prefix} status_effective_at must not predate valid_from")
        if key.get("status") not in {"active", "retired", "revoked"}:
            errors.append(f"{prefix} invalid status")
        if key.get("role") != "certification-signer":
            errors.append(f"{prefix} role must be certification-signer")

    descriptor = classes.get(policy.get("policy_class"))
    if descriptor is not None:
        if descriptor["minimum_classical_signatures"] > 0 and "classical" not in usable_classes:
            errors.append("signing policy cannot meet classical signature floor with configured keys")
        if descriptor["minimum_post_quantum_signatures"] > 0 and "post-quantum" not in usable_classes:
            errors.append("signing policy cannot meet post-quantum signature floor with configured keys")
        if len(seen_keys) < descriptor["minimum_signatures"]:
            errors.append("signing policy has fewer distinct keys than signature threshold")
    return sorted(set(errors))


def _positive_claims(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for item in bundle.get("claim_evidence", []):
        if not isinstance(item, dict):
            continue
        if item.get("status") not in {"supported", "conditional"}:
            continue
        claims.append(
            {
                "property_id": item.get("property_id"),
                "status": item.get("status"),
                "threat_ids": sorted(item.get("threat_ids", [])),
                "limitations": sorted(item.get("limitations", [])),
            }
        )
    return normalize_attestation_payload({"claims": claims})["claims"]


def _verify_envelopes(
    record: dict[str, Any],
    policy: dict[str, Any],
    registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    expected_payload: bytes,
    payload_type: str,
    issued_at: datetime,
    signature_verifier: SignatureVerifier | None,
) -> list[str]:
    errors: list[str] = []
    if signature_verifier is None:
        return ["cryptographic signature verifier is required"]

    formats = {
        item["id"]: item
        for item in registry.get("envelope_formats", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    allowed_formats = set(policy.get("allowed_envelope_formats", []))
    algorithms = _crypto_algorithms(crypto_registry)
    keys = {
        item["key_id"]: item
        for item in policy.get("trusted_keys", [])
        if isinstance(item, dict) and isinstance(item.get("key_id"), str)
    }

    envelopes = record.get("envelopes")
    if not isinstance(envelopes, list) or not envelopes:
        return ["attestation envelopes must be non-empty"]

    expected_digest = "sha256:" + hashlib.sha256(expected_payload).hexdigest()
    verified_keys: dict[str, str] = {}
    seen_envelope_ids: set[str] = set()

    for index, envelope in enumerate(envelopes):
        prefix = f"envelopes[{index}]"
        if not isinstance(envelope, dict):
            errors.append(f"{prefix} must be an object")
            continue
        envelope_id = envelope.get("envelope_id")
        if not isinstance(envelope_id, str) or not envelope_id:
            errors.append(f"{prefix} envelope_id must be non-empty")
        elif envelope_id in seen_envelope_ids:
            errors.append(f"{prefix} duplicate envelope_id {envelope_id}")
        else:
            seen_envelope_ids.add(envelope_id)

        format_id = envelope.get("format")
        descriptor = formats.get(format_id)
        if descriptor is None:
            errors.append(f"{prefix} unknown envelope format {format_id}")
            continue
        if format_id not in allowed_formats:
            errors.append(f"{prefix} envelope format is not allowed by signing policy: {format_id}")
        if envelope.get("payload_digest") != expected_digest:
            errors.append(f"{prefix} payload_digest does not match canonical payload")
        if not isinstance(envelope.get("serialized_envelope"), str) or not envelope["serialized_envelope"]:
            errors.append(f"{prefix} serialized_envelope must be non-empty")
            continue

        try:
            verified = signature_verifier(envelope, expected_payload, payload_type, policy)
        except Exception as exc:
            errors.append(f"{prefix} cryptographic verifier error: {exc}")
            continue
        if not isinstance(verified, list):
            errors.append(f"{prefix} cryptographic verifier must return a list")
            continue
        if not descriptor.get("multiple_signatures_per_envelope") and len(verified) > 1:
            errors.append(f"{prefix} envelope format permits only one counted signature")

        for signature in verified:
            if not isinstance(signature, dict):
                errors.append(f"{prefix} verifier returned malformed signature result")
                continue
            key_id = signature.get("key_id")
            algorithm_id = signature.get("algorithm_id")
            key = keys.get(key_id)
            if key is None:
                errors.append(f"{prefix} signature uses untrusted key {key_id}")
                continue
            if key.get("algorithm_id") != algorithm_id:
                errors.append(f"{prefix} signature algorithm does not match trusted key {key_id}")
                continue
            algorithm = algorithms.get(algorithm_id)
            if algorithm is None or algorithm.get("category") != "signature":
                errors.append(f"{prefix} verifier returned non-signature algorithm {algorithm_id}")
                continue
            if algorithm.get("status") not in {"recommended", "allowed"}:
                errors.append(f"{prefix} algorithm is not permitted for certification signing")
                continue

            key_errors: list[str] = []
            valid_from = _parse_time(key.get("valid_from"), f"key {key_id} valid_from", key_errors)
            valid_until = _parse_time(key.get("valid_until"), f"key {key_id} valid_until", key_errors)
            status_time = _parse_time(
                key.get("status_effective_at"), f"key {key_id} status_effective_at", key_errors
            )
            errors.extend(key_errors)
            if valid_from is None or valid_until is None or not (valid_from <= issued_at < valid_until):
                errors.append(f"{prefix} key {key_id} is outside its validity interval")
                continue
            status = key.get("status")
            if status == "revoked":
                errors.append(f"{prefix} key {key_id} is revoked")
                continue
            if status == "retired" and status_time is not None and issued_at >= status_time:
                errors.append(f"{prefix} key {key_id} was retired before issuance")
                continue
            verified_keys[key_id] = algorithm_id

    policy_classes = {
        item["policy_class"]: item
        for item in registry.get("signature_policies", [])
        if isinstance(item, dict)
    }
    descriptor = policy_classes.get(policy.get("policy_class"))
    if descriptor is None:
        errors.append("unknown signing policy class")
        return sorted(set(errors))

    classical = 0
    post_quantum = 0
    for algorithm_id in verified_keys.values():
        characteristic = algorithms.get(algorithm_id, {}).get("pq_characteristic")
        if characteristic == "classical":
            classical += 1
        elif characteristic == "post-quantum":
            post_quantum += 1

    if len(verified_keys) < descriptor["minimum_signatures"]:
        errors.append("verified signatures do not meet signing threshold")
    if classical < descriptor["minimum_classical_signatures"]:
        errors.append("verified signatures do not meet classical signature floor")
    if post_quantum < descriptor["minimum_post_quantum_signatures"]:
        errors.append("verified signatures do not meet post-quantum signature floor")
    return sorted(set(errors))


def validate_attestation(
    record: dict[str, Any],
    signing_policy: dict[str, Any],
    attestation_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    lifecycle_case: dict[str, Any],
    lifecycle_registry: dict[str, Any],
    evidence_bundle: dict[str, Any],
    assurance_plan: dict[str, Any],
    evidence_registry: dict[str, Any],
    assurance_registry: dict[str, Any],
    catalog: dict[str, Any],
    property_ids: set[str],
    threat_ids: set[str],
    *,
    signature_verifier: SignatureVerifier | None,
) -> list[str]:
    errors = validate_signing_policy(signing_policy, attestation_registry, crypto_registry)
    errors.extend(
        certification_evidence.validate_bundle(
            evidence_bundle,
            assurance_plan,
            evidence_registry,
            assurance_registry,
            catalog,
            property_ids,
            threat_ids,
        )
    )
    if errors:
        return sorted(set(errors))

    if record.get("schema_version") != "0.1":
        errors.append("attestation record schema_version must be 0.1")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return errors + ["attestation payload must be an object"]

    try:
        expected_payload = canonical_payload_bytes(payload, attestation=True)
    except ValueError as exc:
        return errors + [str(exc)]
    expected_digest = "sha256:" + hashlib.sha256(expected_payload).hexdigest()
    if record.get("payload_digest") != expected_digest:
        errors.append("attestation payload_digest does not match canonical payload")

    issued_at = _parse_time(payload.get("issued_at"), "attestation issued_at", errors)
    not_before = _parse_time(payload.get("not_before"), "attestation not_before", errors)
    expires_at = _parse_time(payload.get("expires_at"), "attestation expires_at", errors)
    surveillance_due = _parse_time(
        payload.get("surveillance_due_at"), "attestation surveillance_due_at", errors
    )
    if issued_at is not None and not_before is not None and not_before > issued_at:
        errors.append("attestation not_before must not be after issued_at")
    if issued_at is not None and expires_at is not None and expires_at <= issued_at:
        errors.append("attestation expires_at must be after issued_at")

    event_id = payload.get("lifecycle_event_id")
    prefix = _prefix_case(lifecycle_case, event_id) if isinstance(event_id, str) else None
    if prefix is None:
        errors.append("attestation lifecycle_event_id is not present in lifecycle case")
        return sorted(set(errors))

    prefix_digest = canonical_digest(prefix)
    if payload.get("lifecycle_digest") != prefix_digest:
        errors.append("attestation lifecycle_digest does not bind lifecycle prefix")

    issuance_result = certification_lifecycle.validate_case(
        prefix,
        lifecycle_registry,
        as_of=payload.get("issued_at"),
    )
    if not issuance_result.valid:
        errors.extend("lifecycle: " + item for item in issuance_result.errors)
    if issuance_result.state != "certified":
        errors.append("attestation may be issued only from certified lifecycle state")

    if payload.get("case_id") != lifecycle_case.get("case_id"):
        errors.append("attestation case_id does not match lifecycle case")
    for field in ("product_id", "product_version", "platform"):
        if payload.get(field) != evidence_bundle.get(field) or payload.get(field) != lifecycle_case.get(field):
            errors.append(f"attestation {field} does not match evidence/lifecycle subject")

    expected_bundle_digest = canonical_digest(evidence_bundle)
    if payload.get("evidence_bundle_digest") != expected_bundle_digest:
        errors.append("attestation evidence_bundle_digest mismatch")
    if issuance_result.current_evidence_bundle_digest != expected_bundle_digest:
        errors.append("lifecycle current evidence bundle does not match certified evidence bundle")

    expected_plan_digest = formal_verification.canonical_digest(assurance_plan)
    if payload.get("assurance_plan_digest") != expected_plan_digest:
        errors.append("attestation assurance_plan_digest mismatch")
    if payload.get("assurance_plan_digest") != evidence_bundle.get("assurance_plan_digest"):
        errors.append("attestation assurance_plan_digest does not match evidence bundle")

    for field in ("assurance_profile_ref","configuration_digest","source_digest","artifact_digest"):
        if payload.get(field) != evidence_bundle.get(field):
            errors.append(f"attestation {field} does not match evidence bundle")

    expected_profiles = sorted(evidence_bundle.get("effective_profile_refs", []))
    if sorted(payload.get("effective_profile_refs", [])) != expected_profiles:
        errors.append("attestation effective_profile_refs do not match evidence bundle")

    if payload.get("issuer_id") != signing_policy.get("issuer_id"):
        errors.append("attestation issuer_id does not match signing policy")
    if payload.get("signing_policy_id") != signing_policy.get("policy_id"):
        errors.append("attestation signing_policy_id does not match signing policy")

    lifecycle_expiry = _parse_time(
        issuance_result.certificate_expires_at,
        "lifecycle certificate_expires_at",
        errors,
    )
    lifecycle_due = _parse_time(
        issuance_result.surveillance_due_at,
        "lifecycle surveillance_due_at",
        errors,
    )
    if expires_at is not None and lifecycle_expiry is not None and expires_at > lifecycle_expiry:
        errors.append("attestation expires after lifecycle certificate expiry")
    if surveillance_due is not None and lifecycle_due is not None and surveillance_due != lifecycle_due:
        errors.append("attestation surveillance_due_at does not match lifecycle")
    if not isinstance(payload.get("status_reference"), str) or not payload["status_reference"].startswith("https://"):
        errors.append("attestation status_reference must be HTTPS")

    expected_claims = _positive_claims(evidence_bundle)
    actual_claims = normalize_attestation_payload({"claims": payload.get("claims", [])}).get("claims", [])
    if actual_claims != expected_claims:
        errors.append("attestation published claims do not exactly match positive evidence claims")

    if issued_at is not None:
        errors.extend(
            _verify_envelopes(
                record,
                signing_policy,
                attestation_registry,
                crypto_registry,
                expected_payload,
                attestation_registry["payload_type"],
                issued_at,
                signature_verifier,
            )
        )
    return sorted(set(errors))


def validate_status_statement(
    record: dict[str, Any],
    attestation: dict[str, Any],
    signing_policy: dict[str, Any],
    attestation_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    lifecycle_case: dict[str, Any],
    lifecycle_registry: dict[str, Any],
    *,
    signature_verifier: SignatureVerifier | None,
    previous_status: dict[str, Any] | None = None,
    highest_sequence: int | None = None,
) -> list[str]:
    errors = validate_signing_policy(signing_policy, attestation_registry, crypto_registry)
    payload = record.get("payload")
    att_payload = attestation.get("payload")
    if not isinstance(payload, dict) or not isinstance(att_payload, dict):
        return errors + ["status and attestation payloads must be objects"]

    try:
        expected_payload = canonical_payload_bytes(payload, attestation=False)
    except ValueError as exc:
        return errors + [str(exc)]
    expected_digest = "sha256:" + hashlib.sha256(expected_payload).hexdigest()
    if record.get("payload_digest") != expected_digest:
        errors.append("status payload_digest does not match canonical payload")

    for field in ("attestation_id","case_id"):
        expected = att_payload.get("attestation_id") if field == "attestation_id" else att_payload.get("case_id")
        if payload.get(field) != expected:
            errors.append(f"status {field} does not match attestation")

    sequence = payload.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        errors.append("status sequence must be a non-negative integer")
        sequence = -1
    if highest_sequence is not None and sequence <= highest_sequence:
        errors.append("status sequence rollback detected")

    if sequence == 0:
        if payload.get("previous_status_digest") is not None:
            errors.append("status sequence 0 must have null previous_status_digest")
    else:
        if previous_status is None:
            errors.append("nonzero status sequence requires previous status statement")
        else:
            previous_payload = previous_status.get("payload")
            previous_sequence = previous_payload.get("sequence") if isinstance(previous_payload, dict) else None
            if previous_sequence != sequence - 1:
                errors.append("status sequence is not contiguous with previous statement")
            if payload.get("previous_status_digest") != canonical_digest(previous_payload):
                errors.append("status previous_status_digest mismatch")

    event_id = payload.get("lifecycle_event_id")
    prefix = _prefix_case(lifecycle_case, event_id) if isinstance(event_id, str) else None
    if prefix is None:
        errors.append("status lifecycle_event_id is not present in lifecycle case")
        return sorted(set(errors))
    if payload.get("lifecycle_digest") != canonical_digest(prefix):
        errors.append("status lifecycle_digest mismatch")

    effective_at = _parse_time(payload.get("effective_at"), "status effective_at", errors)
    result = certification_lifecycle.validate_case(
        prefix, lifecycle_registry, as_of=payload.get("effective_at")
    )
    if not result.valid:
        errors.extend("lifecycle: " + item for item in result.errors)
    if payload.get("state") != result.state:
        errors.append("status state does not match lifecycle state")
    if payload.get("evidence_bundle_digest") != result.current_evidence_bundle_digest:
        errors.append("status evidence_bundle_digest does not match lifecycle")
    if payload.get("certificate_expires_at") != result.certificate_expires_at:
        errors.append("status certificate_expires_at does not match lifecycle")
    if payload.get("surveillance_due_at") != result.surveillance_due_at:
        errors.append("status surveillance_due_at does not match lifecycle")
    if payload.get("issuer_id") != signing_policy.get("issuer_id"):
        errors.append("status issuer_id does not match signing policy")
    if payload.get("signing_policy_id") != signing_policy.get("policy_id"):
        errors.append("status signing_policy_id does not match signing policy")

    if effective_at is not None:
        errors.extend(
            _verify_envelopes(
                record,
                signing_policy,
                attestation_registry,
                crypto_registry,
                expected_payload,
                attestation_registry["status_payload_type"],
                effective_at,
                signature_verifier,
            )
        )
    return sorted(set(errors))


def status_is_currently_certified(
    status_record: dict[str, Any],
    *,
    as_of: str,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    payload = status_record.get("payload")
    if not isinstance(payload, dict):
        return False, ["status payload must be an object"]
    now = _parse_time(as_of, "as_of", errors)
    expiry = _parse_time(payload.get("certificate_expires_at"), "status certificate_expires_at", errors)
    due = _parse_time(payload.get("surveillance_due_at"), "status surveillance_due_at", errors)
    if payload.get("state") != "certified":
        errors.append(f"certification status is {payload.get('state')}")
    if now is not None and expiry is not None and now >= expiry:
        errors.append("certification status is expired")
    if now is not None and due is not None and now >= due:
        errors.append("certification status requires fresh surveillance/status")
    return not errors, errors
