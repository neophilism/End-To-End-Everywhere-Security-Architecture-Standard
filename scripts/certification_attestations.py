#!/usr/bin/env python3
"""Semantic validation for E2EESA PR 30 signed certification attestations."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable

import assurance_levels
import certification_evidence
import certification_lifecycle
import formal_verification

Verifier = Callable[[dict[str, Any], bytes, dict[str, Any], str], list[dict[str, str]]]


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _reject_floats(value: object, path: str, errors: list[str]) -> None:
    if isinstance(value, float):
        errors.append(f"{path} must not contain floating-point values")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]", errors)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                errors.append(f"{path} object keys must be strings")
                continue
            _reject_floats(item, f"{path}.{key}", errors)


def canonical_bytes(value: object) -> bytes:
    errors: list[str] = []
    _reject_floats(value, "payload", errors)
    if errors:
        raise ValueError("; ".join(errors))
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _registry_maps(
    attestation_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    formats = {
        item["id"]: item
        for item in attestation_registry.get("envelope_formats", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    policies = {
        item["policy_class"]: item
        for item in attestation_registry.get("signature_policies", [])
        if isinstance(item, dict) and isinstance(item.get("policy_class"), str)
    }
    algorithms = {
        item["id"]: item
        for item in crypto_registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    return formats, policies, algorithms


def validate_attestation_registry(
    registry: dict[str, Any],
    crypto_registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("attestation registry schema_version must be 0.1")
    for field in ("payload_type", "status_payload_type", "registry_version"):
        if not isinstance(registry.get(field), str) or not registry[field].strip():
            errors.append(f"attestation registry {field} must be non-empty")

    formats, policies, algorithms = _registry_maps(registry, crypto_registry)
    if set(formats) != {"jws-compact", "cose-sign1", "dsse"}:
        errors.append("attestation registry must define jws-compact, cose-sign1 and dsse")

    algorithm_ids = registry.get("algorithm_ids")
    if not isinstance(algorithm_ids, list) or not algorithm_ids or len(algorithm_ids) != len(set(algorithm_ids)):
        errors.append("attestation registry algorithm_ids must be a unique non-empty array")
        algorithm_ids = []
    for algorithm_id in algorithm_ids:
        algorithm = algorithms.get(algorithm_id)
        if algorithm is None:
            errors.append(f"attestation registry unknown algorithm {algorithm_id}")
        elif algorithm.get("category") != "signature":
            errors.append(f"attestation algorithm is not a signature algorithm: {algorithm_id}")
        elif algorithm.get("status") not in {"recommended", "allowed"}:
            errors.append(f"attestation algorithm is not permitted for new issuance: {algorithm_id}")

    if set(policies) != {"classical-threshold", "dual-classical-pq"}:
        errors.append("attestation registry must define classical-threshold and dual-classical-pq")
    for policy_class, policy in policies.items():
        for field in ("minimum_signatures", "minimum_classical_signatures", "minimum_post_quantum_signatures"):
            value=policy.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append(f"{policy_class} {field} must be a non-negative integer")
        if isinstance(policy.get("minimum_signatures"), int):
            if policy.get("minimum_classical_signatures",0)+policy.get("minimum_post_quantum_signatures",0) > policy["minimum_signatures"]:
                # This is acceptable only when total is a floor lower than category floors? No: total must at least cover category sum.
                errors.append(f"{policy_class} minimum_signatures must cover class-specific floors")
    return errors


def validate_signing_policy(
    policy: dict[str, Any],
    attestation_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
) -> list[str]:
    errors=validate_attestation_registry(attestation_registry, crypto_registry)
    formats, policy_classes, algorithms=_registry_maps(attestation_registry, crypto_registry)

    required={"schema_version","policy_id","issuer_id","policy_class","allowed_envelope_formats","trusted_keys"}
    missing=sorted(required-policy.keys())
    if missing:
        errors.append("signing policy missing fields: "+", ".join(missing))
        return sorted(set(errors))
    if policy.get("schema_version")!="0.1":
        errors.append("signing policy schema_version must be 0.1")
    policy_class=policy.get("policy_class")
    if policy_class not in policy_classes:
        errors.append(f"unknown signing policy class {policy_class}")

    allowed_formats=policy.get("allowed_envelope_formats")
    if not isinstance(allowed_formats,list) or not allowed_formats or len(allowed_formats)!=len(set(allowed_formats)):
        errors.append("allowed_envelope_formats must be a unique non-empty array")
        allowed_formats=[]
    for fmt in allowed_formats:
        if fmt not in formats:
            errors.append(f"unknown allowed envelope format {fmt}")

    registered_algorithms=set(attestation_registry.get("algorithm_ids",[]))
    keys=policy.get("trusted_keys")
    if not isinstance(keys,list) or not keys:
        errors.append("trusted_keys must be a non-empty array")
        return sorted(set(errors))
    seen:set[str]=set()
    for index,key in enumerate(keys):
        prefix=f"trusted_keys[{index}]"
        if not isinstance(key,dict):
            errors.append(f"{prefix} must be an object")
            continue
        key_id=key.get("key_id")
        if not isinstance(key_id,str) or not key_id:
            errors.append(f"{prefix} key_id must be non-empty")
        elif key_id in seen:
            errors.append(f"{prefix} duplicate key_id {key_id}")
        else:
            seen.add(key_id)

        algorithm_id=key.get("algorithm_id")
        if algorithm_id not in registered_algorithms:
            errors.append(f"{prefix} algorithm_id is not authorized for certification: {algorithm_id}")
        algorithm=algorithms.get(algorithm_id)
        if algorithm is None or algorithm.get("category")!="signature":
            errors.append(f"{prefix} algorithm_id is not a registered signature algorithm")

        for field in ("valid_from","valid_until","status_effective_at"):
            _parse_time(key.get(field),f"{prefix}.{field}",errors)
        start=_parse_time(key.get("valid_from"),f"{prefix}.valid_from-check",[])
        end=_parse_time(key.get("valid_until"),f"{prefix}.valid_until-check",[])
        if start is not None and end is not None and end <= start:
            errors.append(f"{prefix} valid_until must be after valid_from")
        if key.get("status") not in {"active","retired","revoked"}:
            errors.append(f"{prefix} invalid status")
        if key.get("role")!="certification-signer":
            errors.append(f"{prefix} role must be certification-signer")
    return sorted(set(errors))


def _key_valid_for_signing(key: dict[str, Any], issued_at: datetime, errors: list[str], prefix: str) -> bool:
    start=_parse_time(key.get("valid_from"),f"{prefix}.valid_from",errors)
    end=_parse_time(key.get("valid_until"),f"{prefix}.valid_until",errors)
    status_at=_parse_time(key.get("status_effective_at"),f"{prefix}.status_effective_at",errors)
    if start is None or end is None or status_at is None:
        return False
    if not (start <= issued_at < end):
        return False
    status=key.get("status")
    if status=="revoked":
        return False
    if status=="retired" and issued_at >= status_at:
        return False
    return status in {"active","retired"}


def _validate_set_ordering(payload: dict[str, Any], errors: list[str], *, status_payload: bool=False) -> None:
    if not status_payload:
        refs=payload.get("effective_profile_refs")
        if isinstance(refs,list) and refs != sorted(refs):
            errors.append("effective_profile_refs must be lexically sorted")
        claims=payload.get("claims")
        if isinstance(claims,list):
            claim_keys=[]
            for index,claim in enumerate(claims):
                if not isinstance(claim,dict):
                    continue
                threats=claim.get("threat_ids")
                limitations=claim.get("limitations")
                if isinstance(threats,list) and threats != sorted(threats):
                    errors.append(f"claims[{index}].threat_ids must be lexically sorted")
                if isinstance(limitations,list) and limitations != sorted(limitations):
                    errors.append(f"claims[{index}].limitations must be lexically sorted")
                claim_keys.append((
                    str(claim.get("property_id")),
                    str(claim.get("status")),
                    tuple(threats or []),
                    tuple(limitations or []),
                ))
            if claim_keys != sorted(claim_keys):
                errors.append("claims must be lexically sorted by canonical claim key")


def _validate_envelopes(
    record: dict[str, Any],
    payload_bytes: bytes,
    payload_digest: str,
    signing_policy: dict[str, Any],
    attestation_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    verifier: Verifier | None,
    payload_type: str,
    issued_at: datetime,
) -> list[str]:
    errors: list[str]=[]
    if verifier is None:
        return ["cryptographic verifier backend is required"]

    formats, policy_classes, algorithms=_registry_maps(attestation_registry, crypto_registry)
    policy_class=policy_classes.get(signing_policy.get("policy_class"))
    if policy_class is None:
        return ["unknown signing policy class"]

    allowed_formats=set(signing_policy.get("allowed_envelope_formats",[]))
    key_map={
        key["key_id"]:key
        for key in signing_policy.get("trusted_keys",[])
        if isinstance(key,dict) and isinstance(key.get("key_id"),str)
    }

    envelopes=record.get("envelopes")
    if not isinstance(envelopes,list) or not envelopes:
        return ["signed record requires at least one envelope"]
    seen_envelopes:set[str]=set()
    verified_by_key:dict[str,str]={}

    for index,envelope in enumerate(envelopes):
        prefix=f"envelopes[{index}]"
        if not isinstance(envelope,dict):
            errors.append(f"{prefix} must be an object")
            continue
        envelope_id=envelope.get("envelope_id")
        if not isinstance(envelope_id,str) or not envelope_id:
            errors.append(f"{prefix} envelope_id must be non-empty")
        elif envelope_id in seen_envelopes:
            errors.append(f"{prefix} duplicate envelope_id {envelope_id}")
        else:
            seen_envelopes.add(envelope_id)
        fmt=envelope.get("format")
        if fmt not in formats:
            errors.append(f"{prefix} unknown envelope format {fmt}")
            continue
        if fmt not in allowed_formats:
            errors.append(f"{prefix} envelope format is not allowed by signing policy: {fmt}")
        if envelope.get("payload_digest") != payload_digest:
            errors.append(f"{prefix} payload_digest does not match canonical payload")

        try:
            verified=verifier(envelope,payload_bytes,signing_policy,payload_type)
        except Exception as exc:
            errors.append(f"{prefix} cryptographic verifier error: {exc}")
            continue
        if not isinstance(verified,list):
            errors.append(f"{prefix} cryptographic verifier must return a list")
            continue
        if not verified:
            errors.append(f"{prefix} cryptographic verification produced no valid signatures")
        for sig_index,sig in enumerate(verified):
            sig_prefix=f"{prefix}.verified[{sig_index}]"
            if not isinstance(sig,dict):
                errors.append(f"{sig_prefix} must be an object")
                continue
            key_id=sig.get("key_id")
            algorithm_id=sig.get("algorithm_id")
            key=key_map.get(key_id)
            if key is None:
                errors.append(f"{sig_prefix} unknown or unauthorized key {key_id}")
                continue
            if key.get("algorithm_id") != algorithm_id:
                errors.append(f"{sig_prefix} algorithm does not match authorized key")
                continue
            algorithm=algorithms.get(algorithm_id)
            if algorithm is None or algorithm.get("category")!="signature":
                errors.append(f"{sig_prefix} algorithm is not a registered signature algorithm")
                continue
            if algorithm.get("status") not in {"recommended","allowed"}:
                errors.append(f"{sig_prefix} algorithm is not permitted for certification")
                continue
            if not _key_valid_for_signing(key,issued_at,errors,sig_prefix):
                errors.append(f"{sig_prefix} key is not valid for attestation signing time")
                continue
            verified_by_key[key_id]=algorithm_id

    classical=0
    pq=0
    for algorithm_id in verified_by_key.values():
        characteristic=algorithms.get(algorithm_id,{}).get("pq_characteristic")
        if characteristic=="post-quantum":
            pq+=1
        else:
            classical+=1

    total=len(verified_by_key)
    if total < policy_class["minimum_signatures"]:
        errors.append("signature threshold not met")
    if classical < policy_class["minimum_classical_signatures"]:
        errors.append("classical signature threshold not met")
    if pq < policy_class["minimum_post_quantum_signatures"]:
        errors.append("post-quantum signature threshold not met")
    return sorted(set(errors))


def _supported_claims(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    claims=[]
    for item in bundle.get("claim_evidence",[]):
        if not isinstance(item,dict) or item.get("status") not in {"supported","conditional"}:
            continue
        claims.append({
            "property_id":item.get("property_id"),
            "status":item.get("status"),
            "threat_ids":sorted(item.get("threat_ids",[])),
            "limitations":sorted(item.get("limitations",[])),
        })
    return sorted(claims,key=lambda x:(x["property_id"],x["status"],tuple(x["threat_ids"]),tuple(x["limitations"])))


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
    verifier: Verifier | None,
    *,
    as_of: str | None = None,
) -> list[str]:
    errors=validate_signing_policy(signing_policy,attestation_registry,crypto_registry)

    evidence_errors=certification_evidence.validate_bundle(
        evidence_bundle,assurance_plan,evidence_registry,assurance_registry,catalog,property_ids,threat_ids
    )
    errors.extend("evidence bundle: "+e for e in evidence_errors)

    lifecycle=certification_lifecycle.validate_case(lifecycle_case,lifecycle_registry,as_of=as_of)
    errors.extend("lifecycle: "+e for e in lifecycle.errors)
    if lifecycle.state!="certified":
        errors.append(f"lifecycle state must be certified, got {lifecycle.state}")

    payload=record.get("payload")
    if not isinstance(payload,dict):
        return sorted(set(errors+["attestation payload must be an object"]))

    _validate_set_ordering(payload,errors)
    try:
        payload_bytes=canonical_bytes(payload)
        expected_payload_digest="sha256:"+hashlib.sha256(payload_bytes).hexdigest()
    except ValueError as exc:
        return sorted(set(errors+[str(exc)]))

    if record.get("payload_digest") != expected_payload_digest:
        errors.append("attestation payload_digest does not match canonical payload")

    issued_at=_parse_time(payload.get("issued_at"),"payload.issued_at",errors)
    not_before=_parse_time(payload.get("not_before"),"payload.not_before",errors)
    expires_at=_parse_time(payload.get("expires_at"),"payload.expires_at",errors)
    surveillance_due=_parse_time(payload.get("surveillance_due_at"),"payload.surveillance_due_at",errors)

    if issued_at and not_before and issued_at < not_before:
        errors.append("attestation issued_at must not precede not_before")
    if not_before and expires_at and expires_at <= not_before:
        errors.append("attestation expires_at must be after not_before")
    if as_of is not None:
        as_of_dt=_parse_time(as_of,"as_of",errors)
        if as_of_dt and not_before and as_of_dt < not_before:
            errors.append("attestation is not yet valid")
        if as_of_dt and expires_at and as_of_dt >= expires_at:
            errors.append("attestation is expired")

    expected_plan_digest=formal_verification.canonical_digest(assurance_plan)
    expected_config_digest=formal_verification.canonical_digest(assurance_plan["configuration"])
    expected_bundle_digest=canonical_digest(evidence_bundle)
    expected_lifecycle_digest=canonical_digest(lifecycle_case)
    expected_event_id=(
        lifecycle_case.get("events",[])[-1].get("event_id")
        if lifecycle_case.get("events") else None
    )

    matches={
        "case_id":lifecycle_case.get("case_id"),
        "product_id":assurance_plan.get("product_id"),
        "product_version":assurance_plan.get("product_version"),
        "platform":assurance_plan.get("platform"),
        "assurance_profile_ref":assurance_plan.get("assurance_profile_ref"),
        "assurance_plan_digest":expected_plan_digest,
        "configuration_digest":expected_config_digest,
        "effective_profile_refs":sorted(evidence_bundle.get("effective_profile_refs",[])),
        "evidence_bundle_digest":expected_bundle_digest,
        "source_digest":evidence_bundle.get("source_digest"),
        "artifact_digest":evidence_bundle.get("artifact_digest"),
        "lifecycle_digest":expected_lifecycle_digest,
        "lifecycle_event_id":expected_event_id,
        "issuer_id":signing_policy.get("issuer_id"),
        "signing_policy_id":signing_policy.get("policy_id"),
        "expires_at":lifecycle.certificate_expires_at,
        "surveillance_due_at":lifecycle.surveillance_due_at,
        "claims":_supported_claims(evidence_bundle),
    }
    for field,expected in matches.items():
        actual=payload.get(field)
        if actual != expected:
            errors.append(f"attestation payload {field} does not match certified scope")

    if lifecycle.current_evidence_bundle_digest != expected_bundle_digest:
        errors.append("lifecycle current evidence bundle digest does not match validated evidence bundle")

    if expires_at and lifecycle.certificate_expires_at:
        lifecycle_expiry=_parse_time(lifecycle.certificate_expires_at,"lifecycle certificate expiry",errors)
        if lifecycle_expiry and expires_at > lifecycle_expiry:
            errors.append("attestation expires after lifecycle certificate expiry")
    if surveillance_due and lifecycle.surveillance_due_at:
        lifecycle_due=_parse_time(lifecycle.surveillance_due_at,"lifecycle surveillance due",errors)
        if lifecycle_due and surveillance_due != lifecycle_due:
            errors.append("attestation surveillance_due_at differs from lifecycle")

    if issued_at is not None:
        errors.extend(_validate_envelopes(
            record,payload_bytes,expected_payload_digest,signing_policy,
            attestation_registry,crypto_registry,verifier,
            attestation_registry.get("payload_type",""),issued_at,
        ))
    return sorted(set(errors))


def validate_status_statement(
    record: dict[str, Any],
    signing_policy: dict[str, Any],
    attestation_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    lifecycle_case: dict[str, Any],
    lifecycle_registry: dict[str, Any],
    verifier: Verifier | None,
    *,
    previous_record: dict[str, Any] | None = None,
    highest_sequence: int | None = None,
    as_of: str | None = None,
) -> list[str]:
    errors=validate_signing_policy(signing_policy,attestation_registry,crypto_registry)
    lifecycle=certification_lifecycle.validate_case(lifecycle_case,lifecycle_registry,as_of=as_of)
    errors.extend("lifecycle: "+e for e in lifecycle.errors)

    payload=record.get("payload")
    if not isinstance(payload,dict):
        return sorted(set(errors+["status payload must be an object"]))
    try:
        payload_bytes=canonical_bytes(payload)
        expected_digest="sha256:"+hashlib.sha256(payload_bytes).hexdigest()
    except ValueError as exc:
        return sorted(set(errors+[str(exc)]))
    if record.get("payload_digest") != expected_digest:
        errors.append("status payload_digest does not match canonical payload")

    effective_at=_parse_time(payload.get("effective_at"),"status.effective_at",errors)
    sequence=payload.get("sequence")
    if not isinstance(sequence,int) or isinstance(sequence,bool) or sequence<0:
        errors.append("status sequence must be a non-negative integer")
        sequence=-1
    if highest_sequence is not None and sequence < highest_sequence:
        errors.append("status sequence rollback detected")

    if sequence==0 and payload.get("previous_status_digest") is not None:
        errors.append("status sequence 0 must have null previous_status_digest")
    if sequence>0:
        if previous_record is None:
            errors.append("status sequence > 0 requires previous accepted status record")
        else:
            previous_payload=previous_record.get("payload")
            if not isinstance(previous_payload,dict):
                errors.append("previous status record payload must be an object")
            else:
                previous_sequence=previous_payload.get("sequence")
                if sequence != previous_sequence+1:
                    errors.append("status sequence must increment previous accepted sequence by one")
                previous_digest=canonical_digest(previous_payload)
                if payload.get("previous_status_digest") != previous_digest:
                    errors.append("status previous_status_digest does not bind previous accepted status payload")
                if payload.get("case_id") != previous_payload.get("case_id"):
                    errors.append("status case_id differs from previous accepted status")
                if payload.get("attestation_id") != previous_payload.get("attestation_id"):
                    errors.append("status attestation_id differs from previous accepted status")

    expected_event_id=(lifecycle_case.get("events") or [{}])[-1].get("event_id")
    expected_lifecycle_digest=canonical_digest(lifecycle_case)
    expected={
        "case_id":lifecycle_case.get("case_id"),
        "state":lifecycle.state,
        "lifecycle_digest":expected_lifecycle_digest,
        "lifecycle_event_id":expected_event_id,
        "evidence_bundle_digest":lifecycle.current_evidence_bundle_digest,
        "certificate_expires_at":lifecycle.certificate_expires_at,
        "surveillance_due_at":lifecycle.surveillance_due_at,
        "issuer_id":signing_policy.get("issuer_id"),
        "signing_policy_id":signing_policy.get("policy_id"),
    }
    for field,value in expected.items():
        if payload.get(field) != value:
            errors.append(f"status payload {field} does not match lifecycle/signing scope")

    if payload.get("state") not in {"certified","suspended","revoked","expired"}:
        errors.append("status payload state is not publishable")
    if payload.get("state") in {"suspended","revoked","expired"}:
        # This is a valid signed status record but not a current positive certification.
        pass

    if effective_at is not None:
        errors.extend(_validate_envelopes(
            record,payload_bytes,expected_digest,signing_policy,
            attestation_registry,crypto_registry,verifier,
            attestation_registry.get("status_payload_type",""),effective_at,
        ))
    return sorted(set(errors))


def current_certification_from_status(status_record: dict[str, Any]) -> bool:
    payload=status_record.get("payload")
    return isinstance(payload,dict) and payload.get("state")=="certified"
