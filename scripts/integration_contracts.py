#!/usr/bin/env python3
"""Six-project integration contract validation for E2EESA PR 45."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SYSTEMS = {
    "e2eesa",
    "sdk",
    "verified",
    "security-lab",
    "incident-exchange",
    "observatory",
    "research-lab",
}
MUTABILITY = {"preserve", "produce-new", "derive"}
ARTIFACT_CLASSES = {"normative", "request", "result", "evidence", "state", "projection"}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def envelope_core(envelope: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in envelope.items() if key != "envelope_digest"}


def compute_envelope_digest(envelope: dict[str, Any]) -> str:
    return canonical_digest(envelope_core(envelope))


def compute_payload_digest(payload: object) -> str:
    return canonical_digest(payload)


def _parse_time(value: object, field: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{field} must be RFC3339 UTC")
        return
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")


def validate_registry(
    registry: dict[str, Any],
    *,
    root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("integration registry schema_version must be 0.1")

    systems = registry.get("systems")
    if not isinstance(systems, list) or set(systems) != SYSTEMS or len(systems) != len(SYSTEMS):
        errors.append("integration registry systems must define E2EESA plus exactly six downstream systems")

    artifacts = registry.get("artifact_types")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("integration registry artifact_types must be non-empty")
        artifacts = []

    artifact_map: dict[str, dict[str, Any]] = {}
    for index, artifact in enumerate(artifacts):
        prefix = f"artifact_types[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{prefix} must be an object")
            continue
        artifact_type = artifact.get("artifact_type")
        if not isinstance(artifact_type, str) or not artifact_type:
            errors.append(f"{prefix}.artifact_type must be non-empty")
            continue
        if artifact_type in artifact_map:
            errors.append(f"duplicate artifact_type {artifact_type}")
        artifact_map[artifact_type] = artifact

        if artifact.get("artifact_class") not in ARTIFACT_CLASSES:
            errors.append(f"{artifact_type} has invalid artifact_class")
        if artifact.get("mutability") not in MUTABILITY:
            errors.append(f"{artifact_type} has invalid mutability")
        bindings = artifact.get("binding_fields")
        if (
            not isinstance(bindings, list)
            or any(not isinstance(item, str) or not item for item in bindings)
            or len(bindings) != len(set(bindings))
        ):
            errors.append(f"{artifact_type} binding_fields must be unique strings")
        authority = artifact.get("authority_path")
        schema = artifact.get("schema_path")
        if authority is None and schema is None:
            errors.append(f"{artifact_type} must define authority_path or schema_path")
        for label, path_value in (("authority_path", authority), ("schema_path", schema)):
            if path_value is not None and (not isinstance(path_value, str) or not path_value):
                errors.append(f"{artifact_type} {label} must be null or non-empty")
            if root is not None and isinstance(path_value, str):
                if not (root / path_value).is_file():
                    errors.append(f"{artifact_type} {label} does not exist: {path_value}")

    contracts = registry.get("contracts")
    if not isinstance(contracts, list) or len(contracts) != 6:
        errors.append("integration registry must define exactly six contracts")
        contracts = []

    seen_ids: set[str] = set()
    seen_systems: set[str] = set()
    for index, contract in enumerate(contracts):
        prefix = f"contracts[{index}]"
        if not isinstance(contract, dict):
            errors.append(f"{prefix} must be an object")
            continue
        contract_id = contract.get("contract_id")
        if not isinstance(contract_id, str) or not contract_id:
            errors.append(f"{prefix}.contract_id must be non-empty")
        elif contract_id in seen_ids:
            errors.append(f"duplicate contract_id {contract_id}")
        else:
            seen_ids.add(contract_id)

        system_id = contract.get("system_id")
        if system_id not in SYSTEMS - {"e2eesa"}:
            errors.append(f"{prefix} has invalid downstream system_id {system_id}")
        elif system_id in seen_systems:
            errors.append(f"duplicate downstream contract for {system_id}")
        else:
            seen_systems.add(system_id)

        for field_name in ("consumes", "emits"):
            values = contract.get(field_name)
            if (
                not isinstance(values, list)
                or len(values) != len(set(values))
                or any(not isinstance(item, str) for item in values)
            ):
                errors.append(f"{prefix}.{field_name} must be a unique string array")
                continue
            unknown = sorted(set(values) - set(artifact_map))
            if unknown:
                errors.append(
                    f"{prefix}.{field_name} references unknown artifacts: "
                    + ", ".join(unknown)
                )

    if seen_systems != SYSTEMS - {"e2eesa"}:
        errors.append("integration contracts do not cover all six downstream systems")

    return sorted(set(errors))


def validate_envelope(
    envelope: dict[str, Any],
    registry: dict[str, Any],
) -> list[str]:
    errors = validate_registry(registry)
    if errors:
        return errors

    if envelope.get("schema_version") != "0.1":
        errors.append("integration envelope schema_version must be 0.1")

    contracts = {
        item["contract_id"]: item
        for item in registry["contracts"]
        if isinstance(item, dict)
    }
    artifacts = {
        item["artifact_type"]: item
        for item in registry["artifact_types"]
        if isinstance(item, dict)
    }

    contract = contracts.get(envelope.get("contract_id"))
    if contract is None:
        errors.append(f"unknown integration contract {envelope.get('contract_id')}")
        return sorted(set(errors))
    if envelope.get("contract_version") != contract.get("contract_version"):
        errors.append("integration envelope contract_version mismatch")

    producer = envelope.get("producer_system")
    consumer = envelope.get("consumer_system")
    system = contract["system_id"]
    if {producer, consumer} != {"e2eesa", system}:
        errors.append("integration envelope producer/consumer pair does not match contract")

    artifact_type = envelope.get("artifact_type")
    artifact = artifacts.get(artifact_type)
    if artifact is None:
        errors.append(f"unknown integration artifact_type {artifact_type}")
        return sorted(set(errors))

    if producer == system and consumer == "e2eesa":
        if artifact_type not in contract["emits"]:
            errors.append(f"{system} is not permitted to emit {artifact_type}")
    elif producer == "e2eesa" and consumer == system:
        if artifact_type not in contract["consumes"]:
            errors.append(f"{system} is not permitted to consume {artifact_type}")

    if envelope.get("standard_version") != registry.get("standard_version"):
        errors.append("integration envelope standard_version mismatch")
    if envelope.get("authority_path") != artifact.get("authority_path"):
        errors.append("integration envelope authority_path mismatch")
    if envelope.get("schema_path") != artifact.get("schema_path"):
        errors.append("integration envelope schema_path mismatch")

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        errors.append("integration envelope payload must be an object")
        payload = {}

    for binding in artifact.get("binding_fields", []):
        if binding not in payload:
            errors.append(f"integration payload missing required binding field {binding}")

    # Preserve the PR 37 research/production boundary across transport.
    if artifact_type == "research-profile-entry":
        if payload.get("lifecycle_status") != "experimental":
            errors.append("research-profile-entry transport boundary requires experimental lifecycle_status")
        if payload.get("production_selectable") is not False:
            errors.append("research-profile-entry transport boundary requires production_selectable=false")

    expected_payload_digest = compute_payload_digest(payload)
    if envelope.get("payload_digest") != expected_payload_digest:
        errors.append("integration payload_digest does not match canonical payload")

    _parse_time(envelope.get("produced_at"), "integration produced_at", errors)

    expected_envelope_digest = compute_envelope_digest(envelope)
    if envelope.get("envelope_digest") != expected_envelope_digest:
        errors.append("integration envelope_digest does not match canonical envelope")

    return sorted(set(errors))


def build_envelope(
    *,
    registry: dict[str, Any],
    contract_id: str,
    producer_system: str,
    consumer_system: str,
    artifact_type: str,
    payload: dict[str, Any],
    produced_at: str,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    contracts = {item["contract_id"]: item for item in registry["contracts"]}
    artifacts = {item["artifact_type"]: item for item in registry["artifact_types"]}
    contract = contracts[contract_id]
    artifact = artifacts[artifact_type]
    envelope = {
        "schema_version": "0.1",
        "contract_id": contract_id,
        "contract_version": contract["contract_version"],
        "producer_system": producer_system,
        "consumer_system": consumer_system,
        "artifact_type": artifact_type,
        "standard_version": registry["standard_version"],
        "authority_path": artifact["authority_path"],
        "schema_path": artifact["schema_path"],
        "payload_digest": compute_payload_digest(payload),
        "produced_at": produced_at,
        "correlation_id": correlation_id,
        "payload": payload,
        "envelope_digest": "",
    }
    envelope["envelope_digest"] = compute_envelope_digest(envelope)
    return envelope
