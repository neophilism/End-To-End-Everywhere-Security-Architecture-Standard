#!/usr/bin/env python3
"""Observatory evidence/provenance validation for E2EESA PR 34."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def manifest_core(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        key: bundle.get(key)
        for key in (
            "schema_version",
            "bundle_id",
            "revision",
            "previous_bundle_digest",
            "created_at",
            "agents",
            "entities",
            "activities",
            "events",
            "citations",
        )
    }


def compute_manifest_digest(bundle: dict[str, Any]) -> str:
    return canonical_digest(manifest_core(bundle))


def bundle_core(bundle: dict[str, Any]) -> dict[str, Any]:
    value = manifest_core(bundle)
    value["manifest_digest"] = bundle.get("manifest_digest")
    value["integrity_anchors"] = bundle.get("integrity_anchors")
    return value


def compute_bundle_digest(bundle: dict[str, Any]) -> str:
    return canonical_digest(bundle_core(bundle))


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        errors.append(f"{field} must be a UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _find_floats(value: object, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, float):
        found.append(path)
    elif isinstance(value, dict):
        for key, item in value.items():
            found.extend(_find_floats(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_find_floats(item, f"{path}[{index}]"))
    return found


def _unique_map(items: object, id_field: str, label: str, errors: list[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(items, list):
        errors.append(f"{label} must be an array")
        return result
    for index, item in enumerate(items):
        prefix = f"{label}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        item_id = item.get(id_field)
        if not isinstance(item_id, str) or not item_id:
            errors.append(f"{prefix} {id_field} must be non-empty")
        elif item_id in result:
            errors.append(f"{prefix} duplicate {id_field} {item_id}")
        else:
            result[item_id] = item
    return result


def _revision_cycle(entity_id: str, entities: dict[str, dict[str, Any]]) -> bool:
    seen: set[str] = set()
    current: str | None = entity_id
    while current is not None:
        if current in seen:
            return True
        seen.add(current)
        entity = entities.get(current)
        if entity is None:
            return False
        previous = entity.get("revision_of")
        current = previous if isinstance(previous, str) else None
    return False


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if bundle.get("schema_version") != "0.1":
        errors.append("observatory evidence schema_version must be 0.1")

    for path in _find_floats(bundle):
        errors.append(f"observatory canonical JSON subset forbids floating-point values: {path}")

    revision = bundle.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        errors.append("bundle revision must be a positive integer")
    previous = bundle.get("previous_bundle_digest")
    if revision == 1 and previous is not None:
        errors.append("bundle revision 1 must have null previous_bundle_digest")
    if isinstance(revision, int) and revision > 1:
        if not isinstance(previous, str) or SHA256_RE.fullmatch(previous) is None:
            errors.append("bundle revision >1 requires previous_bundle_digest")

    created_at = _parse_time(bundle.get("created_at"), "bundle.created_at", errors)

    agents = _unique_map(bundle.get("agents"), "agent_id", "agents", errors)
    entities = _unique_map(bundle.get("entities"), "entity_id", "entities", errors)
    activities = _unique_map(bundle.get("activities"), "activity_id", "activities", errors)
    events = _unique_map(bundle.get("events"), "event_id", "events", errors)
    citations = _unique_map(bundle.get("citations"), "citation_id", "citations", errors)
    anchors = _unique_map(bundle.get("integrity_anchors"), "anchor_id", "integrity_anchors", errors)

    overlap = sorted(set(agents) & set(entities))
    if overlap:
        errors.append("agent/entity IDs must be globally unambiguous: " + ", ".join(overlap))

    for agent_id, agent in agents.items():
        if agent.get("agent_type") not in {"person", "organization", "software", "service"}:
            errors.append(f"agent {agent_id} has invalid agent_type")
        if not isinstance(agent.get("name"), str) or not agent["name"].strip():
            errors.append(f"agent {agent_id} name must be non-empty")

    for entity_id, entity in entities.items():
        digest = entity.get("content_digest")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            errors.append(f"entity {entity_id} content_digest must be sha256")
        byte_length = entity.get("byte_length")
        if byte_length is not None and (
            not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 0
        ):
            errors.append(f"entity {entity_id} byte_length must be null or non-negative integer")
        acquired = _parse_time(entity.get("acquired_at"), f"entity {entity_id} acquired_at", errors)
        if acquired is not None and created_at is not None and acquired > created_at:
            errors.append(f"entity {entity_id} acquired_at is after bundle creation")
        previous_entity = entity.get("revision_of")
        if previous_entity is not None:
            if previous_entity not in entities:
                errors.append(f"entity {entity_id} revision_of references unknown entity {previous_entity}")
            if previous_entity == entity_id:
                errors.append(f"entity {entity_id} cannot revise itself")
        if _revision_cycle(entity_id, entities):
            errors.append(f"entity revision cycle detected at {entity_id}")

    generated_by: dict[str, str] = {}
    acquire_generated: set[str] = set()

    for activity_id, activity in activities.items():
        activity_type = activity.get("activity_type")
        if activity_type not in {
            "acquire", "extract", "transform", "normalize", "classify", "review", "publish"
        }:
            errors.append(f"activity {activity_id} has invalid activity_type")
        started = _parse_time(activity.get("started_at"), f"activity {activity_id} started_at", errors)
        ended = _parse_time(activity.get("ended_at"), f"activity {activity_id} ended_at", errors)
        if started is not None and ended is not None and ended < started:
            errors.append(f"activity {activity_id} ends before it starts")
        if ended is not None and created_at is not None and ended > created_at:
            errors.append(f"activity {activity_id} ends after bundle creation")

        agent_ids = activity.get("agent_ids")
        if not isinstance(agent_ids, list) or not agent_ids:
            errors.append(f"activity {activity_id} agent_ids must be non-empty")
            agent_ids = []
        for agent_id in agent_ids:
            if agent_id not in agents:
                errors.append(f"activity {activity_id} references unknown agent {agent_id}")

        used = activity.get("used_entity_ids")
        generated = activity.get("generated_entity_ids")
        if not isinstance(used, list) or len(used) != len(set(used)):
            errors.append(f"activity {activity_id} used_entity_ids must be a unique array")
            used = []
        if not isinstance(generated, list) or not generated or len(generated) != len(set(generated)):
            errors.append(f"activity {activity_id} generated_entity_ids must be unique and non-empty")
            generated = []

        for entity_id in used:
            if entity_id not in entities:
                errors.append(f"activity {activity_id} uses unknown entity {entity_id}")
        for entity_id in generated:
            if entity_id not in entities:
                errors.append(f"activity {activity_id} generates unknown entity {entity_id}")
                continue
            if entity_id in generated_by:
                errors.append(
                    f"entity {entity_id} has conflicting generators "
                    f"{generated_by[entity_id]} and {activity_id}"
                )
            else:
                generated_by[entity_id] = activity_id

        acquisition = activity.get("acquisition")
        if activity_type == "acquire":
            if not isinstance(acquisition, dict):
                errors.append(f"acquire activity {activity_id} requires acquisition metadata")
            else:
                source_uri = acquisition.get("source_uri")
                if not isinstance(source_uri, str) or not source_uri:
                    errors.append(f"acquire activity {activity_id} source_uri must be non-empty")
                retrieved = _parse_time(
                    acquisition.get("retrieved_at"),
                    f"activity {activity_id} acquisition.retrieved_at",
                    errors,
                )
                if (
                    retrieved is not None
                    and started is not None
                    and ended is not None
                    and not (started <= retrieved <= ended)
                ):
                    errors.append(
                        f"activity {activity_id} retrieval time must fall within activity interval"
                    )
                for entity_id in generated:
                    entity = entities.get(entity_id)
                    if entity is None:
                        continue
                    acquire_generated.add(entity_id)
                    if entity.get("entity_type") != "source-snapshot":
                        errors.append(
                            f"acquire activity {activity_id} must generate source-snapshot entities"
                        )
                    if entity.get("source_uri") != source_uri:
                        errors.append(
                            f"activity {activity_id} source_uri differs from generated entity {entity_id}"
                        )
                    if retrieved is not None and entity.get("acquired_at") != acquisition.get("retrieved_at"):
                        errors.append(
                            f"entity {entity_id} acquired_at must equal acquisition retrieved_at"
                        )
            if used:
                errors.append(f"acquire activity {activity_id} must not depend on prior evidence entities")
        else:
            if acquisition is not None:
                errors.append(f"non-acquire activity {activity_id} must have null acquisition metadata")
            if generated and not used:
                errors.append(
                    f"non-acquire activity {activity_id} generating evidence must use at least one source entity"
                )
            overlap_ids = set(used) & set(generated)
            if overlap_ids:
                errors.append(
                    f"activity {activity_id} cannot mutate entities in place: "
                    + ", ".join(sorted(overlap_ids))
                )

    for entity_id, entity in entities.items():
        if entity.get("entity_type") == "source-snapshot" and entity.get("source_uri"):
            if entity_id not in acquire_generated:
                errors.append(
                    f"source snapshot {entity_id} with source_uri lacks acquisition provenance"
                )

    for citation_id, citation in citations.items():
        entity_id = citation.get("entity_id")
        if entity_id not in entities:
            errors.append(f"citation {citation_id} references unknown entity {entity_id}")
        if citation.get("locator_kind") not in {
            "page", "line-range", "section", "fragment", "timestamp", "record", "other"
        }:
            errors.append(f"citation {citation_id} has invalid locator_kind")
        if not isinstance(citation.get("locator_value"), str) or not citation["locator_value"].strip():
            errors.append(f"citation {citation_id} locator_value must be non-empty")
        excerpt_digest = citation.get("excerpt_digest")
        if excerpt_digest is not None and (
            not isinstance(excerpt_digest, str) or SHA256_RE.fullmatch(excerpt_digest) is None
        ):
            errors.append(f"citation {citation_id} excerpt_digest must be null or sha256")

    subject_ids = set(agents) | set(entities)
    for event_id, event in events.items():
        start = _parse_time(event.get("occurred_start"), f"event {event_id} occurred_start", errors)
        end = _parse_time(event.get("occurred_end"), f"event {event_id} occurred_end", errors)
        if start is not None and end is not None and end < start:
            errors.append(f"event {event_id} occurrence interval is inverted")
        subjects = event.get("subject_ids")
        if not isinstance(subjects, list) or not subjects:
            errors.append(f"event {event_id} subject_ids must be non-empty")
            subjects = []
        for subject_id in subjects:
            if subject_id not in subject_ids:
                errors.append(f"event {event_id} references unknown subject {subject_id}")
        citation_ids = event.get("citation_ids")
        if not isinstance(citation_ids, list) or not citation_ids:
            errors.append(f"event {event_id} citation_ids must be non-empty")
            citation_ids = []
        for citation_id in citation_ids:
            if citation_id not in citations:
                errors.append(f"event {event_id} references unknown citation {citation_id}")
        attributes = event.get("attributes")
        if not isinstance(attributes, list):
            errors.append(f"event {event_id} attributes must be an array")
        else:
            names: set[str] = set()
            for index, attribute in enumerate(attributes):
                if not isinstance(attribute, dict):
                    errors.append(f"event {event_id} attributes[{index}] must be an object")
                    continue
                name = attribute.get("name")
                if not isinstance(name, str) or not name:
                    errors.append(f"event {event_id} attributes[{index}] name must be non-empty")
                elif name in names:
                    errors.append(f"event {event_id} duplicate attribute name {name}")
                else:
                    names.add(name)
                if isinstance(attribute.get("value"), float):
                    errors.append(f"event {event_id} attribute {name} cannot use floating-point value")

    expected_manifest = compute_manifest_digest(bundle)
    if bundle.get("manifest_digest") != expected_manifest:
        errors.append("manifest_digest does not match canonical evidence core")

    allowed_subject_digests = {expected_manifest}
    allowed_subject_digests.update(
        entity.get("content_digest")
        for entity in entities.values()
        if isinstance(entity.get("content_digest"), str)
    )

    for anchor_id, anchor in anchors.items():
        if anchor.get("anchor_type") not in {
            "detached-signature", "rfc3161-timestamp", "transparency-log"
        }:
            errors.append(f"anchor {anchor_id} has invalid anchor_type")
        subject_digest = anchor.get("subject_digest")
        if subject_digest not in allowed_subject_digests:
            errors.append(f"anchor {anchor_id} references unknown subject digest")
        proof_digest = anchor.get("proof_digest")
        if not isinstance(proof_digest, str) or SHA256_RE.fullmatch(proof_digest) is None:
            errors.append(f"anchor {anchor_id} proof_digest must be sha256")
        observed = _parse_time(anchor.get("observed_at"), f"anchor {anchor_id} observed_at", errors)
        if observed is not None and created_at is not None and observed < created_at:
            errors.append(f"anchor {anchor_id} observed_at predates bundle creation")
        if not isinstance(anchor.get("provider"), str) or not anchor["provider"].strip():
            errors.append(f"anchor {anchor_id} provider must be non-empty")
        if not isinstance(anchor.get("reference"), str) or not anchor["reference"].strip():
            errors.append(f"anchor {anchor_id} reference must be non-empty")
        verification = anchor.get("verification")
        if not isinstance(verification, dict):
            errors.append(f"anchor {anchor_id} verification must be an object")
            continue
        status = verification.get("status")
        if status not in {"unverified", "verified"}:
            errors.append(f"anchor {anchor_id} has invalid verification status")
        evidence_fields = (
            "verifier_name", "verifier_version", "verified_at", "result_digest", "result_ref"
        )
        if status == "verified":
            for field in evidence_fields:
                value = verification.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"verified anchor {anchor_id} requires verification.{field}")
            result_digest = verification.get("result_digest")
            if isinstance(result_digest, str) and SHA256_RE.fullmatch(result_digest) is None:
                errors.append(f"anchor {anchor_id} verification.result_digest must be sha256")
            verified_at = _parse_time(
                verification.get("verified_at"),
                f"anchor {anchor_id} verification.verified_at",
                errors,
            )
            if verified_at is not None and observed is not None and verified_at < observed:
                errors.append(f"anchor {anchor_id} verified_at predates anchor observation")
        elif status == "unverified":
            for field in evidence_fields:
                if verification.get(field) is not None:
                    errors.append(
                        f"unverified anchor {anchor_id} must not claim verification.{field}"
                    )

    expected_bundle = compute_bundle_digest(bundle)
    if bundle.get("bundle_digest") != expected_bundle:
        errors.append("bundle_digest does not match canonical evidence bundle")

    return sorted(set(errors))


def validate_revision_chain(
    current: dict[str, Any],
    previous: dict[str, Any],
) -> list[str]:
    errors = [
        "current: " + error for error in validate_bundle(current)
    ] + [
        "previous: " + error for error in validate_bundle(previous)
    ]
    if current.get("bundle_id") != previous.get("bundle_id"):
        errors.append("revision chain bundle_id mismatch")
    current_revision = current.get("revision")
    previous_revision = previous.get("revision")
    if not isinstance(current_revision, int) or not isinstance(previous_revision, int):
        errors.append("revision chain requires integer revisions")
    elif current_revision != previous_revision + 1:
        errors.append("revision chain must increment revision by exactly one")
    if current.get("previous_bundle_digest") != previous.get("bundle_digest"):
        errors.append("revision chain previous_bundle_digest does not bind predecessor")
    current_time = _parse_time(current.get("created_at"), "current.created_at", errors)
    previous_time = _parse_time(previous.get("created_at"), "previous.created_at", errors)
    if current_time is not None and previous_time is not None and current_time < previous_time:
        errors.append("revision chain creation time regresses")
    return sorted(set(errors))


def provenance_edges(bundle: dict[str, Any]) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    for activity in bundle.get("activities", []):
        if not isinstance(activity, dict):
            continue
        activity_id = activity.get("activity_id")
        for entity_id in activity.get("used_entity_ids", []):
            edges.append({
                "relation": "used",
                "activity_id": str(activity_id),
                "entity_id": str(entity_id),
            })
        for entity_id in activity.get("generated_entity_ids", []):
            edges.append({
                "relation": "wasGeneratedBy",
                "entity_id": str(entity_id),
                "activity_id": str(activity_id),
            })
        for agent_id in activity.get("agent_ids", []):
            edges.append({
                "relation": "wasAssociatedWith",
                "activity_id": str(activity_id),
                "agent_id": str(agent_id),
            })
    for entity in bundle.get("entities", []):
        if not isinstance(entity, dict):
            continue
        previous = entity.get("revision_of")
        if isinstance(previous, str):
            edges.append({
                "relation": "wasDerivedFrom",
                "entity_id": str(entity.get("entity_id")),
                "source_entity_id": previous,
            })
    return edges
