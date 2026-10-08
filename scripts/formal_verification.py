#!/usr/bin/env python3
"""Semantic validation for E2EESA PR 26 formal-verification evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import profile_engine


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return value


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 UTC timestamp")
        return None
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None
    return dt


def _string_list(value: object, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (not nonempty or len(value) > 0)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
        and len(value) == len(set(value))
    )


def registry_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["profile_ref"]: item
        for item in registry.get("profiles", [])
        if isinstance(item, dict) and isinstance(item.get("profile_ref"), str)
    }


def validate_registry(registry: dict[str, Any], catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("formal registry schema_version must be 0.1")
    if not isinstance(registry.get("registry_version"), str) or not registry["registry_version"]:
        errors.append("formal registry registry_version must be non-empty")

    profiles = registry.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        errors.append("formal registry profiles must be a non-empty array")
        return errors

    catalog_refs = {
        profile_engine.profile_ref(profile): profile
        for profile in catalog.get("profiles", [])
        if isinstance(profile, dict)
    }
    seen_refs: set[str] = set()
    seen_kinds: set[str] = set()
    allowed_kinds = {"symbolic-protocol", "computational", "code-refinement"}

    for index, item in enumerate(profiles):
        prefix = f"formal registry profiles[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        required = {
            "profile_ref",
            "proof_kind",
            "supports_unbounded_sessions",
            "requires_machine_checking",
            "description",
        }
        missing = sorted(required - item.keys())
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(missing)}")
        extras = sorted(set(item) - required)
        if extras:
            errors.append(f"{prefix} unknown fields: {', '.join(extras)}")

        ref = item.get("profile_ref")
        if not isinstance(ref, str) or profile_engine.parse_profile_ref(ref) is None:
            errors.append(f"{prefix} has invalid profile_ref")
        elif ref in seen_refs:
            errors.append(f"{prefix} duplicates profile_ref {ref}")
        else:
            seen_refs.add(ref)
            catalog_profile = catalog_refs.get(ref)
            if catalog_profile is None:
                errors.append(f"{prefix} references profile absent from catalog: {ref}")
            elif catalog_profile.get("family_id") != "formal-verification":
                errors.append(f"{prefix} profile is not in formal-verification family: {ref}")

        kind = item.get("proof_kind")
        if kind not in allowed_kinds:
            errors.append(f"{prefix} has invalid proof_kind")
        elif kind in seen_kinds:
            errors.append(f"{prefix} duplicates proof_kind {kind}")
        else:
            seen_kinds.add(kind)

        if not isinstance(item.get("supports_unbounded_sessions"), bool):
            errors.append(f"{prefix} supports_unbounded_sessions must be boolean")
        if item.get("requires_machine_checking") is not True:
            errors.append(f"{prefix} must require machine checking")
        if not isinstance(item.get("description"), str) or not item["description"].strip():
            errors.append(f"{prefix} description must be non-empty")

    return errors


def validate_policy(
    policy: dict[str, Any],
    registry: dict[str, Any],
    catalog: dict[str, Any],
    property_ids: set[str],
    threat_ids: set[str],
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "policy_id",
        "product_id",
        "product_version",
        "platform",
        "configuration",
        "obligations",
    }
    missing = sorted(required - policy.keys())
    if missing:
        errors.append("formal policy missing fields: " + ", ".join(missing))
        return errors
    if policy.get("schema_version") != "0.1":
        errors.append("formal policy schema_version must be 0.1")

    config = policy.get("configuration")
    if not isinstance(config, dict):
        errors.append("formal policy configuration must be an object")
        return errors

    resolved = profile_engine.resolve_configuration(
        catalog,
        config,
        known_property_ids=property_ids,
    )
    if not resolved.valid:
        errors.extend("formal policy configuration: " + item for item in resolved.errors)
        return errors

    formal_profiles = registry_map(registry)
    selected = set(resolved.effective_profiles)

    obligations = policy.get("obligations")
    if not isinstance(obligations, list) or not obligations:
        errors.append("formal policy obligations must be a non-empty array")
        return errors

    seen_ids: set[str] = set()
    for index, obligation in enumerate(obligations):
        prefix = f"formal policy obligations[{index}]"
        if not isinstance(obligation, dict):
            errors.append(f"{prefix} must be an object")
            continue
        obligation_id = obligation.get("obligation_id")
        if not isinstance(obligation_id, str) or not obligation_id:
            errors.append(f"{prefix} obligation_id must be non-empty")
        elif obligation_id in seen_ids:
            errors.append(f"{prefix} duplicate obligation_id {obligation_id}")
        else:
            seen_ids.add(obligation_id)

        ref = obligation.get("formal_profile_ref")
        descriptor = formal_profiles.get(ref)
        if descriptor is None:
            errors.append(f"{prefix} unknown formal_profile_ref {ref}")
            continue
        if ref not in selected:
            errors.append(f"{prefix} formal profile is not selected by configuration: {ref}")

        properties = obligation.get("property_ids")
        if not _string_list(properties, nonempty=True):
            errors.append(f"{prefix} property_ids must be unique and non-empty")
        else:
            for property_id in properties:
                if property_id not in property_ids:
                    errors.append(f"{prefix} unknown property_id {property_id}")

        threats = obligation.get("threat_ids")
        if not _string_list(threats, nonempty=True):
            errors.append(f"{prefix} threat_ids must be unique and non-empty")
        else:
            for threat_id in threats:
                if threat_id not in threat_ids:
                    errors.append(f"{prefix} unknown threat_id {threat_id}")

        if obligation.get("require_machine_checking") is not True:
            errors.append(f"{prefix} PR 26 formal obligations must require machine checking")

        if obligation.get("require_unbounded_sessions") is True:
            if descriptor["proof_kind"] != "symbolic-protocol":
                errors.append(f"{prefix} unbounded sessions are only meaningful for symbolic protocol proof")
            elif descriptor.get("supports_unbounded_sessions") is not True:
                errors.append(f"{prefix} selected profile does not support unbounded sessions")

        if obligation.get("require_artifact_correspondence") is True:
            if descriptor["proof_kind"] != "code-refinement":
                errors.append(f"{prefix} artifact correspondence requires code-refinement profile")

        max_age = obligation.get("maximum_evidence_age_hours")
        if not isinstance(max_age, int) or isinstance(max_age, bool) or not (1 <= max_age <= 8760):
            errors.append(f"{prefix} maximum_evidence_age_hours must be 1..8760")

        if not isinstance(obligation.get("proof_scope"), str) or not obligation["proof_scope"].strip():
            errors.append(f"{prefix} proof_scope must be non-empty")

    return errors


def validate_evidence(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    registry: dict[str, Any],
    catalog: dict[str, Any],
    property_ids: set[str],
    threat_ids: set[str],
) -> list[str]:
    errors = validate_policy(policy, registry, catalog, property_ids, threat_ids)
    if errors:
        return errors

    for field in ("policy_id", "product_id", "product_version", "platform"):
        if evidence.get(field) != policy.get(field):
            errors.append(f"formal evidence {field} does not match policy")

    if evidence.get("schema_version") != "0.1":
        errors.append("formal evidence schema_version must be 0.1")

    expected_config_digest = canonical_digest(policy["configuration"])
    if evidence.get("configuration_digest") != expected_config_digest:
        errors.append("formal evidence configuration_digest does not bind policy configuration")

    source_digest = evidence.get("source_digest")
    artifact_digest = evidence.get("artifact_digest")
    if not isinstance(source_digest, str) or not source_digest.startswith("sha256:"):
        errors.append("formal evidence source_digest must be sha256")
    if artifact_digest is not None and (not isinstance(artifact_digest, str) or not artifact_digest.startswith("sha256:")):
        errors.append("formal evidence artifact_digest must be null or sha256")

    observed_at = _parse_time(evidence.get("observed_at"), "formal evidence observed_at", errors)

    proofs = evidence.get("proofs")
    if not isinstance(proofs, list) or not proofs:
        errors.append("formal evidence proofs must be a non-empty array")
        return errors

    formal_profiles = registry_map(registry)
    seen_ids: set[str] = set()
    valid_proofs: list[dict[str, Any]] = []

    for index, proof in enumerate(proofs):
        prefix = f"formal evidence proofs[{index}]"
        if not isinstance(proof, dict):
            errors.append(f"{prefix} must be an object")
            continue

        proof_id = proof.get("proof_id")
        if not isinstance(proof_id, str) or not proof_id:
            errors.append(f"{prefix} proof_id must be non-empty")
        elif proof_id in seen_ids:
            errors.append(f"{prefix} duplicate proof_id {proof_id}")
        else:
            seen_ids.add(proof_id)

        ref = proof.get("formal_profile_ref")
        descriptor = formal_profiles.get(ref)
        if descriptor is None:
            errors.append(f"{prefix} unknown formal_profile_ref {ref}")
            continue
        if proof.get("proof_kind") != descriptor.get("proof_kind"):
            errors.append(f"{prefix} proof_kind does not match formal profile")

        if proof.get("status") != "passed":
            errors.append(f"{prefix} status must be passed")

        if proof.get("machine_checked") is not True:
            errors.append(f"{prefix} must be machine checked")

        if proof.get("source_digest") != source_digest:
            errors.append(f"{prefix} source_digest does not match evidence source")
        if proof.get("artifact_digest") != artifact_digest:
            errors.append(f"{prefix} artifact_digest does not match evidence artifact")

        properties = proof.get("property_ids")
        if not _string_list(properties, nonempty=True):
            errors.append(f"{prefix} property_ids must be unique and non-empty")
            properties = []
        for property_id in properties:
            if property_id not in property_ids:
                errors.append(f"{prefix} unknown property_id {property_id}")

        threats = proof.get("threat_ids")
        if not _string_list(threats, nonempty=True):
            errors.append(f"{prefix} threat_ids must be unique and non-empty")
            threats = []
        for threat_id in threats:
            if threat_id not in threat_ids:
                errors.append(f"{prefix} unknown threat_id {threat_id}")

        unresolved = proof.get("unresolved_obligations")
        if not isinstance(unresolved, list):
            errors.append(f"{prefix} unresolved_obligations must be an array")
        elif unresolved:
            errors.append(f"{prefix} contains unresolved proof obligations")

        for list_field in ("assumptions", "trusted_axioms", "limitations"):
            if not _string_list(proof.get(list_field, [])):
                errors.append(f"{prefix} {list_field} must be a unique string array")

        tool = proof.get("tool")
        if not isinstance(tool, dict):
            errors.append(f"{prefix} tool must be an object")
        else:
            for field in ("name", "version", "digest"):
                if not isinstance(tool.get(field), str) or not tool[field].strip():
                    errors.append(f"{prefix} tool.{field} must be non-empty")

        if proof.get("session_scope") not in {"not-applicable", "bounded", "unbounded"}:
            errors.append(f"{prefix} invalid session_scope")
        if proof.get("artifact_correspondence") not in {"not-applicable", "source-only", "verified"}:
            errors.append(f"{prefix} invalid artifact_correspondence")

        for digest_field in ("model_digest", "specification_digest", "proof_artifact_digest"):
            value = proof.get(digest_field)
            if not isinstance(value, str) or not value.startswith("sha256:"):
                errors.append(f"{prefix} {digest_field} must be sha256")

        completed_at = _parse_time(proof.get("completed_at"), f"{prefix} completed_at", errors)
        if observed_at is not None and completed_at is not None and completed_at > observed_at:
            errors.append(f"{prefix} completed_at is after evidence observed_at")

        if not isinstance(proof.get("reproduction_ref"), str) or not proof["reproduction_ref"].strip():
            errors.append(f"{prefix} reproduction_ref must be non-empty")

        valid_proofs.append(proof)

    obligations = policy["obligations"]
    for obligation in obligations:
        matches: list[dict[str, Any]] = []
        for proof in valid_proofs:
            if proof.get("formal_profile_ref") != obligation["formal_profile_ref"]:
                continue
            if proof.get("status") != "passed" or proof.get("machine_checked") is not True:
                continue
            if not set(obligation["property_ids"]).issubset(set(proof.get("property_ids", []))):
                continue
            if not set(obligation["threat_ids"]).issubset(set(proof.get("threat_ids", []))):
                continue
            if proof.get("unresolved_obligations") != []:
                continue
            if obligation["require_unbounded_sessions"] and proof.get("session_scope") != "unbounded":
                continue
            if obligation["require_artifact_correspondence"] and proof.get("artifact_correspondence") != "verified":
                continue
            matches.append(proof)

        if not matches:
            errors.append(f"formal obligation unsatisfied: {obligation['obligation_id']}")
            continue

        if observed_at is not None:
            max_age = obligation["maximum_evidence_age_hours"]
            fresh = False
            for proof in matches:
                completed = _parse_time(
                    proof.get("completed_at"),
                    f"proof {proof.get('proof_id')} completed_at",
                    errors,
                )
                if completed is None:
                    continue
                age_hours = (observed_at - completed).total_seconds() / 3600
                if 0 <= age_hours <= max_age:
                    fresh = True
                    break
            if not fresh:
                errors.append(f"formal obligation evidence is stale: {obligation['obligation_id']}")

    return sorted(set(errors))
