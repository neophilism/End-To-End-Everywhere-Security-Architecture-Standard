#!/usr/bin/env python3
"""Research profile registry validation for E2EESA PR 37."""

from __future__ import annotations

import canonical_serialization

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
EXP_TM_RE = re.compile(r"^EXP-TM-[A-Z0-9-]+$")
EXP_SP_RE = re.compile(r"^EXP-SP-[A-Z0-9-]+$")
EXP_COMP_RE = re.compile(r"^EXP-COMP-[A-Z0-9-]+$")

RESEARCH_KINDS = {
    "protocol-profile",
    "algorithm-composition",
    "implementation-technique",
    "evidence-study",
    "verification-method",
}
OUTCOMES = {"supported", "refuted", "inconclusive", "error"}
REPLICATION = {"none", "internal", "independent"}
VECTOR_STATUS = {"generated", "internally-verified", "independently-verified"}
IMPLEMENTATION_MATURITY = {"concept", "prototype", "reference", "independent"}


def canonical_bytes(value: object) -> bytes:
    return canonical_serialization.canonical_bytes(value)


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def entry_core(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key != "entry_digest"}


def compute_entry_digest(entry: dict[str, Any]) -> str:
    return canonical_digest(entry_core(entry))


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _digest(value: object, field: str, errors: list[str], *, nullable: bool=False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        errors.append(f"{field} must be sha256")
        return None
    return value


def _unique_strings(value: object, field: str, errors: list[str], *, nonempty: bool=False) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{field} must be an array")
        return []
    if nonempty and not value:
        errors.append(f"{field} must be non-empty")
    if any(not isinstance(item, str) or not item for item in value):
        errors.append(f"{field} must contain non-empty strings")
        return []
    if len(value) != len(set(value)):
        errors.append(f"{field} must contain unique values")
    if value != sorted(value):
        errors.append(f"{field} must be lexically sorted")
    return [item for item in value if isinstance(item, str)]


def _unique_object_map(
    value: object,
    id_field: str,
    field: str,
    errors: list[str],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(value, list):
        errors.append(f"{field} must be an array")
        return result
    for index, item in enumerate(value):
        prefix=f"{field}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        item_id=item.get(id_field)
        if not isinstance(item_id, str) or not item_id:
            errors.append(f"{prefix}.{id_field} must be non-empty")
        elif item_id in result:
            errors.append(f"{field} duplicate {id_field} {item_id}")
        else:
            result[item_id]=item
    return result


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("research registry schema_version must be 0.1")
    if registry.get("lifecycle_statuses") != ["experimental"]:
        errors.append("research registry lifecycle_statuses must be exactly [experimental]")
    for field, expected in (
        ("research_kinds", RESEARCH_KINDS),
        ("experiment_outcomes", OUTCOMES),
        ("replication_statuses", REPLICATION),
        ("vector_verification_statuses", VECTOR_STATUS),
        ("implementation_maturities", IMPLEMENTATION_MATURITY),
    ):
        values=registry.get(field)
        if not isinstance(values, list) or set(values) != expected or len(values) != len(expected):
            errors.append(f"research registry {field} does not match supported values")

    entries=registry.get("entries")
    if not isinstance(entries, list):
        errors.append("research registry entries must be an array")
        return sorted(set(errors))
    seen: set[tuple[str,str]] = set()
    for index,item in enumerate(entries):
        prefix=f"research registry entries[{index}]"
        if not isinstance(item,dict):
            errors.append(f"{prefix} must be an object")
            continue
        key=(item.get("entry_id"),item.get("entry_version"))
        if key in seen:
            errors.append(f"{prefix} duplicate entry/version {key}")
        seen.add(key)
        if item.get("lifecycle_status")!="experimental":
            errors.append(f"{prefix} lifecycle_status must be experimental")
        if item.get("production_selectable") is not False:
            errors.append(f"{prefix} production_selectable must be false")
        if item.get("research_kind") not in RESEARCH_KINDS:
            errors.append(f"{prefix} invalid research_kind")
        _digest(item.get("entry_digest"),f"{prefix}.entry_digest",errors)
        _parse_time(item.get("updated_at"),f"{prefix}.updated_at",errors)
    return sorted(set(errors))


def _registered_ids(
    threat_registry: dict[str, Any],
    property_registry: dict[str, Any],
    algorithm_registry: dict[str, Any],
) -> tuple[set[str], set[str], set[str], set[str]]:
    threats={
        item["id"] for item in threat_registry.get("threats",[])
        if isinstance(item,dict) and isinstance(item.get("id"),str)
    }
    scenarios={
        item["id"] for item in threat_registry.get("composite_scenarios",[])
        if isinstance(item,dict) and isinstance(item.get("id"),str)
    }
    properties={
        item["id"] for item in property_registry.get("properties",[])
        if isinstance(item,dict) and isinstance(item.get("id"),str)
    }
    algorithms={
        item["id"] for item in algorithm_registry.get("algorithms",[])
        if isinstance(item,dict) and isinstance(item.get("id"),str)
    }
    return threats,scenarios,properties,algorithms


def validate_entry(
    entry: dict[str, Any],
    registry: dict[str, Any],
    threat_registry: dict[str, Any],
    property_registry: dict[str, Any],
    algorithm_registry: dict[str, Any],
    *,
    known_evidence_bundle_digests: Iterable[str] | None = None,
) -> list[str]:
    errors=validate_registry(registry)

    if entry.get("schema_version")!="0.1":
        errors.append("research entry schema_version must be 0.1")
    if entry.get("lifecycle_status")!="experimental":
        errors.append("research entry lifecycle_status must be experimental")
    if entry.get("production_selectable") is not False:
        errors.append("research entry production_selectable must be false")
    if entry.get("research_kind") not in RESEARCH_KINDS:
        errors.append(f"research entry has invalid research_kind {entry.get('research_kind')}")

    entry_id=entry.get("entry_id")
    if not isinstance(entry_id,str) or not entry_id:
        errors.append("research entry_id must be non-empty")
    version=entry.get("entry_version")
    if not isinstance(version,str) or SEMVER_RE.fullmatch(version) is None:
        errors.append("research entry_version must be semantic version")

    revision=entry.get("revision")
    previous=entry.get("previous_entry_digest")
    if not isinstance(revision,int) or isinstance(revision,bool) or revision<1:
        errors.append("research revision must be positive integer")
    elif revision==1 and previous is not None:
        errors.append("research revision 1 must have null previous_entry_digest")
    elif revision>1:
        _digest(previous,"research previous_entry_digest",errors)

    created=_parse_time(entry.get("created_at"),"research created_at",errors)
    updated=_parse_time(entry.get("updated_at"),"research updated_at",errors)
    if created is not None and updated is not None and updated<created:
        errors.append("research updated_at must not precede created_at")

    target=entry.get("target")
    if not isinstance(target,dict):
        errors.append("research target must be an object")
    else:
        for field in ("family_id","profile_id","intended_version"):
            if not isinstance(target.get(field),str) or not target[field]:
                errors.append(f"research target.{field} must be non-empty")
        intended=target.get("intended_version")
        if isinstance(intended,str) and SEMVER_RE.fullmatch(intended) is None:
            errors.append("research target intended_version must be semantic version")

    provenance=_unique_strings(
        entry.get("provenance_evidence_bundle_digests"),
        "provenance_evidence_bundle_digests",
        errors,
        nonempty=True,
    )
    for index,digest in enumerate(provenance):
        _digest(digest,f"provenance_evidence_bundle_digests[{index}]",errors)
    if known_evidence_bundle_digests is not None:
        known=set(known_evidence_bundle_digests)
        missing=sorted(set(provenance)-known)
        if missing:
            errors.append(
                "research provenance references unknown evidence bundles: "
                + ", ".join(missing)
            )

    design=entry.get("design_spec")
    if not isinstance(design,dict):
        errors.append("research design_spec must be an object")
    else:
        _digest(design.get("digest"),"research design_spec.digest",errors)
        if not isinstance(design.get("reference"),str) or not design["reference"]:
            errors.append("research design_spec.reference must be non-empty")

    registered_threats,registered_scenarios,registered_properties,registered_algorithms=(
        _registered_ids(threat_registry,property_registry,algorithm_registry)
    )

    threat_model=entry.get("threat_model")
    exp_threats: dict[str,dict[str,Any]]={}
    if not isinstance(threat_model,dict):
        errors.append("research threat_model must be an object")
    else:
        threat_ids=_unique_strings(
            threat_model.get("registered_threat_ids"),
            "research registered_threat_ids",
            errors,
            nonempty=True,
        )
        unknown=sorted(set(threat_ids)-registered_threats)
        if unknown:
            errors.append("research references unknown registered threats: "+", ".join(unknown))
        scenario_ids=_unique_strings(
            threat_model.get("composite_scenario_ids"),
            "research composite_scenario_ids",
            errors,
        )
        unknown=sorted(set(scenario_ids)-registered_scenarios)
        if unknown:
            errors.append("research references unknown composite scenarios: "+", ".join(unknown))
        exp_threats=_unique_object_map(
            threat_model.get("experimental_threats"),"id","experimental_threats",errors
        )
        for threat_id,item in exp_threats.items():
            if EXP_TM_RE.fullmatch(threat_id) is None:
                errors.append(f"experimental threat id must use EXP-TM- namespace: {threat_id}")
            for field in ("name","description"):
                if not isinstance(item.get(field),str) or not item[field]:
                    errors.append(f"experimental threat {threat_id} {field} must be non-empty")
            _unique_strings(item.get("capabilities"),f"experimental threat {threat_id} capabilities",errors,nonempty=True)

    security=entry.get("security_properties")
    exp_properties: dict[str,dict[str,Any]]={}
    property_ids: list[str]=[]
    if not isinstance(security,dict):
        errors.append("research security_properties must be an object")
    else:
        property_ids=_unique_strings(
            security.get("registered_property_ids"),
            "research registered_property_ids",
            errors,
            nonempty=True,
        )
        unknown=sorted(set(property_ids)-registered_properties)
        if unknown:
            errors.append("research references unknown registered properties: "+", ".join(unknown))
        exp_properties=_unique_object_map(
            security.get("experimental_properties"),"id","experimental_properties",errors
        )
        for property_id,item in exp_properties.items():
            if EXP_SP_RE.fullmatch(property_id) is None:
                errors.append(
                    f"experimental property id must use EXP-SP- namespace: {property_id}"
                )
            for field in ("name","definition"):
                if not isinstance(item.get(field),str) or not item[field]:
                    errors.append(f"experimental property {property_id} {field} must be non-empty")

    algorithm_ids=_unique_strings(
        entry.get("cryptographic_algorithm_ids"),
        "cryptographic_algorithm_ids",
        errors,
    )
    unknown=sorted(set(algorithm_ids)-registered_algorithms)
    if unknown:
        errors.append("research references unknown registered algorithms: "+", ".join(unknown))

    exp_components=_unique_object_map(
        entry.get("experimental_components"),"id","experimental_components",errors
    )
    for component_id,item in exp_components.items():
        if EXP_COMP_RE.fullmatch(component_id) is None:
            errors.append(
                f"experimental component id must use EXP-COMP- namespace: {component_id}"
            )
        for field in ("name","category","reference"):
            if not isinstance(item.get(field),str) or not item[field]:
                errors.append(f"experimental component {component_id} {field} must be non-empty")
        _digest(
            item.get("specification_digest"),
            f"experimental component {component_id} specification_digest",
            errors,
        )

    all_property_ids=set(property_ids)|set(exp_properties)
    hypotheses=_unique_object_map(
        entry.get("hypotheses"),"hypothesis_id","hypotheses",errors
    )
    if not hypotheses:
        errors.append("research entry requires at least one hypothesis")
    for hypothesis_id,item in hypotheses.items():
        for field in ("statement","criterion"):
            if not isinstance(item.get(field),str) or not item[field]:
                errors.append(f"hypothesis {hypothesis_id} {field} must be non-empty")
        targets=_unique_strings(
            item.get("target_property_ids"),
            f"hypothesis {hypothesis_id} target_property_ids",
            errors,
            nonempty=True,
        )
        unknown=sorted(set(targets)-all_property_ids)
        if unknown:
            errors.append(
                f"hypothesis {hypothesis_id} references unknown properties: "
                + ", ".join(unknown)
            )

    vectors=_unique_object_map(entry.get("test_vectors"),"vector_id","test_vectors",errors)
    for vector_id,item in vectors.items():
        for field in ("purpose","media_type","reference"):
            if not isinstance(item.get(field),str) or not item[field]:
                errors.append(f"test vector {vector_id} {field} must be non-empty")
        _digest(item.get("artifact_digest"),f"test vector {vector_id} artifact_digest",errors)
        status=item.get("verification_status")
        if status not in VECTOR_STATUS:
            errors.append(f"test vector {vector_id} invalid verification_status {status}")
        verification_digest=_digest(
            item.get("verification_evidence_digest"),
            f"test vector {vector_id} verification_evidence_digest",
            errors,
            nullable=True,
        )
        verification_ref=item.get("verification_reference")
        if status in {"internally-verified","independently-verified"}:
            if verification_digest is None:
                errors.append(f"verified test vector {vector_id} requires verification evidence digest")
            if not isinstance(verification_ref,str) or not verification_ref:
                errors.append(f"verified test vector {vector_id} requires verification reference")
        elif status=="generated" and (
            item.get("verification_evidence_digest") is not None
            or item.get("verification_reference") is not None
        ):
            errors.append(f"generated-only test vector {vector_id} must not claim verification evidence")

    implementations=_unique_object_map(
        entry.get("implementations"),"implementation_id","implementations",errors
    )
    for implementation_id,item in implementations.items():
        maturity=item.get("maturity")
        if maturity not in IMPLEMENTATION_MATURITY:
            errors.append(f"implementation {implementation_id} invalid maturity {maturity}")
        if item.get("production_use_prohibited") is not True:
            errors.append(f"implementation {implementation_id} must prohibit production use")
        limitations=_unique_strings(
            item.get("limitations"),
            f"implementation {implementation_id} limitations",
            errors,
            nonempty=True,
        )
        if maturity!="concept":
            for field in ("source_reference","language_runtime","build_reference"):
                if not isinstance(item.get(field),str) or not item[field]:
                    errors.append(f"implementation {implementation_id} {field} must be non-empty")
            _digest(
                item.get("source_digest"),
                f"implementation {implementation_id} source_digest",
                errors,
            )
        else:
            if item.get("source_digest") is not None:
                _digest(
                    item.get("source_digest"),
                    f"implementation {implementation_id} source_digest",
                    errors,
                )

    experiments=_unique_object_map(
        entry.get("experiments"),"experiment_id","experiments",errors
    )
    if not experiments:
        errors.append("research entry requires at least one experiment")
    for experiment_id,item in experiments.items():
        hypothesis_ids=_unique_strings(
            item.get("hypothesis_ids"),
            f"experiment {experiment_id} hypothesis_ids",
            errors,
            nonempty=True,
        )
        unknown=sorted(set(hypothesis_ids)-set(hypotheses))
        if unknown:
            errors.append(
                f"experiment {experiment_id} references unknown hypotheses: "
                + ", ".join(unknown)
            )
        vector_ids=_unique_strings(
            item.get("test_vector_ids"),
            f"experiment {experiment_id} test_vector_ids",
            errors,
        )
        unknown=sorted(set(vector_ids)-set(vectors))
        if unknown:
            errors.append(
                f"experiment {experiment_id} references unknown test vectors: "
                + ", ".join(unknown)
            )
        implementation_ids=_unique_strings(
            item.get("implementation_ids"),
            f"experiment {experiment_id} implementation_ids",
            errors,
        )
        unknown=sorted(set(implementation_ids)-set(implementations))
        if unknown:
            errors.append(
                f"experiment {experiment_id} references unknown implementations: "
                + ", ".join(unknown)
            )
        for field in ("methodology_digest","environment_digest","result_digest"):
            _digest(item.get(field),f"experiment {experiment_id} {field}",errors)
        for field in ("methodology_reference","environment_reference","result_reference"):
            if not isinstance(item.get(field),str) or not item[field]:
                errors.append(f"experiment {experiment_id} {field} must be non-empty")
        if item.get("outcome") not in OUTCOMES:
            errors.append(f"experiment {experiment_id} invalid outcome {item.get('outcome')}")
        executed=_parse_time(item.get("executed_at"),f"experiment {experiment_id} executed_at",errors)
        if executed is not None and updated is not None and executed>updated:
            errors.append(f"experiment {experiment_id} execution postdates entry update")
        replication=item.get("replication_status")
        if replication not in REPLICATION:
            errors.append(
                f"experiment {experiment_id} invalid replication_status {replication}"
            )
        replication_digest=_digest(
            item.get("replication_evidence_digest"),
            f"experiment {experiment_id} replication_evidence_digest",
            errors,
            nullable=True,
        )
        replication_ref=item.get("replication_reference")
        if replication in {"internal","independent"}:
            if replication_digest is None:
                errors.append(
                    f"{replication} replication for experiment {experiment_id} requires evidence digest"
                )
            if not isinstance(replication_ref,str) or not replication_ref:
                errors.append(
                    f"{replication} replication for experiment {experiment_id} requires reference"
                )
        elif replication=="none" and (
            item.get("replication_evidence_digest") is not None
            or item.get("replication_reference") is not None
        ):
            errors.append(
                f"unreplicated experiment {experiment_id} must not claim replication evidence"
            )

    evidence=entry.get("evidence")
    if not isinstance(evidence,dict):
        errors.append("research evidence must be an object")
    else:
        for field in (
            "review_evidence_digests",
            "formal_evidence_digests",
            "interoperability_evidence_digests",
            "benchmark_evidence_digests",
        ):
            digests=_unique_strings(evidence.get(field),f"research evidence.{field}",errors)
            for index,digest in enumerate(digests):
                _digest(digest,f"research evidence.{field}[{index}]",errors)

    _unique_strings(entry.get("limitations"),"research limitations",errors,nonempty=True)
    _unique_strings(entry.get("open_questions"),"research open_questions",errors)
    if not isinstance(entry.get("reproduction_ref"),str) or not entry["reproduction_ref"]:
        errors.append("research reproduction_ref must be non-empty")

    if entry.get("entry_digest") != compute_entry_digest(entry):
        errors.append("research entry_digest does not match canonical entry")

    return sorted(set(errors))


def index_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "entry_id": entry["entry_id"],
        "entry_version": entry["entry_version"],
        "entry_digest": entry["entry_digest"],
        "lifecycle_status": entry["lifecycle_status"],
        "research_kind": entry["research_kind"],
        "target_family_id": entry["target"]["family_id"],
        "target_profile_id": entry["target"]["profile_id"],
        "updated_at": entry["updated_at"],
        "production_selectable": entry["production_selectable"],
    }


def validate_index(
    registry: dict[str, Any],
    entries: Iterable[dict[str, Any]],
) -> list[str]:
    errors=validate_registry(registry)
    expected={
        (entry["entry_id"],entry["entry_version"]):index_entry(entry)
        for entry in entries
    }
    actual={
        (item.get("entry_id"),item.get("entry_version")):item
        for item in registry.get("entries",[])
        if isinstance(item,dict)
    }
    if set(actual)!=set(expected):
        errors.append("research registry index entry set differs from supplied entries")
    for key,expected_item in expected.items():
        actual_item=actual.get(key)
        if actual_item is not None and actual_item!=expected_item:
            errors.append(f"research registry index metadata mismatch for {key[0]}@{key[1]}")
    return sorted(set(errors))


def validate_revision_chain(
    current: dict[str, Any],
    previous: dict[str, Any],
    registry: dict[str, Any],
    threat_registry: dict[str, Any],
    property_registry: dict[str, Any],
    algorithm_registry: dict[str, Any],
    *,
    known_evidence_bundle_digests: Iterable[str] | None = None,
) -> list[str]:
    errors=[
        "current: "+error for error in validate_entry(
            current,registry,threat_registry,property_registry,algorithm_registry,
            known_evidence_bundle_digests=known_evidence_bundle_digests,
        )
    ]+[
        "previous: "+error for error in validate_entry(
            previous,registry,threat_registry,property_registry,algorithm_registry,
            known_evidence_bundle_digests=known_evidence_bundle_digests,
        )
    ]
    if current.get("entry_id")!=previous.get("entry_id"):
        errors.append("research revision entry_id mismatch")
    if current.get("entry_version")!=previous.get("entry_version"):
        errors.append("research revision entry_version mismatch")
    if current.get("revision")!=previous.get("revision",0)+1:
        errors.append("research revision must increment by exactly one")
    if current.get("previous_entry_digest")!=previous.get("entry_digest"):
        errors.append("research revision previous_entry_digest mismatch")
    if current.get("target")!=previous.get("target"):
        errors.append("research revision target identity mismatch")
    current_time=_parse_time(current.get("updated_at"),"current.updated_at",errors)
    previous_time=_parse_time(previous.get("updated_at"),"previous.updated_at",errors)
    if current_time is not None and previous_time is not None and current_time<previous_time:
        errors.append("research revision update time regresses")
    return sorted(set(errors))
