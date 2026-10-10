#!/usr/bin/env python3
"""Research-to-production promotion gates for E2EESA PR 38."""

from __future__ import annotations

import canonical_serialization

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import profile_engine
import research_profile_registry

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PROFILE_REF_RE = re.compile(
    r"^(?P<profile_id>[a-z0-9]+(?:-[a-z0-9]+)*)@"
    r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$"
)

STATES = ("experimental", "candidate", "recommended", "required")
TRANSITIONS = {
    ("experimental", "candidate"),
    ("candidate", "recommended"),
    ("recommended", "required"),
}
EVIDENCE_TYPES = {
    "implementation-provenance",
    "independent-security-review",
    "independent-replication",
    "interoperability",
    "formal-verification",
    "test-vector-verification",
    "operational-deployment",
    "public-review",
    "recognized-external-standard",
    "benchmark-evaluation",
}
SEVERITIES = ("informational", "low", "medium", "high", "critical", "blocker")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass
class PromotionResult:
    valid: bool
    eligible: bool
    source_state: str | None
    target_state: str | None
    gate_profile_ref: str | None
    profile_ref: str | None
    errors: list[str] = field(default_factory=list)
    gate_failures: list[str] = field(default_factory=list)
    projected_catalog: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "eligible": self.eligible,
            "source_state": self.source_state,
            "target_state": self.target_state,
            "gate_profile_ref": self.gate_profile_ref,
            "profile_ref": self.profile_ref,
            "errors": self.errors,
            "gate_failures": self.gate_failures,
            "projected_catalog": self.projected_catalog,
        }


def canonical_bytes(value: object) -> bytes:
    return canonical_serialization.canonical_bytes(value)


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def promotion_record_core(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key != "promotion_record_digest"
    }


def compute_promotion_record_digest(record: dict[str, Any]) -> str:
    return canonical_digest(promotion_record_core(record))


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _digest(
    value: object,
    field: str,
    errors: list[str],
    *,
    nullable: bool = False,
) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        errors.append(f"{field} must be sha256")
        return None
    return value


def _profile_ref(profile: dict[str, Any]) -> str:
    return f"{profile.get('profile_id')}@{profile.get('profile_version')}"


def _gate_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["profile_ref"]: item
        for item in registry.get("gate_profiles", [])
        if isinstance(item, dict) and isinstance(item.get("profile_ref"), str)
    }


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("research promotion registry schema_version must be 0.1")
    if registry.get("states") != list(STATES):
        errors.append(
            "research promotion states must be experimental, candidate, recommended, required"
        )

    transitions = registry.get("transitions")
    actual_transitions: set[tuple[str, str]] = set()
    if not isinstance(transitions, list):
        errors.append("research promotion transitions must be an array")
    else:
        for index, item in enumerate(transitions):
            if not isinstance(item, dict):
                errors.append(f"research promotion transitions[{index}] must be an object")
                continue
            pair = (item.get("from"), item.get("to"))
            if pair in actual_transitions:
                errors.append(f"duplicate promotion transition {pair}")
            actual_transitions.add(pair)
    if actual_transitions != TRANSITIONS:
        errors.append("research promotion transition set is invalid")

    profiles = registry.get("gate_profiles")
    if not isinstance(profiles, list) or not profiles:
        errors.append("research promotion gate_profiles must be non-empty")
        profiles = []

    seen_refs: set[str] = set()
    target_paths: dict[str, set[str]] = {
        "candidate": set(),
        "recommended": set(),
        "required": set(),
    }
    numeric_fields = {
        "minimum_nonconcept_implementations",
        "minimum_distinct_implementation_orgs",
        "minimum_independent_security_reviews",
        "minimum_independent_replications",
        "minimum_interoperability_evidence",
        "minimum_formal_verification_evidence",
        "minimum_operational_deployments",
        "minimum_distinct_deployment_orgs",
        "minimum_recognized_external_standards",
        "minimum_public_review_days",
        "minimum_independently_verified_vectors",
        "minimum_approvers",
        "minimum_independent_approver_orgs",
        "minimum_prior_state_days",
    }

    for index, profile in enumerate(profiles):
        prefix = f"research promotion gate_profiles[{index}]"
        if not isinstance(profile, dict):
            errors.append(f"{prefix} must be an object")
            continue
        ref = profile.get("profile_ref")
        if not isinstance(ref, str) or not ref.startswith("promotion-") or "@" not in ref:
            errors.append(f"{prefix} invalid profile_ref")
        elif ref in seen_refs:
            errors.append(f"{prefix} duplicate profile_ref {ref}")
        else:
            seen_refs.add(ref)

        target = profile.get("target_state")
        path = profile.get("path")
        if target not in {"candidate", "recommended", "required"}:
            errors.append(f"{prefix} invalid target_state")
        elif not isinstance(path, str) or not path:
            errors.append(f"{prefix} path must be non-empty")
        elif path in target_paths[target]:
            errors.append(f"{prefix} duplicate path {path} for {target}")
        else:
            target_paths[target].add(path)

        for field_name in numeric_fields:
            value = profile.get(field_name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                errors.append(f"{prefix} {field_name} must be a non-negative integer")

        if profile.get("minimum_approvers", 0) < 1:
            errors.append(f"{prefix} minimum_approvers must be at least 1")
        if (
            isinstance(profile.get("minimum_distinct_implementation_orgs"), int)
            and isinstance(profile.get("minimum_nonconcept_implementations"), int)
            and profile["minimum_distinct_implementation_orgs"]
            > profile["minimum_nonconcept_implementations"]
        ):
            errors.append(
                f"{prefix} distinct implementation organizations exceed implementation count"
            )
        if (
            isinstance(profile.get("minimum_distinct_deployment_orgs"), int)
            and isinstance(profile.get("minimum_operational_deployments"), int)
            and profile["minimum_distinct_deployment_orgs"]
            > profile["minimum_operational_deployments"]
        ):
            errors.append(
                f"{prefix} distinct deployment organizations exceed deployment count"
            )
        if (
            isinstance(profile.get("minimum_independent_approver_orgs"), int)
            and isinstance(profile.get("minimum_approvers"), int)
            and profile["minimum_independent_approver_orgs"]
            > profile["minimum_approvers"]
        ):
            errors.append(
                f"{prefix} independent approver organizations exceed approver count"
            )
        for flag in (
            "allow_open_high_findings",
            "allow_accepted_high_findings",
            "allow_accepted_critical_findings",
        ):
            if not isinstance(profile.get(flag), bool):
                errors.append(f"{prefix} {flag} must be boolean")

    if target_paths["candidate"] != {"candidate-baseline"}:
        errors.append("candidate must expose exactly the candidate-baseline path")
    if target_paths["recommended"] != {
        "implementation-led",
        "formal-assurance-led",
        "external-standard-led",
    }:
        errors.append("recommended promotion paths do not match E2EESA 0.1")
    if target_paths["required"] != {
        "operational-maturity",
        "standards-and-deployment",
    }:
        errors.append("required promotion paths do not match E2EESA 0.1")

    promoted = registry.get("promoted_profiles")
    if not isinstance(promoted, list):
        errors.append("research promotion promoted_profiles must be an array")
        promoted = []
    seen_promoted: set[str] = set()
    for index, item in enumerate(promoted):
        prefix = f"research promotion promoted_profiles[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        ref = item.get("profile_ref")
        if not isinstance(ref, str) or PROFILE_REF_RE.fullmatch(ref) is None:
            errors.append(f"{prefix} invalid profile_ref")
        elif ref in seen_promoted:
            errors.append(f"{prefix} duplicate profile_ref {ref}")
        else:
            seen_promoted.add(ref)
        if item.get("lifecycle_state") not in {"candidate", "recommended", "required"}:
            errors.append(f"{prefix} invalid lifecycle_state")
        _digest(item.get("research_entry_digest"), f"{prefix}.research_entry_digest", errors)
        _digest(item.get("promotion_record_digest"), f"{prefix}.promotion_record_digest", errors)
        _parse_time(item.get("effective_at"), f"{prefix}.effective_at", errors)
        gate_ref = item.get("gate_profile_ref")
        if gate_ref not in seen_refs:
            errors.append(f"{prefix} references unknown gate_profile_ref {gate_ref}")

    return sorted(set(errors))


def _validate_target_catalog(
    record: dict[str, Any],
    catalog: dict[str, Any],
    known_property_ids: set[str],
    errors: list[str],
) -> dict[str, Any] | None:
    target = record.get("target_profile")
    if not isinstance(target, dict):
        errors.append("promotion target_profile must be an object")
        return None

    source_target = record.get("_source_target")
    if not isinstance(source_target, dict):
        errors.append("internal promotion validation missing research target")
        return None

    if target.get("family_id") != source_target.get("family_id"):
        errors.append("promotion target profile family_id differs from research target")
    if target.get("profile_id") != source_target.get("profile_id"):
        errors.append("promotion target profile_id differs from research target")
    if target.get("profile_version") != source_target.get("intended_version"):
        errors.append("promotion target profile_version differs from research intended_version")

    state = record.get("target_state")
    expected_status = "provisional" if state == "candidate" else "recommended"
    if target.get("status") != expected_status:
        errors.append(
            f"{state} promotion target profile status must be {expected_status}"
        )
    if target.get("decision_class") == "experimental":
        errors.append("promoted production profile decision_class must not be experimental")

    projected = copy.deepcopy(catalog)
    families = projected.get("families", [])
    existing_family = next(
        (
            item
            for item in families
            if isinstance(item, dict)
            and item.get("family_id") == target.get("family_id")
        ),
        None,
    )
    family_definition = record.get("target_family_definition")
    if existing_family is None:
        if not isinstance(family_definition, dict):
            errors.append(
                "promotion of a profile in a new family requires target_family_definition"
            )
        else:
            if family_definition.get("family_id") != target.get("family_id"):
                errors.append("target_family_definition family_id mismatch")
            projected.setdefault("families", []).append(copy.deepcopy(family_definition))
    elif family_definition is not None and family_definition != existing_family:
        errors.append(
            "target_family_definition must be null or exactly match existing family"
        )

    target_ref = _profile_ref(target)
    profiles = projected.get("profiles", [])
    existing_index = next(
        (
            index
            for index, item in enumerate(profiles)
            if isinstance(item, dict) and _profile_ref(item) == target_ref
        ),
        None,
    )
    if existing_index is None:
        profiles.append(copy.deepcopy(target))
    else:
        prior = profiles[existing_index]
        if record.get("source_state") == "experimental":
            if prior != target:
                errors.append(
                    "candidate target profile already exists in catalog with different content"
                )
        else:
            profiles[existing_index] = copy.deepcopy(target)

    catalog_errors = profile_engine.validate_catalog(
        projected, known_property_ids=known_property_ids
    )
    errors.extend("projected catalog: " + error for error in catalog_errors)
    return projected


def _validate_reconciliation(
    record: dict[str, Any],
    research_entry: dict[str, Any],
    threat_registry: dict[str, Any],
    property_registry: dict[str, Any],
    algorithm_registry: dict[str, Any],
    catalog: dict[str, Any],
    errors: list[str],
) -> None:
    source_ids: dict[str, set[str]] = {
        "threat": {
            item["id"]
            for item in research_entry.get("threat_model", {}).get(
                "experimental_threats", []
            )
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        },
        "security-property": {
            item["id"]
            for item in research_entry.get("security_properties", {}).get(
                "experimental_properties", []
            )
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        },
        "component": {
            item["id"]
            for item in research_entry.get("experimental_components", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        },
    }
    reconciliations = record.get("reconciliation")
    if not isinstance(reconciliations, list):
        errors.append("promotion reconciliation must be an array")
        return

    seen: set[tuple[str, str]] = set()
    threat_ids = {
        item.get("id")
        for item in threat_registry.get("threats", [])
        if isinstance(item, dict)
    }
    property_ids = {
        item.get("id")
        for item in property_registry.get("properties", [])
        if isinstance(item, dict)
    }
    algorithm_ids = {
        item.get("id")
        for item in algorithm_registry.get("algorithms", [])
        if isinstance(item, dict)
    }
    profile_refs = {
        _profile_ref(item)
        for item in catalog.get("profiles", [])
        if isinstance(item, dict)
    }
    target_profile = record.get("target_profile")
    if isinstance(target_profile, dict):
        profile_refs.add(_profile_ref(target_profile))

    for index, item in enumerate(reconciliations):
        prefix = f"promotion reconciliation[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        kind = item.get("kind")
        experimental_id = item.get("experimental_id")
        key = (kind, experimental_id)
        if key in seen:
            errors.append(f"{prefix} duplicate reconciliation {key}")
        seen.add(key)
        if kind not in source_ids:
            errors.append(f"{prefix} invalid kind {kind}")
            continue
        if experimental_id not in source_ids[kind]:
            errors.append(
                f"{prefix} {experimental_id} is not present in source research entry"
            )
        disposition = item.get("disposition")
        production_id = item.get("production_id")
        rationale = item.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"{prefix} rationale must be non-empty")
        if disposition == "retired":
            if production_id is not None:
                errors.append(f"{prefix} retired reconciliation must have null production_id")
        elif disposition in {"promoted", "superseded"}:
            if not isinstance(production_id, str) or not production_id:
                errors.append(
                    f"{prefix} {disposition} reconciliation requires production_id"
                )
            else:
                if kind == "threat" and production_id not in threat_ids:
                    errors.append(f"{prefix} production threat ID is unknown")
                elif kind == "security-property" and production_id not in property_ids:
                    errors.append(f"{prefix} production security property ID is unknown")
                elif (
                    kind == "component"
                    and production_id not in algorithm_ids
                    and production_id not in profile_refs
                ):
                    errors.append(
                        f"{prefix} production component must map to registered algorithm or profile"
                    )
        else:
            errors.append(f"{prefix} invalid disposition {disposition}")

    expected = {
        (kind, item_id)
        for kind, values in source_ids.items()
        for item_id in values
    }
    if seen != expected:
        missing = sorted(expected - seen)
        extra = sorted(seen - expected)
        if missing:
            errors.append(
                "promotion reconciliation is missing experimental identifiers: "
                + ", ".join(f"{kind}:{item_id}" for kind, item_id in missing)
            )
        if extra:
            errors.append(
                "promotion reconciliation contains unexpected identifiers: "
                + ", ".join(f"{kind}:{item_id}" for kind, item_id in extra)
            )

    target_props = set(
        record.get("target_profile", {}).get("security_properties", [])
        if isinstance(record.get("target_profile"), dict)
        else []
    )
    source_registered = set(
        research_entry.get("security_properties", {}).get(
            "registered_property_ids", []
        )
    )
    reconciled_properties = {
        item.get("production_id")
        for item in reconciliations
        if isinstance(item, dict)
        and item.get("kind") == "security-property"
        and item.get("disposition") in {"promoted", "superseded"}
        and isinstance(item.get("production_id"), str)
    }
    unsupported = sorted(target_props - source_registered - reconciled_properties)
    if unsupported:
        errors.append(
            "promotion target profile claims security properties not studied/reconciled: "
            + ", ".join(unsupported)
        )


def _latest_hypothesis_outcomes(
    research_entry: dict[str, Any],
) -> dict[str, tuple[datetime, str]]:
    latest: dict[str, tuple[datetime, str]] = {}
    for experiment in research_entry.get("experiments", []):
        if not isinstance(experiment, dict):
            continue
        try:
            executed = datetime.strptime(
                experiment.get("executed_at"), "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        outcome = experiment.get("outcome")
        for hypothesis_id in experiment.get("hypothesis_ids", []):
            prior = latest.get(hypothesis_id)
            if prior is None or executed > prior[0]:
                latest[hypothesis_id] = (executed, outcome)
    return latest


def _validate_hypotheses(
    record: dict[str, Any],
    research_entry: dict[str, Any],
    errors: list[str],
    gate_failures: list[str],
) -> None:
    source_ids = {
        item.get("hypothesis_id")
        for item in research_entry.get("hypotheses", [])
        if isinstance(item, dict) and isinstance(item.get("hypothesis_id"), str)
    }
    dispositions = record.get("hypothesis_dispositions")
    if not isinstance(dispositions, list):
        errors.append("promotion hypothesis_dispositions must be an array")
        return

    seen: set[str] = set()
    latest = _latest_hypothesis_outcomes(research_entry)
    for index, item in enumerate(dispositions):
        prefix = f"promotion hypothesis_dispositions[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        hypothesis_id = item.get("hypothesis_id")
        if hypothesis_id in seen:
            errors.append(f"{prefix} duplicate hypothesis_id {hypothesis_id}")
        if isinstance(hypothesis_id, str):
            seen.add(hypothesis_id)
        if hypothesis_id not in source_ids:
            errors.append(f"{prefix} unknown source hypothesis {hypothesis_id}")
            continue
        role = item.get("promotion_role")
        if role not in {"promotion-critical", "non-blocking"}:
            errors.append(f"{prefix} invalid promotion_role")
            continue
        rationale = item.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"{prefix} rationale must be non-empty")
        latest_result = latest.get(hypothesis_id)
        if role == "promotion-critical":
            if latest_result is None:
                gate_failures.append(
                    f"promotion-critical hypothesis {hypothesis_id} has no experiment result"
                )
            elif latest_result[1] != "supported":
                gate_failures.append(
                    f"promotion-critical hypothesis {hypothesis_id} latest outcome is "
                    f"{latest_result[1]}, not supported"
                )
        elif latest_result is None or latest_result[1] != "supported":
            if not isinstance(rationale, str) or len(rationale.strip()) < 12:
                errors.append(
                    f"non-blocking unresolved hypothesis {hypothesis_id} requires substantive rationale"
                )

    if seen != source_ids:
        missing = sorted(source_ids - seen)
        extra = sorted(seen - source_ids)
        if missing:
            errors.append(
                "promotion hypothesis dispositions missing source hypotheses: "
                + ", ".join(missing)
            )
        if extra:
            errors.append(
                "promotion hypothesis dispositions contain unknown hypotheses: "
                + ", ".join(extra)
            )


def _validate_evidence(
    record: dict[str, Any],
    research_entry: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    evidence = record.get("evidence")
    if not isinstance(evidence, list):
        errors.append("promotion evidence must be an array")
        evidence = []

    submitter = record.get("submitter")
    submitter_org = (
        submitter.get("organization_id")
        if isinstance(submitter, dict)
        else None
    )
    requested_at_errors: list[str] = []
    requested_at = _parse_time(
        record.get("requested_at"), "promotion requested_at", requested_at_errors
    )
    errors.extend(requested_at_errors)

    seen_ids: set[str] = set()
    valid_items: list[dict[str, Any]] = []
    implementation_orgs: set[str] = set()
    implementation_ids: set[str] = set()
    review_orgs: set[str] = set()
    replication_orgs: set[str] = set()
    deployment_orgs: set[str] = set()
    independent_evidence_orgs: set[str] = set()
    interop_count = 0
    formal_items: list[dict[str, Any]] = []
    operational_count = 0
    standards_count = 0
    longest_public_review_days = 0

    source_implementations = {
        item.get("implementation_id"): item
        for item in research_entry.get("implementations", [])
        if isinstance(item, dict)
        and isinstance(item.get("implementation_id"), str)
    }
    source_experiments = {
        item.get("experiment_id"): item
        for item in research_entry.get("experiments", [])
        if isinstance(item, dict)
        and isinstance(item.get("experiment_id"), str)
    }

    for index, item in enumerate(evidence):
        prefix = f"promotion evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            errors.append(f"{prefix} evidence_id must be non-empty")
        elif evidence_id in seen_ids:
            errors.append(f"{prefix} duplicate evidence_id {evidence_id}")
        else:
            seen_ids.add(evidence_id)
        evidence_type = item.get("evidence_type")
        if evidence_type not in EVIDENCE_TYPES:
            errors.append(f"{prefix} invalid evidence_type {evidence_type}")
            continue
        if _digest(item.get("evidence_digest"), f"{prefix}.evidence_digest", errors) is None:
            continue
        if not isinstance(item.get("reference"), str) or not item["reference"]:
            errors.append(f"{prefix} reference must be non-empty")
        producer_org = item.get("producer_organization_id")
        if not isinstance(producer_org, str) or not producer_org:
            errors.append(f"{prefix} producer_organization_id must be non-empty")
            continue
        independent = item.get("independent_from_submitter")
        if not isinstance(independent, bool):
            errors.append(f"{prefix} independent_from_submitter must be boolean")
            continue
        if producer_org == submitter_org and independent:
            errors.append(
                f"{prefix} evidence from submitter organization cannot be independent"
            )
        if independent and producer_org != submitter_org:
            independent_evidence_orgs.add(producer_org)
        created_at = _parse_time(
            item.get("created_at"), f"{prefix}.created_at", errors
        )
        if (
            created_at is not None
            and requested_at is not None
            and created_at > requested_at
        ):
            errors.append(f"{prefix} evidence cannot postdate promotion request")

        details = item.get("details")
        if not isinstance(details, dict):
            errors.append(f"{prefix} details must be an object")
            continue

        if evidence_type == "implementation-provenance":
            implementation_id = details.get("implementation_id")
            source = source_implementations.get(implementation_id)
            if source is None:
                errors.append(
                    f"{prefix} references unknown research implementation {implementation_id}"
                )
            else:
                if source.get("maturity") == "concept":
                    errors.append(
                        f"{prefix} concept implementation cannot satisfy production promotion"
                    )
                if details.get("source_digest") != source.get("source_digest"):
                    errors.append(
                        f"{prefix} source_digest does not match research implementation"
                    )
                implementation_ids.add(implementation_id)
                implementation_orgs.add(producer_org)

        elif evidence_type == "independent-security-review":
            if not independent:
                errors.append(
                    f"{prefix} independent-security-review must be independent of submitter"
                )
            else:
                review_orgs.add(producer_org)
            if details.get("status") not in {"pass", "pass-with-findings"}:
                errors.append(
                    f"{prefix} security review status must be pass or pass-with-findings"
                )

        elif evidence_type == "independent-replication":
            if not independent:
                errors.append(
                    f"{prefix} independent-replication must be independent of submitter"
                )
            experiment_id = details.get("experiment_id")
            experiment = source_experiments.get(experiment_id)
            if experiment is None:
                errors.append(
                    f"{prefix} references unknown research experiment {experiment_id}"
                )
            else:
                if experiment.get("replication_status") != "independent":
                    errors.append(
                        f"{prefix} source research experiment is not independently replicated"
                    )
                if (
                    details.get("replication_evidence_digest")
                    != experiment.get("replication_evidence_digest")
                ):
                    errors.append(
                        f"{prefix} replication digest does not match research entry"
                    )
            if independent:
                replication_orgs.add(producer_org)

        elif evidence_type == "interoperability":
            implementation_refs = details.get("implementation_ids")
            if (
                not isinstance(implementation_refs, list)
                or len(implementation_refs) < 2
                or len(implementation_refs) != len(set(implementation_refs))
            ):
                errors.append(
                    f"{prefix} interoperability evidence requires at least two unique implementation_ids"
                )
            elif any(ref not in source_implementations for ref in implementation_refs):
                errors.append(
                    f"{prefix} interoperability evidence references unknown implementation"
                )
            else:
                interop_count += 1

        elif evidence_type == "formal-verification":
            covered = details.get("covered_property_ids")
            if (
                not isinstance(covered, list)
                or not covered
                or len(covered) != len(set(covered))
            ):
                errors.append(
                    f"{prefix} formal-verification requires unique non-empty covered_property_ids"
                )
            else:
                formal_items.append(item)

        elif evidence_type == "test-vector-verification":
            vector_id = details.get("vector_id")
            vectors = {
                item.get("vector_id"): item
                for item in research_entry.get("test_vectors", [])
                if isinstance(item, dict)
            }
            vector = vectors.get(vector_id)
            if vector is None:
                errors.append(f"{prefix} references unknown test vector {vector_id}")
            elif vector.get("verification_status") != "independently-verified":
                errors.append(
                    f"{prefix} research test vector is not independently verified"
                )

        elif evidence_type == "operational-deployment":
            if not isinstance(details.get("deployment_id"), str) or not details["deployment_id"]:
                errors.append(f"{prefix} deployment_id must be non-empty")
            else:
                operational_count += 1
                deployment_orgs.add(producer_org)

        elif evidence_type == "public-review":
            start = _parse_time(
                details.get("started_at"), f"{prefix}.details.started_at", errors
            )
            end = _parse_time(
                details.get("ended_at"), f"{prefix}.details.ended_at", errors
            )
            if start is not None and end is not None:
                if end < start:
                    errors.append(f"{prefix} public review ends before it starts")
                else:
                    days = (end - start).days
                    longest_public_review_days = max(
                        longest_public_review_days, days
                    )
            _digest(
                details.get("disposition_digest"),
                f"{prefix}.details.disposition_digest",
                errors,
            )
            if not isinstance(details.get("disposition_reference"), str) or not details["disposition_reference"]:
                errors.append(
                    f"{prefix} public review requires disposition_reference"
                )
            if not isinstance(details.get("public_review_reference"), str) or not details["public_review_reference"]:
                errors.append(
                    f"{prefix} public review requires public_review_reference"
                )

        elif evidence_type == "recognized-external-standard":
            if details.get("status") != "final":
                errors.append(
                    f"{prefix} recognized external standard must have final status"
                )
            for field_name in (
                "standards_body",
                "designation",
                "specification_reference",
            ):
                if not isinstance(details.get(field_name), str) or not details[field_name]:
                    errors.append(
                        f"{prefix} recognized standard {field_name} must be non-empty"
                    )
            if _digest(
                details.get("specification_digest"),
                f"{prefix}.details.specification_digest",
                errors,
            ) is not None and details.get("target_profile_ref") == _profile_ref(
                record.get("target_profile", {})
            ):
                standards_count += 1
            else:
                if details.get("target_profile_ref") != _profile_ref(
                    record.get("target_profile", {})
                ):
                    errors.append(
                        f"{prefix} recognized standard target_profile_ref mismatch"
                    )

        valid_items.append(item)

    independently_verified_vectors = sum(
        1
        for item in research_entry.get("test_vectors", [])
        if isinstance(item, dict)
        and item.get("verification_status") == "independently-verified"
        and isinstance(item.get("verification_evidence_digest"), str)
        and isinstance(item.get("verification_reference"), str)
        and item.get("verification_reference")
    )

    independent_replications = len(replication_orgs)
    independent_security_reviews = len(review_orgs)

    return {
        "items": valid_items,
        "implementation_count": len(implementation_ids),
        "implementation_org_count": len(implementation_orgs),
        "independent_security_reviews": independent_security_reviews,
        "independent_replications": independent_replications,
        "interoperability_count": interop_count,
        "formal_items": formal_items,
        "operational_count": operational_count,
        "deployment_org_count": len(deployment_orgs),
        "standards_count": standards_count,
        "longest_public_review_days": longest_public_review_days,
        "independently_verified_vectors": independently_verified_vectors,
        "independent_evidence_orgs": independent_evidence_orgs,
    }


def _validate_findings(
    record: dict[str, Any],
    gate: dict[str, Any],
    errors: list[str],
    gate_failures: list[str],
) -> None:
    findings = record.get("findings")
    if not isinstance(findings, list):
        errors.append("promotion findings must be an array")
        return
    seen: set[str] = set()
    for index, item in enumerate(findings):
        prefix = f"promotion findings[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        finding_id = item.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            errors.append(f"{prefix} finding_id must be non-empty")
        elif finding_id in seen:
            errors.append(f"{prefix} duplicate finding_id {finding_id}")
        else:
            seen.add(finding_id)
        severity = item.get("severity")
        status = item.get("status")
        if severity not in SEVERITY_RANK:
            errors.append(f"{prefix} invalid severity {severity}")
            continue
        if status not in {"open", "resolved", "accepted"}:
            errors.append(f"{prefix} invalid status {status}")
            continue
        if not isinstance(item.get("summary"), str) or not item["summary"].strip():
            errors.append(f"{prefix} summary must be non-empty")

        if status in {"resolved", "accepted"}:
            _digest(item.get("evidence_digest"), f"{prefix}.evidence_digest", errors)
            if not isinstance(item.get("reference"), str) or not item["reference"]:
                errors.append(f"{prefix} resolved/accepted finding requires reference")
        elif item.get("evidence_digest") is not None or item.get("reference") is not None:
            errors.append(
                f"{prefix} open finding must not claim resolution/acceptance evidence"
            )

        if severity == "blocker":
            if status != "resolved":
                gate_failures.append(
                    f"blocker finding {finding_id} must be resolved before promotion"
                )
        elif severity == "critical":
            if status == "open":
                gate_failures.append(
                    f"critical finding {finding_id} is open"
                )
            elif status == "accepted" and not gate["allow_accepted_critical_findings"]:
                gate_failures.append(
                    f"critical finding {finding_id} risk acceptance is not permitted by gate"
                )
        elif severity == "high":
            if status == "open" and not gate["allow_open_high_findings"]:
                gate_failures.append(f"high finding {finding_id} is open")
            if status == "accepted" and not gate["allow_accepted_high_findings"]:
                gate_failures.append(
                    f"high finding {finding_id} risk acceptance is not permitted by gate"
                )


def _validate_approvals(
    record: dict[str, Any],
    gate: dict[str, Any],
    errors: list[str],
    gate_failures: list[str],
) -> None:
    approvals = record.get("approvals")
    if not isinstance(approvals, list):
        errors.append("promotion approvals must be an array")
        return
    submitter_org = (
        record.get("submitter", {}).get("organization_id")
        if isinstance(record.get("submitter"), dict)
        else None
    )
    decision = record.get("decision")
    decided_at: datetime | None = None
    if isinstance(decision, dict) and decision.get("decided_at") is not None:
        decided_at = _parse_time(
            decision.get("decided_at"), "promotion decision.decided_at", errors
        )
    seen_approvers: set[str] = set()
    independent_orgs: set[str] = set()
    valid_count = 0
    for index, approval in enumerate(approvals):
        prefix = f"promotion approvals[{index}]"
        if not isinstance(approval, dict):
            errors.append(f"{prefix} must be an object")
            continue
        approver_id = approval.get("approver_id")
        if not isinstance(approver_id, str) or not approver_id:
            errors.append(f"{prefix} approver_id must be non-empty")
        elif approver_id in seen_approvers:
            errors.append(f"{prefix} duplicate approver_id {approver_id}")
        else:
            seen_approvers.add(approver_id)
        org = approval.get("organization_id")
        if not isinstance(org, str) or not org:
            errors.append(f"{prefix} organization_id must be non-empty")
        elif org != submitter_org:
            independent_orgs.add(org)
        if not isinstance(approval.get("role"), str) or not approval["role"]:
            errors.append(f"{prefix} role must be non-empty")
        approved_at = _parse_time(
            approval.get("approved_at"), f"{prefix}.approved_at", errors
        )
        if (
            approved_at is not None
            and decided_at is not None
            and approved_at > decided_at
        ):
            errors.append(f"{prefix} approval cannot postdate decision")
        _digest(
            approval.get("approval_evidence_digest"),
            f"{prefix}.approval_evidence_digest",
            errors,
        )
        if not isinstance(approval.get("reference"), str) or not approval["reference"]:
            errors.append(f"{prefix} reference must be non-empty")
        valid_count += 1

    if valid_count < gate["minimum_approvers"]:
        gate_failures.append(
            f"gate requires at least {gate['minimum_approvers']} approvers, got {valid_count}"
        )
    if len(independent_orgs) < gate["minimum_independent_approver_orgs"]:
        gate_failures.append(
            "gate requires at least "
            f"{gate['minimum_independent_approver_orgs']} independent approver organizations, "
            f"got {len(independent_orgs)}"
        )


def _apply_gate_thresholds(
    record: dict[str, Any],
    gate: dict[str, Any],
    metrics: dict[str, Any],
    errors: list[str],
    gate_failures: list[str],
) -> None:
    threshold_pairs = (
        (
            "implementation_count",
            "minimum_nonconcept_implementations",
            "non-concept implementations",
        ),
        (
            "implementation_org_count",
            "minimum_distinct_implementation_orgs",
            "distinct implementation organizations",
        ),
        (
            "independent_security_reviews",
            "minimum_independent_security_reviews",
            "independent security-review organizations",
        ),
        (
            "independent_replications",
            "minimum_independent_replications",
            "independent replication organizations",
        ),
        (
            "interoperability_count",
            "minimum_interoperability_evidence",
            "interoperability evidence items",
        ),
        (
            "operational_count",
            "minimum_operational_deployments",
            "operational deployment evidence items",
        ),
        (
            "deployment_org_count",
            "minimum_distinct_deployment_orgs",
            "distinct deployment organizations",
        ),
        (
            "standards_count",
            "minimum_recognized_external_standards",
            "recognized final external standards",
        ),
        (
            "longest_public_review_days",
            "minimum_public_review_days",
            "continuous public-review days",
        ),
        (
            "independently_verified_vectors",
            "minimum_independently_verified_vectors",
            "independently verified test vectors",
        ),
    )
    for metric_name, gate_name, label in threshold_pairs:
        actual = metrics[metric_name]
        minimum = gate[gate_name]
        if actual < minimum:
            gate_failures.append(
                f"gate requires at least {minimum} {label}, got {actual}"
            )

    formal_min = gate["minimum_formal_verification_evidence"]
    formal_items = metrics["formal_items"]
    if len(formal_items) < formal_min:
        gate_failures.append(
            f"gate requires at least {formal_min} formal-verification evidence items, "
            f"got {len(formal_items)}"
        )
    if formal_min > 0:
        target_properties = set(record["target_profile"]["security_properties"])
        covered: set[str] = set()
        for item in formal_items:
            details = item.get("details", {})
            values = details.get("covered_property_ids")
            if isinstance(values, list):
                covered.update(value for value in values if isinstance(value, str))
        missing = sorted(target_properties - covered)
        if missing:
            gate_failures.append(
                "formal-assurance promotion path lacks formal coverage for: "
                + ", ".join(missing)
            )

    requested_at_errors: list[str] = []
    requested_at = _parse_time(
        record.get("requested_at"), "promotion requested_at", requested_at_errors
    )
    errors.extend(requested_at_errors)
    source_state = record.get("source_state")
    prior_effective = record.get("prior_state_effective_at")
    minimum_days = gate["minimum_prior_state_days"]
    if source_state == "experimental":
        if prior_effective is not None:
            errors.append(
                "experimental source state must have null prior_state_effective_at"
            )
    else:
        if prior_effective is None:
            errors.append(
                "non-experimental source state requires prior_state_effective_at"
            )
        else:
            prior_errors: list[str] = []
            prior_dt = _parse_time(
                prior_effective,
                "promotion prior_state_effective_at",
                prior_errors,
            )
            errors.extend(prior_errors)
            if (
                requested_at is not None
                and prior_dt is not None
                and requested_at >= prior_dt
            ):
                days = (requested_at - prior_dt).days
                if days < minimum_days:
                    gate_failures.append(
                        f"gate requires at least {minimum_days} days in prior state, got {days}"
                    )
            elif requested_at is not None and prior_dt is not None:
                errors.append("prior_state_effective_at cannot postdate request")


def validate_promotion(
    record: dict[str, Any],
    research_entry: dict[str, Any],
    research_registry: dict[str, Any],
    promotion_registry: dict[str, Any],
    threat_registry: dict[str, Any],
    property_registry: dict[str, Any],
    algorithm_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    *,
    previous_record: dict[str, Any] | None = None,
) -> PromotionResult:
    errors = validate_registry(promotion_registry)
    gate_failures: list[str] = []

    research_errors = research_profile_registry.validate_entry(
        research_entry,
        research_registry,
        threat_registry,
        property_registry,
        algorithm_registry,
    )
    errors.extend("source research: " + error for error in research_errors)

    source_state = record.get("source_state")
    target_state = record.get("target_state")
    gate_ref = record.get("gate_profile_ref")
    target_profile = record.get("target_profile")
    profile_ref = (
        _profile_ref(target_profile) if isinstance(target_profile, dict) else None
    )
    result = PromotionResult(
        valid=False,
        eligible=False,
        source_state=source_state if isinstance(source_state, str) else None,
        target_state=target_state if isinstance(target_state, str) else None,
        gate_profile_ref=gate_ref if isinstance(gate_ref, str) else None,
        profile_ref=profile_ref,
        errors=errors,
        gate_failures=gate_failures,
    )

    if record.get("schema_version") != "0.1":
        errors.append("promotion record schema_version must be 0.1")

    if (source_state, target_state) not in TRANSITIONS:
        errors.append(
            f"promotion transition {source_state!r} -> {target_state!r} is not allowed"
        )

    gate = _gate_map(promotion_registry).get(gate_ref)
    if gate is None:
        errors.append(f"promotion references unknown gate profile {gate_ref}")
    elif gate.get("target_state") != target_state:
        errors.append("promotion gate target_state does not match record target_state")

    source = record.get("source_research")
    if not isinstance(source, dict):
        errors.append("promotion source_research must be an object")
    else:
        for field_name in ("entry_id", "entry_version", "entry_digest"):
            expected_field = (
                "entry_digest"
                if field_name == "entry_digest"
                else field_name
            )
            if source.get(field_name) != research_entry.get(expected_field):
                errors.append(
                    f"promotion source_research.{field_name} does not match research entry"
                )

    submitter = record.get("submitter")
    if not isinstance(submitter, dict):
        errors.append("promotion submitter must be an object")
    else:
        for field_name in ("actor_id", "organization_id"):
            if not isinstance(submitter.get(field_name), str) or not submitter[field_name]:
                errors.append(f"promotion submitter.{field_name} must be non-empty")

    requested_at = _parse_time(record.get("requested_at"), "promotion requested_at", errors)

    sequence = record.get("sequence")
    previous_digest = record.get("previous_promotion_record_digest")
    if source_state == "experimental":
        if sequence != 1:
            errors.append("experimental -> candidate promotion sequence must be 1")
        if previous_digest is not None:
            errors.append(
                "experimental -> candidate promotion must have null previous promotion digest"
            )
        if previous_record is not None:
            errors.append(
                "experimental -> candidate promotion must not supply previous_record"
            )
    else:
        if previous_record is None:
            errors.append("non-experimental promotion requires previous_record")
        else:
            if previous_record.get("decision", {}).get("status") != "approved":
                errors.append("previous promotion record must be approved")
            if previous_record.get("target_state") != source_state:
                errors.append("previous promotion target_state does not equal current source_state")
            if previous_record.get("promotion_id") != record.get("promotion_id"):
                errors.append("promotion_id must remain stable across lifecycle")
            if previous_record.get("promotion_record_digest") != previous_digest:
                errors.append("previous_promotion_record_digest mismatch")
            if sequence != previous_record.get("sequence", 0) + 1:
                errors.append("promotion sequence must increment by exactly one")
            previous_profile = previous_record.get("target_profile")
            if isinstance(previous_profile, dict) and isinstance(target_profile, dict):
                if (
                    previous_profile.get("profile_id") != target_profile.get("profile_id")
                    or previous_profile.get("profile_version")
                    != target_profile.get("profile_version")
                    or previous_profile.get("family_id")
                    != target_profile.get("family_id")
                ):
                    errors.append("promotion lifecycle must preserve target profile identity")
            previous_decided = previous_record.get("decision", {}).get("decided_at")
            if record.get("prior_state_effective_at") != previous_decided:
                errors.append(
                    "prior_state_effective_at must equal previous approved decision time"
                )

    source_target = research_entry.get("target")
    internal_record = copy.deepcopy(record)
    internal_record["_source_target"] = source_target
    known_property_ids = {
        item.get("id")
        for item in property_registry.get("properties", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    projected_catalog = _validate_target_catalog(
        internal_record, profile_catalog, known_property_ids, errors
    )
    result.projected_catalog = projected_catalog

    _validate_reconciliation(
        record,
        research_entry,
        threat_registry,
        property_registry,
        algorithm_registry,
        projected_catalog if projected_catalog is not None else profile_catalog,
        errors,
    )
    _validate_hypotheses(record, research_entry, errors, gate_failures)
    metrics = _validate_evidence(record, research_entry, errors)

    if gate is not None:
        _validate_findings(record, gate, errors, gate_failures)
        _validate_approvals(record, gate, errors, gate_failures)
        _apply_gate_thresholds(record, gate, metrics, errors, gate_failures)

    decision = record.get("decision")
    if not isinstance(decision, dict):
        errors.append("promotion decision must be an object")
    else:
        status = decision.get("status")
        if status not in {"pending", "approved", "rejected"}:
            errors.append(f"promotion decision has invalid status {status}")
        if not isinstance(decision.get("rationale"), str) or not decision["rationale"].strip():
            errors.append("promotion decision rationale must be non-empty")
        decided_at_value = decision.get("decided_at")
        if status == "pending":
            if decided_at_value is not None:
                errors.append("pending promotion decision must have null decided_at")
        else:
            decided_at = _parse_time(
                decided_at_value, "promotion decision.decided_at", errors
            )
            if (
                requested_at is not None
                and decided_at is not None
                and decided_at < requested_at
            ):
                errors.append("promotion decision cannot predate request")
        if status == "approved" and gate_failures:
            errors.append(
                "approved promotion does not satisfy selected gate: "
                + " | ".join(sorted(set(gate_failures)))
            )

    if record.get("promotion_record_digest") != compute_promotion_record_digest(record):
        errors.append("promotion_record_digest does not match canonical record")

    result.errors = sorted(set(errors))
    result.gate_failures = sorted(set(gate_failures))
    result.valid = not result.errors
    result.eligible = not result.gate_failures and not [
        error for error in result.errors
        if not error.startswith("approved promotion does not satisfy selected gate:")
    ]
    return result


def promotion_state_entry(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("decision", {}).get("status") != "approved":
        raise ValueError("only approved promotion records can create state entries")
    profile = record["target_profile"]
    return {
        "profile_ref": _profile_ref(profile),
        "research_entry_digest": record["source_research"]["entry_digest"],
        "lifecycle_state": record["target_state"],
        "promotion_record_digest": record["promotion_record_digest"],
        "effective_at": record["decision"]["decided_at"],
        "gate_profile_ref": record["gate_profile_ref"],
    }


def project_promotion_registry(
    registry: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    updated = copy.deepcopy(registry)
    entry = promotion_state_entry(record)
    existing = updated.get("promoted_profiles", [])
    replaced = False
    for index, item in enumerate(existing):
        if isinstance(item, dict) and item.get("profile_ref") == entry["profile_ref"]:
            existing[index] = entry
            replaced = True
            break
    if not replaced:
        existing.append(entry)
    existing.sort(key=lambda item: item["profile_ref"])
    updated["promoted_profiles"] = existing
    return updated


def validate_promotion_registry_state(
    registry: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[str]:
    errors = validate_registry(registry)
    latest: dict[str, dict[str, Any]] = {}
    state_rank = {"candidate": 1, "recommended": 2, "required": 3}
    for record in records:
        if record.get("decision", {}).get("status") != "approved":
            continue
        profile = record.get("target_profile")
        if not isinstance(profile, dict):
            continue
        ref = _profile_ref(profile)
        current = latest.get(ref)
        if current is None or record.get("sequence", 0) > current.get("sequence", 0):
            latest[ref] = record

    expected = {
        ref: promotion_state_entry(record)
        for ref, record in latest.items()
    }
    actual = {
        item.get("profile_ref"): item
        for item in registry.get("promoted_profiles", [])
        if isinstance(item, dict)
    }
    if set(expected) != set(actual):
        errors.append("promotion registry promoted profile set differs from approved records")
    for ref, expected_item in expected.items():
        actual_item = actual.get(ref)
        if actual_item is not None and actual_item != expected_item:
            errors.append(f"promotion registry state mismatch for {ref}")

    for ref, record in latest.items():
        state = record.get("target_state")
        item = actual.get(ref)
        if (
            item is not None
            and state in state_rank
            and item.get("lifecycle_state") in state_rank
            and state_rank[item["lifecycle_state"]] != state_rank[state]
        ):
            errors.append(f"promotion registry lifecycle rank mismatch for {ref}")

    return sorted(set(errors))
