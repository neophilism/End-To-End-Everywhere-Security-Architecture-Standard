#!/usr/bin/env python3
"""Confidence/classification validation for E2EESA PR 36."""

from __future__ import annotations

import canonical_serialization

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import observatory_evidence

CONFIDENCE_MODELS = {
    "dimensional-ordinal",
    "stix-0-100",
    "calibrated-probability",
}
CLASSIFICATION_MODES = {"human-reviewed", "automated", "mixed"}
MIXED_STRATEGIES = {"human-final", "consensus", "declared-weighted"}


def canonical_bytes(value: object) -> bytes:
    return canonical_serialization.canonical_bytes(value)


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def record_core(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key != "classification_digest"
    }


def compute_classification_digest(record: dict[str, Any]) -> str:
    return canonical_digest(record_core(record))


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


def _string_set(
    value: object,
    field: str,
    errors: list[str],
    *,
    nonempty: bool = True,
) -> list[str]:
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


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("confidence/classification registry schema_version must be 0.1")

    modes = registry.get("classification_modes")
    if set(modes or []) != CLASSIFICATION_MODES or len(modes or []) != len(CLASSIFICATION_MODES):
        errors.append("classification_modes must define human-reviewed, automated and mixed exactly once")

    strategies = registry.get("mixed_resolution_strategies")
    if set(strategies or []) != MIXED_STRATEGIES or len(strategies or []) != len(MIXED_STRATEGIES):
        errors.append("mixed_resolution_strategies must define all supported strategies exactly once")

    confidence_models = registry.get("confidence_models")
    if not isinstance(confidence_models, list):
        errors.append("confidence_models must be an array")
        confidence_models = []
    model_ids = [
        item.get("id")
        for item in confidence_models
        if isinstance(item, dict)
    ]
    if set(model_ids) != CONFIDENCE_MODELS or len(model_ids) != len(CONFIDENCE_MODELS):
        errors.append("confidence_models must define all supported confidence semantics exactly once")

    for item in confidence_models:
        if not isinstance(item, dict):
            errors.append("confidence model entry must be an object")
            continue
        model_id = item.get("id")
        if model_id == "stix-0-100":
            if item.get("minimum") != 0 or item.get("maximum") != 100:
                errors.append("STIX confidence registry range must be 0..100")
            if item.get("probability") is not False:
                errors.append("STIX confidence must not be marked probability")
        if model_id == "calibrated-probability":
            if item.get("minimum") != 0 or item.get("maximum") != 10000:
                errors.append("calibrated probability registry range must be 0..10000 basis points")
            if item.get("unit") != "basis-points":
                errors.append("calibrated probability unit must be basis-points")
            if item.get("probability") is not True:
                errors.append("calibrated-probability must be marked probability")

    if set(registry.get("ordinal_levels") or []) != {"unknown", "low", "moderate", "high"}:
        errors.append("ordinal_levels registry mismatch")
    if set(registry.get("dimension_levels") or []) != {
        "unknown", "weak", "limited", "strong", "very-strong"
    }:
        errors.append("dimension_levels registry mismatch")
    if set(registry.get("conflict_levels") or []) != {
        "unknown", "none", "minor", "material"
    }:
        errors.append("conflict_levels registry mismatch")
    return sorted(set(errors))


def validate_policy(
    policy: dict[str, Any],
    registry: dict[str, Any],
) -> list[str]:
    errors = validate_registry(registry)
    if policy.get("schema_version") != "0.1":
        errors.append("confidence/classification policy schema_version must be 0.1")

    mode = policy.get("classification_mode")
    if mode not in CLASSIFICATION_MODES:
        errors.append(f"unknown classification_mode {mode}")

    taxonomy = policy.get("taxonomy")
    if not isinstance(taxonomy, dict):
        errors.append("policy taxonomy must be an object")
    else:
        for field in ("taxonomy_id", "version", "reference"):
            if not isinstance(taxonomy.get(field), str) or not taxonomy[field]:
                errors.append(f"policy taxonomy.{field} must be non-empty")

    allowed = policy.get("allowed_assessment_confidence_models")
    if not isinstance(allowed, list) or not allowed:
        errors.append("allowed_assessment_confidence_models must be non-empty")
        allowed_set: set[str] = set()
    else:
        allowed_set = set(allowed)
        if len(allowed) != len(allowed_set):
            errors.append("allowed_assessment_confidence_models must be unique")
        unknown = sorted(allowed_set - CONFIDENCE_MODELS)
        if unknown:
            errors.append(
                "policy has unknown assessment confidence models: " + ", ".join(unknown)
            )

    final_model = policy.get("final_confidence_model")
    if final_model not in CONFIDENCE_MODELS:
        errors.append(f"unknown final_confidence_model {final_model}")
    elif final_model not in allowed_set:
        errors.append("final_confidence_model must be allowed for assessments")

    minimum_citations = policy.get("minimum_evidence_citations")
    if (
        not isinstance(minimum_citations, int)
        or isinstance(minimum_citations, bool)
        or minimum_citations < 1
    ):
        errors.append("minimum_evidence_citations must be a positive integer")

    max_age = policy.get("max_calibration_age_days")
    if "calibrated-probability" in allowed_set:
        if not isinstance(max_age, int) or isinstance(max_age, bool) or not (1 <= max_age <= 3650):
            errors.append(
                "policies allowing calibrated-probability require max_calibration_age_days 1..3650"
            )
    elif max_age is not None:
        errors.append(
            "max_calibration_age_days must be null when calibrated-probability is not allowed"
        )

    if policy.get("automated_output_must_record_model") is not True:
        errors.append("automated_output_must_record_model must be true")
    if policy.get("human_override_reason_required") is not True:
        errors.append("human_override_reason_required must be true")

    mixed = policy.get("mixed_resolution")
    if mode != "mixed":
        if mixed is not None:
            errors.append("non-mixed policy must have null mixed_resolution")
        if mode == "human-reviewed" and "calibrated-probability" in allowed_set:
            errors.append("human-reviewed policy must not allow calibrated-probability")
    else:
        if not isinstance(mixed, dict):
            errors.append("mixed policy requires mixed_resolution")
        else:
            strategy = mixed.get("strategy")
            if strategy not in MIXED_STRATEGIES:
                errors.append(f"unknown mixed resolution strategy {strategy}")
            source = mixed.get("consensus_confidence_source")
            human_weight = mixed.get("human_weight_percent")
            automated_weight = mixed.get("automated_weight_percent")
            if strategy == "human-final":
                if source is not None:
                    errors.append("human-final strategy must have null consensus_confidence_source")
                if human_weight is not None or automated_weight is not None:
                    errors.append("human-final strategy must not declare weights")
            elif strategy == "consensus":
                if source not in {"human", "automated"}:
                    errors.append(
                        "consensus strategy requires consensus_confidence_source human or automated"
                    )
                if human_weight is not None or automated_weight is not None:
                    errors.append("consensus strategy must not declare weights")
            elif strategy == "declared-weighted":
                if source is not None:
                    errors.append("declared-weighted strategy must have null confidence source")
                if final_model != "stix-0-100":
                    errors.append("declared-weighted strategy requires final STIX 0-100 confidence")
                if "stix-0-100" not in allowed_set:
                    errors.append("declared-weighted strategy requires STIX confidence to be allowed")
                for field, value in (
                    ("human_weight_percent", human_weight),
                    ("automated_weight_percent", automated_weight),
                ):
                    if (
                        not isinstance(value, int)
                        or isinstance(value, bool)
                        or not (1 <= value <= 99)
                    ):
                        errors.append(f"declared-weighted {field} must be 1..99")
                if isinstance(human_weight, int) and isinstance(automated_weight, int):
                    if human_weight + automated_weight != 100:
                        errors.append("declared-weighted human and automated weights must sum to 100")

    return sorted(set(errors))


def _validate_confidence(
    confidence: object,
    *,
    allowed_models: set[str],
    registry: dict[str, Any],
    role: str,
    assessed_at: datetime | None,
    max_calibration_age_days: int | None,
    classifier_model_digest: str | None,
    field: str,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(confidence, dict):
        return [f"{field} must be a confidence object"]

    model = confidence.get("model")
    if model not in CONFIDENCE_MODELS:
        return [f"{field} has unknown confidence model {model}"]
    if model not in allowed_models:
        errors.append(f"{field} confidence model {model} is not allowed by policy")

    if model == "dimensional-ordinal":
        if confidence.get("level") not in set(registry["ordinal_levels"]):
            errors.append(f"{field} invalid ordinal confidence level")
        for name in (
            "source_reliability",
            "evidence_directness",
            "corroboration",
            "freshness",
        ):
            if confidence.get(name) not in set(registry["dimension_levels"]):
                errors.append(f"{field} invalid {name}")
        if confidence.get("conflicting_evidence") not in set(registry["conflict_levels"]):
            errors.append(f"{field} invalid conflicting_evidence")
        if not isinstance(confidence.get("rationale"), str) or not confidence["rationale"].strip():
            errors.append(f"{field} dimensional confidence requires rationale")

    elif model == "stix-0-100":
        value = confidence.get("value")
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not (0 <= value <= 100)
        ):
            errors.append(f"{field} STIX confidence value must be integer 0..100")
        if not isinstance(confidence.get("rationale"), str) or not confidence["rationale"].strip():
            errors.append(f"{field} STIX confidence requires rationale")

    elif model == "calibrated-probability":
        if role == "human":
            errors.append(f"{field} human assessment cannot use calibrated-probability")
        probability = confidence.get("probability_basis_points")
        if (
            not isinstance(probability, int)
            or isinstance(probability, bool)
            or not (0 <= probability <= 10000)
        ):
            errors.append(f"{field} calibrated probability must be 0..10000 basis points")
        if not isinstance(confidence.get("rationale"), str) or not confidence["rationale"].strip():
            errors.append(f"{field} calibrated probability requires rationale")
        calibration = confidence.get("calibration")
        if not isinstance(calibration, dict):
            errors.append(f"{field} calibrated probability requires calibration evidence")
        else:
            model_digest = calibration.get("model_digest")
            if classifier_model_digest is None:
                errors.append(f"{field} calibrated probability requires classifier model identity")
            elif model_digest != classifier_model_digest:
                errors.append(f"{field} calibration model_digest does not match classifier model")
            dataset_digest = calibration.get("evaluation_dataset_digest")
            if not isinstance(dataset_digest, str) or not dataset_digest.startswith("sha256:"):
                errors.append(f"{field} calibration evaluation_dataset_digest must be sha256")
            sample_count = calibration.get("sample_count")
            if (
                not isinstance(sample_count, int)
                or isinstance(sample_count, bool)
                or sample_count < 1
            ):
                errors.append(f"{field} calibration sample_count must be positive")
            brier = calibration.get("brier_score_millionths")
            if (
                not isinstance(brier, int)
                or isinstance(brier, bool)
                or not (0 <= brier <= 1_000_000)
            ):
                errors.append(f"{field} Brier score millionths must be 0..1000000")
            ece = calibration.get("expected_calibration_error_basis_points")
            if ece is not None and (
                not isinstance(ece, int)
                or isinstance(ece, bool)
                or not (0 <= ece <= 10000)
            ):
                errors.append(f"{field} calibration error basis points must be null or 0..10000")
            if not isinstance(calibration.get("calibration_method"), str) or not calibration["calibration_method"].strip():
                errors.append(f"{field} calibration_method must be non-empty")
            evaluated_at = _parse_time(
                calibration.get("evaluated_at"),
                f"{field}.calibration.evaluated_at",
                errors,
            )
            if evaluated_at is not None and assessed_at is not None:
                if evaluated_at > assessed_at:
                    errors.append(f"{field} calibration cannot postdate assessment")
                if max_calibration_age_days is None:
                    errors.append(f"{field} calibrated probability policy lacks calibration age limit")
                elif assessed_at > evaluated_at + timedelta(days=max_calibration_age_days):
                    errors.append(f"{field} calibration evidence is stale")

    return errors


def _labels(
    assessment: object,
    field: str,
    errors: list[str],
) -> list[str]:
    if not isinstance(assessment, dict):
        errors.append(f"{field} must be an object")
        return []
    return _string_set(assessment.get("labels"), f"{field}.labels", errors)


def validate_record(
    record: dict[str, Any],
    policy: dict[str, Any],
    bundle: dict[str, Any],
    registry: dict[str, Any],
) -> list[str]:
    errors = validate_policy(policy, registry)
    errors.extend(
        "source bundle: " + error
        for error in observatory_evidence.validate_bundle(bundle)
    )
    if errors:
        return sorted(set(errors))

    if record.get("schema_version") != "0.1":
        errors.append("classification record schema_version must be 0.1")
    if record.get("source_bundle_digest") != bundle.get("bundle_digest"):
        errors.append("classification source_bundle_digest mismatch")
    if record.get("mode") != policy.get("classification_mode"):
        errors.append("classification mode does not match policy")
    if record.get("taxonomy") != policy.get("taxonomy"):
        errors.append("classification taxonomy does not match policy")

    revision = record.get("revision")
    previous = record.get("previous_record_digest")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        errors.append("classification revision must be a positive integer")
    elif revision == 1 and previous is not None:
        errors.append("classification revision 1 must have null previous_record_digest")
    elif revision > 1 and (
        not isinstance(previous, str) or not previous.startswith("sha256:")
    ):
        errors.append("classification revision >1 requires previous_record_digest")

    target = record.get("target")
    entity_ids = {item["entity_id"] for item in bundle["entities"]}
    event_ids = {item["event_id"] for item in bundle["events"]}
    if not isinstance(target, dict):
        errors.append("classification target must be an object")
    else:
        kind = target.get("kind")
        target_id = target.get("id")
        if kind == "entity" and target_id not in entity_ids:
            errors.append(f"classification target references unknown entity {target_id}")
        elif kind == "event" and target_id not in event_ids:
            errors.append(f"classification target references unknown event {target_id}")
        elif kind not in {"entity", "event"}:
            errors.append(f"classification target has invalid kind {kind}")

    citation_ids = _string_set(
        record.get("evidence_citation_ids"),
        "evidence_citation_ids",
        errors,
    )
    known_citations = {item["citation_id"] for item in bundle["citations"]}
    unknown_citations = sorted(set(citation_ids) - known_citations)
    if unknown_citations:
        errors.append(
            "classification references unknown citations: " + ", ".join(unknown_citations)
        )
    minimum_citations = policy["minimum_evidence_citations"]
    if len(citation_ids) < minimum_citations:
        errors.append(
            f"classification requires at least {minimum_citations} evidence citations"
        )

    created_at = _parse_time(record.get("created_at"), "classification.created_at", errors)
    bundle_created = _parse_time(bundle.get("created_at"), "source bundle created_at", errors)
    if created_at is not None and bundle_created is not None and created_at < bundle_created:
        errors.append("classification cannot predate source evidence bundle")

    agents = {item["agent_id"]: item for item in bundle["agents"]}
    allowed_models = set(policy["allowed_assessment_confidence_models"])
    max_age = policy.get("max_calibration_age_days")
    human = record.get("human_assessment")
    automated = record.get("automated_assessment")
    human_labels: list[str] = []
    automated_labels: list[str] = []
    human_confidence: dict[str, Any] | None = None
    automated_confidence: dict[str, Any] | None = None
    human_time: datetime | None = None
    automated_time: datetime | None = None

    if isinstance(human, dict):
        human_agent = agents.get(human.get("agent_id"))
        if human_agent is None:
            errors.append("human assessment references unknown agent")
        elif human_agent.get("agent_type") != "person":
            errors.append("human assessment agent must be PR 34 person agent")
        human_labels = _labels(human, "human_assessment", errors)
        human_time = _parse_time(
            human.get("assessed_at"),
            "human_assessment.assessed_at",
            errors,
        )
        if created_at is not None and human_time is not None and human_time > created_at:
            errors.append("human assessment cannot postdate classification creation")
        human_confidence = human.get("confidence") if isinstance(human.get("confidence"), dict) else None
        errors.extend(_validate_confidence(
            human.get("confidence"),
            allowed_models=allowed_models,
            registry=registry,
            role="human",
            assessed_at=human_time,
            max_calibration_age_days=max_age,
            classifier_model_digest=None,
            field="human_assessment.confidence",
        ))
        if not isinstance(human.get("rationale"), str) or not human["rationale"].strip():
            errors.append("human_assessment rationale must be non-empty")

    if isinstance(automated, dict):
        automated_agent = agents.get(automated.get("agent_id"))
        if automated_agent is None:
            errors.append("automated assessment references unknown agent")
        elif automated_agent.get("agent_type") not in {"software", "service"}:
            errors.append("automated assessment agent must be PR 34 software/service agent")
        automated_labels = _labels(automated, "automated_assessment", errors)
        automated_time = _parse_time(
            automated.get("assessed_at"),
            "automated_assessment.assessed_at",
            errors,
        )
        if created_at is not None and automated_time is not None and automated_time > created_at:
            errors.append("automated assessment cannot postdate classification creation")
        classifier = automated.get("classifier")
        model_digest: str | None = None
        if not isinstance(classifier, dict):
            errors.append("automated assessment requires classifier identity")
        else:
            for field in ("model_id", "model_version"):
                if not isinstance(classifier.get(field), str) or not classifier[field]:
                    errors.append(f"automated classifier {field} must be non-empty")
            for field in ("model_digest", "configuration_digest"):
                value = classifier.get(field)
                if not isinstance(value, str) or not value.startswith("sha256:"):
                    errors.append(f"automated classifier {field} must be sha256")
            model_digest = classifier.get("model_digest") if isinstance(classifier.get("model_digest"), str) else None
        automated_confidence = automated.get("confidence") if isinstance(automated.get("confidence"), dict) else None
        errors.extend(_validate_confidence(
            automated.get("confidence"),
            allowed_models=allowed_models,
            registry=registry,
            role="automated",
            assessed_at=automated_time,
            max_calibration_age_days=max_age,
            classifier_model_digest=model_digest,
            field="automated_assessment.confidence",
        ))

    mode = policy["classification_mode"]
    status = record.get("status")
    final_labels = _string_set(
        record.get("final_labels"),
        "final_labels",
        errors,
        nonempty=status == "classified",
    )
    final_confidence = record.get("final_confidence")
    resolution = record.get("mixed_resolution")

    if status not in {"classified", "needs-review"}:
        errors.append(f"invalid classification status {status}")
    elif status == "classified":
        if not final_labels:
            errors.append("classified record requires final labels")
        if not isinstance(final_confidence, dict):
            errors.append("classified record requires final confidence")
    else:
        if final_labels:
            errors.append("needs-review record must not publish final labels")
        if final_confidence is not None:
            errors.append("needs-review record must not publish final confidence")

    if isinstance(final_confidence, dict):
        if final_confidence.get("model") != policy["final_confidence_model"]:
            errors.append("final confidence model does not match policy")

    if mode == "human-reviewed":
        if not isinstance(human, dict):
            errors.append("human-reviewed mode requires human assessment")
        if automated is not None:
            errors.append("human-reviewed mode must not contain automated assessment")
        if resolution is not None:
            errors.append("human-reviewed mode must not contain mixed resolution")
        if status != "classified":
            errors.append("human-reviewed mode must resolve to classified")
        if set(final_labels) != set(human_labels):
            errors.append("human-reviewed final labels must equal human labels")
        if human_confidence is not None and final_confidence != human_confidence:
            errors.append("human-reviewed final confidence must equal human confidence")

    elif mode == "automated":
        if human is not None:
            errors.append("automated mode must not contain human assessment")
        if not isinstance(automated, dict):
            errors.append("automated mode requires automated assessment")
        if resolution is not None:
            errors.append("automated mode must not contain mixed resolution")
        if status != "classified":
            errors.append("automated mode must resolve to classified")
        if set(final_labels) != set(automated_labels):
            errors.append("automated final labels must equal automated labels")
        if automated_confidence is not None and final_confidence != automated_confidence:
            errors.append("automated final confidence must equal automated confidence")

    elif mode == "mixed":
        if not isinstance(human, dict) or not isinstance(automated, dict):
            errors.append("mixed mode requires both human and automated assessments")
        if not isinstance(resolution, dict):
            errors.append("mixed mode requires mixed_resolution")
        else:
            configured = policy["mixed_resolution"]
            strategy = resolution.get("strategy")
            if strategy != configured["strategy"]:
                errors.append("mixed resolution strategy does not match policy")
            for field in (
                "confidence_source",
                "human_weight_percent",
                "automated_weight_percent",
            ):
                expected = (
                    configured.get("consensus_confidence_source")
                    if field == "confidence_source"
                    else configured.get(field)
                )
                if resolution.get(field) != expected:
                    errors.append(f"mixed resolution {field} does not match policy")

            labels_agree = set(human_labels) == set(automated_labels)
            if strategy == "human-final":
                if status != "classified":
                    errors.append("human-final mixed strategy must resolve to classified")
                if set(final_labels) != set(human_labels):
                    errors.append("human-final labels must equal human assessment")
                if human_confidence is not None and final_confidence != human_confidence:
                    errors.append("human-final confidence must equal human assessment")
                override = resolution.get("override_reason")
                if not labels_agree and (
                    not isinstance(override, str) or not override.strip()
                ):
                    errors.append(
                        "human-final disagreement requires override/disagreement rationale"
                    )

            elif strategy == "consensus":
                if labels_agree:
                    if status != "classified":
                        errors.append("consensus agreement must resolve to classified")
                    if set(final_labels) != set(human_labels):
                        errors.append("consensus final labels must equal agreed labels")
                    source = configured["consensus_confidence_source"]
                    source_confidence = (
                        human_confidence if source == "human" else automated_confidence
                    )
                    if source_confidence is not None and final_confidence != source_confidence:
                        errors.append(
                            "consensus final confidence must copy configured source exactly"
                        )
                else:
                    if status != "needs-review":
                        errors.append("consensus disagreement must resolve to needs-review")
                    if final_labels or final_confidence is not None:
                        errors.append("consensus disagreement must not publish final result")

            elif strategy == "declared-weighted":
                if labels_agree:
                    if status != "classified":
                        errors.append("weighted agreement must resolve to classified")
                    if set(final_labels) != set(human_labels):
                        errors.append("weighted final labels must equal agreed labels")
                    if (
                        not isinstance(human_confidence, dict)
                        or human_confidence.get("model") != "stix-0-100"
                        or not isinstance(automated_confidence, dict)
                        or automated_confidence.get("model") != "stix-0-100"
                    ):
                        errors.append(
                            "declared-weighted strategy requires STIX 0-100 confidence from both assessments"
                        )
                    elif isinstance(final_confidence, dict):
                        human_weight = configured["human_weight_percent"]
                        automated_weight = configured["automated_weight_percent"]
                        expected_value = (
                            human_confidence["value"] * human_weight
                            + automated_confidence["value"] * automated_weight
                            + 50
                        ) // 100
                        if final_confidence.get("model") != "stix-0-100":
                            errors.append("weighted final confidence must use STIX 0-100")
                        if final_confidence.get("value") != expected_value:
                            errors.append(
                                f"weighted final confidence must equal deterministic value {expected_value}"
                            )
                        if not isinstance(final_confidence.get("rationale"), str) or not final_confidence["rationale"].strip():
                            errors.append("weighted final confidence requires rationale")
                else:
                    if status != "needs-review":
                        errors.append("weighted label disagreement must resolve to needs-review")
                    if final_labels or final_confidence is not None:
                        errors.append("weighted disagreement must not publish final result")

    expected_digest = compute_classification_digest(record)
    if record.get("classification_digest") != expected_digest:
        errors.append("classification_digest does not match canonical record")

    return sorted(set(errors))


def validate_revision_chain(
    current: dict[str, Any],
    previous: dict[str, Any],
    policy: dict[str, Any],
    bundle: dict[str, Any],
    registry: dict[str, Any],
) -> list[str]:
    errors = [
        "current: " + error
        for error in validate_record(current, policy, bundle, registry)
    ] + [
        "previous: " + error
        for error in validate_record(previous, policy, bundle, registry)
    ]

    if current.get("record_id") != previous.get("record_id"):
        errors.append("classification revision chain record_id mismatch")
    if current.get("revision") != previous.get("revision", 0) + 1:
        errors.append("classification revision must increment by exactly one")
    if current.get("previous_record_digest") != previous.get("classification_digest"):
        errors.append("classification revision previous_record_digest mismatch")
    for field in ("source_bundle_digest", "target", "taxonomy"):
        if current.get(field) != previous.get(field):
            errors.append(f"classification revision chain must preserve {field}")

    current_time = _parse_time(current.get("created_at"), "current.created_at", errors)
    previous_time = _parse_time(previous.get("created_at"), "previous.created_at", errors)
    if current_time is not None and previous_time is not None and current_time < previous_time:
        errors.append("classification revision creation time regresses")

    return sorted(set(errors))
