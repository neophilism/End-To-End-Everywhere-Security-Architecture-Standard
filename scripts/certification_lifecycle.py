#!/usr/bin/env python3
"""Event-sourced certification lifecycle validation for E2EESA PR 29."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ACTOR_ROLES = {
    "applicant",
    "intake-reviewer",
    "evaluator",
    "decision-maker",
    "surveillance-reviewer",
    "appeal-reviewer",
    "system",
}


@dataclass
class LifecycleResult:
    valid: bool
    state: str
    current_evidence_bundle_digest: str | None = None
    certificate_expires_at: str | None = None
    surveillance_due_at: str | None = None
    appeal_origin_state: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "state": self.state,
            "current_evidence_bundle_digest": self.current_evidence_bundle_digest,
            "certificate_expires_at": self.certificate_expires_at,
            "surveillance_due_at": self.surveillance_due_at,
            "appeal_origin_state": self.appeal_origin_state,
            "errors": self.errors,
        }


def _parse_time(value: object, field_name: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field_name} must be an RFC3339 UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field_name} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def transition_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("event_type")),
        str(item.get("from_state")),
        str(item.get("to_state")),
    )


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("certification lifecycle registry schema_version must be 0.1")
    if not isinstance(registry.get("registry_version"), str) or not registry["registry_version"].strip():
        errors.append("certification lifecycle registry registry_version must be non-empty")

    transitions = registry.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return errors + ["certification lifecycle registry transitions must be non-empty"]

    seen: set[tuple[str, str, str]] = set()
    allowed_fields = {
        "event_type",
        "from_state",
        "to_state",
        "actor_role",
        "requires_reason",
        "requires_evidence_bundle",
        "requires_validity_window",
    }

    for index, item in enumerate(transitions):
        prefix = f"certification lifecycle registry transitions[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = sorted(allowed_fields - item.keys())
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(missing)}")
        extras = sorted(set(item) - allowed_fields)
        if extras:
            errors.append(f"{prefix} unknown fields: {', '.join(extras)}")

        for field_name in ("event_type", "from_state", "to_state"):
            value = item.get(field_name)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{prefix} {field_name} must be non-empty")

        role = item.get("actor_role")
        if role not in ACTOR_ROLES:
            errors.append(f"{prefix} invalid actor_role")

        for field_name in ("requires_reason", "requires_evidence_bundle", "requires_validity_window"):
            if not isinstance(item.get(field_name), bool):
                errors.append(f"{prefix} {field_name} must be boolean")

        key = transition_key(item)
        if key in seen:
            errors.append(f"{prefix} duplicate transition {key[0]} {key[1]}->{key[2]}")
        else:
            seen.add(key)

    if not any(k == ("submit", "draft", "submitted") for k in seen):
        errors.append("certification lifecycle registry must contain draft submit transition")
    if not any(k == ("approve", "decision-review", "certified") for k in seen):
        errors.append("certification lifecycle registry must contain approval transition")
    if any(item.get("event_type") == "reinstate" and item.get("from_state") == "revoked" for item in transitions if isinstance(item, dict)):
        errors.append("certification lifecycle must not permit direct reinstatement from revoked")

    return errors


def validate_case(
    case: dict[str, Any],
    registry: dict[str, Any],
    *,
    as_of: str | datetime | None = None,
) -> LifecycleResult:
    registry_errors = validate_registry(registry)
    result = LifecycleResult(valid=False, state="draft", errors=list(registry_errors))
    if registry_errors:
        return result

    required_case_fields = {
        "schema_version",
        "case_id",
        "product_id",
        "product_version",
        "platform",
        "initial_state",
        "events",
    }
    missing = sorted(required_case_fields - case.keys())
    if missing:
        result.errors.append("certification lifecycle case missing fields: " + ", ".join(missing))
        return result

    if case.get("schema_version") != "0.1":
        result.errors.append("certification lifecycle case schema_version must be 0.1")
    if case.get("initial_state") != "draft":
        result.errors.append("certification lifecycle case initial_state must be draft")

    events = case.get("events")
    if not isinstance(events, list):
        result.errors.append("certification lifecycle case events must be an array")
        return result

    transition_map = {
        transition_key(item): item
        for item in registry["transitions"]
        if isinstance(item, dict)
    }

    current_state = "draft"
    current_bundle: str | None = None
    decision_bundle: str | None = None
    certificate_expires: datetime | None = None
    surveillance_due: datetime | None = None
    applicant_actor_ids: set[str] = set()
    decision_cycle_evaluators: set[str] = set()
    last_adverse_actor_id: str | None = None
    appeal_origin_state: str | None = None
    appeal_adverse_actor_id: str | None = None
    corrective_origin_state: str | None = None
    renewal_review_bundle: str | None = None
    event_ids: set[str] = set()
    previous_time: datetime | None = None

    for index, event in enumerate(events):
        prefix = f"certification lifecycle events[{index}]"
        if not isinstance(event, dict):
            result.errors.append(f"{prefix} must be an object")
            continue

        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            result.errors.append(f"{prefix} event_id must be non-empty")
        elif event_id in event_ids:
            result.errors.append(f"{prefix} duplicate event_id {event_id}")
        else:
            event_ids.add(event_id)

        event_time = _parse_time(event.get("occurred_at"), f"{prefix} occurred_at", result.errors)
        if event_time is not None and previous_time is not None and event_time < previous_time:
            result.errors.append(f"{prefix} occurred_at decreases relative to previous event")
        if event_time is not None:
            previous_time = event_time

        declared_from = event.get("from_state")
        declared_to = event.get("to_state")
        event_type = event.get("event_type")
        if declared_from != current_state:
            result.errors.append(
                f"{prefix} from_state {declared_from} does not match derived state {current_state}"
            )

        transition = transition_map.get((event_type, declared_from, declared_to))
        if transition is None:
            result.errors.append(
                f"{prefix} illegal transition: {event_type} {declared_from}->{declared_to}"
            )
            continue

        actor_id = event.get("actor_id")
        actor_role = event.get("actor_role")
        if not isinstance(actor_id, str) or not actor_id.strip():
            result.errors.append(f"{prefix} actor_id must be non-empty")
        if actor_role != transition["actor_role"]:
            result.errors.append(
                f"{prefix} actor_role {actor_role} does not match required role {transition['actor_role']}"
            )

        if actor_role == "applicant" and isinstance(actor_id, str):
            applicant_actor_ids.add(actor_id)
        if actor_role == "evaluator" and isinstance(actor_id, str):
            decision_cycle_evaluators.add(actor_id)

        reason = event.get("reason")
        if transition["requires_reason"]:
            if not isinstance(reason, str) or not reason.strip():
                result.errors.append(f"{prefix} requires a non-empty reason")
        elif reason is not None and not isinstance(reason, str):
            result.errors.append(f"{prefix} reason must be null or string")

        bundle = event.get("evidence_bundle_digest")
        if transition["requires_evidence_bundle"]:
            if not _valid_digest(bundle):
                result.errors.append(f"{prefix} requires a valid evidence_bundle_digest")
            else:
                current_bundle = bundle
        elif bundle is not None:
            if not _valid_digest(bundle):
                result.errors.append(f"{prefix} evidence_bundle_digest must be null or sha256")
            else:
                current_bundle = bundle

        expires_value = event.get("certificate_expires_at")
        surveillance_value = event.get("surveillance_due_at")
        event_expires: datetime | None = None
        event_surveillance: datetime | None = None

        if transition["requires_validity_window"]:
            event_expires = _parse_time(
                expires_value, f"{prefix} certificate_expires_at", result.errors
            )
            event_surveillance = _parse_time(
                surveillance_value, f"{prefix} surveillance_due_at", result.errors
            )
            if event_time is not None and event_expires is not None and event_expires <= event_time:
                result.errors.append(f"{prefix} certificate_expires_at must be after event time")
            if event_time is not None and event_surveillance is not None and event_surveillance <= event_time:
                result.errors.append(f"{prefix} surveillance_due_at must be after event time")
            if event_expires is not None and event_surveillance is not None and event_surveillance > event_expires:
                result.errors.append(f"{prefix} surveillance_due_at must not exceed certificate expiry")

            if event_type == "surveillance-pass" and certificate_expires is not None:
                if event_expires is not None and event_expires != certificate_expires:
                    result.errors.append(
                        f"{prefix} surveillance-pass must preserve current certificate expiry"
                    )
            if event_expires is not None:
                certificate_expires = event_expires
            if event_surveillance is not None:
                surveillance_due = event_surveillance
        else:
            if expires_value is not None:
                result.errors.append(f"{prefix} certificate_expires_at must be null for this transition")
            if surveillance_value is not None:
                result.errors.append(f"{prefix} surveillance_due_at must be null for this transition")

        if event_type == "begin-evaluation":
            decision_cycle_evaluators = set()
            if isinstance(actor_id, str):
                decision_cycle_evaluators.add(actor_id)

        if event_type == "advance-to-decision":
            if _valid_digest(bundle):
                decision_bundle = bundle

        if event_type in {"approve", "deny"}:
            if isinstance(actor_id, str):
                if actor_id in applicant_actor_ids:
                    result.errors.append(f"{prefix} decision-maker must not be an applicant actor")
                if actor_id in decision_cycle_evaluators:
                    result.errors.append(f"{prefix} decision-maker must not be an evaluator in this decision cycle")
            if event_type == "approve":
                if decision_bundle is None:
                    result.errors.append(f"{prefix} approval has no bundle advanced to decision")
                elif bundle != decision_bundle:
                    result.errors.append(f"{prefix} approval bundle differs from bundle advanced to decision")
            if event_type == "deny":
                last_adverse_actor_id = actor_id if isinstance(actor_id, str) else None
            decision_cycle_evaluators = set()
            decision_bundle = None

        if event_type == "require-corrective-action":
            corrective_origin_state = "surveillance-review"
        elif event_type == "renewal-corrective-action":
            corrective_origin_state = "renewal-review"
        elif event_type == "corrective-action-submitted":
            if corrective_origin_state is None:
                result.errors.append(f"{prefix} corrective action has no originating review state")
            elif declared_to != corrective_origin_state:
                result.errors.append(
                    f"{prefix} corrective action must return to origin state {corrective_origin_state}"
                )
            if declared_to == "renewal-review" and _valid_digest(bundle):
                renewal_review_bundle = bundle
            corrective_origin_state = None

        if event_type == "begin-renewal" and _valid_digest(bundle):
            renewal_review_bundle = bundle

        if event_type == "renew":
            if renewal_review_bundle is None:
                result.errors.append(f"{prefix} renewal has no reviewed evidence bundle")
            elif bundle != renewal_review_bundle:
                result.errors.append(f"{prefix} renewal bundle differs from bundle under renewal review")
            renewal_review_bundle = None

        if event_type in {"suspend", "revoke"}:
            last_adverse_actor_id = actor_id if isinstance(actor_id, str) else None

        if event_type == "open-appeal":
            appeal_origin_state = current_state
            appeal_adverse_actor_id = last_adverse_actor_id
            if appeal_adverse_actor_id is None:
                result.errors.append(f"{prefix} appeal has no recorded adverse decision actor")

        if event_type in {"appeal-upheld", "appeal-remanded"}:
            if isinstance(actor_id, str) and actor_id == appeal_adverse_actor_id:
                result.errors.append(f"{prefix} appeal reviewer must not be adverse decision actor")
            if event_type == "appeal-upheld":
                if appeal_origin_state is None:
                    result.errors.append(f"{prefix} appeal has no origin state")
                elif declared_to != appeal_origin_state:
                    result.errors.append(
                        f"{prefix} appeal-upheld must return to origin state {appeal_origin_state}"
                    )
            else:
                decision_cycle_evaluators = set()
                decision_bundle = current_bundle
            appeal_origin_state = None
            appeal_adverse_actor_id = None

        if event_type in {"renew", "reinstate"} and isinstance(actor_id, str):
            if actor_id in applicant_actor_ids:
                result.errors.append(f"{prefix} decision-maker must not be an applicant actor")

        if event_type == "expire":
            if certificate_expires is None:
                result.errors.append(f"{prefix} cannot expire without certificate expiry")
            elif event_time is not None and event_time < certificate_expires:
                result.errors.append(f"{prefix} expire event occurs before certificate expiry")

        if event_type == "approve" and _valid_digest(bundle):
            current_bundle = bundle
        if event_type == "renew" and _valid_digest(bundle):
            current_bundle = bundle
        if event_type == "reinstate" and _valid_digest(bundle):
            current_bundle = bundle

        current_state = declared_to

    as_of_dt: datetime | None
    if as_of is None:
        as_of_dt = previous_time
    elif isinstance(as_of, datetime):
        as_of_dt = as_of if as_of.tzinfo is not None else as_of.replace(tzinfo=timezone.utc)
    else:
        as_of_dt = _parse_time(as_of, "as_of", result.errors)

    if as_of_dt is not None and previous_time is not None and previous_time > as_of_dt:
        result.errors.append("lifecycle contains events after validation as_of time")

    if as_of_dt is not None and current_state == "certified":
        if certificate_expires is not None and as_of_dt >= certificate_expires:
            result.errors.append("active certification is expired as of validation time")
        if surveillance_due is not None and as_of_dt >= surveillance_due:
            result.errors.append("active certification has overdue surveillance as of validation time")
    if as_of_dt is not None and current_state == "suspended":
        if certificate_expires is not None and as_of_dt >= certificate_expires:
            result.errors.append("suspended certification is past expiry and requires expire transition")

    result.state = current_state
    result.current_evidence_bundle_digest = current_bundle
    result.certificate_expires_at = (
        certificate_expires.strftime("%Y-%m-%dT%H:%M:%SZ")
        if certificate_expires is not None
        else None
    )
    result.surveillance_due_at = (
        surveillance_due.strftime("%Y-%m-%dT%H:%M:%SZ")
        if surveillance_due is not None
        else None
    )
    result.appeal_origin_state = appeal_origin_state
    result.errors = sorted(set(result.errors))
    result.valid = not result.errors
    return result
