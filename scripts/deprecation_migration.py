#!/usr/bin/env python3
"""Deprecation and emergency migration engine for E2EESA PR 39."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import crypto_registry
import profile_engine

VALID_STATUSES = crypto_registry.VALID_STATUSES
STATUS_RANK = crypto_registry.STATUS_RANK
ACTIVE_STATUSES = {"recommended", "allowed", "provisional", "experimental"}
REPLACEMENT_STATUSES = {"recommended", "allowed", "provisional"}


@dataclass
class MigrationCaseResult:
    valid: bool
    lifecycle_status: str | None
    completed_dependents: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    overdue: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "lifecycle_status": self.lifecycle_status,
            "completed_dependents": self.completed_dependents,
            "errors": self.errors,
            "overdue": self.overdue,
        }


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


def plan_core(plan: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in plan.items() if key != "plan_digest"}


def compute_plan_digest(plan: dict[str, Any]) -> str:
    return canonical_digest(plan_core(plan))


def case_core(case: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in case.items() if key != "case_digest"}


def compute_case_digest(case: dict[str, Any]) -> str:
    return canonical_digest(case_core(case))


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if value is None:
        return None
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


def _digest(value: object, field: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        errors.append(f"{field} must be sha256")
        return None
    try:
        int(value[7:], 16)
    except ValueError:
        errors.append(f"{field} must be sha256")
        return None
    return value


def validate_registry(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("deprecation migration registry schema_version must be 0.1")
    expected = {
        "modes": {"planned", "emergency"},
        "strategies": {
            "overlap-prefer-new",
            "scheduled-cutover",
            "emergency-stop",
        },
        "legacy_processing_policies": {
            "hard-cutoff",
            "historical-read-verify-only",
            "migration-only",
        },
        "fallback_policies": {"disabled", "bounded-until-new-use-stop"},
        "reason_classes": {
            "cryptanalytic-break",
            "active-exploitation",
            "standard-withdrawal",
            "security-margin",
            "interoperability-retirement",
            "implementation-risk",
            "ecosystem-migration",
            "other",
        },
        "dependent_actions": {
            "replace",
            "deprecate",
            "legacy",
            "retire",
            "update-requirement",
        },
        "event_types": {
            "activate-plan",
            "replacement-available",
            "prefer-replacement",
            "stop-new-use",
            "enter-legacy-processing",
            "prohibit",
            "dependent-migrated",
            "complete",
            "emergency-stop",
            "post-emergency-review",
        },
    }
    for field_name, values in expected.items():
        actual = registry.get(field_name)
        if (
            not isinstance(actual, list)
            or len(actual) != len(set(actual))
            or set(actual) != values
        ):
            errors.append(
                f"deprecation migration registry {field_name} does not match supported values"
            )
    return sorted(set(errors))


def _profile_ref(profile: dict[str, Any]) -> str:
    return f"{profile.get('profile_id')}@{profile.get('profile_version')}"


def _lookup_asset(
    asset: dict[str, Any],
    crypto: dict[str, Any],
    catalog: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    kind = asset.get("kind")
    asset_id = asset.get("id")
    if kind == "algorithm":
        item = next(
            (
                item
                for item in crypto.get("algorithms", [])
                if isinstance(item, dict) and item.get("id") == asset_id
            ),
            None,
        )
        return item, item.get("status") if isinstance(item, dict) else None
    if kind == "suite":
        item = next(
            (
                item
                for item in crypto.get("suites", [])
                if isinstance(item, dict) and item.get("id") == asset_id
            ),
            None,
        )
        return item, item.get("status") if isinstance(item, dict) else None
    if kind == "profile":
        item = next(
            (
                item
                for item in catalog.get("profiles", [])
                if isinstance(item, dict) and _profile_ref(item) == asset_id
            ),
            None,
        )
        return item, item.get("status") if isinstance(item, dict) else None
    return None, None


def known_dependents(
    asset: dict[str, Any],
    crypto: dict[str, Any],
    catalog: dict[str, Any],
) -> list[tuple[str, str]]:
    kind = asset.get("kind")
    asset_id = asset.get("id")
    result: list[tuple[str, str]] = []
    if kind == "algorithm":
        for suite in crypto.get("suites", []):
            if (
                isinstance(suite, dict)
                and asset_id in suite.get("algorithm_ids", [])
                and isinstance(suite.get("id"), str)
            ):
                result.append(("suite", suite["id"]))
    elif kind == "profile":
        for profile in catalog.get("profiles", []):
            if (
                isinstance(profile, dict)
                and asset_id in profile.get("requires_profile_refs", [])
            ):
                result.append(("profile", _profile_ref(profile)))
    return sorted(result)


def _safe_replacement(
    plan: dict[str, Any],
    crypto: dict[str, Any],
    catalog: dict[str, Any],
    errors: list[str],
) -> None:
    replacement = plan.get("replacement")
    mode = plan.get("mode")
    asset = plan.get("asset")
    if replacement is None:
        if mode == "planned":
            errors.append("planned migration requires replacement")
        return
    if not isinstance(replacement, dict):
        errors.append("migration replacement must be null or object")
        return
    if not isinstance(asset, dict):
        errors.append("migration asset must be an object")
        return
    if replacement.get("kind") != asset.get("kind"):
        errors.append("migration replacement must use the same asset kind")
        return
    if replacement.get("id") == asset.get("id"):
        errors.append("migration replacement must differ from retiring asset")
        return
    replacement_item, replacement_status = _lookup_asset(replacement, crypto, catalog)
    if replacement_item is None:
        errors.append("migration replacement is not registered")
        return
    if replacement_status not in REPLACEMENT_STATUSES:
        errors.append(
            f"migration replacement status {replacement_status} is not production-eligible"
        )
    asset_item, _ = _lookup_asset(asset, crypto, catalog)
    if isinstance(asset_item, dict):
        if asset.get("kind") == "algorithm":
            if replacement_item.get("category") != asset_item.get("category"):
                errors.append("algorithm replacement must use the same registry category")
            if mode == "emergency" and replacement_status == "provisional":
                errors.append(
                    "emergency replacement must be recommended or allowed, not provisional"
                )
        elif asset.get("kind") == "suite":
            if replacement_item.get("protocol") != asset_item.get("protocol"):
                errors.append("suite replacement must use the same protocol")
        elif asset.get("kind") == "profile":
            if replacement_item.get("family_id") != asset_item.get("family_id"):
                errors.append("profile replacement must remain in the same profile family")
            if asset.get("id") in replacement_item.get("requires_profile_refs", []):
                errors.append("profile replacement must not require retiring profile")


def _validate_timeline(plan: dict[str, Any], errors: list[str]) -> None:
    timeline = plan.get("timeline")
    if not isinstance(timeline, dict):
        errors.append("migration timeline must be an object")
        return
    times = {
        name: _parse_time(timeline.get(name), f"migration timeline.{name}", errors)
        for name in (
            "effective_at",
            "replacement_available_at",
            "new_use_stop_at",
            "legacy_processing_stop_at",
            "prohibit_at",
        )
    }
    effective = times["effective_at"]
    replacement = times["replacement_available_at"]
    stop = times["new_use_stop_at"]
    legacy_stop = times["legacy_processing_stop_at"]
    prohibit = times["prohibit_at"]
    detected = _parse_time(
        plan.get("reason", {}).get("detected_at")
        if isinstance(plan.get("reason"), dict)
        else None,
        "migration reason.detected_at",
        errors,
    )
    if detected is not None and effective is not None and effective < detected:
        errors.append("migration effective_at cannot predate trigger detection")

    mode = plan.get("mode")
    strategy = plan.get("strategy")
    legacy_policy = plan.get("legacy_processing_policy")

    if mode == "planned":
        if strategy not in {"overlap-prefer-new", "scheduled-cutover"}:
            errors.append("planned migration requires planned cutover strategy")
        if None not in (effective, replacement, stop, prohibit):
            if not (effective <= replacement <= stop <= prohibit):
                errors.append(
                    "planned timeline must satisfy effective <= replacement <= new-use-stop <= prohibit"
                )
        if legacy_policy == "hard-cutoff":
            if legacy_stop is not None:
                errors.append("hard-cutoff plan must have null legacy_processing_stop_at")
            if stop is not None and prohibit is not None and stop != prohibit:
                errors.append(
                    "planned hard-cutoff requires new_use_stop_at == prohibit_at"
                )
        else:
            if legacy_stop is None:
                errors.append(
                    "bounded legacy-processing policy requires legacy_processing_stop_at"
                )
            elif stop is not None and prohibit is not None:
                if not (stop <= legacy_stop <= prohibit):
                    errors.append(
                        "planned legacy window must end between new-use stop and prohibition"
                    )
        if strategy == "scheduled-cutover" and legacy_policy == "hard-cutoff":
            if stop is not None and prohibit is not None and stop != prohibit:
                errors.append("scheduled hard cutover must prohibit at cutover")

    elif mode == "emergency":
        if strategy != "emergency-stop":
            errors.append("emergency mode requires emergency-stop strategy")
        if effective is not None and prohibit is not None and prohibit != effective:
            errors.append("emergency plan must prohibit at effective_at")
        if effective is not None and stop is not None and stop > effective:
            errors.append("emergency new_use_stop_at must not follow effective_at")
        if legacy_policy == "hard-cutoff":
            if legacy_stop is not None:
                errors.append(
                    "emergency hard-cutoff must have null legacy_processing_stop_at"
                )
        else:
            if legacy_stop is None:
                errors.append(
                    "emergency historical/migration processing requires stop deadline"
                )
            elif prohibit is not None and legacy_stop <= prohibit:
                errors.append(
                    "emergency legacy-processing deadline must follow emergency prohibition"
                )
        if replacement is not None and detected is not None and replacement < detected:
            errors.append(
                "emergency replacement availability cannot predate trigger detection"
            )
    else:
        errors.append(f"invalid migration mode {mode}")


def _validate_legacy_controls(plan: dict[str, Any], errors: list[str]) -> None:
    controls = plan.get("controls")
    if not isinstance(controls, dict):
        errors.append("migration controls must be an object")
        return
    policy = plan.get("legacy_processing_policy")
    historical_cutoff = controls.get("historical_cutoff_at")
    if controls.get("configuration_rollback_blocked") is not True:
        errors.append("migration must block configuration rollback reactivation")

    if policy == "hard-cutoff":
        if historical_cutoff is not None:
            errors.append("hard-cutoff must have null historical_cutoff_at")
    elif policy in {"historical-read-verify-only", "migration-only"}:
        cutoff = _parse_time(
            historical_cutoff, "migration controls.historical_cutoff_at", errors
        )
        stop = _parse_time(
            plan.get("timeline", {}).get("new_use_stop_at")
            if isinstance(plan.get("timeline"), dict)
            else None,
            "migration timeline.new_use_stop_at",
            errors,
        )
        if cutoff is not None and stop is not None and cutoff > stop:
            errors.append(
                "historical cutoff must not follow new-use stop"
            )
        if controls.get("isolated_legacy_processing") is not True:
            errors.append(
                "historical/migration-only processing must be isolated from ordinary negotiation"
            )
        if controls.get("audited_legacy_processing") is not True:
            errors.append(
                "historical/migration-only processing must be audited"
            )
    else:
        errors.append(f"invalid legacy_processing_policy {policy}")

    fallback = plan.get("fallback_policy")
    mode = plan.get("mode")
    strategy = plan.get("strategy")
    if fallback == "bounded-until-new-use-stop":
        if mode != "planned" or strategy != "overlap-prefer-new":
            errors.append(
                "bounded fallback is only allowed for planned overlap-prefer-new"
            )
        if controls.get("downgrade_protection") is not True:
            errors.append("bounded fallback requires downgrade protection")
        if controls.get("fallback_telemetry") is not True:
            errors.append("bounded fallback requires fallback telemetry")
    elif fallback == "disabled":
        pass
    else:
        errors.append(f"invalid fallback_policy {fallback}")
    if mode == "emergency" and fallback != "disabled":
        errors.append("emergency migration must disable fallback")


def _validate_dependents(
    plan: dict[str, Any],
    crypto: dict[str, Any],
    catalog: dict[str, Any],
    registry: dict[str, Any],
    errors: list[str],
) -> None:
    dependents = plan.get("dependents")
    if not isinstance(dependents, list):
        errors.append("migration dependents must be an array")
        return
    known = set(known_dependents(plan.get("asset", {}), crypto, catalog))
    seen_known: set[tuple[str, str]] = set()
    seen_ids: set[tuple[str, str]] = set()
    allowed_actions = set(registry.get("dependent_actions", []))
    effective = _parse_time(
        plan.get("timeline", {}).get("effective_at")
        if isinstance(plan.get("timeline"), dict)
        else None,
        "migration timeline.effective_at",
        errors,
    )
    for index, item in enumerate(dependents):
        prefix = f"migration dependents[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        kind = item.get("kind")
        dependent_id = item.get("id")
        key = (kind, dependent_id)
        if key in seen_ids:
            errors.append(f"{prefix} duplicate dependent {key}")
        seen_ids.add(key)
        if key in known:
            seen_known.add(key)
        if item.get("action") not in allowed_actions:
            errors.append(f"{prefix} invalid action {item.get('action')}")
        if not isinstance(item.get("owner"), str) or not item["owner"]:
            errors.append(f"{prefix} owner must be non-empty")
        deadline = _parse_time(
            item.get("deadline_at"), f"{prefix}.deadline_at", errors
        )
        if effective is not None and deadline is not None and deadline < effective:
            errors.append(f"{prefix} deadline cannot predate plan effective time")
        _digest(item.get("evidence_digest"), f"{prefix}.evidence_digest", errors)
        if not isinstance(item.get("reference"), str) or not item["reference"]:
            errors.append(f"{prefix} reference must be non-empty")
        replacement_id = item.get("replacement_id")
        if item.get("action") in {"replace", "update-requirement"}:
            if not isinstance(replacement_id, str) or not replacement_id:
                errors.append(
                    f"{prefix} action {item.get('action')} requires replacement_id"
                )
        elif replacement_id is not None:
            errors.append(
                f"{prefix} action {item.get('action')} must have null replacement_id"
            )

    missing = sorted(known - seen_known)
    if missing:
        errors.append(
            "migration plan omits known registry dependents: "
            + ", ".join(f"{kind}:{item_id}" for kind, item_id in missing)
        )


def _validate_evidence_approvals(
    plan: dict[str, Any],
    errors: list[str],
) -> None:
    evidence = plan.get("evidence")
    if not isinstance(evidence, list):
        errors.append("migration evidence must be an array")
        evidence = []
    seen: set[str] = set()
    types: set[str] = set()
    for index, item in enumerate(evidence):
        prefix = f"migration evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            errors.append(f"{prefix} evidence_id must be non-empty")
        elif evidence_id in seen:
            errors.append(f"{prefix} duplicate evidence_id {evidence_id}")
        else:
            seen.add(evidence_id)
        evidence_type = item.get("evidence_type")
        if evidence_type not in {
            "replacement-verification",
            "migration-test",
            "dependent-impact",
            "fallback-telemetry",
            "emergency-analysis",
        }:
            errors.append(f"{prefix} invalid evidence_type {evidence_type}")
        else:
            types.add(evidence_type)
        _digest(item.get("evidence_digest"), f"{prefix}.evidence_digest", errors)
        if not isinstance(item.get("reference"), str) or not item["reference"]:
            errors.append(f"{prefix} reference must be non-empty")

    if "dependent-impact" not in types:
        errors.append("migration plan requires dependent-impact evidence")
    if plan.get("mode") == "planned":
        if "replacement-verification" not in types:
            errors.append("planned migration requires replacement-verification evidence")
        if "migration-test" not in types:
            errors.append("planned migration requires migration-test evidence")
    if plan.get("mode") == "emergency" and "emergency-analysis" not in types:
        errors.append("emergency migration requires emergency-analysis evidence")
    if (
        plan.get("fallback_policy") == "bounded-until-new-use-stop"
        and "fallback-telemetry" not in types
    ):
        errors.append("bounded fallback requires fallback-telemetry evidence")

    approvals = plan.get("approvals")
    if not isinstance(approvals, list):
        errors.append("migration approvals must be an array")
        return
    seen_approvers: set[str] = set()
    roles: set[str] = set()
    effective = _parse_time(
        plan.get("timeline", {}).get("effective_at")
        if isinstance(plan.get("timeline"), dict)
        else None,
        "migration timeline.effective_at",
        errors,
    )
    for index, item in enumerate(approvals):
        prefix = f"migration approvals[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        approver = item.get("approver_id")
        if not isinstance(approver, str) or not approver:
            errors.append(f"{prefix} approver_id must be non-empty")
        elif approver in seen_approvers:
            errors.append(f"{prefix} duplicate approver_id {approver}")
        else:
            seen_approvers.add(approver)
        role = item.get("role")
        if not isinstance(role, str) or not role:
            errors.append(f"{prefix} role must be non-empty")
        else:
            roles.add(role)
        approved_at = _parse_time(
            item.get("approved_at"), f"{prefix}.approved_at", errors
        )
        if (
            approved_at is not None
            and effective is not None
            and approved_at > effective
        ):
            errors.append(f"{prefix} approval cannot postdate plan effective time")
        _digest(item.get("evidence_digest"), f"{prefix}.evidence_digest", errors)
        if not isinstance(item.get("reference"), str) or not item["reference"]:
            errors.append(f"{prefix} reference must be non-empty")

    if plan.get("mode") == "planned":
        if len(seen_approvers) < 2:
            errors.append("planned migration requires at least two approvers")
        if len(roles) < 2:
            errors.append("planned migration approvals must include at least two roles")
    elif plan.get("mode") == "emergency":
        if not seen_approvers:
            errors.append("emergency migration requires an emergency approver")
        if "emergency-security-authority" not in roles:
            errors.append(
                "emergency migration requires emergency-security-authority approval"
            )


def validate_plan(
    plan: dict[str, Any],
    registry: dict[str, Any],
    crypto: dict[str, Any],
    catalog: dict[str, Any],
) -> list[str]:
    errors = validate_registry(registry)
    if plan.get("schema_version") != "0.1":
        errors.append("migration plan schema_version must be 0.1")

    asset = plan.get("asset")
    if not isinstance(asset, dict) or asset.get("kind") not in {
        "algorithm",
        "suite",
        "profile",
    }:
        errors.append("migration asset must identify algorithm, suite, or profile")
        asset = {}
    asset_item, current_status = _lookup_asset(asset, crypto, catalog)
    if asset_item is None:
        errors.append("migration asset is not registered")
    if plan.get("current_status") != current_status:
        errors.append(
            f"migration current_status mismatch: plan={plan.get('current_status')} registry={current_status}"
        )
    if current_status == "prohibited":
        errors.append("migration asset is already prohibited")
    if plan.get("terminal_status") != "prohibited":
        errors.append("migration terminal_status must be prohibited")

    mode = plan.get("mode")
    strategy = plan.get("strategy")
    if mode not in set(registry.get("modes", [])):
        errors.append(f"invalid migration mode {mode}")
    if strategy not in set(registry.get("strategies", [])):
        errors.append(f"invalid migration strategy {strategy}")

    reason = plan.get("reason")
    if not isinstance(reason, dict):
        errors.append("migration reason must be an object")
    else:
        reason_class = reason.get("reason_class")
        if reason_class not in set(registry.get("reason_classes", [])):
            errors.append(f"invalid migration reason_class {reason_class}")
        if not isinstance(reason.get("summary"), str) or not reason["summary"].strip():
            errors.append("migration reason summary must be non-empty")
        _digest(reason.get("evidence_digest"), "migration reason.evidence_digest", errors)
        if not isinstance(reason.get("reference"), str) or not reason["reference"]:
            errors.append("migration reason reference must be non-empty")
        _parse_time(reason.get("detected_at"), "migration reason.detected_at", errors)
        if reason_class in {"cryptanalytic-break", "active-exploitation"} and mode != "emergency":
            errors.append(
                f"{reason_class} retirement requires emergency mode"
            )

    _safe_replacement(plan, crypto, catalog, errors)
    _validate_timeline(plan, errors)
    _validate_legacy_controls(plan, errors)
    _validate_dependents(plan, crypto, catalog, registry, errors)
    _validate_evidence_approvals(plan, errors)

    if plan.get("plan_digest") != compute_plan_digest(plan):
        errors.append("migration plan_digest does not match canonical plan")

    return sorted(set(errors))


def _event_status_effect(
    event_type: str,
    legacy_policy: str,
    current: str,
) -> str:
    if event_type == "activate-plan":
        return "deprecated"
    if event_type == "enter-legacy-processing":
        return "legacy"
    if event_type == "stop-new-use" and legacy_policy != "hard-cutoff":
        return "legacy"
    if event_type in {"prohibit", "emergency-stop"}:
        return "prohibited"
    return current


def validate_case(
    case: dict[str, Any],
    plan: dict[str, Any],
    registry: dict[str, Any],
    crypto: dict[str, Any],
    catalog: dict[str, Any],
    *,
    as_of: str | None = None,
) -> MigrationCaseResult:
    errors = [
        "plan: " + error
        for error in validate_plan(plan, registry, crypto, catalog)
    ]
    overdue: list[str] = []

    if case.get("schema_version") != "0.1":
        errors.append("migration case schema_version must be 0.1")
    if case.get("plan_id") != plan.get("plan_id"):
        errors.append("migration case plan_id mismatch")
    if case.get("plan_digest") != plan.get("plan_digest"):
        errors.append("migration case plan_digest mismatch")

    events = case.get("events")
    if not isinstance(events, list):
        errors.append("migration case events must be an array")
        events = []
    allowed_events = set(registry.get("event_types", []))
    seen_ids: set[str] = set()
    event_times: list[datetime] = []
    by_type: dict[str, list[dict[str, Any]]] = {}
    completed_dependents: set[str] = set()
    lifecycle = plan.get("current_status")
    lifecycle_rank = {
        "recommended": 0,
        "allowed": 0,
        "provisional": 0,
        "experimental": 0,
        "deprecated": 1,
        "legacy": 2,
        "prohibited": 3,
    }
    detected = _parse_time(
        plan.get("reason", {}).get("detected_at")
        if isinstance(plan.get("reason"), dict)
        else None,
        "migration reason.detected_at",
        errors,
    )

    for index, event in enumerate(events):
        prefix = f"migration events[{index}]"
        if not isinstance(event, dict):
            errors.append(f"{prefix} must be an object")
            continue
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            errors.append(f"{prefix} event_id must be non-empty")
        elif event_id in seen_ids:
            errors.append(f"{prefix} duplicate event_id {event_id}")
        else:
            seen_ids.add(event_id)
        event_type = event.get("event_type")
        if event_type not in allowed_events:
            errors.append(f"{prefix} invalid event_type {event_type}")
            continue
        occurred = _parse_time(event.get("occurred_at"), f"{prefix}.occurred_at", errors)
        if occurred is not None:
            if detected is not None and occurred < detected:
                errors.append(f"{prefix} cannot predate migration trigger")
            if event_times and occurred < event_times[-1]:
                errors.append("migration events must be chronological")
            event_times.append(occurred)
        _digest(event.get("evidence_digest"), f"{prefix}.evidence_digest", errors)
        if not isinstance(event.get("reference"), str) or not event["reference"]:
            errors.append(f"{prefix} reference must be non-empty")
        dependent_id = event.get("dependent_id")
        if event_type == "dependent-migrated":
            if not isinstance(dependent_id, str) or not dependent_id:
                errors.append(f"{prefix} dependent-migrated requires dependent_id")
            else:
                completed_dependents.add(dependent_id)
        elif dependent_id is not None:
            errors.append(f"{prefix} only dependent-migrated may set dependent_id")

        new_status = _event_status_effect(
            event_type, plan.get("legacy_processing_policy"), lifecycle
        )
        if (
            lifecycle in lifecycle_rank
            and new_status in lifecycle_rank
            and lifecycle_rank[new_status] < lifecycle_rank[lifecycle]
        ):
            errors.append(
                f"{prefix} lifecycle event would move backward from {lifecycle} to {new_status}"
            )
        lifecycle = new_status
        by_type.setdefault(event_type, []).append(event)

    timeline = plan.get("timeline", {})
    effective = _parse_time(timeline.get("effective_at"), "migration timeline.effective_at", errors)
    replacement_due = _parse_time(
        timeline.get("replacement_available_at"),
        "migration timeline.replacement_available_at",
        errors,
    )
    stop_due = _parse_time(
        timeline.get("new_use_stop_at"),
        "migration timeline.new_use_stop_at",
        errors,
    )
    legacy_due = _parse_time(
        timeline.get("legacy_processing_stop_at"),
        "migration timeline.legacy_processing_stop_at",
        errors,
    )
    prohibit_due = _parse_time(
        timeline.get("prohibit_at"),
        "migration timeline.prohibit_at",
        errors,
    )

    def first_time(event_type: str) -> datetime | None:
        items = by_type.get(event_type, [])
        if not items:
            return None
        local_errors: list[str] = []
        value = _parse_time(
            items[0].get("occurred_at"),
            f"migration first {event_type}",
            local_errors,
        )
        errors.extend(local_errors)
        return value

    mode = plan.get("mode")
    if mode == "planned":
        activate = first_time("activate-plan")
        if activate is not None and effective is not None and activate < effective:
            errors.append("activate-plan cannot predate effective_at")
        replacement_event = first_time("replacement-available")
        if (
            replacement_event is not None
            and replacement_due is not None
            and replacement_event > replacement_due
        ):
            errors.append("replacement became available after plan deadline")
        stop_event = first_time("stop-new-use")
        if stop_event is not None and stop_due is not None and stop_event > stop_due:
            errors.append("new-use stop occurred after deadline")
        prohibit_event = first_time("prohibit")
        if (
            prohibit_event is not None
            and prohibit_due is not None
            and prohibit_event > prohibit_due
        ):
            errors.append("prohibition occurred after deadline")
        if plan.get("legacy_processing_policy") != "hard-cutoff":
            legacy_event = first_time("enter-legacy-processing")
            if legacy_event is None and stop_event is not None:
                errors.append(
                    "bounded legacy policy requires enter-legacy-processing event"
                )
    elif mode == "emergency":
        emergency = first_time("emergency-stop")
        if emergency is not None and effective is not None and emergency > effective:
            errors.append("emergency stop occurred after effective deadline")
        if "prohibit" in by_type:
            errors.append("emergency-stop is the prohibition event; separate prohibit event is not allowed")
        review = first_time("post-emergency-review")
        if emergency is not None and review is not None:
            if review > emergency + timedelta(hours=24):
                errors.append("post-emergency review exceeded 24-hour deadline")
        if "activate-plan" in by_type:
            errors.append("emergency case must not use activate-plan")

    dependent_deadlines = {
        item.get("id"): _parse_time(
            item.get("deadline_at"),
            f"dependent {item.get('id')} deadline",
            errors,
        )
        for item in plan.get("dependents", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for dependent_id in completed_dependents:
        if dependent_id not in dependent_deadlines:
            errors.append(
                f"dependent-migrated references unknown plan dependent {dependent_id}"
            )

    now: datetime | None = None
    if as_of is not None:
        now = _parse_time(as_of, "migration as_of", errors)
    if now is not None:
        if mode == "planned":
            if effective is not None and now > effective and "activate-plan" not in by_type:
                overdue.append("plan activation is overdue")
            if (
                replacement_due is not None
                and now > replacement_due
                and "replacement-available" not in by_type
            ):
                overdue.append("replacement availability is overdue")
            if stop_due is not None and now > stop_due and "stop-new-use" not in by_type:
                overdue.append("new-use stop is overdue")
            if (
                prohibit_due is not None
                and now > prohibit_due
                and "prohibit" not in by_type
            ):
                overdue.append("prohibition is overdue")
            if (
                legacy_due is not None
                and now > legacy_due
                and plan.get("legacy_processing_policy") != "hard-cutoff"
                and "prohibit" not in by_type
            ):
                overdue.append("legacy-processing shutdown is overdue")
        elif mode == "emergency":
            if effective is not None and now > effective and "emergency-stop" not in by_type:
                overdue.append("emergency stop is overdue")
            emergency = first_time("emergency-stop")
            if (
                emergency is not None
                and now > emergency + timedelta(hours=24)
                and "post-emergency-review" not in by_type
            ):
                overdue.append("post-emergency review is overdue")

        for dependent_id, deadline in dependent_deadlines.items():
            if (
                deadline is not None
                and now > deadline
                and dependent_id not in completed_dependents
            ):
                overdue.append(
                    f"dependent migration is overdue: {dependent_id}"
                )

        all_dependents = set(dependent_deadlines)
        if (
            "complete" in by_type
            and all_dependents - completed_dependents
        ):
            errors.append("migration cannot complete with unresolved dependents")

    if case.get("case_digest") != compute_case_digest(case):
        errors.append("migration case_digest does not match canonical case")

    all_errors = sorted(set(errors))
    all_overdue = sorted(set(overdue))
    return MigrationCaseResult(
        valid=not all_errors and not all_overdue,
        lifecycle_status=lifecycle if isinstance(lifecycle, str) else None,
        completed_dependents=sorted(completed_dependents),
        errors=all_errors,
        overdue=all_overdue,
    )


def operation_allowed(
    plan: dict[str, Any],
    case: dict[str, Any],
    *,
    operation: str,
    as_of: str,
    material_created_at: str | None = None,
) -> bool:
    now = datetime.strptime(as_of, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    timeline = plan["timeline"]
    stop = datetime.strptime(
        timeline["new_use_stop_at"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    legacy_stop = (
        datetime.strptime(
            timeline["legacy_processing_stop_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        if timeline["legacy_processing_stop_at"] is not None
        else None
    )
    event_types: set[str] = set()
    for event in case.get("events", []):
        if not isinstance(event, dict):
            continue
        event_type = event.get("event_type")
        occurred_at = event.get("occurred_at")
        if not isinstance(event_type, str) or not isinstance(occurred_at, str):
            continue
        try:
            occurred = datetime.strptime(
                occurred_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if occurred <= now:
            event_types.add(event_type)
    stopped = "stop-new-use" in event_types or "emergency-stop" in event_types
    prohibited = "prohibit" in event_types or "emergency-stop" in event_types

    if operation in {"new-security-use", "negotiate", "key-or-state-creation"}:
        if stopped or prohibited or now >= stop:
            return False
        return True

    policy = plan["legacy_processing_policy"]
    if policy == "hard-cutoff":
        return False
    if legacy_stop is not None and now > legacy_stop:
        return False
    cutoff_text = plan["controls"]["historical_cutoff_at"]
    if cutoff_text is None or material_created_at is None:
        return False
    cutoff = datetime.strptime(cutoff_text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    created = datetime.strptime(
        material_created_at, "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    if created > cutoff:
        return False

    if operation == "historical-read-verify":
        return policy == "historical-read-verify-only"
    if operation == "migration-transform":
        return policy == "migration-only"
    return False


def project_registries(
    plan: dict[str, Any],
    case: dict[str, Any],
    crypto: dict[str, Any],
    catalog: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    projected_crypto = copy.deepcopy(crypto)
    projected_catalog = copy.deepcopy(catalog)
    errors: list[str] = []
    status = plan.get("current_status")
    for event in case.get("events", []):
        if not isinstance(event, dict):
            continue
        status = _event_status_effect(
            event.get("event_type"),
            plan.get("legacy_processing_policy"),
            status,
        )

    asset = plan.get("asset", {})
    kind = asset.get("kind")
    asset_id = asset.get("id")
    reason = (
        plan.get("reason", {}).get("summary")
        if isinstance(plan.get("reason"), dict)
        else "E2EESA migration"
    )

    if kind == "algorithm":
        algorithm = next(
            (
                item
                for item in projected_crypto.get("algorithms", [])
                if item.get("id") == asset_id
            ),
            None,
        )
        if algorithm is None:
            errors.append("projection cannot find target algorithm")
        else:
            algorithm["status"] = status
            if status in {"deprecated", "prohibited"}:
                algorithm["status_reason"] = reason
            elif "status_reason" in algorithm:
                algorithm.pop("status_reason", None)

            impacted = [
                suite
                for suite in projected_crypto.get("suites", [])
                if asset_id in suite.get("algorithm_ids", [])
            ]
            if status == "prohibited":
                impacted_ids = {suite.get("id") for suite in impacted}
                projected_crypto["suites"] = [
                    suite
                    for suite in projected_crypto.get("suites", [])
                    if suite.get("id") not in impacted_ids
                ]
            elif status in {"deprecated", "legacy"}:
                for suite in impacted:
                    suite_status = suite.get("status")
                    if (
                        suite_status in STATUS_RANK
                        and STATUS_RANK[suite_status] < STATUS_RANK[status]
                    ):
                        suite["status"] = status

    elif kind == "suite":
        suite = next(
            (
                item
                for item in projected_crypto.get("suites", [])
                if item.get("id") == asset_id
            ),
            None,
        )
        if suite is None:
            errors.append("projection cannot find target suite")
        else:
            suite["status"] = status

    elif kind == "profile":
        profile = next(
            (
                item
                for item in projected_catalog.get("profiles", [])
                if _profile_ref(item) == asset_id
            ),
            None,
        )
        if profile is None:
            errors.append("projection cannot find target profile")
        else:
            profile["status"] = status
    else:
        errors.append("projection has invalid asset kind")

    errors.extend(
        "projected crypto registry: " + error
        for error in crypto_registry.validate_registry(projected_crypto)
    )
    known_properties = None
    errors.extend(
        "projected profile catalog: " + error
        for error in profile_engine.validate_catalog(
            projected_catalog, known_property_ids=known_properties
        )
    )
    return projected_crypto, projected_catalog, sorted(set(errors))
