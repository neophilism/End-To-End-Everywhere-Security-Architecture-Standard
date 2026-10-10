#!/usr/bin/env python3
"""Evaluate E2EESA identity recovery and replacement authority.

Verified authorizers and trusted history are inputs from cryptographic or
transparency verification performed by a caller. This module validates their
composition; it never treats a service assertion or elapsed time as authority.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MODES = {"no-recovery", "retained-authority", "preauthorized-contact-threshold"}
HISTORY_SOURCES = {"retained-local-view", "key-transparency-proof"}
AUTHORIZER_TYPES = {"retained-authority", "contact", "account", "server", "support"}
OPERATIONS = {"recover-identity", "create-replacement"}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _id(value: Any) -> bool:
    return isinstance(value, str) and ID_RE.fullmatch(value) is not None


def _unique_ids(value: Any) -> bool:
    return isinstance(value, list) and all(_id(item) for item in value) and len(value) == len(set(value))


def validate_policy(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version", "policy_id", "mode", "trusted_history_source",
        "authorized_retained_authority_ids", "authorized_contact_ids",
        "contact_threshold", "allow_peer_verification_transfer",
        "allow_group_membership_transfer", "maturity",
    }
    extra = sorted(set(policy) - required)
    missing = sorted(required - policy.keys())
    if extra:
        errors.append(f"recovery policy: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"recovery policy: missing fields: {', '.join(missing)}")
    if policy.get("schema_version") != "0.1":
        errors.append("recovery policy: schema_version must be 0.1")
    if not _id(policy.get("policy_id")):
        errors.append("recovery policy: invalid policy_id")
    mode = policy.get("mode")
    if mode not in MODES:
        errors.append("recovery policy: unsupported mode")
    if policy.get("trusted_history_source") not in HISTORY_SOURCES:
        errors.append("recovery policy: unsupported trusted_history_source")
    retained = policy.get("authorized_retained_authority_ids")
    contacts = policy.get("authorized_contact_ids")
    if not _unique_ids(retained):
        errors.append("recovery policy: authorized_retained_authority_ids must be unique ids")
        retained = []
    if not _unique_ids(contacts):
        errors.append("recovery policy: authorized_contact_ids must be unique ids")
        contacts = []
    threshold = policy.get("contact_threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0:
        errors.append("recovery policy: contact_threshold must be a non-negative integer")
        threshold = 0
    if mode == "no-recovery" and (retained or contacts or threshold):
        errors.append("recovery policy: no-recovery must not configure recovery authorities")
    if mode == "retained-authority" and (len(retained) < 1 or contacts or threshold):
        errors.append("recovery policy: retained-authority requires retained authorities only")
    if mode == "preauthorized-contact-threshold":
        if retained:
            errors.append("recovery policy: contact threshold must not use retained authorities")
        if not contacts or threshold < 2 or threshold > len(contacts):
            errors.append("recovery policy: contact threshold must be between 2 and the authorized contact count")
    if policy.get("allow_peer_verification_transfer") is not False:
        errors.append("recovery policy: peer verification transfer is prohibited")
    if policy.get("allow_group_membership_transfer") is not False:
        errors.append("recovery policy: group membership transfer is prohibited")
    if policy.get("maturity") != "development-only":
        errors.append("recovery policy: AUD-08 mechanisms must remain development-only pending review")
    return errors


def validate_trusted_state(state: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version", "identity_id", "state_hash", "history_epoch",
        "history_source", "freshness_proof_id", "revoked_authority_ids",
    }
    extra = sorted(set(state) - required)
    missing = sorted(required - state.keys())
    if extra:
        errors.append(f"trusted state: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"trusted state: missing fields: {', '.join(missing)}")
    if state.get("schema_version") != "0.1":
        errors.append("trusted state: schema_version must be 0.1")
    if not _id(state.get("identity_id")):
        errors.append("trusted state: invalid identity_id")
    if not isinstance(state.get("state_hash"), str) or not HASH_RE.fullmatch(state.get("state_hash", "")):
        errors.append("trusted state: state_hash must be sha256:<64 lowercase hex>")
    epoch = state.get("history_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        errors.append("trusted state: history_epoch must be a non-negative integer")
    if state.get("history_source") not in HISTORY_SOURCES:
        errors.append("trusted state: unsupported history_source")
    if not _id(state.get("freshness_proof_id")):
        errors.append("trusted state: invalid freshness_proof_id")
    if not _unique_ids(state.get("revoked_authority_ids")):
        errors.append("trusted state: revoked_authority_ids must be unique ids")
    return errors


def validate_event(event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version", "event_id", "operation", "prior_identity_id",
        "prior_state_hash", "observed_history_epoch", "resulting_identity_id",
        "resulting_state_hash", "freshness_proof_id", "verified_authorizers",
        "account_delay_elapsed",
    }
    extra = sorted(set(event) - required)
    missing = sorted(required - event.keys())
    if extra:
        errors.append(f"recovery event: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"recovery event: missing fields: {', '.join(missing)}")
    if event.get("schema_version") != "0.1":
        errors.append("recovery event: schema_version must be 0.1")
    for field in ("event_id", "prior_identity_id", "resulting_identity_id", "freshness_proof_id"):
        if not _id(event.get(field)):
            errors.append(f"recovery event: invalid {field}")
    if event.get("operation") not in OPERATIONS:
        errors.append("recovery event: unsupported operation")
    for field in ("prior_state_hash", "resulting_state_hash"):
        if not isinstance(event.get(field), str) or not HASH_RE.fullmatch(event.get(field, "")):
            errors.append(f"recovery event: {field} must be sha256:<64 lowercase hex>")
    epoch = event.get("observed_history_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        errors.append("recovery event: observed_history_epoch must be a non-negative integer")
    if not isinstance(event.get("account_delay_elapsed"), bool):
        errors.append("recovery event: account_delay_elapsed must be boolean")
    authorizers = event.get("verified_authorizers")
    if not isinstance(authorizers, list) or not authorizers:
        errors.append("recovery event: verified_authorizers must be a non-empty array")
        authorizers = []
    seen: set[tuple[str, str]] = set()
    fields = {"type", "id", "prior_state_hash", "resulting_identity_id", "observed_history_epoch"}
    for index, authorizer in enumerate(authorizers):
        prefix = f"recovery event: verified_authorizers[{index}]"
        if not isinstance(authorizer, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if set(authorizer) != fields:
            errors.append(f"{prefix} fields must be exactly {', '.join(sorted(fields))}")
        kind = authorizer.get("type")
        aid = authorizer.get("id")
        if kind not in AUTHORIZER_TYPES:
            errors.append(f"{prefix}: unsupported type")
        if not _id(aid):
            errors.append(f"{prefix}: invalid id")
        elif isinstance(kind, str):
            marker = (kind, aid)
            if marker in seen:
                errors.append("recovery event: verified_authorizers must be unique")
            seen.add(marker)
        if not isinstance(authorizer.get("prior_state_hash"), str) or not HASH_RE.fullmatch(authorizer.get("prior_state_hash", "")):
            errors.append(f"{prefix}: invalid prior_state_hash")
        if not _id(authorizer.get("resulting_identity_id")):
            errors.append(f"{prefix}: invalid resulting_identity_id")
        auth_epoch = authorizer.get("observed_history_epoch")
        if not isinstance(auth_epoch, int) or isinstance(auth_epoch, bool) or auth_epoch < 0:
            errors.append(f"{prefix}: observed_history_epoch must be non-negative")
    return errors


def evaluate_recovery(
    policy: dict[str, Any],
    trusted_state: dict[str, Any],
    event: dict[str, Any],
) -> dict[str, Any]:
    errors = validate_policy(policy) + validate_trusted_state(trusted_state) + validate_event(event)
    if errors:
        return {"valid": False, "decision": "invalid", "errors": errors}

    if policy["trusted_history_source"] != trusted_state["history_source"]:
        errors.append("trusted history source does not match policy")
    if event["prior_identity_id"] != trusted_state["identity_id"]:
        errors.append("event prior identity does not match trusted history")
    if event["prior_state_hash"] != trusted_state["state_hash"]:
        errors.append("event prior state is stale or does not match trusted history")
    if event["observed_history_epoch"] != trusted_state["history_epoch"]:
        errors.append("event history epoch is stale or concurrent")
    if event["freshness_proof_id"] != trusted_state["freshness_proof_id"]:
        errors.append("event freshness proof does not match trusted history")

    valid_authorizers: list[dict[str, Any]] = []
    revoked = set(trusted_state["revoked_authority_ids"])
    for authorizer in event["verified_authorizers"]:
        if authorizer["prior_state_hash"] != trusted_state["state_hash"]:
            errors.append(f"authorizer {authorizer['id']} did not bind the trusted prior state")
        if authorizer["resulting_identity_id"] != event["resulting_identity_id"]:
            errors.append(f"authorizer {authorizer['id']} did not bind the resulting identity")
        if authorizer["observed_history_epoch"] != trusted_state["history_epoch"]:
            errors.append(f"authorizer {authorizer['id']} used a stale history epoch")
        if authorizer["id"] in revoked:
            errors.append(f"authorizer {authorizer['id']} was revoked in trusted history")
        if (
            authorizer["prior_state_hash"] == trusted_state["state_hash"]
            and authorizer["resulting_identity_id"] == event["resulting_identity_id"]
            and authorizer["observed_history_epoch"] == trusted_state["history_epoch"]
            and authorizer["id"] not in revoked
        ):
            valid_authorizers.append(authorizer)

    forbidden = [a for a in valid_authorizers if a["type"] in {"account", "server", "support"}]
    if forbidden:
        errors.append("account, server, support, and elapsed-delay evidence are not cryptographic recovery authority")

    mode = policy["mode"]
    decision = "denied"
    if mode == "no-recovery":
        errors.append("policy explicitly provides no recovery; create an unlinked replacement identity")
    elif mode == "retained-authority":
        if event["operation"] != "recover-identity":
            errors.append("retained authority requires recover-identity")
        if event["resulting_identity_id"] != event["prior_identity_id"]:
            errors.append("retained authority recovery must preserve the identity id")
        allowed = set(policy["authorized_retained_authority_ids"])
        accepted = {a["id"] for a in valid_authorizers if a["type"] == "retained-authority" and a["id"] in allowed}
        if not accepted:
            errors.append("no valid pre-authorized retained authority")
        decision = "recovered-identity"
    elif mode == "preauthorized-contact-threshold":
        if event["operation"] != "create-replacement":
            errors.append("contact threshold authorizes replacement, not inherited continuity")
        if event["resulting_identity_id"] == event["prior_identity_id"]:
            errors.append("replacement identity must use a new identity id")
        allowed = set(policy["authorized_contact_ids"])
        accepted = {a["id"] for a in valid_authorizers if a["type"] == "contact" and a["id"] in allowed}
        if len(accepted) < policy["contact_threshold"]:
            errors.append(
                f"contact threshold requires {policy['contact_threshold']} distinct pre-authorized contacts; got {len(accepted)}"
            )
        decision = "replacement-identity"

    if errors:
        return {"valid": False, "decision": "denied", "errors": errors}

    return {
        "valid": True,
        "decision": decision,
        "errors": [],
        "production_eligible": False,
        "independent_review": "pending",
        "peer_verification": "reverification-required",
        "group_membership": "explicit-reenrollment-required",
        "revocation_scope": "new protected content after accepted transition; offline peers require synchronized history",
        "limitations": [
            "service account state and elapsed delay do not establish cryptographic authority",
            "global erasure or immediate offline-peer revocation is not claimed",
            "registry presence does not establish protocol maturity or production approval",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate an E2EESA identity recovery event.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("trusted_state", type=Path)
    parser.add_argument("event", type=Path)
    args = parser.parse_args()
    try:
        result = evaluate_recovery(load_json(args.policy), load_json(args.trusted_state), load_json(args.event))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        result = {"valid": False, "decision": "invalid", "errors": [str(exc)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
