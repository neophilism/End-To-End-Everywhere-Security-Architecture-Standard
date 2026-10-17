#!/usr/bin/env python3
"""AUD-11 reference hardware recovery attempt reservation model.

This is NOT an HSM, attestation verifier, hardware rate limiter or proof of
non-resettable counters. It checks selected policy and receipt consistency.
Actual release MUST be gated by an attested hardware-enforced atomic reservation
and independent monotonic evidence shared by every authorized replica.
"""
from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from canonical_serialization import canonical_bytes

ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
POLICY_FIELDS = {
    "schema_version", "policy_id", "budget_id", "secret_class",
    "maximum_attempts", "authority_mode", "hardware_id",
    "approved_code_measurement", "approved_policy_digest",
    "replica_ids", "authenticated_initiators", "reset_authority_ids",
}
STATE_FIELDS = {
    "schema_version", "policy_id", "budget_id", "epoch",
    "attempts_used", "counter", "replica_ids",
}
RECEIPT_FIELDS = {
    "hardware_id", "code_measurement", "policy_digest", "replica_id",
    "epoch", "counter", "attestation_evidence_ref",
}
REQUEST_FIELDS = {
    "operation", "initiator_id", "authentication_evidence_ref",
    "replica_id", "reset_authority_id", "reset_evidence_ref",
}


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _id(x: Any) -> bool:
    return isinstance(x, str) and ID.fullmatch(x) is not None


def _digest(x: Any) -> bool:
    return isinstance(x, str) and DIGEST.fullmatch(x) is not None


def _ids(x: Any) -> bool:
    return isinstance(x, list) and bool(x) and all(_id(a) for a in x) and len(set(x)) == len(x)


def _exact(doc: Any, keys: set[str], name: str) -> None:
    _require(isinstance(doc, dict) and set(doc) == keys, f"{name} fields invalid")


def _natural(x: Any, positive: bool = False) -> bool:
    return type(x) is int and (x > 0 if positive else x >= 0)


def validate_policy(policy: dict[str, Any]) -> None:
    _exact(policy, POLICY_FIELDS, "budget policy")
    _require(policy["schema_version"] == "0.1", "unsupported budget policy version")
    for field in ("policy_id", "budget_id", "hardware_id"):
        _require(_id(policy[field]), "invalid " + field)
    for field in ("approved_code_measurement", "approved_policy_digest"):
        _require(_digest(policy[field]), "invalid " + field)
    _require(isinstance(policy["secret_class"], str) and policy["secret_class"]
             in {"user-chosen-low-entropy", "generated-high-entropy"}, "unknown secret class")
    _require(_natural(policy["maximum_attempts"], positive=True) and policy["maximum_attempts"] <= 1000,
             "maximum_attempts must be an explicit bounded policy")
    _require(isinstance(policy["authority_mode"], str) and
             policy["authority_mode"] in {"single-hardware-counter", "shared-monotonic-counter"},
             "invalid cross-replica counter authority")
    _require(_ids(policy["replica_ids"]), "at least one uniquely declared replica required")
    if policy["authority_mode"] == "single-hardware-counter":
        _require(len(policy["replica_ids"]) == 1, "single hardware counter cannot cover extra replicas")
    _require(_ids(policy["authenticated_initiators"]), "authenticated initiator ids required")
    _require(isinstance(policy["reset_authority_ids"], list) and
             all(_id(a) for a in policy["reset_authority_ids"]) and
             len(policy["reset_authority_ids"]) == len(set(policy["reset_authority_ids"])),
             "invalid reset authority set")


def validate_state(state: dict[str, Any], policy: dict[str, Any]) -> None:
    validate_policy(policy)
    _exact(state, STATE_FIELDS, "budget state")
    _require(state["schema_version"] == "0.1", "unsupported state version")
    _require(state["policy_id"] == policy["policy_id"] and
             state["budget_id"] == policy["budget_id"], "budget state policy binding mismatch")
    _require(_natural(state["epoch"]) and _natural(state["counter"]) and _natural(state["attempts_used"]),
             "negative or nonintegral attempt count")
    _require(state["attempts_used"] <= policy["maximum_attempts"], "budget overrun")
    _require(state["counter"] >= state["attempts_used"] + state["epoch"], "counter rollback across epochs")
    _require(state["replica_ids"] == policy["replica_ids"], "replica registry substitution")


def state_digest(state: dict[str, Any], policy: dict[str, Any]) -> str:
    validate_state(state, policy)
    payload = b"E2EESA-AUD11-BUDGET-v1\x00" + canonical_bytes(state)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def new_budget_state(policy: dict[str, Any]) -> dict[str, Any]:
    validate_policy(policy)
    return {
        "schema_version": "0.1",
        "policy_id": policy["policy_id"],
        "budget_id": policy["budget_id"],
        "epoch": 0,
        "attempts_used": 0,
        "counter": 0,
        "replica_ids": list(policy["replica_ids"]),
    }


def _preconditions(
    policy: dict[str, Any], state: dict[str, Any],
    receipt: dict[str, Any], request: dict[str, Any], *,
    trusted_head: str | None,
) -> str | None:
    validate_state(state, policy)
    if not _digest(trusted_head) or state_digest(state, policy) != trusted_head:
        return "untrusted-or-rolled-back-counter-state"
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        return "attestation-receipt-required"
    if (receipt["hardware_id"] != policy["hardware_id"]
            or receipt["code_measurement"] != policy["approved_code_measurement"]
            or receipt["policy_digest"] != policy["approved_policy_digest"]):
        return "hardware-or-measurement-mismatch"
    if not _id(receipt["attestation_evidence_ref"]):
        return "no-externally-verifiable-attestation-reference"
    if (not _id(receipt["replica_id"]) or
            receipt["replica_id"] not in policy["replica_ids"]):
        return "unregistered-hardware-replica"
    if (type(receipt["epoch"]) is not int or type(receipt["counter"]) is not int
            or receipt["epoch"] != state["epoch"] or receipt["counter"] != state["counter"]):
        return "hardware-counter-or-epoch-mismatch"

    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS:
        return "invalid-recovery-request"
    if request["operation"] not in {"guess", "reset"}:
        return "unsupported-recovery-operation"
    if (not _id(request["initiator_id"]) or
            request["initiator_id"] not in policy["authenticated_initiators"] or
            not _id(request["authentication_evidence_ref"])):
        return "unauthenticated-attempt-initiation"
    if request["replica_id"] != receipt["replica_id"]:
        return "replica-substitution"
    return None


def reserve(
    policy: dict[str, Any], state: dict[str, Any],
    receipt: dict[str, Any], request: dict[str, Any], *,
    trusted_head: str | None,
) -> dict[str, Any]:
    """Plan a reservation only; do not release a secret.

    The host MUST verify the actual attestation, authentication references
    and hardware counter, atomically advance the hardware counter and shared
    independent head BEFORE checking the guess / releasing outer envelope.
    """

    issue = _preconditions(policy, state, receipt, request, trusted_head=trusted_head)
    def deny(reason: str) -> dict[str, Any]:
        return {"preconditions_met": False, "reason": reason,
                "may_release_secret": False, "proposed_state": None}
    if issue:
        return deny(issue)

    next_state = copy.deepcopy(state)
    if request["operation"] == "guess":
        if request["reset_authority_id"] is not None or request["reset_evidence_ref"] is not None:
            return deny("normal-guess-cannot-reset-counter")
        if state["attempts_used"] >= policy["maximum_attempts"]:
            return deny("recovery-budget-exhausted")
        next_state["attempts_used"] += 1
        next_state["counter"] += 1
    else:
        if (not _id(request["reset_authority_id"]) or
                request["reset_authority_id"] not in policy["reset_authority_ids"] or
                not _id(request["reset_evidence_ref"])):
            return deny("separate-reset-authority-required")
        next_state["epoch"] += 1
        next_state["counter"] += 1
        next_state["attempts_used"] = 0

    return {
        "preconditions_met": True,
        "reason": "atomic-hardware-reservation-required",
        "may_release_secret": False,
        "proposed_state": next_state,
        "proposed_head": state_digest(next_state, policy),
        "assurance": "reference-consistency-only-no-attestation-or-hardware-proof",
    }
