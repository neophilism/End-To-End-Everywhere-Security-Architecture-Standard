#!/usr/bin/env python3
"""AUD-15: applied group updates and claims are not inferred from proposals.

This is a consistency checker for trusted evidence, not an MLS, sender-key or
pairwise cryptographic implementation. Its outputs MUST NOT be treated as a
signature, key-generation, transcript-authentication or deployment proof.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
import canonical_serialization
import group_e2ee_engine

HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENT = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
RECEIPT_FIELDS = {
    "schema_version", "group_id", "profile_ref", "previous_epoch",
    "applied_epoch", "operation_kind", "commit_status",
    "prior_state_digest", "applied_state_digest", "membership_digest",
    "authorizer_evidence_ref", "transition_proof_ref", "commit_digest",
    "claims_post_quantum_group_confidentiality",
}
TRUST_FIELDS = {
    "group_id", "previous_epoch", "previous_state_digest",
    "independently_verified_commit_digest",
}
KINDS = {
    "group-mls-rfc9420@0.1.0": "mls-applied-commit",
    "group-sender-key-aead@0.1.0": "sender-state-rotation",
    "group-pairwise-fanout@0.1.0": "pairwise-membership-update",
}


def _hash(value: Any, domain: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\x00" +
                                      canonical_serialization.canonical_bytes(value)).hexdigest()


def membership_commitment(members: list[str]) -> str:
    if not isinstance(members, list) or not members or not all(
        isinstance(x, str) and IDENT.fullmatch(x) for x in members
    ) or len(members) != len(set(members)):
        raise ValueError("invalid authorized membership list")
    return _hash(sorted(members), b"E2EESA-GROUP-MEMBERS-v1")


def commit_digest(receipt: dict[str, Any]) -> str:
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise ValueError("invalid applied transition receipt shape")
    return _hash({k: v for k, v in receipt.items() if k != "commit_digest"},
                 b"E2EESA-GROUP-APPLIED-COMMIT-v1")


def evaluate(
    policy: dict[str, Any], event: dict[str, Any], checkpoint: dict[str, Any],
    receipt: dict[str, Any], trusted: dict[str, Any], group_registry: dict[str, Any],
    crypto_registry: dict[str, Any], profile_catalog: dict[str, Any],
) -> dict[str, Any]:
    def fail(reason: str) -> dict[str, Any]:
        return {"consistent": False, "reason": reason, "cryptographically_verified": False}

    validation = group_e2ee_engine.validate_group_case(
        policy, event, checkpoint, group_registry, crypto_registry, profile_catalog
    )
    if validation:
        return fail("invalid-group-epoch-membership-or-message")
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        return fail("missing-applied-transition-receipt")
    if not isinstance(trusted, dict) or set(trusted) != TRUST_FIELDS:
        return fail("missing-independent-prior-state-and-commit-anchor")
    if receipt["schema_version"] != "0.1":
        return fail("invalid-update-receipt-version")
    profile = policy.get("profile_ref")
    if not isinstance(profile, str) or profile not in KINDS:
        return fail("unsupported-group-profile")
    if receipt["profile_ref"] != profile or receipt["operation_kind"] != KINDS[profile]:
        return fail("wrong-group-update-construction")
    if receipt["commit_status"] != "applied":
        return fail("proposal-or-queued-update-is-not-committed")
    if (type(receipt["previous_epoch"]) is not int or type(receipt["applied_epoch"]) is not int
            or receipt["previous_epoch"] != event["previous_epoch"]
            or receipt["applied_epoch"] != event["new_epoch"]):
        return fail("unapplied-or-stale-group-epoch")
    if not isinstance(receipt["group_id"], str) or receipt["group_id"] != event["group_id"]:
        return fail("group-id-mismatch")
    if receipt["claims_post_quantum_group_confidentiality"] is not False:
        return fail("unsupported-group-post-quantum-claim")
    if any(not isinstance(receipt[key], str) or not HASH.fullmatch(receipt[key])
           for key in ("prior_state_digest", "applied_state_digest", "membership_digest", "commit_digest")):
        return fail("invalid-state-or-commitment-digest")
    if receipt["prior_state_digest"] == receipt["applied_state_digest"]:
        return fail("no-new-keyed-group-state")
    if any(not isinstance(receipt[key], str) or not IDENT.fullmatch(receipt[key])
           for key in ("authorizer_evidence_ref", "transition_proof_ref")):
        return fail("missing-authorization-or-application-proof-reference")
    try:
        actual_members = membership_commitment(event["new_member_device_ids"])
        actual_digest = commit_digest(receipt)
    except (ValueError, TypeError):
        return fail("malformed-group-commitment")
    if receipt["membership_digest"] != actual_members:
        return fail("committed-recipient-set-mismatch")
    if receipt["commit_digest"] != actual_digest:
        return fail("tampered-group-update-receipt")

    # The trusted anchor is a separate API input from a host that authenticated
    # the prior state and this *applied*, not proposed, update receipt.
    if (trusted["group_id"] != receipt["group_id"] or
        type(trusted["previous_epoch"]) is not int or
        trusted["previous_epoch"] != receipt["previous_epoch"] or
        trusted["previous_state_digest"] != receipt["prior_state_digest"] or
        trusted["independently_verified_commit_digest"] != receipt["commit_digest"]):
        return fail("independent-group-state-or-commit-anchor-mismatch")
    return {"consistent": True, "reason": "applied-update-consistency-only",
            "cryptographically_verified": False}
