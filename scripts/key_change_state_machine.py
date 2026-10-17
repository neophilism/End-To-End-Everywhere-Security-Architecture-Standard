#!/usr/bin/env python3
"""AUD-09: deterministic key-change journal and fail-closed send decisions.

This is a *reference* state transition engine, not an endpoint UI, identity
proof verifier, or durable store. Callers MUST authenticate accepted identity
state and atomically commit the journal plus independent monotonic head anchor
before relying on a returned decision.
"""
from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from canonical_serialization import canonical_bytes
import key_verification_engine

SCHEMA = "0.1"
ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HEX = re.compile(r"^(?:[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$")
HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
MODES = {"strict-reverification", "acknowledge-change"}
CHANGE_CLASSES = {"authorized-subordinate", "identity-replacement", "unverified-change"}
EVENT_KINDS = {"observed", "acknowledged", "verified"}


def require(test: bool, message: str) -> None:
    if not test:
        raise ValueError(message)


def valid_id(value: Any) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def valid_subject(value: Any) -> bool:
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _sha256(domain: bytes, value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\x00" + canonical_bytes(value)).hexdigest()


def policy_check(policy: dict[str, Any]) -> None:
    require(isinstance(policy, dict) and set(policy) == {"schema_version", "policy_id", "mode"},
            "policy must have exactly schema_version, policy_id and mode")
    require(policy["schema_version"] == SCHEMA, "unsupported policy schema")
    require(valid_id(policy["policy_id"]), "invalid policy id")
    require(policy["mode"] in MODES, "unsupported send policy")


def new_state(*, peer_id: str, initial_subject_digest: str, policy: dict[str, Any]) -> dict[str, Any]:
    policy_check(policy)
    require(valid_id(peer_id), "invalid peer id")
    require(valid_subject(initial_subject_digest), "invalid initial subject")
    return {
        "schema_version": SCHEMA,
        "peer_id": peer_id,
        "policy_id": policy["policy_id"],
        "initial_subject_digest": initial_subject_digest,
        "events": [],
    }


def _genesis(state: dict[str, Any]) -> str:
    return _sha256(
        b"E2EESA-AUD09-GENESIS-v1",
        {key: state[key] for key in ("schema_version", "peer_id", "policy_id", "initial_subject_digest")},
    )


def _event_digest(event: dict[str, Any]) -> str:
    return _sha256(b"E2EESA-AUD09-EVENT-v1", {key: value for key, value in event.items() if key != "event_hash"})


def inspect_state(state: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Replay and validate the entire journal. Fail on altered/missing events.

    The caller MUST additionally compare the returned head with an independently
    persisted trusted head/revision; a self-contained hash chain cannot detect
    rollback of a whole valid prefix.
    """
    policy_check(policy)
    require(isinstance(state, dict), "state must be an object")
    require(set(state) == {"schema_version", "peer_id", "policy_id", "initial_subject_digest", "events"},
            "unknown or missing state fields")
    require(state["schema_version"] == SCHEMA, "unsupported state schema")
    require(valid_id(state["peer_id"]), "invalid peer id")
    require(state["policy_id"] == policy["policy_id"], "policy binding mismatch")
    require(valid_subject(state["initial_subject_digest"]), "invalid initial subject")
    require(isinstance(state["events"], list) and len(state["events"]) <= 10000, "invalid event history")

    subject = state["initial_subject_digest"]
    head = _genesis(state)
    verified = False
    ever_verified = False
    acknowledged = False
    classification = None
    change_seq = None
    prior_verified = False
    record_ids: set[str] = set()
    notices: list[dict[str, Any]] = []

    for seq, event in enumerate(state["events"], start=1):
        require(isinstance(event, dict) and set(event) == {
            "sequence", "kind", "subject_digest", "change_class", "authority_evidence_ref",
            "verification_record_id", "was_verified", "previous_event_hash", "event_hash",
        }, f"invalid event fields at sequence {seq}")
        require(type(event["sequence"]) is int and event["sequence"] == seq, "nonmonotonic event sequence")
        require(event["kind"] in EVENT_KINDS, "invalid event kind")
        require(valid_subject(event["subject_digest"]), "invalid event subject digest")
        require(event["previous_event_hash"] == head, "event hash-chain predecessor mismatch")
        require(event["event_hash"] == _event_digest(event), "event digest mismatch")

        if event["kind"] == "observed":
            require(event["subject_digest"] != subject, "unchanged subject cannot produce change event")
            require(event["change_class"] in CHANGE_CLASSES, "invalid change classification")
            evidence = event["authority_evidence_ref"]
            if event["change_class"] == "authorized-subordinate":
                require(valid_id(evidence), "authorized subordinate change requires trusted evidence ref")
            else:
                require(evidence is None, "unsupported evidence on unverified/replacement change")
            require(event["verification_record_id"] is None, "observation cannot mark verified")
            require(type(event["was_verified"]) is bool and event["was_verified"] == verified,
                    "observation prior trust mismatch")
            subject = event["subject_digest"]
            prior_verified = verified
            verified = False
            acknowledged = False
            classification = event["change_class"]
            change_seq = seq
            notices.append({
                "sequence": seq,
                "kind": "cryptographic-subject-change",
                "classification": classification,
                "previously_verified": prior_verified,
                "new_subject_digest": subject,
                "requires_user_notice": True,
                "requires_fresh_comparison": prior_verified or classification == "identity-replacement",
                "message_key": "security.identity-replacement" if classification == "identity-replacement"
                    else "security.verified-key-change" if prior_verified else "security.unverified-key-change",
            })

        elif event["kind"] == "acknowledged":
            require(change_seq is not None and not acknowledged and not verified, "no pending notice to acknowledge")
            require(event["subject_digest"] == subject, "acknowledgement subject mismatch")
            require(event["change_class"] is None and event["authority_evidence_ref"] is None
                    and event["verification_record_id"] is None and event["was_verified"] is None,
                    "acknowledgement cannot supply new trust")
            acknowledged = True

        else:
            record = event["verification_record_id"]
            require(valid_id(record) and record not in record_ids, "fresh unique manual record required")
            require(event["subject_digest"] == subject, "verification subject mismatch")
            require(event["change_class"] is None and event["authority_evidence_ref"] is None
                    and event["was_verified"] is None, "verification may not rewrite identity-change evidence")
            record_ids.add(record)
            verified = True
            ever_verified = True
            acknowledged = True

        head = event["event_hash"]

    return {
        "head": head,
        "revision": len(state["events"]),
        "subject_digest": subject,
        "trust": "verified" if verified else "invalidated" if ever_verified else "unverified",
        "acknowledged": acknowledged,
        "change_class": classification,
        "last_change_sequence": change_seq,
        "notices": notices,
        "verification_record_ids": sorted(record_ids),
    }


def _append(state: dict[str, Any], policy: dict[str, Any], event: dict[str, Any], *, expected_head: str) -> dict[str, Any]:
    inspected = inspect_state(state, policy)
    require(valid_hash(expected_head) and expected_head == inspected["head"],
            "trusted history anchor missing or stale")
    result = copy.deepcopy(state)
    full_event = {
        "sequence": inspected["revision"] + 1,
        "kind": event["kind"],
        "subject_digest": event["subject_digest"],
        "change_class": event["change_class"],
        "authority_evidence_ref": event["authority_evidence_ref"],
        "verification_record_id": event["verification_record_id"],
        "was_verified": event["was_verified"],
        "previous_event_hash": inspected["head"],
    }
    full_event["event_hash"] = _event_digest(full_event)
    result["events"].append(full_event)
    inspect_state(result, policy)
    return result


def valid_hash(value: Any) -> bool:
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def observe(
    state: dict[str, Any], policy: dict[str, Any], *,
    accepted_subject_digest: str, classification: str,
    authority_evidence_ref: str | None = None, trusted_head: str,
) -> dict[str, Any]:
    """Record every observed change (including changes to unverified peers).

    The caller verifies identity-transition evidence BEFORE choosing
    authorized-subordinate; arbitrary service assertions do not qualify.
    The caller atomically persists the returned journal and trusted head
    before using it for any send or displayed trust decision.
    """
    old = inspect_state(state, policy)
    require(old["head"] == trusted_head, "trusted history anchor missing or stale")
    require(valid_subject(accepted_subject_digest), "invalid accepted subject")
    if accepted_subject_digest == old["subject_digest"]:
        return copy.deepcopy(state)
    require(classification in CHANGE_CLASSES, "invalid change classification")
    require(
        classification != "authorized-subordinate" or valid_id(authority_evidence_ref),
        "authorized subordinate change requires independently verified evidence ref",
    )
    require(
        classification == "authorized-subordinate" or authority_evidence_ref is None,
        "untrusted classification may not carry authorization evidence",
    )
    return _append(
        state, policy, {
            "kind": "observed", "subject_digest": accepted_subject_digest,
            "change_class": classification,
            "authority_evidence_ref": authority_evidence_ref,
            "verification_record_id": None,
            "was_verified": old["trust"] == "verified",
        }, expected_head=trusted_head,
    )


def acknowledge(
    state: dict[str, Any], policy: dict[str, Any], *,
    noticed_change_sequence: int, trusted_head: str,
) -> dict[str, Any]:
    old = inspect_state(state, policy)
    require(old["head"] == trusted_head, "trusted history anchor missing or stale")
    require(type(noticed_change_sequence) is int and noticed_change_sequence == old["last_change_sequence"],
            "acknowledgement must reference latest change notice")
    return _append(
        state, policy, {
            "kind": "acknowledged", "subject_digest": old["subject_digest"],
            "change_class": None, "authority_evidence_ref": None,
            "verification_record_id": None, "was_verified": None,
        }, expected_head=trusted_head,
    )


def confirm_manual_verification(
    state: dict[str, Any], policy: dict[str, Any], *,
    trusted_head: str, record: dict[str, Any],
    verification_policy: dict[str, Any], first_snapshot: dict[str, Any],
    second_snapshot: dict[str, Any], crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
) -> dict[str, Any]:
    old = inspect_state(state, policy)
    require(old["head"] == trusted_head, "trusted history anchor missing or stale")
    require(isinstance(record, dict), "manual comparison record required")
    errors = key_verification_engine.validate_record(
        record, verification_policy, first_snapshot, second_snapshot, crypto_registry, profile_catalog
    )
    require(not errors, "invalid manual comparison: " + "; ".join(errors))
    status = key_verification_engine.verification_status(
        record, verification_policy, first_snapshot, second_snapshot, crypto_registry, profile_catalog
    )
    require(status["status"] == "verified" and record.get("user_confirmed") is True,
            "fresh explicit out-of-band comparison required")
    require(record["subject_digest_hex"] == old["subject_digest"], "verification subject is stale")
    require(record["record_id"] not in old["verification_record_ids"], "manual verification record replay")
    return _append(
        state, policy, {
            "kind": "verified", "subject_digest": old["subject_digest"],
            "change_class": None, "authority_evidence_ref": None,
            "verification_record_id": record["record_id"], "was_verified": None,
        }, expected_head=trusted_head,
    )


def send_decision(
    state: dict[str, Any], policy: dict[str, Any], *,
    target_subject_digest: str, trusted_head: str | None,
    queued_subject_digest: str | None = None, queued_revision: int | None = None,
) -> dict[str, Any]:
    """Deny if history is not independently anchored, target changed, or a queued
    message predates any change (including subject A -> B -> A).
    """
    current = inspect_state(state, policy)
    def decision(allow: bool, reason: str) -> dict[str, Any]:
        return {
            "allowed": allow, "reason": reason, "trust": current["trust"],
            "current_subject_digest": current["subject_digest"],
            "requires_visible_notice": current["trust"] != "verified",
            "latest_change_sequence": current["last_change_sequence"],
        }
    if not valid_hash(trusted_head) or trusted_head != current["head"]:
        return decision(False, "trusted-history-anchor-mismatch")
    if not valid_subject(target_subject_digest) or target_subject_digest != current["subject_digest"]:
        return decision(False, "recipient-subject-mismatch")
    if (queued_subject_digest is None) != (queued_revision is None):
        return decision(False, "invalid-queued-recipient-binding")
    if queued_subject_digest is not None:
        if not valid_subject(queued_subject_digest) or type(queued_revision) is not int:
            return decision(False, "invalid-queued-recipient-binding")
        if queued_revision < 0 or queued_revision > current["revision"]:
            return decision(False, "invalid-queued-recipient-binding")
        if queued_subject_digest != target_subject_digest:
            return decision(False, "queued-recipient-mismatch")
        if any(
            e["kind"] == "observed" and e["sequence"] > queued_revision
            for e in state["events"]
        ):
            return decision(False, "queued-content-requires-fresh-authorization")
    if current["trust"] == "verified":
        return decision(True, "fresh-manual-verification")
    if current["change_class"] == "identity-replacement":
        return decision(False, "replacement-requires-fresh-verification")
    if policy["mode"] == "acknowledge-change" and current["acknowledged"] and current["last_change_sequence"] is not None:
        return decision(True, "explicitly-acknowledged-unverified-change")
    return decision(False, "manual-reverification-required" if policy["mode"] == "strict-reverification"
                    else "unacknowledged-or-unverified-recipient")
