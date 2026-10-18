"""AUD-15 reference-only group healing and flow-specific assurance evaluator.

Does not implement MLS, cryptography, sender-key distribution or endpoint measurement.
"""
from __future__ import annotations

FLOWS = {"direct_message", "group_message", "media", "attachment", "backup"}


def evaluate_group_healing(record):
    def deny(reason):
        return {"healed": False, "reason": reason, "endpoint_verified": False}
    fields = {
        "group_profile", "accepted_epoch", "compromise_epoch",
        "applied_update_epoch", "applied_commit_verified",
        "fresh_secret_contribution_verified", "stale_members_excluded",
        "sender_distribution_verified", "endpoint_still_compromised",
    }
    if not isinstance(record, dict) or set(record) != fields:
        return deny("malformed-evidence")
    if record["group_profile"] not in ("group-mls-rfc9420@0.1.0",
                                      "group-sender-key-aead@0.1.0"):
        return deny("unsupported-group-profile")
    for key in ("accepted_epoch", "compromise_epoch", "applied_update_epoch"):
        if type(record[key]) is not int or record[key] < 0:
            return deny("invalid-epoch")
    for key in ("applied_commit_verified", "fresh_secret_contribution_verified",
                "stale_members_excluded", "sender_distribution_verified",
                "endpoint_still_compromised"):
        if type(record[key]) is not bool:
            return deny("malformed-verification-flag")
    if record["endpoint_still_compromised"]:
        return deny("ongoing-endpoint-compromise")
    if not record["applied_commit_verified"]:
        return deny("proposal-or-timer-is-not-applied-update")
    if record["applied_update_epoch"] <= record["compromise_epoch"]:
        return deny("no-post-compromise-applied-update")
    if record["applied_update_epoch"] > record["accepted_epoch"]:
        return deny("future-update-not-accepted")
    if not record["fresh_secret_contribution_verified"]:
        return deny("fresh-honest-secret-not-demonstrated")
    if not record["stale_members_excluded"]:
        return deny("stale-member-exposure")
    if (record["group_profile"] == "group-sender-key-aead@0.1.0"
            and not record["sender_distribution_verified"]):
        return deny("sender-keys-not-redistributed-over-trusted-channels")
    return {"healed": False, "reason": "structurally-consistent-but-not-crypto-proof",
            "reference_conditions_satisfied": True, "endpoint_verified": False}


def eligible_flow_assurance(flow, *, pairwise_pq_verified, group_pq_verified,
                            media_pq_verified, attachment_pq_verified,
                            backup_pq_verified):
    if flow not in FLOWS:
        return {"pq_claim_supported": False, "reason": "unsupported-flow"}
    flags = {
        "direct_message": pairwise_pq_verified,
        "group_message": group_pq_verified,
        "media": media_pq_verified,
        "attachment": attachment_pq_verified,
        "backup": backup_pq_verified,
    }
    flag = flags[flow]
    if type(flag) is not bool:
        return {"pq_claim_supported": False, "reason": "invalid-flow-verification"}
    return {"pq_claim_supported": flag, "reason":
            "requires-real-endpoint-evidence" if flag else "no-flow-specific-proof"}
