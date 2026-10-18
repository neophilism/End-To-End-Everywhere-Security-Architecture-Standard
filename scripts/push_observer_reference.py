"""AUD-17 push observer and response-correlation reference checks.

Pure policy. No real provider capture, anonymity guarantee or deployed endpoint.
"""
from __future__ import annotations


def assess_push_observation(record):
    def deny(reason):
        return {"eligible": False, "reason": reason,
                "provider_confidentiality_verified": False}
    fields = {"mode", "declared_outer_fields", "actual_outer_fields",
              "encrypted_fields", "recipient_key_verified", "provider_can_decrypt",
              "plaintext_relationship_ids", "routing_token_reused_across_services",
              "response_correlation_tested", "provider_observed_timing"}
    if not isinstance(record, dict) or set(record) != fields:
        return deny("malformed-push-observation")
    if record["mode"] not in ("wake-only", "encrypted-payload"):
        return deny("unsupported-push-mode")
    for key in ("recipient_key_verified", "provider_can_decrypt",
                "plaintext_relationship_ids", "routing_token_reused_across_services",
                "response_correlation_tested", "provider_observed_timing"):
        if type(record[key]) is not bool:
            return deny("malformed-claim-flag")
    for key in ("declared_outer_fields", "actual_outer_fields", "encrypted_fields"):
        if not isinstance(record[key], list) or not all(
                isinstance(x, str) and x for x in record[key]):
            return deny("malformed-field-inventory")
        if len(set(record[key])) != len(record[key]):
            return deny("duplicate-observer-field")
    if not set(record["actual_outer_fields"]).issubset(record["declared_outer_fields"]):
        return deny("undeclared-provider-visible-field")
    if record["plaintext_relationship_ids"]:
        return deny("plaintext-relationship-identifier")
    if record["routing_token_reused_across_services"]:
        return deny("cross-service-token-linkability")
    if record["mode"] == "wake-only" and record["encrypted_fields"]:
        return deny("wake-only-cannot-carry-protected-payload")
    if record["mode"] == "encrypted-payload":
        if (not record["encrypted_fields"] or
                not record["recipient_key_verified"] or
                record["provider_can_decrypt"]):
            return deny("encrypted-payload-confidentiality-not-proven")
    if not record["response_correlation_tested"]:
        return deny("untested-response-correlation")
    return {"eligible": True, "reason": "structural-observer-inventory-consistent",
            "provider_confidentiality_verified": False,
            "privacy_limitation": "routing-and-timing-may-remain-observable",
            "observed_timing": record["provider_observed_timing"]}


def response_policy(*, mode, delay_verified, batching_verified,
                    no_receipt_verified):
    if mode not in ("immediate", "delayed", "batched", "no-receipt"):
        return {"reference_consistent": False}
    if any(type(flag) is not bool for flag in
           (delay_verified, batching_verified, no_receipt_verified)):
        return {"reference_consistent": False}
    needed = {"delayed": delay_verified, "batched": batching_verified,
              "no-receipt": no_receipt_verified}
    return {"reference_consistent": mode == "immediate" or needed.get(mode, False),
            "anonymity_proven": False}
