#!/usr/bin/env python3
"""AUD-17: fail-closed push-provider observation and response correlation policy.

This validates reported observations, NOT actual provider packets, ciphertext
or event confidentiality. Source-bound capture of real packets and crypto key
isolation remains a mandatory separate conformance requirement.
"""
from __future__ import annotations

import re
from typing import Any

ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
PROFILE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*@[0-9]+\.[0-9]+\.[0-9]+$")
OUTER = {"push-token", "ttl", "priority", "ciphertext-size", "routing-class"}
MODES = {"wake-only", "opaque-encrypted-payload"}
RESPONSES = {"no-receipt", "bounded-delay", "batch"}
POLICY_FIELDS = {
    "schema_version", "policy_id", "provider_id", "app_scope_id",
    "endpoint_recipient_id", "endpoint_key_fingerprint", "encryption_profile_ref",
    "mode", "allowed_outer_fields", "response_mode", "minimum_response_delay_seconds",
    "minimum_response_batch_size",
}
OBS_FIELDS = {
    "observation_id", "provider_id", "app_scope_id", "token_digest",
    "mode", "outer_fields", "payload_class", "payload_length_bytes",
    "recipient_id", "recipient_key_fingerprint", "encryption_profile_ref",
    "provider_can_decrypt", "send_epoch", "response_epoch", "batch_count",
}

def _id(x: Any) -> bool:
    return isinstance(x, str) and ID.fullmatch(x) is not None

def _sha(x: Any) -> bool:
    return isinstance(x, str) and SHA.fullmatch(x) is not None

def _nat(x: Any) -> bool:
    return type(x) is int and x >= 0

def _exact(x: Any, fields: set[str]) -> bool:
    return isinstance(x, dict) and set(x) == fields

def validate_policy(p: dict[str, Any]) -> None:
    if not _exact(p, POLICY_FIELDS):
        raise ValueError("invalid push policy fields")
    if p["schema_version"] != "0.1":
        raise ValueError("unsupported push policy version")
    for x in ("policy_id", "provider_id", "app_scope_id", "endpoint_recipient_id"):
        if not _id(p[x]):
            raise ValueError("invalid "+x)
    if not _sha(p["endpoint_key_fingerprint"]):
        raise ValueError("invalid independently pinned endpoint key fingerprint")
    if not isinstance(p["encryption_profile_ref"], str) or not PROFILE.fullmatch(p["encryption_profile_ref"]):
        raise ValueError("invalid endpoint encryption profile pin")
    if p["mode"] not in MODES:
        raise ValueError("unsupported push mode")
    fields = p["allowed_outer_fields"]
    if not isinstance(fields, list) or len(fields) != len(set(fields)) or not set(fields).issubset(OUTER):
        raise ValueError("unexpected push outer fields; relationship identifiers forbidden")
    if p["response_mode"] not in RESPONSES:
        raise ValueError("unsupported response correlation policy")
    if not _nat(p["minimum_response_delay_seconds"]) or not _nat(p["minimum_response_batch_size"]):
        raise ValueError("invalid response policy bounds")
    if p["response_mode"] == "bounded-delay":
        if p["minimum_response_delay_seconds"] == 0 or p["minimum_response_batch_size"] != 0:
            raise ValueError("delayed response requires positive delay and zero batch size")
    elif p["response_mode"] == "batch":
        if p["minimum_response_batch_size"] < 2 or p["minimum_response_delay_seconds"] != 0:
            raise ValueError("batch response requires at least two and zero delay")
    elif p["minimum_response_delay_seconds"] or p["minimum_response_batch_size"]:
        raise ValueError("no-receipt mode cannot configure response timing")

def evaluate_observation(policy: dict[str, Any], observed: Any) -> dict[str, Any]:
    validate_policy(policy)
    def deny(reason: str) -> dict[str, Any]:
        return {"accepted": False, "reason": reason, "provider_confidentiality_proved": False,
                "relationship_anonymity_proved": False}
    if not _exact(observed, OBS_FIELDS):
        return deny("invalid-observation")
    if not _id(observed["observation_id"]) or not _sha(observed["token_digest"]):
        return deny("invalid-observation-identity")
    if (observed["provider_id"] != policy["provider_id"]
            or observed["app_scope_id"] != policy["app_scope_id"]):
        return deny("provider-or-app-scope-mismatch")
    if observed["mode"] != policy["mode"]:
        return deny("push-mode-downgrade")
    fields = observed["outer_fields"]
    if not isinstance(fields, list) or any(not isinstance(f, str) for f in fields) or len(fields) != len(set(fields)):
        return deny("malformed-outer-fields")
    if not set(fields).issubset(set(policy["allowed_outer_fields"])):
        return deny("undeclared-outer-metadata")
    if not _nat(observed["payload_length_bytes"]) or not _nat(observed["send_epoch"]):
        return deny("invalid-payload-or-timestamp")
    if observed["recipient_id"] != policy["endpoint_recipient_id"]:
        return deny("wrong-endpoint-recipient")
    if type(observed["provider_can_decrypt"]) is not bool:
        return deny("invalid-provider-decryption-evidence")
    if observed["mode"] == "wake-only":
        if (observed["payload_class"] != "empty"
                or observed["payload_length_bytes"] != 0
                or observed["recipient_key_fingerprint"] is not None
                or observed["encryption_profile_ref"] is not None):
            return deny("wake-only-must-carry-no-payload")
    else:
        if (observed["payload_class"] != "endpoint-ciphertext"
                or observed["payload_length_bytes"] <= 0
                or observed["recipient_key_fingerprint"] != policy["endpoint_key_fingerprint"]
                or observed["encryption_profile_ref"] != policy["encryption_profile_ref"]
                or observed["provider_can_decrypt"]):
            return deny("provider-decryptable-or-unbound-ciphertext")
    if observed["mode"] == "wake-only" and observed["provider_can_decrypt"]:
        return deny("wake-only-provider-content-claim-invalid")

    rmode=policy["response_mode"]
    response=observed["response_epoch"]
    count=observed["batch_count"]
    if rmode == "no-receipt":
        if response is not None or count is not None:
            return deny("automatic-response-forbidden")
    elif rmode == "bounded-delay":
        if not _nat(response) or response < observed["send_epoch"] + policy["minimum_response_delay_seconds"] or count is not None:
            return deny("unbounded-or-premature-automatic-response")
    else:
        if not _nat(response) or response < observed["send_epoch"] or type(count) is not int or count < policy["minimum_response_batch_size"]:
            return deny("insufficient-or-malformed-response-batch")

    return {
        "accepted": True, "reason": "reported-boundary-consistent",
        "provider_confidentiality_proved": False,
        "relationship_anonymity_proved": False,
        "observable_metadata": sorted(set(fields) | {"delivery-timing", "token-correlation"}),
        "limits": ["provider-observes-routing-token-and-arrival-time",
                   "timing-and-global-observer-correlation-remain-possible",
                   "packet-capture-and-endpoint-key-isolation-not-verified"],
    }

def evaluate_observations(policies: list[dict[str, Any]], observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Cross-service token reuse is forbidden even if individual events pass."""
    if not isinstance(policies,list) or not isinstance(observations,list):
        raise ValueError("policy and observation collections required")
    index={}
    for p in policies:
        validate_policy(p)
        k=(p["provider_id"],p["app_scope_id"])
        if k in index:
            raise ValueError("duplicate provider/app policy")
        index[k]=p
    result=[]
    seen_ids=set()
    seen_token_scopes:dict[str,tuple[str,str]]={}
    for x in observations:
        if not isinstance(x,dict):
            result.append({"accepted":False,"reason":"invalid-observation"})
            continue
        k=(x.get("provider_id"), x.get("app_scope_id"))
        policy=index.get(k)
        if policy is None:
            result.append({"accepted":False,"reason":"undeclared-provider-or-app"})
            continue
        decision=evaluate_observation(policy,x)
        if decision["accepted"]:
            if x["observation_id"] in seen_ids:
                decision={"accepted":False,"reason":"replayed-observation-id"}
            elif x["token_digest"] in seen_token_scopes and seen_token_scopes[x["token_digest"]] != k:
                decision={"accepted":False,"reason":"cross-service-token-reuse"}
        if _id(x.get("observation_id")):
            seen_ids.add(x["observation_id"])
        if decision["accepted"]:
            seen_token_scopes[x["token_digest"]]=k
        result.append(decision)
    return {
        "accepted":all(d["accepted"] for d in result),
        "results":result,
        "provider_confidentiality_proved":False,
        "relationship_anonymity_proved":False,
    }
