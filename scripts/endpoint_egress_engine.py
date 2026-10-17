#!/usr/bin/env python3
"""AUD-10 reference endpoint egress guard.

IMPORTANT: The host MUST bind these declarations to inspected source/build and
instrument *all* actual exports. A caller-supplied label is not proof about
actual plaintext, recipients, key isolation, or authorization. This engine
rejects undeclared observed edges; it is not an OS data-loss-prevention system.
"""
from __future__ import annotations

import re
from typing import Any

ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
PROFILE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*@[0-9]+\.[0-9]+\.[0-9]+$")
PHASES = {"success", "failure", "crash", "retry", "analytics", "background", "user-action"}
DERIVED = {"plaintext", "classifier", "embedding", "content-hash", "preview",
           "search-index", "diagnostic", "telemetry", "provider-api-call"}
KINDS = DERIVED | {"ciphertext", "protocol-metadata", "public-data"}
SCOPES = {"none", "e2ee-recipient", "provider-key"}
METADATA = {"ciphertext-size", "packet-count", "delivery-time", "routing-token",
            "encrypted-content-length"}
FLOW_FIELDS = {"flow_id", "source_class", "e2ee_profile_ref", "endpoint_recipients",
               "metadata_exposures", "explicit_disclosures", "public_destinations"}
EVENT_FIELDS = {"event_id", "flow_id", "phase", "output_kind", "content_ids",
                "destination_id", "recipient_id", "recipient_key_fingerprint",
                "e2ee_profile_ref", "encryption_scope", "metadata_fields",
                "authorization_id", "purpose_id", "event_epoch"}
DISCLOSURE_FIELDS = {"authorization_id", "purpose_id", "selected_content_ids",
                     "recipient_ids", "output_kinds", "expires_at_epoch"}


def _require(ok: Any, explanation: str) -> None:
    if not ok:
        raise ValueError(explanation)


def _id(value: Any) -> bool:
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _ids(value: Any, *, nonempty: bool = False) -> bool:
    return isinstance(value, list) and (not nonempty or len(value) > 0) and all(
        _id(x) for x in value
    ) and len(value) == len(set(value))


def _exact(value: Any, fields: set[str], prefix: str) -> None:
    _require(isinstance(value, dict) and set(value) == fields,
             prefix + " has missing or unexpected fields")


def validate_policy(policy: dict[str, Any]) -> None:
    _exact(policy, {"schema_version", "policy_id", "flows"}, "egress policy")
    _require(policy["schema_version"] == "0.1", "unsupported egress policy schema")
    _require(_id(policy["policy_id"]), "invalid egress policy id")
    flows = policy["flows"]
    _require(isinstance(flows, list) and bool(flows), "flows must be a non-empty list")
    seen_flows: set[str] = set()
    seen_auths: set[str] = set()
    for flow in flows:
        _exact(flow, FLOW_FIELDS, "flow")
        _require(_id(flow["flow_id"]) and flow["flow_id"] not in seen_flows,
                 "invalid or duplicate flow id")
        seen_flows.add(flow["flow_id"])
        _require(flow["source_class"] in {"protected", "public"}, "unsupported source class")
        _require(flow["e2ee_profile_ref"] is None or (
            isinstance(flow["e2ee_profile_ref"], str)
            and PROFILE.fullmatch(flow["e2ee_profile_ref"])
        ), "invalid encryption profile pin")
        endpoints = flow["endpoint_recipients"]
        _require(isinstance(endpoints, list), "endpoint_recipients must be a list")
        seen_recipients: set[str] = set()
        for endpoint in endpoints:
            _exact(endpoint, {"recipient_id", "key_fingerprint"}, "endpoint recipient")
            _require(_id(endpoint["recipient_id"]) and endpoint["recipient_id"] not in seen_recipients,
                     "invalid or duplicate endpoint recipient")
            seen_recipients.add(endpoint["recipient_id"])
            key = endpoint["key_fingerprint"]
            _require(isinstance(key, str) and FINGERPRINT.fullmatch(key),
                     "invalid pinned recipient key")
        exposures = flow["metadata_exposures"]
        _require(isinstance(exposures, list), "metadata_exposures must be an array")
        seen_destinations: set[str] = set()
        for exposure in exposures:
            _exact(exposure, {"destination_id", "permitted_fields"}, "metadata exposure")
            name = exposure["destination_id"]
            _require(_id(name) and name not in seen_destinations, "invalid or duplicate observer")
            seen_destinations.add(name)
            fields = exposure["permitted_fields"]
            _require(isinstance(fields, list) and all(
                isinstance(x, str) and x in METADATA for x in fields
            ) and len(fields) == len(set(fields)), "invalid/duplicate allowed metadata fields")
        _require(_ids(flow["public_destinations"]), "invalid public destinations")
        _require(isinstance(flow["explicit_disclosures"], list), "disclosures must be a list")
        if flow["source_class"] == "public":
            _require(not endpoints and not flow["explicit_disclosures"] and flow["e2ee_profile_ref"] is None,
                     "public-flow declarations cannot claim E2EE or protected disclosures")
        else:
            _require(flow["e2ee_profile_ref"] is not None or not endpoints,
                     "protected endpoint encryption requires an exact profile pin")
            _require(not flow["public_destinations"], "public output must be an explicit selected disclosure")
        for auth in flow["explicit_disclosures"]:
            _exact(auth, DISCLOSURE_FIELDS, "explicit disclosure")
            aid = auth["authorization_id"]
            _require(_id(aid) and aid not in seen_auths, "invalid or reused authorization id")
            seen_auths.add(aid)
            _require(_id(auth["purpose_id"]), "invalid disclosure purpose")
            _require(_ids(auth["selected_content_ids"], nonempty=True), "finite selected content ids required")
            _require(_ids(auth["recipient_ids"], nonempty=True), "explicit disclosure recipients required")
            kinds = auth["output_kinds"]
            _require(isinstance(kinds, list) and bool(kinds) and
                     all(isinstance(k, str) and k in DERIVED for k in kinds) and
                     len(kinds) == len(set(kinds)), "explicit disclosure kinds must be specific")
            expiry = auth["expires_at_epoch"]
            _require(type(expiry) is int and expiry > 0, "invalid disclosure expiry")


def validate_event(event: Any) -> str | None:
    if not isinstance(event, dict) or set(event) != EVENT_FIELDS:
        return "malformed-event"
    if not _id(event["event_id"]) or not _id(event["flow_id"]):
        return "malformed-event"
    if not isinstance(event["phase"], str) or event["phase"] not in PHASES:
        return "malformed-event"
    if not isinstance(event["output_kind"], str) or event["output_kind"] not in KINDS:
        return "malformed-event"
    if not _ids(event["content_ids"], nonempty=True):
        return "malformed-event"
    if not _id(event["destination_id"]):
        return "malformed-event"
    if event["recipient_id"] is not None and not _id(event["recipient_id"]):
        return "malformed-event"
    if event["recipient_key_fingerprint"] is not None and (
        not isinstance(event["recipient_key_fingerprint"], str)
        or not FINGERPRINT.fullmatch(event["recipient_key_fingerprint"])
    ):
        return "malformed-event"
    if event["e2ee_profile_ref"] is not None and (
        not isinstance(event["e2ee_profile_ref"], str)
        or not PROFILE.fullmatch(event["e2ee_profile_ref"])
    ):
        return "malformed-event"
    if not isinstance(event["encryption_scope"], str) or event["encryption_scope"] not in SCOPES:
        return "malformed-event"
    fields = event["metadata_fields"]
    if not isinstance(fields, list) or any(not isinstance(f, str) or f not in METADATA for f in fields) or len(fields) != len(set(fields)):
        return "malformed-event"
    if event["authorization_id"] is not None and not _id(event["authorization_id"]):
        return "malformed-event"
    if event["purpose_id"] is not None and not _id(event["purpose_id"]):
        return "malformed-event"
    if type(event["event_epoch"]) is not int or event["event_epoch"] < 0:
        return "malformed-event"
    return None


def evaluate_event(policy: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed for every observed success/failure/retry/crash/analytics/background egress."""
    validate_policy(policy)
    issue = validate_event(event)
    if issue:
        return {"allowed": False, "reason": issue}
    flow = next((f for f in policy["flows"] if f["flow_id"] == event["flow_id"]), None)
    def deny(reason: str) -> dict[str, Any]:
        return {"allowed": False, "reason": reason}
    if flow is None:
        return deny("undeclared-flow")

    output = event["output_kind"]
    dest = event["destination_id"]
    exposures = {x["destination_id"]: set(x["permitted_fields"]) for x in flow["metadata_exposures"]}
    fields = set(event["metadata_fields"])

    if output == "public-data":
        if (flow["source_class"] == "public" and dest in flow["public_destinations"]
                and event["encryption_scope"] == "none" and event["authorization_id"] is None
                and event["purpose_id"] is None and event["recipient_id"] is None
                and event["recipient_key_fingerprint"] is None and event["e2ee_profile_ref"] is None
                and not fields):
            return {"allowed": True, "reason": "declared-public-flow"}
        return deny("public-output-not-authorized")

    if flow["source_class"] != "protected":
        return deny("public-flow-cannot-export-protected-data")

    if output == "ciphertext":
        endpoints = {e["recipient_id"]: e["key_fingerprint"] for e in flow["endpoint_recipients"]}
        recipient = event["recipient_id"]
        if (recipient not in endpoints or event["encryption_scope"] != "e2ee-recipient"
                or event["recipient_key_fingerprint"] != endpoints.get(recipient)
                or event["e2ee_profile_ref"] != flow["e2ee_profile_ref"]
                or event["authorization_id"] is not None or event["purpose_id"] is not None):
            return deny("endpoint-ciphertext-binding-invalid")
        if dest != recipient and dest not in exposures:
            return deny("undeclared-transport-observer")
        permitted = exposures.get(dest, set())
        if not fields.issubset(permitted):
            return deny("undeclared-metadata-leakage")
        return {"allowed": True, "reason": "declared-recipient-ciphertext"}

    if output == "protocol-metadata":
        if (dest in exposures and fields and fields.issubset(exposures[dest])
                and event["encryption_scope"] == "none" and event["recipient_id"] is None
                and event["recipient_key_fingerprint"] is None and event["e2ee_profile_ref"] is None
                and event["authorization_id"] is None and event["purpose_id"] is None):
            return {"allowed": True, "reason": "declared-protocol-metadata"}
        return deny("undeclared-protocol-metadata")

    # All classifier/embedding/preview/hash/diagnostic/provider exports
    # are protected-derived regardless of encoding or service labels.
    if event["phase"] != "user-action":
        return deny("automatic-content-derived-export")
    if (event["encryption_scope"] != "none" or event["recipient_key_fingerprint"] is not None
            or event["e2ee_profile_ref"] is not None or fields):
        return deny("disclosure-encryption-or-metadata-mismatch")
    auth = next((a for a in flow["explicit_disclosures"]
                 if a["authorization_id"] == event["authorization_id"]), None)
    if auth is None:
        return deny("absent-explicit-disclosure")
    if (event["purpose_id"] != auth["purpose_id"] or dest not in auth["recipient_ids"]
            or event["recipient_id"] != dest or output not in auth["output_kinds"]
            or event["event_epoch"] > auth["expires_at_epoch"]
            or set(event["content_ids"]) != set(auth["selected_content_ids"])):
        return deny("disclosure-scope-mismatch")
    return {"allowed": True, "reason": "finite-user-selected-disclosure"}


def evaluate_batch(policy: dict[str, Any], events: list[dict[str, Any]],
                   *, spent_authorization_ids: list[str] | None = None) -> dict[str, Any]:
    """Evaluate an observed egress batch, including failed/background paths.

    The host must atomically persist newly spent IDs before allowing export.
    The caller must also durably prevent cross-invocation ID reuse.
    """
    validate_policy(policy)
    _require(isinstance(events, list), "events must be a list")
    spent = spent_authorization_ids if spent_authorization_ids is not None else []
    _require(_ids(spent), "spent authorization ids must be a unique ID list")
    spent_set = set(spent)
    results = []
    seen_events: set[str] = set()
    for event in events:
        result = evaluate_event(policy, event)
        if result["allowed"] and event["event_id"] in seen_events:
            result = {"allowed": False, "reason": "replayed-egress-event-id"}
        if result["allowed"] and result["reason"] == "finite-user-selected-disclosure":
            auth = event["authorization_id"]
            if auth in spent_set:
                result = {"allowed": False, "reason": "spent-disclosure-authorization"}
            else:
                spent_set.add(auth)
        if isinstance(event, dict) and _id(event.get("event_id")):
            seen_events.add(event["event_id"])
        results.append(result)
    return {
        "allowed": all(x["allowed"] for x in results),
        "results": results,
        "new_spent_authorization_ids": sorted(spent_set - set(spent)),
    }
