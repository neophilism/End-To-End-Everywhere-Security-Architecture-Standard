#!/usr/bin/env python3
"""AUD-20.1: reference checks for TLS service-identity, PKI CT and ECH.

All result flags are consistency-only. Certificate validation, live CT policy
enforcement, RFC 9849 ECH acceptance, and client/server runtime observations
MUST be performed by independent trusted platform adapters.
"""
from __future__ import annotations
import re
from typing import Any

ID = re.compile(r"^[a-z0-9][a-z0-9.-]{1,252}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
POLICY = {
    "schema_version", "service_name", "trust_model", "require_ct",
    "require_ech", "allow_authenticated_ech_disable",
}
EVIDENCE = {
    "schema_version", "service_name", "tls_version",
    "certificate_chain_valid", "certificate_time_valid",
    "reference_identifier_valid", "common_name_fallback_used",
    "ct_applicable", "platform_ct_enforced", "platform_ct_valid",
    "ech_offered", "ech_accepted", "ech_rejected",
    "ech_rejection_authenticated_for_public_name",
    "ech_retry_authenticated_and_accepted", "plain_fallback_used",
    "dns_observable", "ip_observable", "timing_observable",
    "platform_observation_digest",
}
ANCHOR = {"service_name", "platform_observation_digest", "assessor_reference"}


def evaluate(policy: dict[str, Any], evidence: dict[str, Any],
             trusted_observation: dict[str, Any]) -> dict[str, Any]:
    def response(ok: bool, reason: str, ech_protected: bool = False) -> dict[str, Any]:
        return {"consistent": ok, "reason": reason, "ech_protection_supported": ech_protected,
                "fully_anonymous": False, "cryptographically_verified": False}

    if not isinstance(policy, dict) or set(policy) != POLICY:
        return response(False, "invalid-pki-ech-policy")
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE:
        return response(False, "invalid-platform-evidence")
    if not isinstance(trusted_observation, dict) or set(trusted_observation) != ANCHOR:
        return response(False, "missing-independent-platform-anchor")
    if policy["schema_version"] != "0.1" or evidence["schema_version"] != "0.1":
        return response(False, "unsupported-pki-ech-version")
    if not isinstance(policy["service_name"], str) or not ID.fullmatch(policy["service_name"]):
        return response(False, "invalid-service-name")
    if policy["trust_model"] not in ("public-web-pki", "private-pki"):
        return response(False, "unknown-trust-model")
    if any(type(policy[field]) is not bool for field in (
        "require_ct", "require_ech", "allow_authenticated_ech_disable")):
        return response(False, "invalid-policy-boolean")
    if policy["require_ech"] and policy["allow_authenticated_ech_disable"]:
        return response(False, "required-ech-cannot-be-disabled")
    if policy["trust_model"] == "private-pki" and policy["require_ct"]:
        return response(False, "private-pki-ct-policy-not-applicable")
    if (evidence["service_name"] != policy["service_name"] or
        evidence["tls_version"] != "TLS1.3"):
        return response(False, "wrong-service-or-tls-version")
    if any(type(evidence[field]) is not bool for field in (
        "certificate_chain_valid","certificate_time_valid","reference_identifier_valid",
        "common_name_fallback_used","ct_applicable","platform_ct_enforced",
        "platform_ct_valid","ech_offered","ech_accepted","ech_rejected",
        "ech_rejection_authenticated_for_public_name",
        "ech_retry_authenticated_and_accepted","plain_fallback_used",
        "dns_observable","ip_observable","timing_observable",
    )):
        return response(False, "malformed-platform-boolean")
    if not all(evidence[field] for field in (
        "certificate_chain_valid","certificate_time_valid","reference_identifier_valid")):
        return response(False, "certificate-path-or-rfc9525-identity-failure")
    if evidence["common_name_fallback_used"]:
        return response(False, "rfc9525-common-name-fallback-prohibited")
    if (policy["trust_model"] == "private-pki" and evidence["ct_applicable"]
        or policy["trust_model"] == "public-web-pki" and policy["require_ct"] and
            not all(evidence[field] for field in (
                "ct_applicable","platform_ct_enforced","platform_ct_valid"))):
        return response(False, "ct-applicability-or-platform-enforcement-failure")
    if (not isinstance(evidence["platform_observation_digest"], str) or
        not DIGEST.fullmatch(evidence["platform_observation_digest"]) or
        trusted_observation["service_name"] != policy["service_name"] or
        trusted_observation["platform_observation_digest"] != evidence["platform_observation_digest"] or
        not isinstance(trusted_observation["assessor_reference"], str) or
        len(trusted_observation["assessor_reference"].strip()) < 8):
        return response(False, "independent-platform-observation-mismatch")
    if evidence["ech_accepted"] and evidence["ech_rejected"]:
        return response(False, "contradictory-ech-acceptance")
    if evidence["ech_accepted"] and (not evidence["ech_offered"] or evidence["plain_fallback_used"]):
        return response(False, "invalid-ech-final-handshake")
    if evidence["ech_retry_authenticated_and_accepted"] and (
        not evidence["ech_accepted"] or not evidence["ech_offered"]
        or evidence["plain_fallback_used"] or not evidence["ech_rejection_authenticated_for_public_name"]):
        return response(False, "unverified-ech-retry-transition")
    if policy["require_ech"]:
        if not evidence["ech_accepted"] or evidence["plain_fallback_used"]:
            return response(False, "required-ech-unavailable-or-downgraded")
        return response(True, "ech-accepted-with-residual-routing-metadata", True)

    if evidence["ech_accepted"]:
        return response(True, "ech-accepted-with-residual-routing-metadata", True)
    if evidence["ech_rejected"]:
        if (not evidence["ech_offered"] or not evidence["plain_fallback_used"] or
            not policy["allow_authenticated_ech_disable"] or
            not evidence["ech_rejection_authenticated_for_public_name"]):
            return response(False, "unauthenticated-ech-disable-or-fallback")
        return response(True, "authenticated-ech-disable-no-ech-privacy")
    if evidence["ech_offered"]:
        return response(False, "ech-offered-but-no-verified-outcome")
    if evidence["plain_fallback_used"]:
        return response(False, "unoffered-ech-must-not-be-labeled-fallback")
    return response(True, "non-ech-policy-no-ech-privacy")
