#!/usr/bin/env python3
"""AUD-18 construction-specific hybrid TLS claims.

This checks reference declarations, NOT cryptographic combiner correctness,
trust-provider authenticity, TLS security, independent review or certification.
"""
from __future__ import annotations

import re
from typing import Any

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GROUPS = {
    "X25519MLKEM768": ("ALG-X25519", "ALG-ML-KEM-768"),
    "SecP256r1MLKEM768": ("ALG-ECDH-P256", "ALG-ML-KEM-768"),
    "SecP384r1MLKEM1024": ("ALG-ECDH-P384", "ALG-ML-KEM-1024"),
}
REQUIRED = {
    "schema_version", "profile_ref", "negotiated_group_id",
    "traditional_algorithm_id", "pq_kem_algorithm_id",
    "protocol_specification", "combiner_specification",
    "negotiated_tls_version", "hybrid_transcript_sha256",
    "traditional_secret_integrated", "pq_secret_integrated",
    "downgrade_rejected", "claimed_property_id", "combiner_property_scope",
}
TRUST = {"independently_verified_transcript_sha256",
         "independently_verified_group_id", "assessor_reference"}


def assess(declaration: dict[str, Any], trusted: dict[str, Any],
           crypto_registry: dict[str, Any], transport_registry: dict[str, Any]) -> dict[str, Any]:
    def result(consistent: bool, reason: str) -> dict[str, Any]:
        return {"consistent": consistent, "reason": reason,
                "cryptographically_verified": False, "certified": False}

    if not isinstance(declaration, dict) or set(declaration) != REQUIRED:
        return result(False, "invalid-hybrid-claim-shape")
    if not isinstance(trusted, dict) or set(trusted) != TRUST:
        return result(False, "missing-independent-transcript-record")
    if not isinstance(crypto_registry, dict) or not isinstance(transport_registry, dict):
        return result(False, "missing-registries")
    group = declaration["negotiated_group_id"]
    if not isinstance(group, str) or group not in GROUPS:
        return result(False, "unregistered-or-nonhybrid-group")
    if declaration["schema_version"] != "0.1" or declaration["profile_ref"] != "transport-tls13-hybrid@0.1.0":
        return result(False, "wrong-claim-profile")
    if (declaration["protocol_specification"] != "RFC 10024"
            or declaration["combiner_specification"] != "RFC 9954"
            or declaration["negotiated_tls_version"] != "TLS1.3"):
        return result(False, "wrong-protocol-or-combiner")
    classical, pq = GROUPS[group]
    if (declaration["traditional_algorithm_id"] != classical
            or declaration["pq_kem_algorithm_id"] != pq):
        return result(False, "wrong-hybrid-algorithm-pair")
    registry_groups = transport_registry.get("groups")
    if not isinstance(registry_groups, list):
        return result(False, "malformed-group-registry")
    matches = [x for x in registry_groups if isinstance(x, dict) and x.get("id") == group]
    if (len(matches) != 1 or matches[0].get("kind") != "hybrid"
            or matches[0].get("specification") != "RFC 10024"
            or matches[0].get("status") not in ("recommended", "allowed")):
        return result(False, "hybrid-group-not-allowed")
    algorithms = crypto_registry.get("algorithms")
    if not isinstance(algorithms, list):
        return result(False, "malformed-primitive-registry")
    for identifier, category, quantum in (
        (classical, "key-agreement", "classical"),
        (pq, "kem", "post-quantum"),
    ):
        entries = [x for x in algorithms if isinstance(x, dict) and x.get("id") == identifier]
        if (len(entries) != 1 or entries[0].get("status") not in ("recommended", "allowed")
                or entries[0].get("category") != category
                or entries[0].get("pq_characteristic") != quantum):
            return result(False, "component-lifecycle-or-role-rejected")
    if (declaration["traditional_secret_integrated"] is not True
            or declaration["pq_secret_integrated"] is not True
            or declaration["downgrade_rejected"] is not True):
        return result(False, "component-or-downgrade-not-supported")
    if (declaration["claimed_property_id"] != "SP-PQ-CONFIDENTIALITY"
            or declaration["combiner_property_scope"] != "construction-specific-confidentiality"):
        return result(False, "hybrid-property-must-not-be-generalized")
    transcript = declaration["hybrid_transcript_sha256"]
    if (not isinstance(transcript, str) or not DIGEST.fullmatch(transcript)
            or trusted["independently_verified_transcript_sha256"] != transcript
            or trusted["independently_verified_group_id"] != group
            or not isinstance(trusted["assessor_reference"], str)
            or len(trusted["assessor_reference"].strip()) < 8):
        return result(False, "untrusted-transcript-or-group")
    return result(True, "versioned-reference-declaration-consistent")
