#!/usr/bin/env python3
"""AUD-14.1: exact PQXDH associated-data and source-version binding checks.

This is a deterministic reference checker, NOT a PQXDH/ML-KEM implementation.
Trusted inputs must originate from independent cryptographic identity/prekey
verification; self-supplied claims are not verification.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

PROFILE_REQUIRES_BRAID = {
    "pairwise-pqxdh-double-ratchet@0.1.0": False,
    "pairwise-pqxdh-spqr@0.1.0": True,
    "pairwise-pqxdh-triple-ratchet@0.1.0": True,
}
KEM_IDS = {"ALG-ML-KEM-512", "ALG-ML-KEM-768", "ALG-ML-KEM-1024"}
PQXDH_REVISION = "PROTO-PQXDH-R3-2024"
BRAID_REVISION = "MLKEM-BRAID-R1-2025-09-26"
AD_CONVENTION = "pqxdh-r3-published-ad@0.1.0"
HEX = re.compile(r"^(?:[0-9a-f]{2})+$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RECORD_FIELDS = {
    "schema_version", "profile_ref", "initialization_protocol_id",
    "braid_component_revision", "ad_convention", "kem_algorithm_id",
    "encoded_initiator_identity_hex", "encoded_responder_identity_hex",
    "encoded_pq_prekey_hex", "kem_ciphertext_hex", "associated_data_hex",
}
TRUST_FIELDS = {
    "profile_ref", "ad_convention", "kem_algorithm_id",
    "initiator_identity_sha256", "responder_identity_sha256",
    "pq_prekey_sha256", "kem_ciphertext_sha256",
}


def _decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or len(value) > 2 * 1024 * 1024 or not HEX.fullmatch(value):
        raise ValueError("invalid lower-case non-empty hex bytes: " + field)
    return bytes.fromhex(value)


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def validate(record: dict[str, Any], trusted: dict[str, Any]) -> dict[str, Any]:
    """Evaluate exact byte consistency against separately trusted digests.

    A consistent result never proves that the sender signature, KEM, AEAD or
    trust-provider verification was performed by a real endpoint.
    """
    def fail(reason: str) -> dict[str, Any]:
        return {"consistent": False, "reason": reason, "cryptographically_verified": False}

    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        return fail("malformed-binding-record")
    if not isinstance(trusted, dict) or set(trusted) != TRUST_FIELDS:
        return fail("missing-independent-trust-bindings")
    if record["schema_version"] != "0.1" or not isinstance(record["profile_ref"], str):
        return fail("invalid-binding-schema-or-profile")
    profile = record["profile_ref"]
    if profile not in PROFILE_REQUIRES_BRAID:
        return fail("unsupported-pairwise-profile")
    if record["initialization_protocol_id"] != PQXDH_REVISION:
        return fail("wrong-pqxdh-revision")
    expected_braid = BRAID_REVISION if PROFILE_REQUIRES_BRAID[profile] else None
    if record["braid_component_revision"] != expected_braid:
        return fail("wrong-or-missing-mlkem-braid-revision")
    if record["ad_convention"] != AD_CONVENTION:
        return fail("unapproved-wire-binding-convention")
    if not isinstance(record["kem_algorithm_id"], str) or record["kem_algorithm_id"] not in KEM_IDS:
        return fail("unsupported-kem")
    if any(record[name] != trusted[name] for name in ("profile_ref", "ad_convention", "kem_algorithm_id")):
        return fail("profile-or-wire-downgrade")
    if any(not isinstance(trusted[field], str) or not DIGEST.fullmatch(trusted[field])
           for field in TRUST_FIELDS if field.endswith("_sha256")):
        return fail("missing-trusted-digests")
    try:
        initiator = _decode(record["encoded_initiator_identity_hex"], "initiator-identity")
        responder = _decode(record["encoded_responder_identity_hex"], "responder-identity")
        pqprekey = _decode(record["encoded_pq_prekey_hex"], "pq-prekey")
        ciphertext = _decode(record["kem_ciphertext_hex"], "kem-ciphertext")
        observed_ad = _decode(record["associated_data_hex"], "associated-data")
    except ValueError:
        return fail("invalid-wire-bytes")

    # Both identities use the same caller-pinned EncodeEC; this reference only
    # checks a nonempty distinct identity encoding and a common curve tag.
    if len(initiator) < 2 or len(initiator) != len(responder) or initiator[:1] != responder[:1] or initiator == responder:
        return fail("inconsistent-ec-identity-encoding")
    if len(pqprekey) < 2 or len(ciphertext) < 2:
        return fail("incomplete-pq-material")
    bindings = (
        (initiator, "initiator_identity_sha256"),
        (responder, "responder_identity_sha256"),
        (pqprekey, "pq_prekey_sha256"),
        (ciphertext, "kem_ciphertext_sha256"),
    )
    if any(_sha(value) != trusted[name] for value, name in bindings):
        return fail("untrusted-key-or-ciphertext-substitution")

    # Signal PQXDH R3 section 3.3: AD = EncodeEC(IKa) || EncodeEC(IKb).
    # For a generic KEM that does not bind its public key to the shared
    # secret, append EncodeKEM(PQPK). Our selected ML-KEM variants already
    # bind the public key; adding this extra AD under this old convention
    # would be a wire incompatibility and needs a NEW versioned convention.
    if observed_ad != initiator + responder:
        return fail("pqxdh-associated-data-mismatch")

    return {"consistent": True, "reason": "trusted-byte-and-profile-consistency",
            "cryptographically_verified": False}


def published_ad_for_mlk(em_ik: bytes, recipient_ik: bytes) -> bytes:
    """Build the exact published PQXDH R3 AD for the currently pinned ML-KEM role."""
    if type(em_ik) is not bytes or type(recipient_ik) is not bytes or not em_ik or not recipient_ik:
        raise ValueError("encoded identity keys must be nonempty bytes")
    return em_ik + recipient_ik
