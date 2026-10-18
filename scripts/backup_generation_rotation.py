#!/usr/bin/env python3
"""AUD-12 authenticated backup generation transition reference.

A structural checker cannot prove fresh BDEK bytes, correct AEAD operation, or
failed decryption using an old credential. The result deliberately remains
non-certifying even when independently verifiable evidence references exist.
No raw secrets are accepted or emitted.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from canonical_serialization import canonical_bytes

ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
MODES = {"backup-user-secret@0.1.0", "backup-hardware-assisted@0.1.0"}
GEN_FIELDS = {
    "schema_version", "identity_id", "profile_ref", "backup_id", "generation",
    "recovery_credential_epoch", "bdek_id", "bdek_commitment",
    "encrypted_content_digest", "inner_recovery_wrap_digest",
    "argon2_salt_digest", "content_aead_algorithm_id",
}
AUTH_FIELDS = {
    "old_generation_digest", "new_generation_digest",
    "authorization_context_digest", "verified_identity_authority_evidence_ref",
}
EVIDENCE_FIELDS = {
    "fresh_bdek_generation_evidence_ref", "independent_distinct_key_check_ref",
    "new_ciphertext_aead_test_ref", "new_credential_decryption_test_ref",
    "old_credential_rejection_test_ref", "old_snapshots_may_remain_decryptable",
    "generated_bdek_random_bits", "hardware_budget_release_evidence_ref",
}


def _id(v: Any) -> bool:
    return isinstance(v, str) and ID.fullmatch(v) is not None


def _hash(v: Any) -> bool:
    return isinstance(v, str) and HASH.fullmatch(v) is not None


def _fields(d: Any, keys: set[str]) -> bool:
    return isinstance(d, dict) and set(d) == keys


def _digest(label: bytes, d: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(label + b"\x00" + canonical_bytes(d)).hexdigest()


def manifest_digest(manifest: dict[str, Any]) -> str:
    errors = validate_manifest(manifest)
    if errors:
        raise ValueError("; ".join(errors))
    return _digest(b"E2EESA-AUD12-GENERATION-v1", manifest)


def transition_digest(old_hash: str, new_hash: str) -> str:
    if not _hash(old_hash) or not _hash(new_hash):
        raise ValueError("invalid generation digests")
    return _digest(b"E2EESA-AUD12-TRANSITION-v1",
                   {"old_generation_digest": old_hash, "new_generation_digest": new_hash})


def validate_manifest(m: Any) -> list[str]:
    errors: list[str] = []
    if not _fields(m, GEN_FIELDS):
        return ["invalid generation manifest fields"]
    if m["schema_version"] != "0.1":
        errors.append("unsupported generation manifest version")
    for field in ("identity_id", "backup_id", "bdek_id", "content_aead_algorithm_id"):
        if not _id(m[field]):
            errors.append("invalid " + field)
    if not isinstance(m["profile_ref"], str) or m["profile_ref"] not in MODES:
        errors.append("not a server-hosted recoverable backup profile")
    for field in ("generation", "recovery_credential_epoch"):
        if type(m[field]) is not int or m[field] < 1:
            errors.append("invalid " + field)
    for field in ("bdek_commitment", "encrypted_content_digest",
                  "inner_recovery_wrap_digest", "argon2_salt_digest"):
        if not _hash(m[field]):
            errors.append("invalid " + field)
    return sorted(set(errors))


def evaluate_transition(old: dict[str, Any], new: dict[str, Any],
                        authorization: dict[str, Any], evidence: dict[str, Any],
                        *, trusted_previous_digest: str | None) -> dict[str, Any]:
    """Return reference policy consistency; never assert decrypted-secret safety."""

    def deny(reason: str) -> dict[str, Any]:
        return {"policy_consistent": False, "reason": reason, "release_ready": False}

    for label, manifest in (("old", old), ("new", new)):
        errors = validate_manifest(manifest)
        if errors:
            return deny(label + "-manifest-invalid: " + "; ".join(errors))
    oldhash, newhash = manifest_digest(old), manifest_digest(new)
    if not _hash(trusted_previous_digest) or trusted_previous_digest != oldhash:
        return deny("independent-previous-generation-checkpoint-mismatch")
    for field in ("identity_id", "profile_ref", "backup_id", "content_aead_algorithm_id"):
        if old[field] != new[field]:
            return deny("unapproved-identity-profile-or-algorithm-transition")
    if (new["generation"] != old["generation"] + 1 or
            new["recovery_credential_epoch"] != old["recovery_credential_epoch"] + 1):
        return deny("nonmonotonic-generation-or-credential-epoch")
    if new["bdek_id"] == old["bdek_id"] or new["bdek_commitment"] == old["bdek_commitment"]:
        return deny("fresh-backup-key-not-demonstrated")
    if (new["inner_recovery_wrap_digest"] == old["inner_recovery_wrap_digest"] or
            new["encrypted_content_digest"] == old["encrypted_content_digest"]):
        return deny("new-credential-envelope-and-ciphertext-required")
    if not _fields(authorization, AUTH_FIELDS):
        return deny("invalid-authorization-record")
    if (authorization["old_generation_digest"] != oldhash
            or authorization["new_generation_digest"] != newhash
            or authorization["authorization_context_digest"] != transition_digest(oldhash, newhash)
            or not _id(authorization["verified_identity_authority_evidence_ref"])):
        return deny("unauthenticated-or-stale-generation-transition")
    if not _fields(evidence, EVIDENCE_FIELDS):
        return deny("incomplete-cryptographic-test-evidence-record")
    for name in (
        "fresh_bdek_generation_evidence_ref", "independent_distinct_key_check_ref",
        "new_ciphertext_aead_test_ref", "new_credential_decryption_test_ref",
        "old_credential_rejection_test_ref",
    ):
        if not _id(evidence[name]):
            return deny("missing-actual-crypto-test-reference")
    if type(evidence["generated_bdek_random_bits"]) is not int or evidence["generated_bdek_random_bits"] < 256:
        return deny("insufficient-reported-bdek-entropy")
    if evidence["old_snapshots_may_remain_decryptable"] is not True:
        return deny("retained-ciphertext-limitation-must-be-disclosed")
    if old["profile_ref"] == "backup-hardware-assisted@0.1.0":
        if not _id(evidence["hardware_budget_release_evidence_ref"]):
            return deny("missing-attested-hardware-budget-evidence")
    elif evidence["hardware_budget_release_evidence_ref"] is not None:
        return deny("unsupported-hardware-claim-on-user-secret-profile")
    return {
        "policy_consistent": True,
        "reason": "metadata-and-evidence-bindings-consistent",
        "release_ready": False,
        "cryptographic_testing_verified": False,
        "old_generation_digest": oldhash,
        "new_generation_digest": newhash,
        "required_external_checks": [
            "authenticate-authorizing-identity-proof",
            "verify-independent-generation-floor",
            "verify-256-bit-fresh-entropy-and-true-key-separation",
            "verify-new-credential-decrypts-new-aead-ciphertext",
            "verify-old-credential-cannot-decrypt-new-ciphertext",
            "verify-hardware-release-if-applicable",
            "document-retained-historical-envelopes",
        ],
    }
