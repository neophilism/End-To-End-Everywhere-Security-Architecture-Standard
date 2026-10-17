#!/usr/bin/env python3
"""AUD-13: bounded pairwise prekey publication and initialization policy checks.

No protocol primitive is implemented. Cryptographic signatures, authoritative
time and actual erasure are caller-verified preconditions and must not be
inferred from labels in a fixture or this reference policy evaluator.
"""
from __future__ import annotations
import re
from typing import Any

PROFILES = {
    "pairwise-x3dh-double-ratchet@0.1.0": False,
    "pairwise-pqxdh-double-ratchet@0.1.0": True,
    "pairwise-pqxdh-spqr@0.1.0": True,
    "pairwise-pqxdh-triple-ratchet@0.1.0": True,
}
KEMS = {"ALG-ML-KEM-512": "constrained-interop-exception",
        "ALG-ML-KEM-768": "recommended",
        "ALG-ML-KEM-1024": "recommended"}
ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
POLICY_FIELDS = {
    "schema_version", "policy_id", "pairwise_profile_ref",
    "pq_kem_algorithm_id", "pq_strength_policy", "strength_exception_reason",
    "recommended_signed_prekey_lifetime_seconds", "maximum_signed_prekey_lifetime_seconds",
    "private_key_deletion_grace_seconds", "clock_uncertainty_limit_seconds",
    "minimum_one_time_prekey_stock", "minimum_pq_one_time_prekey_stock",
}
BUNDLE_FIELDS = {
    "profile_ref", "bundle_id", "authorized_recipient_id", "signature_evidence_ref",
    "trusted_time_epoch", "clock_uncertainty_seconds",
    "signed_prekey_published_epoch", "signed_prekey_expires_epoch",
    "signed_prekey_verified", "one_time_prekey_available", "one_time_prekey_consumed",
    "pq_kem_algorithm_id", "pq_signed_prekey_present", "pq_signed_prekey_verified",
    "pq_one_time_prekey_available", "pq_one_time_prekey_consumed",
    "last_resort_pq_prekey_used", "available_one_time_stock", "available_pq_one_time_stock",
    "prior_signed_prekey_retired_epoch", "prior_private_key_deleted_epoch",
    "recipient_authorization_evidence_ref",
}
DAY = 86400


def _id(x: Any) -> bool:
    return isinstance(x, str) and ID.fullmatch(x) is not None


def _natural(x: Any, positive: bool = False) -> bool:
    return type(x) is int and (x > 0 if positive else x >= 0)


def _require(ok: Any, msg: str) -> None:
    if not ok:
        raise ValueError(msg)


def validate_policy(p: dict[str, Any]) -> None:
    _require(isinstance(p, dict) and set(p) == POLICY_FIELDS, "invalid prekey policy fields")
    _require(p["schema_version"] == "0.1" and _id(p["policy_id"]), "invalid policy identity")
    _require(isinstance(p["pairwise_profile_ref"], str) and
             p["pairwise_profile_ref"] in PROFILES, "unsupported pairwise profile")
    pq = PROFILES[p["pairwise_profile_ref"]]
    kem = p["pq_kem_algorithm_id"]
    if pq:
        _require(isinstance(kem, str) and kem in KEMS, "PQXDH requires exact supported KEM pin")
        strength = p["pq_strength_policy"]
        _require(strength == KEMS[kem], "KEM strength policy must match exact selected parameter set")
        reason = p["strength_exception_reason"]
        if kem == "ALG-ML-KEM-512":
            _require(isinstance(reason, str) and len(reason.strip()) >= 20,
                     "constrained interoperability exception requires case-specific rationale")
        else:
            _require(reason is None, "recommended KEM cannot carry exception rationale")
    else:
        _require(kem is None and p["pq_strength_policy"] == "not-applicable" and
                 p["strength_exception_reason"] is None,
                 "classical X3DH has no PQ KEM role and must not advertise PQ security")
    rec = p["recommended_signed_prekey_lifetime_seconds"]
    maximum = p["maximum_signed_prekey_lifetime_seconds"]
    grace = p["private_key_deletion_grace_seconds"]
    skew = p["clock_uncertainty_limit_seconds"]
    _require(_natural(rec, True) and rec <= 7 * DAY, "recommended lifetime must not exceed seven-day policy")
    _require(_natural(maximum, True) and rec <= maximum <= 30 * DAY, "maximum lifetime must not exceed thirty-day policy")
    _require(_natural(grace) and grace <= 7 * DAY, "private deletion grace must be explicitly bounded")
    _require(_natural(skew) and skew <= DAY, "clock uncertainty policy must be bounded")
    for field in ("minimum_one_time_prekey_stock", "minimum_pq_one_time_prekey_stock"):
        _require(_natural(p[field]), "invalid one-time prekey stock policy")
    if not pq:
        _require(p["minimum_pq_one_time_prekey_stock"] == 0, "classical profile cannot require PQ prekeys")


def evaluate_bundle(policy: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Evaluate against a pre-authenticated bundle/clock, without claiming proof."""
    validate_policy(policy)

    def fail(reason: str) -> dict[str, Any]:
        return {"policy_consistent": False, "reason": reason, "cryptographically_verified": False}

    if not isinstance(b, dict) or set(b) != BUNDLE_FIELDS:
        return fail("malformed-bundle-evidence")
    if b["profile_ref"] != policy["pairwise_profile_ref"]:
        return fail("profile-downgrade-or-mismatch")
    if not _id(b["bundle_id"]) or not _id(b["authorized_recipient_id"]):
        return fail("invalid-bundle-identity")
    if not _id(b["signature_evidence_ref"]) or not _id(b["recipient_authorization_evidence_ref"]):
        return fail("missing-independent-signature-or-recipient-binding-evidence")
    if b["signed_prekey_verified"] is not True:
        return fail("unverified-signed-prekey")
    for key in ("trusted_time_epoch", "clock_uncertainty_seconds",
                "signed_prekey_published_epoch", "signed_prekey_expires_epoch",
                "available_one_time_stock", "available_pq_one_time_stock"):
        if not _natural(b[key]):
            return fail("malformed-time-or-stock")
    for key in ("one_time_prekey_available", "one_time_prekey_consumed",
                "pq_signed_prekey_present", "pq_signed_prekey_verified",
                "pq_one_time_prekey_available", "pq_one_time_prekey_consumed",
                "last_resort_pq_prekey_used"):
        if type(b[key]) is not bool:
            return fail("malformed-one-time-prekey-evidence")
    now, skew = b["trusted_time_epoch"], b["clock_uncertainty_seconds"]
    published, expires = b["signed_prekey_published_epoch"], b["signed_prekey_expires_epoch"]
    if skew > policy["clock_uncertainty_limit_seconds"]:
        return fail("clock-uncertainty-exceeds-policy")
    if published >= expires or expires - published > policy["maximum_signed_prekey_lifetime_seconds"]:
        return fail("signed-prekey-lifetime-exceeds-policy")
    if now - skew < published or now + skew >= expires:
        return fail("future-or-expired-signed-prekey")
    if now - skew - published >= policy["maximum_signed_prekey_lifetime_seconds"]:
        return fail("stale-offline-prekey-bundle")
    if b["one_time_prekey_available"] and not b["one_time_prekey_consumed"]:
        return fail("available-one-time-prekey-not-consumed")
    if not b["one_time_prekey_available"] and b["one_time_prekey_consumed"]:
        return fail("nonexistent-one-time-prekey-claimed-consumed")
    if b["one_time_prekey_available"] != (b["available_one_time_stock"] > 0):
        return fail("inconsistent-one-time-stock")
    pq = PROFILES[policy["pairwise_profile_ref"]]
    if pq:
        if b["pq_kem_algorithm_id"] != policy["pq_kem_algorithm_id"]:
            return fail("missing-or-downgraded-pq-kem")
        if not b["pq_signed_prekey_present"] or not b["pq_signed_prekey_verified"]:
            return fail("pq-signed-prekey-missing-or-unverified")
        if b["pq_one_time_prekey_available"] and not b["pq_one_time_prekey_consumed"]:
            return fail("available-pq-one-time-prekey-not-consumed")
        if not b["pq_one_time_prekey_available"] and b["pq_one_time_prekey_consumed"]:
            return fail("nonexistent-pq-one-time-prekey-claimed-consumed")
        if b["pq_one_time_prekey_available"] != (b["available_pq_one_time_stock"] > 0):
            return fail("inconsistent-pq-prekey-stock")
        if b["last_resort_pq_prekey_used"] == b["pq_one_time_prekey_available"]:
            return fail("pq-last-resort-selection-inconsistent")
    else:
        if (b["pq_kem_algorithm_id"] is not None or b["pq_signed_prekey_present"]
                or b["pq_signed_prekey_verified"] or b["pq_one_time_prekey_available"]
                or b["pq_one_time_prekey_consumed"] or b["last_resort_pq_prekey_used"]
                or b["available_pq_one_time_stock"] != 0):
            return fail("classical-profile-cannot-import-pq-evidence")
    retired = b["prior_signed_prekey_retired_epoch"]
    deleted = b["prior_private_key_deleted_epoch"]
    if retired is None:
        if deleted is not None:
            return fail("private-deletion-without-retirement")
    elif not _natural(retired):
        return fail("invalid-retirement-timestamp")
    else:
        if retired > now + skew:
            return fail("retirement-in-future")
        cutoff = retired + policy["private_key_deletion_grace_seconds"]
        if now - skew > cutoff and deleted is None:
            return fail("private-prekey-retained-past-grace")
        if deleted is not None and (not _natural(deleted) or deleted < retired or deleted > cutoff):
            return fail("invalid-or-late-private-prekey-deletion")

    below_stock = b["available_one_time_stock"] < policy["minimum_one_time_prekey_stock"]
    pq_below = pq and b["available_pq_one_time_stock"] < policy["minimum_pq_one_time_prekey_stock"]
    return {
        "policy_consistent": True,
        "reason": "reference-policy-consistent",
        "cryptographically_verified": False,
        "low_one_time_stock": below_stock,
        "low_pq_one_time_stock": bool(pq_below),
        "pq_last_resort_used": b["last_resort_pq_prekey_used"],
        "retained_private_key_warning": retired is not None and deleted is None,
        "assurance": "cryptographic-signature-key-isolation-and-erasure-require-real-endpoint-evidence",
    }
