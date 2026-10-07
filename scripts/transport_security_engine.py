#!/usr/bin/env python3
"""Semantic validator for E2EESA TLS 1.3 transport-security profiles."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PROFILE_MODES = {
    "transport-tls13-classical@0.1.0": "classical",
    "transport-tls13-hybrid@0.1.0": "hybrid",
}
TLS13_CIPHER_SUITES = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def _profile_index(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in catalog.get("profiles", []):
        if not isinstance(item, dict):
            continue
        pid = item.get("profile_id")
        version = item.get("profile_version")
        if isinstance(pid, str) and isinstance(version, str):
            result[f"{pid}@{version}"] = item
    return result


def _group_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("groups", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _cipher_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("cipher_suites", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _algorithm_index(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item.get("id"): item
        for item in registry.get("algorithms", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def validate_registry(
    registry: dict[str, Any],
    source: str = "transport security registry",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version","registry_version","standard_version","tls_protocol",
        "transport_modes","cipher_suites","groups","obsoleted_groups",
        "identity_verification",
    }
    extra = sorted(set(registry) - required)
    missing = sorted(required - registry.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if registry.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    tls = registry.get("tls_protocol")
    if not isinstance(tls, dict):
        errors.append(f"{source}: tls_protocol must be an object")
    else:
        if tls.get("id") != "TLS-1.3-RFC9846":
            errors.append(f"{source}: TLS protocol id must be TLS-1.3-RFC9846")
        if tls.get("version") != "TLS1.3":
            errors.append(f"{source}: TLS version must be TLS1.3")
        if tls.get("specification") != "RFC 9846":
            errors.append(f"{source}: TLS 1.3 must pin RFC 9846")

    groups = registry.get("groups")
    if not isinstance(groups, list):
        errors.append(f"{source}: groups must be an array")
        groups = []
    by_group = _group_index(registry)
    expected_groups = {
        "X25519": ("traditional", 29),
        "secp256r1": ("traditional", 23),
        "secp384r1": ("traditional", 24),
        "SecP256r1MLKEM768": ("hybrid", 4587),
        "X25519MLKEM768": ("hybrid", 4588),
        "SecP384r1MLKEM1024": ("hybrid", 4589),
    }
    if set(by_group) != set(expected_groups):
        errors.append(f"{source}: transport group registry does not match E2EESA 0.1 required set")
    for group_id, (kind, value) in expected_groups.items():
        item = by_group.get(group_id, {})
        if item.get("kind") != kind:
            errors.append(f"{source}: {group_id} has wrong kind")
        if item.get("iana_value") != value:
            errors.append(f"{source}: {group_id} has wrong IANA value")
    if by_group.get("X25519MLKEM768", {}).get("status") != "recommended":
        errors.append(f"{source}: X25519MLKEM768 must be the recommended hybrid group")
    for gid in ("SecP256r1MLKEM768","X25519MLKEM768","SecP384r1MLKEM1024"):
        if by_group.get(gid, {}).get("specification") != "RFC 10024":
            errors.append(f"{source}: {gid} must pin RFC 10024")

    ciphers = registry.get("cipher_suites")
    if not isinstance(ciphers, list):
        errors.append(f"{source}: cipher_suites must be an array")
        ciphers = []
    by_cipher = _cipher_index(registry)
    if set(by_cipher) != TLS13_CIPHER_SUITES:
        errors.append(f"{source}: TLS 1.3 cipher-suite registry is incomplete")
    for cipher in by_cipher.values():
        if cipher.get("specification") != "RFC 9846":
            errors.append(f"{source}: TLS cipher suite must pin RFC 9846")

    obsolete = {
        item.get("id"): item
        for item in registry.get("obsoleted_groups", [])
        if isinstance(item, dict)
    }
    if obsolete.get("X25519Kyber768Draft00", {}).get("replacement") != "X25519MLKEM768":
        errors.append(f"{source}: obsolete X25519Kyber group must point to X25519MLKEM768")
    if obsolete.get("SecP256r1Kyber768Draft00", {}).get("replacement") != "SecP256r1MLKEM768":
        errors.append(f"{source}: obsolete P-256 Kyber group must point to SecP256r1MLKEM768")

    identity = registry.get("identity_verification")
    if not isinstance(identity, dict):
        errors.append(f"{source}: identity_verification must be an object")
    else:
        if identity.get("specification") != "RFC 9525":
            errors.append(f"{source}: service identity verification must pin RFC 9525")
        if identity.get("common_name_fallback") != "prohibited":
            errors.append(f"{source}: Common Name fallback must be prohibited")
    return sorted(set(errors))


def validate_policy(
    policy: dict[str, Any],
    transport_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "transport security policy",
) -> list[str]:
    errors = validate_registry(transport_registry)
    required = {
        "schema_version","policy_id","profile_ref","registry_version",
        "transport_mode","quic_version","minimum_tls_version","maximum_tls_version",
        "allowed_group_ids","preferred_group_id","require_hybrid_group",
        "allowed_cipher_suites","preferred_cipher_suite",
        "authentication_mode","trust_model","service_identity_verification",
        "require_certificate_chain_validation","require_reference_identifier_match",
        "require_fresh_key_share","require_ephemeral_key_exchange_on_resumption",
        "require_alpn","allowed_alpns","allow_0rtt",
        "zero_rtt_application_profile","zero_rtt_replay_protection_required",
        "require_fail_closed_on_transport_downgrade",
        "require_fail_closed_on_hybrid_downgrade",
        "require_no_common_name_fallback","require_e2ee_layer_independence",
    }
    allowed = required | {"notes"}
    extra = sorted(set(policy) - allowed)
    missing = sorted(required - policy.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if policy.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(policy.get("policy_id"), str) or not ID_RE.fullmatch(policy.get("policy_id", "")):
        errors.append(f"{source}: invalid policy_id")

    profile_ref = policy.get("profile_ref")
    mode = PROFILE_MODES.get(profile_ref)
    profile = _profile_index(profile_catalog).get(profile_ref)
    if mode is None:
        errors.append(f"{source}: unsupported profile_ref: {profile_ref}")
    elif profile is None:
        errors.append(f"{source}: profile_ref not found in catalog")
    elif profile.get("family_id") != "transport-security":
        errors.append(f"{source}: profile_ref must belong to transport-security")

    if policy.get("registry_version") != transport_registry.get("registry_version"):
        errors.append(f"{source}: registry_version does not match transport registry")

    if policy.get("minimum_tls_version") != "TLS1.3" or policy.get("maximum_tls_version") != "TLS1.3":
        errors.append(f"{source}: E2EESA transport profiles require TLS 1.3 only")

    transport_mode = policy.get("transport_mode")
    quic_version = policy.get("quic_version")
    if transport_mode == "tls-stream":
        if quic_version is not None:
            errors.append(f"{source}: tls-stream profile must set quic_version to null")
    elif transport_mode == "quic":
        if quic_version not in {"v1","v2"}:
            errors.append(f"{source}: QUIC transport requires quic_version v1 or v2")
    else:
        errors.append(f"{source}: unsupported transport_mode")

    groups = _group_index(transport_registry)
    allowed_groups = policy.get("allowed_group_ids")
    if not isinstance(allowed_groups, list) or not allowed_groups:
        errors.append(f"{source}: allowed_group_ids must be non-empty")
        allowed_groups = []
    if len(allowed_groups) != len(set(allowed_groups)):
        errors.append(f"{source}: allowed_group_ids must be unique")
    for gid in allowed_groups:
        group = groups.get(gid)
        if group is None:
            errors.append(f"{source}: unknown allowed group: {gid}")
        elif group.get("status") in {"deprecated","prohibited"}:
            errors.append(f"{source}: deprecated/prohibited group is not allowed: {gid}")

    preferred = policy.get("preferred_group_id")
    if preferred not in allowed_groups:
        errors.append(f"{source}: preferred_group_id must be in allowed_group_ids")

    if mode == "classical":
        if policy.get("require_hybrid_group") is not False:
            errors.append(f"{source}: classical profile must set require_hybrid_group=false")
        if policy.get("require_fail_closed_on_hybrid_downgrade") is not False:
            errors.append(f"{source}: classical profile must not claim hybrid downgrade enforcement")
        for gid in allowed_groups:
            if groups.get(gid, {}).get("kind") != "traditional":
                errors.append(f"{source}: classical profile may only allow traditional groups")
    if mode == "hybrid":
        if policy.get("require_hybrid_group") is not True:
            errors.append(f"{source}: hybrid profile requires require_hybrid_group=true")
        if policy.get("require_fail_closed_on_hybrid_downgrade") is not True:
            errors.append(f"{source}: hybrid profile must fail closed on hybrid downgrade")
        for gid in allowed_groups:
            if groups.get(gid, {}).get("kind") != "hybrid":
                errors.append(f"{source}: hybrid profile may only allow RFC 10024 hybrid groups")

    ciphers = _cipher_index(transport_registry)
    allowed_ciphers = policy.get("allowed_cipher_suites")
    if not isinstance(allowed_ciphers, list) or not allowed_ciphers:
        errors.append(f"{source}: allowed_cipher_suites must be non-empty")
        allowed_ciphers = []
    if len(allowed_ciphers) != len(set(allowed_ciphers)):
        errors.append(f"{source}: allowed_cipher_suites must be unique")
    for cid in allowed_ciphers:
        if cid not in ciphers:
            errors.append(f"{source}: unknown TLS cipher suite: {cid}")
    if policy.get("preferred_cipher_suite") not in allowed_ciphers:
        errors.append(f"{source}: preferred_cipher_suite must be in allowed_cipher_suites")

    if policy.get("authentication_mode") not in {"server-certificate","mutual-certificate"}:
        errors.append(f"{source}: invalid authentication_mode")
    if policy.get("trust_model") not in {"public-web-pki","private-pki"}:
        errors.append(f"{source}: invalid trust_model")
    if policy.get("service_identity_verification") != "RFC9525":
        errors.append(f"{source}: service identity verification must be RFC9525")

    for field in (
        "require_certificate_chain_validation",
        "require_reference_identifier_match",
        "require_fresh_key_share",
        "require_ephemeral_key_exchange_on_resumption",
        "require_alpn",
        "require_fail_closed_on_transport_downgrade",
        "require_no_common_name_fallback",
        "require_e2ee_layer_independence",
    ):
        if policy.get(field) is not True:
            errors.append(f"{source}: {field} must be true")

    alpns = policy.get("allowed_alpns")
    if not isinstance(alpns, list) or not alpns or len(alpns) != len(set(alpns)):
        errors.append(f"{source}: allowed_alpns must be a non-empty unique array")
    elif any(not isinstance(x, str) or not x or len(x) > 64 for x in alpns):
        errors.append(f"{source}: invalid ALPN identifier")

    allow_0rtt = policy.get("allow_0rtt")
    replay_required = policy.get("zero_rtt_replay_protection_required")
    app_profile = policy.get("zero_rtt_application_profile")
    if not isinstance(allow_0rtt, bool) or not isinstance(replay_required, bool):
        errors.append(f"{source}: 0-RTT policy flags must be boolean")
    elif allow_0rtt:
        if not isinstance(app_profile, str) or not app_profile:
            errors.append(f"{source}: enabling 0-RTT requires an application replay-safety profile")
        if replay_required is not True:
            errors.append(f"{source}: enabling 0-RTT requires replay protection")
    else:
        if app_profile is not None:
            errors.append(f"{source}: disabled 0-RTT must set zero_rtt_application_profile to null")
        if replay_required is not False:
            errors.append(f"{source}: disabled 0-RTT must set replay-protection flag false")

    algorithms = _algorithm_index(crypto_registry)
    if not any(
        isinstance(item, dict)
        and item.get("id") == "ALG-ML-KEM-768"
        and item.get("category") == "kem"
        for item in crypto_registry.get("algorithms", [])
    ):
        errors.append(f"{source}: cryptographic registry must contain ML-KEM-768")
    if mode == "hybrid" and preferred in {"SecP384r1MLKEM1024"}:
        if "ALG-ML-KEM-1024" not in algorithms:
            errors.append(f"{source}: ML-KEM-1024 must be registered for P-384 hybrid group")

    if "notes" in policy and not isinstance(policy["notes"], str):
        errors.append(f"{source}: notes must be a string")
    return sorted(set(errors))


def validate_handshake(
    policy: dict[str, Any],
    evidence: dict[str, Any],
    transport_registry: dict[str, Any],
    crypto_registry: dict[str, Any],
    profile_catalog: dict[str, Any],
    source: str = "transport handshake evidence",
) -> list[str]:
    errors = validate_policy(
        policy, transport_registry, crypto_registry, profile_catalog
    )
    if errors:
        return errors

    required = {
        "schema_version","connection_id","profile_ref","transport_mode","quic_version",
        "tls_version","offered_group_ids","selected_group_id","selected_cipher_suite",
        "alpn","fresh_key_share_verified","session_resumed","psk_key_exchange_mode",
        "early_data_used","zero_rtt_application_profile_applied",
        "zero_rtt_replay_protection_verified",
        "server_certificate_chain_validated","server_reference_identifier",
        "expected_reference_identifier","reference_identifier_match",
        "common_name_fallback_used","certificate_currently_valid",
        "certificate_signature_algorithm_id","trust_model",
        "client_certificate_requested","client_certificate_present",
        "client_certificate_validated","client_identity_authorized",
        "hybrid_to_classical_fallback_occurred",
        "obsolete_prestandard_kyber_group_used",
        "transport_key_exchange_pq_protected",
        "pq_authentication_claimed_from_transport",
        "application_e2ee_terminated_or_decrypted_by_transport",
    }
    extra = sorted(set(evidence) - required)
    missing = sorted(required - evidence.keys())
    if extra:
        errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if missing:
        errors.append(f"{source}: missing fields: {', '.join(missing)}")
    if errors:
        return sorted(set(errors))

    if evidence.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(evidence.get("connection_id"), str) or not ID_RE.fullmatch(evidence.get("connection_id", "")):
        errors.append(f"{source}: invalid connection_id")
    if evidence.get("profile_ref") != policy.get("profile_ref"):
        errors.append(f"{source}: profile_ref does not match policy")
    if evidence.get("transport_mode") != policy.get("transport_mode"):
        errors.append(f"{source}: transport_mode does not match policy")
    if evidence.get("quic_version") != policy.get("quic_version"):
        errors.append(f"{source}: quic_version does not match policy")
    if evidence.get("tls_version") != "TLS1.3":
        errors.append(f"{source}: negotiated TLS version must be TLS1.3")

    offered = evidence.get("offered_group_ids")
    if not isinstance(offered, list) or not offered or len(offered) != len(set(offered)):
        errors.append(f"{source}: offered_group_ids must be a non-empty unique array")
        offered = []
    selected = evidence.get("selected_group_id")
    if selected not in offered:
        errors.append(f"{source}: selected group was not offered")
    if selected not in policy.get("allowed_group_ids", []):
        errors.append(f"{source}: selected group is not allowed by policy")

    group = _group_index(transport_registry).get(selected)
    mode = PROFILE_MODES[policy["profile_ref"]]
    if group is None:
        errors.append(f"{source}: selected group is not registered")
    elif mode == "classical" and group.get("kind") != "traditional":
        errors.append(f"{source}: classical profile negotiated a non-traditional group")
    elif mode == "hybrid" and group.get("kind") != "hybrid":
        errors.append(f"{source}: hybrid profile negotiated a non-hybrid group")

    cipher = evidence.get("selected_cipher_suite")
    if cipher not in policy.get("allowed_cipher_suites", []):
        errors.append(f"{source}: selected cipher suite is not allowed by policy")
    if cipher not in TLS13_CIPHER_SUITES:
        errors.append(f"{source}: selected cipher suite is not an E2EESA TLS 1.3 suite")

    if evidence.get("alpn") not in policy.get("allowed_alpns", []):
        errors.append(f"{source}: negotiated ALPN is not allowed")
    if evidence.get("fresh_key_share_verified") is not True:
        errors.append(f"{source}: fresh TLS key share must be verified")

    resumed = evidence.get("session_resumed")
    psk_mode = evidence.get("psk_key_exchange_mode")
    if not isinstance(resumed, bool):
        errors.append(f"{source}: session_resumed must be boolean")
    if psk_mode == "psk_ke":
        errors.append(f"{source}: PSK-only resumption is prohibited; ephemeral key exchange is required")
    if resumed:
        if psk_mode != "psk_dhe_ke":
            errors.append(f"{source}: resumed connection must use psk_dhe_ke")
    elif psk_mode != "none":
        errors.append(f"{source}: non-resumed connection must use psk_key_exchange_mode=none")

    early = evidence.get("early_data_used")
    if not isinstance(early, bool):
        errors.append(f"{source}: early_data_used must be boolean")
    elif early:
        if policy.get("allow_0rtt") is not True:
            errors.append(f"{source}: 0-RTT early data used despite policy prohibition")
        if evidence.get("zero_rtt_application_profile_applied") is not True:
            errors.append(f"{source}: 0-RTT requires approved application replay-safety profile")
        if evidence.get("zero_rtt_replay_protection_verified") is not True:
            errors.append(f"{source}: 0-RTT replay protection did not verify")
    else:
        if evidence.get("zero_rtt_application_profile_applied") is not False:
            errors.append(f"{source}: unused 0-RTT must not claim application replay profile")
        if evidence.get("zero_rtt_replay_protection_verified") is not False:
            errors.append(f"{source}: unused 0-RTT must not claim replay-protection verification")

    for field in (
        "server_certificate_chain_validated",
        "reference_identifier_match",
        "certificate_currently_valid",
    ):
        if evidence.get(field) is not True:
            errors.append(f"{source}: {field} must be true")
    expected_name = evidence.get("expected_reference_identifier")
    presented_name = evidence.get("server_reference_identifier")
    if not isinstance(expected_name, str) or not expected_name:
        errors.append(f"{source}: expected_reference_identifier must be non-empty")
    if not isinstance(presented_name, str) or not presented_name:
        errors.append(f"{source}: server_reference_identifier must be non-empty")
    if expected_name != presented_name:
        errors.append(f"{source}: RFC 9525 service reference identifier mismatch")
    if evidence.get("common_name_fallback_used") is not False:
        errors.append(f"{source}: Common Name fallback is prohibited")

    signature_id = evidence.get("certificate_signature_algorithm_id")
    signature = _algorithm_index(crypto_registry).get(signature_id)
    if signature is None:
        errors.append(f"{source}: certificate signature algorithm is not registered")
    else:
        if signature.get("category") != "signature":
            errors.append(f"{source}: certificate signature algorithm must be a signature algorithm")
        if signature.get("status") == "prohibited":
            errors.append(f"{source}: prohibited certificate signature algorithm")
    if evidence.get("trust_model") != policy.get("trust_model"):
        errors.append(f"{source}: trust_model does not match policy")

    auth_mode = policy.get("authentication_mode")
    if auth_mode == "mutual-certificate":
        for field in (
            "client_certificate_requested",
            "client_certificate_present",
            "client_certificate_validated",
            "client_identity_authorized",
        ):
            if evidence.get(field) is not True:
                errors.append(f"{source}: mutual TLS requires {field}=true")
    else:
        for field in (
            "client_certificate_requested",
            "client_certificate_present",
            "client_certificate_validated",
            "client_identity_authorized",
        ):
            if evidence.get(field) is not False:
                errors.append(f"{source}: server-certificate mode must set {field}=false")

    if evidence.get("hybrid_to_classical_fallback_occurred") is not False:
        errors.append(f"{source}: hybrid/classical fallback event is not permitted for a conforming handshake")
    if evidence.get("obsolete_prestandard_kyber_group_used") is not False:
        errors.append(f"{source}: pre-standard Kyber TLS groups are obsolete and prohibited")

    pq_exchange = evidence.get("transport_key_exchange_pq_protected")
    if mode == "hybrid":
        if pq_exchange is not True:
            errors.append(f"{source}: hybrid profile must confirm PQ-protected key exchange")
    else:
        if pq_exchange is not False:
            errors.append(f"{source}: classical profile must not claim PQ-protected key exchange")

    if evidence.get("pq_authentication_claimed_from_transport") is not False:
        errors.append(
            f"{source}: transport profile does not by itself establish post-quantum authentication"
        )
    if evidence.get("application_e2ee_terminated_or_decrypted_by_transport") is not False:
        errors.append(
            f"{source}: transport layer must not terminate or decrypt a separate application E2EE layer"
        )
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate E2EESA TLS 1.3 transport evidence.")
    parser.add_argument("policy", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("transport_registry", type=Path)
    parser.add_argument("crypto_registry", type=Path)
    parser.add_argument("profile_catalog", type=Path)
    args = parser.parse_args()
    try:
        errors = validate_handshake(
            load_json(args.policy),
            load_json(args.evidence),
            load_json(args.transport_registry),
            load_json(args.crypto_registry),
            load_json(args.profile_catalog),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1
    print(json.dumps({"valid": not errors, "errors": errors}, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
