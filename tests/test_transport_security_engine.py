from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "transport_security_engine.py"

spec = importlib.util.spec_from_file_location("transport_security_engine", MODULE_PATH)
transport_security_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = transport_security_engine
spec.loader.exec_module(transport_security_engine)


class TransportSecurityEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/transport-security.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/transport/policies/{name}.json")

    def evidence(self, name: str) -> dict:
        return self.load(f"fixtures/transport/evidence/{name}.json")

    def validate_policy(self, name: str, policy: dict | None = None) -> list[str]:
        return transport_security_engine.validate_policy(
            policy if policy is not None else self.policy(name),
            self.registry(),
            self.crypto(),
            self.catalog(),
        )

    def validate(self, policy_name: str, evidence_name: str | None = None, evidence: dict | None = None) -> list[str]:
        ev = evidence if evidence is not None else self.evidence(evidence_name or policy_name)
        return transport_security_engine.validate_handshake(
            self.policy(policy_name),
            ev,
            self.registry(),
            self.crypto(),
            self.catalog(),
        )

    def test_registry_pins_current_2026_tls_and_hybrid_rfcs(self) -> None:
        self.assertEqual(transport_security_engine.validate_registry(self.registry()), [])
        self.assertEqual(self.registry()["tls_protocol"]["specification"], "RFC 9846")
        groups = {g["id"]: g for g in self.registry()["groups"]}
        self.assertEqual(groups["X25519MLKEM768"]["iana_value"], 4588)
        self.assertEqual(groups["SecP256r1MLKEM768"]["iana_value"], 4587)
        self.assertEqual(groups["SecP384r1MLKEM1024"]["iana_value"], 4589)

    def test_two_transport_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "transport-security"
        }
        self.assertEqual(refs, set(transport_security_engine.PROFILE_MODES))

    def test_all_valid_policies_pass(self) -> None:
        for name in ("classical-public", "hybrid-public", "hybrid-mtls", "hybrid-quic"):
            with self.subTest(name=name):
                self.assertEqual(self.validate_policy(name), [])

    def test_classical_policy_cannot_allow_hybrid_group(self) -> None:
        policy = copy.deepcopy(self.policy("classical-public"))
        policy["allowed_group_ids"] = ["X25519MLKEM768"]
        policy["preferred_group_id"] = "X25519MLKEM768"
        errors = self.validate_policy("classical-public", policy)
        self.assertTrue(any("only allow traditional" in e for e in errors), errors)

    def test_hybrid_policy_cannot_allow_classical_fallback(self) -> None:
        policy = copy.deepcopy(self.policy("hybrid-public"))
        policy["allowed_group_ids"].append("X25519")
        errors = self.validate_policy("hybrid-public", policy)
        self.assertTrue(any("only allow RFC 10024 hybrid groups" in e for e in errors), errors)

    def test_hybrid_policy_must_fail_closed_on_hybrid_downgrade(self) -> None:
        policy = copy.deepcopy(self.policy("hybrid-public"))
        policy["require_fail_closed_on_hybrid_downgrade"] = False
        errors = self.validate_policy("hybrid-public", policy)
        self.assertTrue(any("must fail closed" in e for e in errors), errors)

    def test_valid_reference_handshakes_pass(self) -> None:
        cases = (
            ("classical-public", "classical-public"),
            ("hybrid-public", "hybrid-public"),
            ("hybrid-mtls", "hybrid-mtls"),
            ("hybrid-quic", "hybrid-quic"),
            ("hybrid-public", "hybrid-resumed"),
        )
        for policy_name, evidence_name in cases:
            with self.subTest(policy=policy_name, evidence=evidence_name):
                self.assertEqual(self.validate(policy_name, evidence_name), [])

    def test_tls12_is_rejected(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["tls_version"] = "TLS1.2"
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("must be TLS1.3" in e for e in errors), errors)

    def test_hybrid_handshake_rejects_classical_selected_group(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["offered_group_ids"].append("X25519")
        evidence["selected_group_id"] = "X25519"
        evidence["transport_key_exchange_pq_protected"] = False
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("not allowed by policy" in e for e in errors), errors)
        self.assertTrue(any("non-hybrid group" in e for e in errors), errors)

    def test_obsolete_kyber_draft_group_claim_is_rejected(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["obsolete_prestandard_kyber_group_used"] = True
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("pre-standard Kyber" in e for e in errors), errors)

    def test_fresh_key_share_is_required(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["fresh_key_share_verified"] = False
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("fresh TLS key share" in e for e in errors), errors)

    def test_psk_only_resumption_is_rejected(self) -> None:
        evidence = self.evidence("hybrid-resumed")
        evidence["psk_key_exchange_mode"] = "psk_ke"
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("PSK-only resumption" in e for e in errors), errors)

    def test_service_reference_identifier_must_match(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["server_reference_identifier"] = "evil.example.test"
        evidence["reference_identifier_match"] = False
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("reference identifier mismatch" in e for e in errors), errors)

    def test_common_name_fallback_is_rejected(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["common_name_fallback_used"] = True
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("Common Name fallback" in e for e in errors), errors)

    def test_invalid_certificate_chain_or_time_is_rejected(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["server_certificate_chain_validated"] = False
        self.assertTrue(self.validate("hybrid-public", evidence=evidence))

        evidence = self.evidence("hybrid-public")
        evidence["certificate_currently_valid"] = False
        self.assertTrue(self.validate("hybrid-public", evidence=evidence))

    def test_mutual_tls_requires_client_certificate_and_authorization(self) -> None:
        for field in (
            "client_certificate_requested",
            "client_certificate_present",
            "client_certificate_validated",
            "client_identity_authorized",
        ):
            with self.subTest(field=field):
                evidence = self.evidence("hybrid-mtls")
                evidence[field] = False
                errors = self.validate("hybrid-mtls", evidence=evidence)
                self.assertTrue(any(field in e for e in errors), errors)

    def test_default_policy_rejects_0rtt(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["early_data_used"] = True
        evidence["zero_rtt_application_profile_applied"] = True
        evidence["zero_rtt_replay_protection_verified"] = True
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("despite policy prohibition" in e for e in errors), errors)

    def test_explicit_replay_safe_0rtt_profile_can_pass(self) -> None:
        policy = copy.deepcopy(self.policy("hybrid-public"))
        policy["allow_0rtt"] = True
        policy["zero_rtt_application_profile"] = "http-safe-read-v1"
        policy["zero_rtt_replay_protection_required"] = True
        self.assertEqual(
            transport_security_engine.validate_policy(
                policy, self.registry(), self.crypto(), self.catalog()
            ),
            [],
        )
        evidence = self.evidence("hybrid-public")
        evidence["early_data_used"] = True
        evidence["zero_rtt_application_profile_applied"] = True
        evidence["zero_rtt_replay_protection_verified"] = True
        self.assertEqual(
            transport_security_engine.validate_handshake(
                policy, evidence, self.registry(), self.crypto(), self.catalog()
            ),
            [],
        )

    def test_hybrid_profile_requires_pq_protected_key_exchange(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["transport_key_exchange_pq_protected"] = False
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("must confirm PQ-protected" in e for e in errors), errors)

    def test_classical_profile_cannot_claim_pq_key_exchange(self) -> None:
        evidence = self.evidence("classical-public")
        evidence["transport_key_exchange_pq_protected"] = True
        errors = self.validate("classical-public", evidence=evidence)
        self.assertTrue(any("must not claim PQ-protected" in e for e in errors), errors)

    def test_transport_profile_cannot_claim_pq_authentication_by_itself(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["pq_authentication_claimed_from_transport"] = True
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("does not by itself establish post-quantum authentication" in e for e in errors), errors)

    def test_transport_cannot_terminate_application_e2ee(self) -> None:
        evidence = self.evidence("hybrid-public")
        evidence["application_e2ee_terminated_or_decrypted_by_transport"] = True
        errors = self.validate("hybrid-public", evidence=evidence)
        self.assertTrue(any("must not terminate or decrypt" in e for e in errors), errors)

    def test_quic_version_must_match_policy(self) -> None:
        evidence = self.evidence("hybrid-quic")
        evidence["quic_version"] = "v1"
        errors = self.validate("hybrid-quic", evidence=evidence)
        self.assertTrue(any("quic_version does not match policy" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
