from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "metadata_privacy_engine.py"

spec = importlib.util.spec_from_file_location("metadata_privacy_engine", MODULE_PATH)
metadata_privacy_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = metadata_privacy_engine
spec.loader.exec_module(metadata_privacy_engine)


class MetadataPrivacyEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/metadata-privacy-mechanisms.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/metadata/policies/{name}.json")

    def evidence(self, name: str) -> dict:
        return self.load(f"fixtures/metadata/evidence/{name}.json")

    def validate_policy(self, policy: dict) -> list[str]:
        return metadata_privacy_engine.validate_policy(
            policy, self.registry(), self.crypto(), self.catalog()
        )

    def validate(self, policy_name: str, evidence: dict | None = None) -> list[str]:
        return metadata_privacy_engine.validate_delivery_evidence(
            self.policy(policy_name),
            evidence if evidence is not None else self.evidence(policy_name),
            self.registry(),
            self.crypto(),
            self.catalog(),
        )

    def test_protocol_registry_is_valid(self) -> None:
        self.assertEqual(
            metadata_privacy_engine.validate_protocol_registry(self.registry()),
            [],
        )

    def test_three_metadata_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "metadata-privacy"
        }
        self.assertEqual(refs, set(metadata_privacy_engine.PROFILE_MODES))

    def test_all_three_policies_pass(self) -> None:
        for name in ("minimized", "sender-hidden", "relay"):
            with self.subTest(name=name):
                self.assertEqual(self.validate_policy(self.policy(name)), [])

    def test_retention_limits_are_enforced(self) -> None:
        policy = copy.deepcopy(self.policy("minimized"))
        policy["max_post_delivery_metadata_retention_seconds"] = 86401
        errors = self.validate_policy(policy)
        self.assertTrue(any("exceeds 24 hours" in e for e in errors), errors)

        policy = copy.deepcopy(self.policy("sender-hidden"))
        policy["max_service_source_ip_retention_seconds"] = 3601
        errors = self.validate_policy(policy)
        self.assertTrue(any("exceeds one hour" in e for e in errors), errors)

    def test_relay_policy_requires_registered_ohttp_algorithm_categories(self) -> None:
        policy = copy.deepcopy(self.policy("relay"))
        policy["ohttp_kem_algorithm_id"] = "ALG-SHA256"
        errors = self.validate_policy(policy)
        self.assertTrue(any("expected kem" in e for e in errors), errors)

    def test_all_valid_delivery_evidence_passes(self) -> None:
        for name in ("minimized", "sender-hidden", "relay"):
            with self.subTest(name=name):
                self.assertEqual(self.validate(name), [])

    def test_sender_hidden_rejects_service_visible_sender(self) -> None:
        evidence = self.evidence("sender-hidden")
        evidence["sender_identity_visible_to_service"] = True
        errors = self.validate("sender-hidden", evidence)
        self.assertTrue(any("must not expose sender identity" in e for e in errors), errors)

    def test_sender_hidden_requires_recipient_authentication_material(self) -> None:
        evidence = self.evidence("sender-hidden")
        evidence["sender_credential_inside_e2ee_envelope"] = False
        errors = self.validate("sender-hidden", evidence)
        self.assertTrue(any("sender credential" in e for e in errors), errors)

        evidence = self.evidence("sender-hidden")
        evidence["recipient_delivery_capability_verified"] = False
        errors = self.validate("sender-hidden", evidence)
        self.assertTrue(any("delivery capability" in e for e in errors), errors)

    def test_durable_social_graph_content_metadata_and_tracking_ids_are_rejected(self) -> None:
        for field in (
            "durable_sender_recipient_mapping_written",
            "content_derived_service_metadata_written",
            "stable_cross_service_identifier_attached",
        ):
            with self.subTest(field=field):
                evidence = self.evidence("minimized")
                evidence[field] = True
                self.assertTrue(self.validate("minimized", evidence))

    def test_relay_profile_hides_client_network_address_from_service_and_gateway(self) -> None:
        evidence = self.evidence("relay")
        evidence["service_observed_client_network_address"] = True
        errors = self.validate("relay", evidence)
        self.assertTrue(any("service must not observe client network address" in e for e in errors), errors)

        evidence = self.evidence("relay")
        evidence["gateway_observed_client_network_address"] = True
        errors = self.validate("relay", evidence)
        self.assertTrue(any("gateway must not observe client network address" in e for e in errors), errors)

    def test_relay_cannot_see_application_plaintext(self) -> None:
        evidence = self.evidence("relay")
        evidence["relay_observed_application_plaintext"] = True
        errors = self.validate("relay", evidence)
        self.assertTrue(any("relay must not observe application plaintext" in e for e in errors), errors)

    def test_personalized_gateway_config_and_identifying_headers_are_rejected(self) -> None:
        evidence = self.evidence("relay")
        evidence["gateway_key_config_personalized"] = True
        errors = self.validate("relay", evidence)
        self.assertTrue(any("personalized OHTTP key configuration" in e for e in errors), errors)

        evidence = self.evidence("relay")
        evidence["relay_added_identifying_headers"] = True
        errors = self.validate("relay", evidence)
        self.assertTrue(any("must not add client-identifying" in e for e in errors), errors)

    def test_relay_gateway_operator_independence_is_required(self) -> None:
        evidence = self.evidence("relay")
        evidence["relay_gateway_independent_operators"] = False
        errors = self.validate("relay", evidence)
        self.assertTrue(any("independently operated" in e for e in errors), errors)

    def test_relay_requires_padding_and_replay_protection(self) -> None:
        evidence = self.evidence("relay")
        evidence["request_padding_applied"] = False
        errors = self.validate("relay", evidence)
        self.assertTrue(any("requires request padding" in e for e in errors), errors)

        evidence = self.evidence("relay")
        evidence["padding_multiple_bytes"] = 128
        errors = self.validate("relay", evidence)
        self.assertTrue(any("below policy minimum" in e for e in errors), errors)

        evidence = self.evidence("relay")
        evidence["ohttp_replay_protection_enforced"] = False
        errors = self.validate("relay", evidence)
        self.assertTrue(any("replay protection" in e for e in errors), errors)

    def test_relay_source_ip_cannot_be_durably_retained(self) -> None:
        evidence = self.evidence("relay")
        evidence["relay_source_ip_retention_seconds"] = 1
        errors = self.validate("relay", evidence)
        self.assertTrue(any("relay source-IP retention exceeds policy" in e for e in errors), errors)

    def test_post_delivery_retention_evidence_cannot_exceed_policy(self) -> None:
        evidence = self.evidence("sender-hidden")
        evidence["post_delivery_metadata_retention_seconds"] = 3601
        errors = self.validate("sender-hidden", evidence)
        self.assertTrue(any("post-delivery metadata retention exceeds policy" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
