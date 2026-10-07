from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "contact_discovery_engine.py"

spec = importlib.util.spec_from_file_location("contact_discovery_engine", MODULE_PATH)
contact_discovery_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = contact_discovery_engine
spec.loader.exec_module(contact_discovery_engine)


class ContactDiscoveryEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/contact-discovery-mechanisms.json")

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/contact-discovery/policies/{name}.json")

    def evidence(self, name: str) -> dict:
        return self.load(f"fixtures/contact-discovery/evidence/{name}.json")

    def validate(self, name: str, evidence: dict | None = None) -> list[str]:
        return contact_discovery_engine.validate_evidence(
            self.policy(name),
            evidence if evidence is not None else self.evidence(name),
            self.registry(),
            self.catalog(),
        )

    def test_registry_and_profiles(self) -> None:
        self.assertEqual(contact_discovery_engine.validate_registry(self.registry()), [])
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "contact-discovery"
        }
        self.assertEqual(refs, set(contact_discovery_engine.PROFILE_MODES))

    def test_valid_policies_and_evidence(self) -> None:
        for name in ("exact", "voprf", "attested"):
            with self.subTest(name=name):
                self.assertEqual(
                    contact_discovery_engine.validate_policy(
                        self.policy(name), self.registry(), self.catalog()
                    ),
                    [],
                )
                self.assertEqual(self.validate(name), [])

    def test_raw_address_book_and_hash_uploads_are_rejected(self) -> None:
        for field in ("raw_address_book_sent_to_service","raw_identifier_hashes_sent_to_service"):
            evidence = self.evidence("voprf")
            evidence[field] = True
            self.assertTrue(self.validate("voprf", evidence))

    def test_exact_profile_is_single_explicit_query(self) -> None:
        policy = copy.deepcopy(self.policy("exact"))
        policy["max_batch_size"] = 2
        errors = contact_discovery_engine.validate_policy(policy, self.registry(), self.catalog())
        self.assertTrue(any("max_batch_size must be 1" in e for e in errors), errors)
        evidence = self.evidence("exact")
        evidence["exact_user_supplied_query"] = False
        errors = self.validate("exact", evidence)
        self.assertTrue(any("explicitly user supplied" in e for e in errors), errors)

    def test_voprf_hides_inputs_and_outputs_from_evaluator(self) -> None:
        evidence = self.evidence("voprf")
        evidence["service_observed_query_identifiers"] = True
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("must not learn query identifiers" in e for e in errors), errors)
        evidence = self.evidence("voprf")
        evidence["service_observed_query_outputs"] = True
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("must not learn finalized query outputs" in e for e in errors), errors)

    def test_voprf_proof_key_snapshot_and_budget_are_required(self) -> None:
        for field, value, phrase in (
            ("voprf_proof_verified", False, "proof must verify"),
            ("voprf_public_key_id", "wrong-key", "public key id mismatch"),
            ("directory_snapshot_authenticated", False, "snapshot must authenticate"),
            ("online_query_budget_enforced", False, "enumeration budget"),
        ):
            evidence = self.evidence("voprf")
            evidence[field] = value
            errors = self.validate("voprf", evidence)
            self.assertTrue(any(phrase in e for e in errors), errors)

    def test_attested_profile_requires_attestation_measurement_and_private_host(self) -> None:
        for field in (
            "attestation_verified",
            "measurement_authorized",
            "encrypted_channel_terminated_inside_trusted_boundary",
        ):
            evidence = self.evidence("attested")
            evidence[field] = False
            self.assertTrue(self.validate("attested", evidence))
        evidence = self.evidence("attested")
        evidence["host_observed_plaintext_identifiers"] = True
        self.assertTrue(self.validate("attested", evidence))

    def test_query_persistence_and_missing_zeroization_are_rejected(self) -> None:
        evidence = self.evidence("attested")
        evidence["query_persisted_after_completion"] = True
        self.assertTrue(self.validate("attested", evidence))
        evidence = self.evidence("attested")
        evidence["query_memory_zeroized"] = False
        self.assertTrue(self.validate("attested", evidence))

    def test_discoverability_result_minimization_and_batch_limit(self) -> None:
        evidence = self.evidence("voprf")
        evidence["discoverability_policy_enforced"] = False
        self.assertTrue(self.validate("voprf", evidence))
        evidence = self.evidence("voprf")
        evidence["only_matching_registered_entries_returned"] = False
        self.assertTrue(self.validate("voprf", evidence))
        evidence = self.evidence("voprf")
        evidence["query_count"] = self.policy("voprf")["max_batch_size"] + 1
        evidence["normalized_identifier_count"] = evidence["query_count"]
        self.assertTrue(self.validate("voprf", evidence))


if __name__ == "__main__":
    unittest.main()
