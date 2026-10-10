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
        return self.load("fixtures/profiles/development-catalog.json")

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

    def test_registry_is_valid_and_pins_rfc9497_voprf(self) -> None:
        self.assertEqual(contact_discovery_engine.validate_registry(self.registry()), [])
        suite = self.registry()["voprf_suites"][0]
        self.assertEqual(suite["mode"], "VOPRF")
        self.assertEqual(suite["mode_value"], "0x01")
        self.assertEqual(suite["ciphersuite_identifier"], "ristretto255-SHA512")

    def test_three_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "contact-discovery"
        }
        self.assertEqual(refs, set(contact_discovery_engine.PROFILE_MODES))

    def test_exact_handle_does_not_claim_query_unlinkability(self) -> None:
        profile = next(
            p for p in self.catalog()["profiles"]
            if p["profile_id"] == "contact-exact-handle"
        )
        self.assertEqual(profile["security_properties"], ["SP-METADATA-MINIMIZATION"])

    def test_all_valid_policies_pass(self) -> None:
        for name in ("exact", "voprf", "attested"):
            with self.subTest(name=name):
                self.assertEqual(
                    contact_discovery_engine.validate_policy(
                        self.policy(name), self.registry(), self.catalog()
                    ),
                    [],
                )

    def test_all_valid_evidence_passes(self) -> None:
        for name in ("exact", "voprf", "attested"):
            with self.subTest(name=name):
                self.assertEqual(self.validate(name), [])

    def test_raw_address_book_and_hash_upload_are_rejected(self) -> None:
        evidence = self.evidence("voprf")
        evidence["raw_address_book_sent_to_service"] = True
        self.assertTrue(self.validate("voprf", evidence))
        evidence = self.evidence("voprf")
        evidence["raw_identifier_hashes_sent_to_service"] = True
        self.assertTrue(self.validate("voprf", evidence))

    def test_discoverability_policy_and_result_minimization_are_required(self) -> None:
        evidence = self.evidence("voprf")
        evidence["discoverability_policy_enforced"] = False
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("discoverability opt-in policy" in e for e in errors), errors)

        evidence = self.evidence("voprf")
        evidence["only_matching_registered_entries_returned"] = False
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("only matching discoverable entries" in e for e in errors), errors)

    def test_exact_handle_is_single_user_supplied_query(self) -> None:
        policy = copy.deepcopy(self.policy("exact"))
        policy["max_batch_size"] = 2
        errors = contact_discovery_engine.validate_policy(
            policy, self.registry(), self.catalog()
        )
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

    def test_voprf_proof_key_and_directory_snapshot_are_required(self) -> None:
        evidence = self.evidence("voprf")
        evidence["voprf_proof_verified"] = False
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("VOPRF proof must verify" in e for e in errors), errors)

        evidence = self.evidence("voprf")
        evidence["voprf_public_key_id"] = "wrong-key"
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("public key id mismatch" in e for e in errors), errors)

        evidence = self.evidence("voprf")
        evidence["directory_snapshot_authenticated"] = False
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("directory snapshot must authenticate" in e for e in errors), errors)

    def test_voprf_enumeration_budget_is_required(self) -> None:
        evidence = self.evidence("voprf")
        evidence["online_query_budget_enforced"] = False
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("enumeration budget" in e for e in errors), errors)

    def test_query_batch_limit_is_enforced(self) -> None:
        evidence = self.evidence("voprf")
        evidence["query_count"] = self.policy("voprf")["max_batch_size"] + 1
        evidence["normalized_identifier_count"] = evidence["query_count"]
        errors = self.validate("voprf", evidence)
        self.assertTrue(any("query_count exceeds policy" in e for e in errors), errors)

    def test_attested_profile_requires_attestation_and_measurement(self) -> None:
        evidence = self.evidence("attested")
        evidence["attestation_verified"] = False
        errors = self.validate("attested", evidence)
        self.assertTrue(any("remote attestation must verify" in e for e in errors), errors)

        evidence = self.evidence("attested")
        evidence["measurement_authorized"] = False
        errors = self.validate("attested", evidence)
        self.assertTrue(any("measured code must be authorized" in e for e in errors), errors)

    def test_attested_channel_must_terminate_inside_boundary(self) -> None:
        evidence = self.evidence("attested")
        evidence["encrypted_channel_terminated_inside_trusted_boundary"] = False
        errors = self.validate("attested", evidence)
        self.assertTrue(any("terminate inside trusted boundary" in e for e in errors), errors)

    def test_attested_host_plaintext_and_query_persistence_are_rejected(self) -> None:
        evidence = self.evidence("attested")
        evidence["host_observed_plaintext_identifiers"] = True
        errors = self.validate("attested", evidence)
        self.assertTrue(any("host must not observe plaintext" in e for e in errors), errors)

        evidence = self.evidence("attested")
        evidence["query_persisted_after_completion"] = True
        errors = self.validate("attested", evidence)
        self.assertTrue(any("must not persist after completion" in e for e in errors), errors)

    def test_attested_memory_zeroization_is_required(self) -> None:
        evidence = self.evidence("attested")
        evidence["query_memory_zeroized"] = False
        errors = self.validate("attested", evidence)
        self.assertTrue(any("memory zeroization" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
