from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import integration_contracts  # noqa: E402


class IntegrationContractTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/integration-contracts.json")

    def fixture(self) -> dict:
        value=self.load("fixtures/integration-contracts/valid/sdk-configuration-envelope.json")
        value["payload_digest"]=integration_contracts.compute_payload_digest(value["payload"])
        value["envelope_digest"]=integration_contracts.compute_envelope_digest(value)
        return value

    def test_registry_is_valid_and_paths_exist(self) -> None:
        self.assertEqual(
            integration_contracts.validate_registry(self.registry(), root=ROOT),
            [],
        )

    def test_exactly_six_downstream_contracts_exist(self) -> None:
        registry=self.registry()
        systems={item["system_id"] for item in registry["contracts"]}
        self.assertEqual(
            systems,
            {"sdk","verified","security-lab","incident-exchange","observatory","research-lab"},
        )

    def test_sdk_configuration_envelope_is_valid(self) -> None:
        envelope=self.fixture()
        self.assertEqual(
            integration_contracts.validate_envelope(envelope,self.registry()),[]
        )

    def test_builder_produces_valid_envelope(self) -> None:
        registry=self.registry()
        payload=self.fixture()["payload"]
        envelope=integration_contracts.build_envelope(
            registry=registry,
            contract_id="sdk-contract",
            producer_system="sdk",
            consumer_system="e2eesa",
            artifact_type="configuration",
            payload=payload,
            produced_at="2026-10-08T05:30:00Z",
            correlation_id="build-test",
        )
        self.assertEqual(
            integration_contracts.validate_envelope(envelope,registry),[]
        )

    def test_direction_violation_fails(self) -> None:
        envelope=self.fixture()
        envelope["producer_system"]="e2eesa"
        envelope["consumer_system"]="sdk"
        envelope["artifact_type"]="conformance-result"
        envelope["authority_path"]=None
        envelope["schema_path"]="schemas/conformance-result.schema.json"
        envelope["payload"]={"standard_version":"0.1.0-dev"}
        envelope["payload_digest"]=integration_contracts.compute_payload_digest(envelope["payload"])
        envelope["envelope_digest"]=integration_contracts.compute_envelope_digest(envelope)
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("not permitted to consume" in e for e in errors))

    def test_payload_digest_tamper_fails(self) -> None:
        envelope=self.fixture()
        envelope["payload"]["notes"]="tampered after digest"
        envelope["envelope_digest"]=integration_contracts.compute_envelope_digest(envelope)
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("payload_digest" in e for e in errors))

    def test_envelope_digest_tamper_fails(self) -> None:
        envelope=self.fixture()
        envelope["envelope_digest"]="sha256:"+"9"*64
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("envelope_digest" in e for e in errors))

    def test_missing_required_binding_fails(self) -> None:
        envelope=self.fixture()
        del envelope["payload"]["selected_profiles"]
        envelope["payload_digest"]=integration_contracts.compute_payload_digest(envelope["payload"])
        envelope["envelope_digest"]=integration_contracts.compute_envelope_digest(envelope)
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("selected_profiles" in e for e in errors))

    def test_schema_path_substitution_fails(self) -> None:
        envelope=self.fixture()
        envelope["schema_path"]="schemas/profile.schema.json"
        envelope["envelope_digest"]=integration_contracts.compute_envelope_digest(envelope)
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("schema_path mismatch" in e for e in errors))

    def test_contract_version_drift_fails(self) -> None:
        envelope=self.fixture()
        envelope["contract_version"]="2.0.0"
        envelope["envelope_digest"]=integration_contracts.compute_envelope_digest(envelope)
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("contract_version mismatch" in e for e in errors))

    def test_unknown_artifact_fails(self) -> None:
        envelope=self.fixture()
        envelope["artifact_type"]="not-registered"
        envelope["envelope_digest"]=integration_contracts.compute_envelope_digest(envelope)
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("unknown integration artifact_type" in e for e in errors))

    def test_wrong_standard_version_fails(self) -> None:
        envelope=self.fixture()
        envelope["standard_version"]="9.9.9"
        envelope["envelope_digest"]=integration_contracts.compute_envelope_digest(envelope)
        errors=integration_contracts.validate_envelope(envelope,self.registry())
        self.assertTrue(any("standard_version mismatch" in e for e in errors))

    def test_every_contract_artifact_exists_in_closed_registry(self) -> None:
        registry=self.registry()
        artifact_ids={item["artifact_type"] for item in registry["artifact_types"]}
        for contract in registry["contracts"]:
            with self.subTest(contract=contract["contract_id"]):
                self.assertTrue(set(contract["consumes"]) <= artifact_ids)
                self.assertTrue(set(contract["emits"]) <= artifact_ids)

    def test_research_entry_cannot_escalate_through_transport(self) -> None:
        registry=self.registry()
        payload={
            "entry_id":"example-research",
            "entry_version":"0.1.0",
            "entry_digest":"sha256:"+"1"*64,
            "lifecycle_status":"recommended",
            "production_selectable":True,
        }
        envelope=integration_contracts.build_envelope(
            registry=registry,
            contract_id="research-lab-contract",
            producer_system="research-lab",
            consumer_system="e2eesa",
            artifact_type="research-profile-entry",
            payload=payload,
            produced_at="2026-10-08T05:30:00Z",
        )
        errors=integration_contracts.validate_envelope(envelope,registry)
        self.assertTrue(any("requires experimental lifecycle_status" in e for e in errors))
        self.assertTrue(any("requires production_selectable=false" in e for e in errors))

    def test_research_entry_experimental_boundary_can_pass_transport_contract(self) -> None:
        registry=self.registry()
        payload={
            "entry_id":"example-research",
            "entry_version":"0.1.0",
            "entry_digest":"sha256:"+"1"*64,
            "lifecycle_status":"experimental",
            "production_selectable":False,
        }
        envelope=integration_contracts.build_envelope(
            registry=registry,
            contract_id="research-lab-contract",
            producer_system="research-lab",
            consumer_system="e2eesa",
            artifact_type="research-profile-entry",
            payload=payload,
            produced_at="2026-10-08T05:30:00Z",
        )
        self.assertEqual(
            integration_contracts.validate_envelope(envelope,registry),[]
        )

    def test_preserve_artifacts_are_not_downstream_emittable(self) -> None:
        registry=self.registry()
        artifacts={item["artifact_type"]:item for item in registry["artifact_types"]}
        for contract in registry["contracts"]:
            for artifact_type in contract["emits"]:
                with self.subTest(contract=contract["contract_id"],artifact=artifact_type):
                    self.assertNotEqual(artifacts[artifact_type]["mutability"],"preserve")


if __name__ == "__main__":
    unittest.main()
