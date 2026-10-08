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

import observatory_evidence  # noqa: E402
import research_profile_registry  # noqa: E402


class ResearchProfileRegistryTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/research-profile-registry.json")

    def threat_registry(self) -> dict:
        return self.load("registry/threat-model.json")

    def property_registry(self) -> dict:
        return self.load("registry/security-properties.json")

    def algorithm_registry(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def evidence_bundle(self) -> dict:
        bundle=self.load("fixtures/observatory-evidence/valid/bundle.json")
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        return bundle

    def entry(self, bundle: dict | None=None) -> dict:
        bundle=bundle or self.evidence_bundle()
        entry=self.load("fixtures/research-profile-registry/valid/entry.json")
        entry["provenance_evidence_bundle_digests"]=[bundle["bundle_digest"]]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        return entry

    def validate(self, entry: dict | None=None, bundle: dict | None=None):
        bundle=bundle or self.evidence_bundle()
        entry=entry or self.entry(bundle)
        return research_profile_registry.validate_entry(
            entry,
            self.registry(),
            self.threat_registry(),
            self.property_registry(),
            self.algorithm_registry(),
            known_evidence_bundle_digests=[bundle["bundle_digest"]],
        )

    def test_registry_is_valid(self) -> None:
        self.assertEqual(research_profile_registry.validate_registry(self.registry()),[])

    def test_inconclusive_research_entry_is_valid(self) -> None:
        entry=self.entry()
        self.assertEqual(self.validate(entry),[])
        self.assertEqual(entry["experiments"][0]["outcome"],"inconclusive")
        self.assertFalse(entry["production_selectable"])
        self.assertEqual(entry["lifecycle_status"],"experimental")

    def test_research_entry_cannot_be_production_selectable(self) -> None:
        entry=self.entry()
        entry["production_selectable"]=True
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("production_selectable must be false" in e for e in errors))

    def test_research_entry_cannot_self_promote_lifecycle(self) -> None:
        entry=self.entry()
        entry["lifecycle_status"]="recommended"
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("lifecycle_status must be experimental" in e for e in errors))

    def test_unknown_registered_threat_fails(self) -> None:
        entry=self.entry()
        entry["threat_model"]["registered_threat_ids"].append("TM-NOT-REGISTERED")
        entry["threat_model"]["registered_threat_ids"].sort()
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("unknown registered threats" in e for e in errors))

    def test_unknown_composite_scenario_fails(self) -> None:
        entry=self.entry()
        entry["threat_model"]["composite_scenario_ids"]=["CS-NOT-REGISTERED"]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("unknown composite scenarios" in e for e in errors))

    def test_unknown_registered_property_fails(self) -> None:
        entry=self.entry()
        entry["security_properties"]["registered_property_ids"].append("SP-NOT-REGISTERED")
        entry["security_properties"]["registered_property_ids"].sort()
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("unknown registered properties" in e for e in errors))

    def test_unknown_registered_algorithm_fails(self) -> None:
        entry=self.entry()
        entry["cryptographic_algorithm_ids"].append("ALG-NOT-REGISTERED")
        entry["cryptographic_algorithm_ids"].sort()
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("unknown registered algorithms" in e for e in errors))

    def test_experimental_threat_requires_exp_namespace(self) -> None:
        entry=self.entry()
        entry["threat_model"]["experimental_threats"]=[{
            "id":"TM-EXPERIMENT",
            "name":"Example",
            "description":"Example experimental threat.",
            "capabilities":["example capability"]
        }]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("EXP-TM-" in e for e in errors))

    def test_experimental_property_requires_exp_namespace(self) -> None:
        entry=self.entry()
        entry["security_properties"]["experimental_properties"]=[{
            "id":"SP-EXPERIMENT",
            "name":"Example",
            "definition":"Example experimental property."
        }]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("EXP-SP-" in e for e in errors))

    def test_experimental_component_requires_exp_namespace(self) -> None:
        entry=self.entry()
        entry["experimental_components"]=[{
            "id":"COMP-EXPERIMENT",
            "name":"Example",
            "category":"protocol-component",
            "specification_digest":"sha256:"+"a"*64,
            "reference":"https://example.org/component"
        }]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("EXP-COMP-" in e for e in errors))

    def test_hypothesis_must_reference_known_property(self) -> None:
        entry=self.entry()
        entry["hypotheses"][0]["target_property_ids"]=["EXP-SP-MISSING"]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("references unknown properties" in e for e in errors))

    def test_experiment_must_reference_known_hypothesis(self) -> None:
        entry=self.entry()
        entry["experiments"][0]["hypothesis_ids"]=["missing-hypothesis"]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("references unknown hypotheses" in e for e in errors))

    def test_experiment_must_reference_known_vector(self) -> None:
        entry=self.entry()
        entry["experiments"][0]["test_vector_ids"]=["missing-vector"]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("references unknown test vectors" in e for e in errors))

    def test_experiment_must_reference_known_implementation(self) -> None:
        entry=self.entry()
        entry["experiments"][0]["implementation_ids"]=["missing-implementation"]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("references unknown implementations" in e for e in errors))

    def test_independent_replication_requires_evidence(self) -> None:
        entry=self.entry()
        experiment=entry["experiments"][0]
        experiment["replication_status"]="independent"
        experiment["replication_evidence_digest"]=None
        experiment["replication_reference"]=None
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("independent replication" in e for e in errors))

    def test_independent_replication_with_evidence_is_valid(self) -> None:
        entry=self.entry()
        experiment=entry["experiments"][0]
        experiment["replication_status"]="independent"
        experiment["replication_evidence_digest"]="sha256:"+"b"*64
        experiment["replication_reference"]="https://example.org/independent-replication"
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        self.assertEqual(self.validate(entry),[])

    def test_independently_verified_vector_requires_evidence(self) -> None:
        entry=self.entry()
        vector=entry["test_vectors"][0]
        vector["verification_status"]="independently-verified"
        vector["verification_evidence_digest"]=None
        vector["verification_reference"]=None
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("requires verification evidence digest" in e for e in errors))

    def test_generated_vector_cannot_claim_verification(self) -> None:
        entry=self.entry()
        vector=entry["test_vectors"][0]
        vector["verification_status"]="generated"
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("must not claim verification evidence" in e for e in errors))

    def test_nonconcept_implementation_requires_source_digest(self) -> None:
        entry=self.entry()
        entry["implementations"][0]["source_digest"]=None
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("source_digest must be sha256" in e for e in errors))

    def test_implementation_cannot_be_marked_for_production(self) -> None:
        entry=self.entry()
        entry["implementations"][0]["production_use_prohibited"]=False
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("must prohibit production use" in e for e in errors))

    def test_entry_requires_limitations(self) -> None:
        entry=self.entry()
        entry["limitations"]=[]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry)
        self.assertTrue(any("research limitations must be non-empty" in e for e in errors))

    def test_provenance_bundle_must_be_known_when_scope_is_supplied(self) -> None:
        bundle=self.evidence_bundle()
        entry=self.entry(bundle)
        entry["provenance_evidence_bundle_digests"]=["sha256:"+"9"*64]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        errors=self.validate(entry,bundle)
        self.assertTrue(any("unknown evidence bundles" in e for e in errors))

    def test_entry_digest_tamper_fails(self) -> None:
        entry=self.entry()
        entry["entry_digest"]="sha256:"+"9"*64
        errors=self.validate(entry)
        self.assertTrue(any("entry_digest does not match" in e for e in errors))

    def test_registry_index_can_bind_exact_entry(self) -> None:
        entry=self.entry()
        registry=copy.deepcopy(self.registry())
        registry["entries"]=[research_profile_registry.index_entry(entry)]
        self.assertEqual(
            research_profile_registry.validate_index(registry,[entry]),[]
        )

    def test_registry_index_digest_substitution_fails(self) -> None:
        entry=self.entry()
        registry=copy.deepcopy(self.registry())
        item=research_profile_registry.index_entry(entry)
        item["entry_digest"]="sha256:"+"9"*64
        registry["entries"]=[item]
        errors=research_profile_registry.validate_index(registry,[entry])
        self.assertTrue(any("index metadata mismatch" in e for e in errors))

    def test_registry_index_extra_entry_fails(self) -> None:
        entry=self.entry()
        registry=copy.deepcopy(self.registry())
        registry["entries"]=[
            research_profile_registry.index_entry(entry),
            {
                **research_profile_registry.index_entry(entry),
                "entry_id":"unexpected-entry"
            }
        ]
        errors=research_profile_registry.validate_index(registry,[entry])
        self.assertTrue(any("index entry set differs" in e for e in errors))

    def test_revision_chain_is_valid(self) -> None:
        bundle=self.evidence_bundle()
        previous=self.entry(bundle)
        current=copy.deepcopy(previous)
        current["revision"]=2
        current["previous_entry_digest"]=previous["entry_digest"]
        current["updated_at"]="2026-10-08T01:00:00Z"
        current["open_questions"].append("Has an independent implementation reproduced the same result?")
        current["open_questions"].sort()
        current["entry_digest"]=research_profile_registry.compute_entry_digest(current)
        self.assertEqual(
            research_profile_registry.validate_revision_chain(
                current,previous,self.registry(),self.threat_registry(),
                self.property_registry(),self.algorithm_registry(),
                known_evidence_bundle_digests=[bundle["bundle_digest"]],
            ),[]
        )

    def test_revision_chain_rejects_wrong_predecessor(self) -> None:
        bundle=self.evidence_bundle()
        previous=self.entry(bundle)
        current=copy.deepcopy(previous)
        current["revision"]=2
        current["previous_entry_digest"]="sha256:"+"9"*64
        current["updated_at"]="2026-10-08T01:00:00Z"
        current["entry_digest"]=research_profile_registry.compute_entry_digest(current)
        errors=research_profile_registry.validate_revision_chain(
            current,previous,self.registry(),self.threat_registry(),
            self.property_registry(),self.algorithm_registry(),
            known_evidence_bundle_digests=[bundle["bundle_digest"]],
        )
        self.assertTrue(any("previous_entry_digest mismatch" in e for e in errors))

    def test_revision_chain_preserves_target_identity(self) -> None:
        bundle=self.evidence_bundle()
        previous=self.entry(bundle)
        current=copy.deepcopy(previous)
        current["revision"]=2
        current["previous_entry_digest"]=previous["entry_digest"]
        current["updated_at"]="2026-10-08T01:00:00Z"
        current["target"]["profile_id"]="different-target"
        current["entry_digest"]=research_profile_registry.compute_entry_digest(current)
        errors=research_profile_registry.validate_revision_chain(
            current,previous,self.registry(),self.threat_registry(),
            self.property_registry(),self.algorithm_registry(),
            known_evidence_bundle_digests=[bundle["bundle_digest"]],
        )
        self.assertTrue(any("target identity mismatch" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
