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


class ObservatoryEvidenceTests(unittest.TestCase):
    def load(self) -> dict:
        return json.loads(
            (ROOT / "fixtures/observatory-evidence/valid/bundle.json").read_text(
                encoding="utf-8"
            )
        )

    def prepared(self) -> dict:
        bundle=self.load()
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        return bundle

    def validate(self,bundle:dict)->list[str]:
        return observatory_evidence.validate_bundle(bundle)

    def test_complete_bundle_is_valid(self) -> None:
        bundle=self.prepared()
        self.assertEqual(self.validate(bundle),[])

    def test_manifest_tamper_is_detected(self) -> None:
        bundle=self.prepared()
        bundle["entities"][0]["byte_length"]=2048
        errors=self.validate(bundle)
        self.assertTrue(any("manifest_digest does not match" in e for e in errors))
        self.assertTrue(any("bundle_digest does not match" in e for e in errors))

    def test_anchor_metadata_changes_bundle_not_manifest(self) -> None:
        bundle=self.prepared()
        manifest=bundle["manifest_digest"]
        bundle["integrity_anchors"].append({
            "anchor_id":"anchor-tsa-001",
            "anchor_type":"rfc3161-timestamp",
            "subject_digest":manifest,
            "proof_digest":"sha256:"+"1"*64,
            "observed_at":"2026-10-07T22:01:00Z",
            "provider":"Example TSA",
            "reference":"https://example.org/timestamps/001",
            "verification":{
                "status":"unverified",
                "verifier_name":None,
                "verifier_version":None,
                "verified_at":None,
                "result_digest":None,
                "result_ref":None
            }
        })
        self.assertEqual(observatory_evidence.compute_manifest_digest(bundle),manifest)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        self.assertEqual(self.validate(bundle),[])

    def test_duplicate_entity_id_fails(self) -> None:
        bundle=self.prepared()
        bundle["entities"].append(copy.deepcopy(bundle["entities"][0]))
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("duplicate entity_id" in e for e in errors))

    def test_agent_and_entity_ids_must_be_unambiguous(self) -> None:
        bundle=self.prepared()
        bundle["agents"][0]["agent_id"]="entity-source-001"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("globally unambiguous" in e for e in errors))

    def test_source_snapshot_requires_acquisition_provenance(self) -> None:
        bundle=self.prepared()
        bundle["activities"]=bundle["activities"][1:]
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("lacks acquisition provenance" in e for e in errors))

    def test_acquisition_source_must_match_entity_source(self) -> None:
        bundle=self.prepared()
        bundle["activities"][0]["acquisition"]["source_uri"]="https://evil.example/source.json"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("source_uri differs from generated entity" in e for e in errors))

    def test_non_acquisition_generation_requires_source_input(self) -> None:
        bundle=self.prepared()
        bundle["activities"][1]["used_entity_ids"]=[]
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("must use at least one source entity" in e for e in errors))

    def test_entities_cannot_have_conflicting_generators(self) -> None:
        bundle=self.prepared()
        second=copy.deepcopy(bundle["activities"][1])
        second["activity_id"]="activity-extract-002"
        bundle["activities"].append(second)
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("conflicting generators" in e for e in errors))

    def test_revision_cycle_fails(self) -> None:
        bundle=self.prepared()
        bundle["entities"][0]["revision_of"]="entity-derived-001"
        bundle["entities"][1]["revision_of"]="entity-source-001"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("revision cycle detected" in e for e in errors))

    def test_unknown_revision_target_fails(self) -> None:
        bundle=self.prepared()
        bundle["entities"][1]["revision_of"]="entity-missing"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("revision_of references unknown entity" in e for e in errors))

    def test_citation_must_bind_known_immutable_entity(self) -> None:
        bundle=self.prepared()
        bundle["citations"][0]["entity_id"]="entity-missing"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("citation citation-source-lines references unknown entity" in e for e in errors))

    def test_event_requires_known_citation(self) -> None:
        bundle=self.prepared()
        bundle["events"][0]["citation_ids"]=["citation-missing"]
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("references unknown citation" in e for e in errors))

    def test_event_time_range_cannot_invert(self) -> None:
        bundle=self.prepared()
        bundle["events"][0]["occurred_end"]="2026-10-07T20:00:00Z"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("occurrence interval is inverted" in e for e in errors))

    def test_activity_time_range_cannot_invert(self) -> None:
        bundle=self.prepared()
        bundle["activities"][0]["ended_at"]="2026-10-07T20:59:59Z"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("ends before it starts" in e for e in errors))

    def test_verified_anchor_requires_verification_evidence(self) -> None:
        bundle=self.prepared()
        bundle["integrity_anchors"].append({
            "anchor_id":"anchor-signature-001",
            "anchor_type":"detached-signature",
            "subject_digest":bundle["manifest_digest"],
            "proof_digest":"sha256:"+"2"*64,
            "observed_at":"2026-10-07T22:01:00Z",
            "provider":"Example signer",
            "reference":"urn:example:signature:001",
            "verification":{
                "status":"verified",
                "verifier_name":None,
                "verifier_version":None,
                "verified_at":None,
                "result_digest":None,
                "result_ref":None
            }
        })
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("verified anchor anchor-signature-001 requires" in e for e in errors))

    def test_unverified_anchor_cannot_claim_verification_metadata(self) -> None:
        bundle=self.prepared()
        bundle["integrity_anchors"].append({
            "anchor_id":"anchor-log-001",
            "anchor_type":"transparency-log",
            "subject_digest":bundle["manifest_digest"],
            "proof_digest":"sha256:"+"3"*64,
            "observed_at":"2026-10-07T22:01:00Z",
            "provider":"Example transparency log",
            "reference":"https://example.org/log/entry/1",
            "verification":{
                "status":"unverified",
                "verifier_name":"fake-verifier",
                "verifier_version":None,
                "verified_at":None,
                "result_digest":None,
                "result_ref":None
            }
        })
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("must not claim verification.verifier_name" in e for e in errors))

    def test_anchor_must_reference_manifest_or_entity_digest(self) -> None:
        bundle=self.prepared()
        bundle["integrity_anchors"].append({
            "anchor_id":"anchor-tsa-001",
            "anchor_type":"rfc3161-timestamp",
            "subject_digest":"sha256:"+"9"*64,
            "proof_digest":"sha256:"+"1"*64,
            "observed_at":"2026-10-07T22:01:00Z",
            "provider":"Example TSA",
            "reference":"https://example.org/timestamps/001",
            "verification":{
                "status":"unverified",
                "verifier_name":None,
                "verifier_version":None,
                "verified_at":None,
                "result_digest":None,
                "result_ref":None
            }
        })
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("references unknown subject digest" in e for e in errors))

    def test_canonical_subset_rejects_float_values(self) -> None:
        bundle=self.prepared()
        bundle["events"][0]["attributes"].append({"name":"confidence","value":0.9})
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("forbids floating-point values" in e for e in errors))

    def test_revision_one_cannot_claim_predecessor(self) -> None:
        bundle=self.prepared()
        bundle["previous_bundle_digest"]="sha256:"+"4"*64
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        errors=self.validate(bundle)
        self.assertTrue(any("revision 1 must have null" in e for e in errors))

    def test_revision_chain_binds_exact_predecessor(self) -> None:
        previous=self.prepared()
        current=copy.deepcopy(previous)
        current["revision"]=2
        current["previous_bundle_digest"]=previous["bundle_digest"]
        current["created_at"]="2026-10-08T22:00:00Z"
        current["manifest_digest"]=observatory_evidence.compute_manifest_digest(current)
        current["bundle_digest"]=observatory_evidence.compute_bundle_digest(current)
        self.assertEqual(observatory_evidence.validate_revision_chain(current,previous),[])

    def test_revision_chain_rejects_skipped_revision(self) -> None:
        previous=self.prepared()
        current=copy.deepcopy(previous)
        current["revision"]=3
        current["previous_bundle_digest"]=previous["bundle_digest"]
        current["created_at"]="2026-10-08T22:00:00Z"
        current["manifest_digest"]=observatory_evidence.compute_manifest_digest(current)
        current["bundle_digest"]=observatory_evidence.compute_bundle_digest(current)
        errors=observatory_evidence.validate_revision_chain(current,previous)
        self.assertTrue(any("increment revision by exactly one" in e for e in errors))

    def test_provenance_edges_map_to_prov_relations(self) -> None:
        bundle=self.prepared()
        edges=observatory_evidence.provenance_edges(bundle)
        relations={edge["relation"] for edge in edges}
        self.assertIn("used",relations)
        self.assertIn("wasGeneratedBy",relations)
        self.assertIn("wasAssociatedWith",relations)


if __name__ == "__main__":
    unittest.main()
