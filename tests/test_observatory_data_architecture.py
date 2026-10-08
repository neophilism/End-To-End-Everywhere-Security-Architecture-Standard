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

import observatory_data_architecture  # noqa: E402
import observatory_evidence  # noqa: E402


class ObservatoryDataArchitectureTests(unittest.TestCase):
    def load_json(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load_json("registry/observatory-data-architecture.json")

    def bundle(self) -> dict:
        bundle=self.load_json("fixtures/observatory-evidence/valid/bundle.json")
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        return bundle

    def projections(self):
        bundle=self.bundle()
        registry=self.registry()
        rows=observatory_data_architecture.relational_rows(bundle)
        graph=observatory_data_architecture.property_graph_projection(bundle,registry)
        rdf=observatory_data_architecture.prov_rdf_projection(bundle,registry)
        search=observatory_data_architecture.search_projection(bundle,registry)
        manifest=observatory_data_architecture.build_projection_manifest(
            bundle,registry,"2026-10-07T23:00:00Z"
        )
        return bundle,registry,rows,graph,rdf,search,manifest

    def test_registry_is_valid(self) -> None:
        self.assertEqual(
            observatory_data_architecture.validate_registry(self.registry()),[]
        )

    def test_relational_rows_are_deterministic_and_complete(self) -> None:
        bundle=self.bundle()
        rows1=observatory_data_architecture.relational_rows(bundle)
        rows2=observatory_data_architecture.relational_rows(copy.deepcopy(bundle))
        self.assertEqual(rows1,rows2)
        self.assertEqual(set(rows1),set(observatory_data_architecture.TABLES))
        expected_counts={
            "evidence_bundles":1,
            "content_objects":2,
            "agents":2,
            "entities":2,
            "activities":2,
            "activity_acquisitions":1,
            "activity_agents":2,
            "activity_used_entities":1,
            "activity_generated_entities":2,
            "events":1,
            "event_subjects":1,
            "event_attributes":1,
            "citations":1,
            "event_citations":1,
            "integrity_anchors":0,
            "anchor_verification":0,
        }
        self.assertEqual({table:len(items) for table,items in rows1.items()},expected_counts)
        self.assertEqual(
            rows1["event_attributes"][0]["value_json"],
            "published",
        )

    def test_relational_rowset_digest_is_stable(self) -> None:
        rows=observatory_data_architecture.relational_rows(self.bundle())
        digest1=observatory_data_architecture.relational_rowset_digest(rows)
        reordered={table:list(reversed(items)) for table,items in rows.items()}
        digest2=observatory_data_architecture.relational_rowset_digest(reordered)
        self.assertEqual(digest1,digest2)

    def test_conflicting_content_length_for_same_digest_fails(self) -> None:
        bundle=self.bundle()
        duplicate=copy.deepcopy(bundle["entities"][1])
        duplicate["entity_id"]="entity-derived-002"
        duplicate["content_digest"]=bundle["entities"][0]["content_digest"]
        duplicate["byte_length"]=999
        duplicate["source_identifier"]="conflicting-length"
        bundle["entities"].append(duplicate)
        bundle["activities"][1]["generated_entity_ids"].append("entity-derived-002")
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        with self.assertRaisesRegex(ValueError,"conflicting byte lengths"):
            observatory_data_architecture.relational_rows(bundle)

    def test_property_graph_projection_is_deterministic(self) -> None:
        bundle=self.bundle()
        graph1=observatory_data_architecture.property_graph_projection(bundle,self.registry())
        graph2=observatory_data_architecture.property_graph_projection(
            copy.deepcopy(bundle),self.registry()
        )
        self.assertEqual(graph1,graph2)
        self.assertEqual(graph1["source_bundle_digest"],bundle["bundle_digest"])
        node_types={node["node_type"] for node in graph1["nodes"]}
        self.assertTrue({"Bundle","Agent","Entity","Activity","Event","Citation"}.issubset(node_types))
        edge_types={edge["edge_type"] for edge in graph1["edges"]}
        self.assertTrue({
            "CONTAINS","USED","WAS_GENERATED_BY","WAS_ASSOCIATED_WITH",
            "CITES","CITATION_SOURCE","HAS_SUBJECT"
        }.issubset(edge_types))

    def test_property_graph_anchor_edges_bind_manifest_and_entities(self) -> None:
        bundle=self.bundle()
        bundle["integrity_anchors"]=[
            {
                "anchor_id":"anchor-manifest",
                "anchor_type":"rfc3161-timestamp",
                "subject_digest":bundle["manifest_digest"],
                "proof_digest":"sha256:"+"1"*64,
                "observed_at":"2026-10-07T23:01:00Z",
                "provider":"Example TSA",
                "reference":"https://example.org/timestamp/1",
                "verification":{
                    "status":"unverified","verifier_name":None,"verifier_version":None,
                    "verified_at":None,"result_digest":None,"result_ref":None
                }
            },
            {
                "anchor_id":"anchor-entity",
                "anchor_type":"transparency-log",
                "subject_digest":bundle["entities"][0]["content_digest"],
                "proof_digest":"sha256:"+"2"*64,
                "observed_at":"2026-10-07T23:01:00Z",
                "provider":"Example log",
                "reference":"https://example.org/log/1",
                "verification":{
                    "status":"unverified","verifier_name":None,"verifier_version":None,
                    "verified_at":None,"result_digest":None,"result_ref":None
                }
            }
        ]
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        graph=observatory_data_architecture.property_graph_projection(bundle,self.registry())
        anchor_edges=[e for e in graph["edges"] if e["edge_type"]=="ANCHORS"]
        self.assertEqual(len(anchor_edges),2)

    def test_rdf_projection_uses_w3c_prov_predicates(self) -> None:
        bundle=self.bundle()
        rdf=observatory_data_architecture.prov_rdf_projection(bundle,self.registry())
        predicates={triple["predicate"] for triple in rdf["triples"]}
        self.assertIn("http://www.w3.org/ns/prov#used",predicates)
        self.assertIn("http://www.w3.org/ns/prov#wasGeneratedBy",predicates)
        self.assertIn("http://www.w3.org/ns/prov#wasAssociatedWith",predicates)
        self.assertEqual(rdf["source_bundle_digest"],bundle["bundle_digest"])

    def test_rdf_revision_maps_to_was_derived_from(self) -> None:
        bundle=self.bundle()
        bundle["entities"][1]["revision_of"]="entity-source-001"
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        rdf=observatory_data_architecture.prov_rdf_projection(bundle,self.registry())
        self.assertTrue(any(
            triple["predicate"]=="http://www.w3.org/ns/prov#wasDerivedFrom"
            for triple in rdf["triples"]
        ))

    def test_search_projection_uses_only_evidence_metadata(self) -> None:
        bundle=self.bundle()
        search=observatory_data_architecture.search_projection(bundle,self.registry())
        self.assertEqual(search["source_bundle_digest"],bundle["bundle_digest"])
        self.assertEqual(len(search["documents"]),6)
        corpus="\n".join(doc["body"] for doc in search["documents"])
        self.assertIn("https://example.org/source.json",corpus)
        self.assertIn("Lines establishing the publication event.",corpus)
        self.assertNotIn("invented source document prose",corpus)

    def test_search_projection_has_content_digest_for_entity(self) -> None:
        search=observatory_data_architecture.search_projection(self.bundle(),self.registry())
        entity=next(doc for doc in search["documents"] if doc["source_id"]=="entity-source-001")
        self.assertEqual(entity["digests"],["sha256:"+"a"*64])

    def test_projection_manifest_binds_all_projection_digests(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        self.assertEqual(
            manifest["relational_rowset_digest"],
            observatory_data_architecture.relational_rowset_digest(rows),
        )
        by_id={item["projection_id"]:item for item in manifest["projections"]}
        self.assertEqual(
            by_id["property-graph"]["projection_digest"],
            observatory_data_architecture.canonical_digest(graph),
        )
        self.assertEqual(
            by_id["prov-rdf"]["projection_digest"],
            observatory_data_architecture.canonical_digest(rdf),
        )
        self.assertEqual(
            by_id["search-documents"]["projection_digest"],
            observatory_data_architecture.canonical_digest(search),
        )
        self.assertEqual(
            manifest["manifest_digest"],
            observatory_data_architecture.projection_manifest_digest(manifest),
        )

    def test_rebuild_at_different_time_keeps_logical_manifest_digest(self) -> None:
        bundle=self.bundle()
        registry=self.registry()
        first=observatory_data_architecture.build_projection_manifest(
            bundle,registry,"2026-10-07T23:00:00Z"
        )
        second=observatory_data_architecture.build_projection_manifest(
            bundle,registry,"2026-10-08T23:00:00Z"
        )
        self.assertNotEqual(first["generated_at"],second["generated_at"])
        self.assertEqual(first["manifest_digest"],second["manifest_digest"])
        self.assertEqual(first["relational_rowset_digest"],second["relational_rowset_digest"])
        self.assertEqual(first["projections"],second["projections"])

    def test_complete_projection_set_is_valid(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        self.assertEqual(
            observatory_data_architecture.validate_projection_set(
                bundle,registry,rows,graph,rdf,search,manifest
            ),[]
        )

    def test_tampered_relational_row_fails(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        rows["agents"][0]["name"]="Tampered"
        errors=observatory_data_architecture.validate_projection_set(
            bundle,registry,rows,graph,rdf,search,manifest
        )
        self.assertTrue(any("relational projection differs" in e for e in errors))

    def test_tampered_graph_edge_fails(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        graph["edges"]=graph["edges"][:-1]
        errors=observatory_data_architecture.validate_projection_set(
            bundle,registry,rows,graph,rdf,search,manifest
        )
        self.assertTrue(any("property graph projection differs" in e for e in errors))

    def test_tampered_rdf_triple_fails(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        rdf["triples"]=rdf["triples"][:-1]
        errors=observatory_data_architecture.validate_projection_set(
            bundle,registry,rows,graph,rdf,search,manifest
        )
        self.assertTrue(any("PROV RDF projection differs" in e for e in errors))

    def test_tampered_search_document_fails(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        search["documents"][0]["body"]="Tampered"
        errors=observatory_data_architecture.validate_projection_set(
            bundle,registry,rows,graph,rdf,search,manifest
        )
        self.assertTrue(any("search projection differs" in e for e in errors))

    def test_projection_manifest_digest_tamper_fails(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        manifest["manifest_digest"]="sha256:"+"9"*64
        errors=observatory_data_architecture.validate_projection_set(
            bundle,registry,rows,graph,rdf,search,manifest
        )
        self.assertTrue(any("projection manifest digest mismatch" in e for e in errors))

    def test_projection_manifest_source_bundle_tamper_fails(self) -> None:
        bundle,registry,rows,graph,rdf,search,manifest=self.projections()
        manifest["source_bundle_digest"]="sha256:"+"9"*64
        manifest["manifest_digest"]=observatory_data_architecture.projection_manifest_digest(manifest)
        errors=observatory_data_architecture.validate_projection_set(
            bundle,registry,rows,graph,rdf,search,manifest
        )
        self.assertTrue(any("source_bundle_digest mismatch" in e for e in errors))

    def test_reference_postgres_schema_has_canonical_tables_and_guards(self) -> None:
        sql=(ROOT/"reference/observatory/postgres.sql").read_text(encoding="utf-8")
        for table in observatory_data_architecture.TABLES:
            self.assertIn(f"e2eesa_observatory.{table}",sql)
        self.assertIn("reject_canonical_mutation",sql)
        self.assertIn("BEFORE UPDATE OR DELETE",sql)
        self.assertIn("REFERENCES e2eesa_observatory.evidence_bundles",sql)
        self.assertIn("UNIQUE (bundle_digest, entity_id)",sql)
        self.assertIn("projection_checkpoints",sql)

    def test_projection_registry_makes_every_projection_non_authoritative(self) -> None:
        registry=self.registry()
        for item in registry["projections"]:
            self.assertFalse(item["authoritative"])
            self.assertTrue(item["rebuildable"])


if __name__ == "__main__":
    unittest.main()
