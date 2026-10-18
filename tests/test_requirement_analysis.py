"""AUD-21 independent authored requirement analysis status and stale-review tests."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import requirement_analysis as a

D = "sha256:" + "2" * 64
E = "sha256:" + "3" * 64
F = "sha256:" + "4" * 64
R1 = "REQ-" + "a" * 64
R2 = "REQ-" + "b" * 64


class RequirementAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.reqs = [
            {"requirement_id": R1, "document_path": "spec/example.md", "text_digest": D, "text": "An endpoint MUST authenticate."},
            {"requirement_id": R2, "document_path": "spec/example.md", "text_digest": E, "text": "An endpoint MUST reject replay."},
        ]
        self.basis = {"registry/threat-model.json": F}
        self.first = {
            "logical_id": "E2EESA-R-00001", "requirement_id": R1, "document_path": "spec/example.md",
            "text_digest": D, "author_id": "security-author",
            "rationale": "This specifically authenticates the endpoint key before accepting protected content from the remote peer.",
            "threat_ids": ["TM-NET-ACTIVE"], "security_property_ids": ["SP-INTEGRITY"],
            "evidence_expectations": ["signature-checks"], "external_standard_ids": [],
            "dependencies": [], "context_digest": None, "review": None,
        }
        self.rebuild(self.first, [])
        self.doc = {"schema_version": "0.1", "analysis_version": "0.1.0", "records": [self.first]}

    def rebuild(self, row, dependency_digests):
        req = next(r for r in self.reqs if r["requirement_id"] == row["requirement_id"])
        row["context_digest"] = a.current_context_digest(row, req, dependency_digests, self.basis)

    def inspect(self, doc=None, basis=None, verifier=None):
        return a.check_analyses(doc or self.doc, self.reqs, {"TM-NET-ACTIVE"},
                                {"SP-INTEGRITY"}, set(), basis or self.basis,
                                authenticated_review=verifier,
                                document_rationales={"spec/example.md": "Broad document rationale."})

    def test_malformed_unhashable_references_fail_closed(self):
        for bad in ([], {}, ["nested"]):
            with self.subTest(requirement=bad):
                doc = copy.deepcopy(self.doc)
                doc["records"][0]["requirement_id"] = bad
                result = self.inspect(doc)
                self.assertTrue(result["errors"])
                self.assertEqual(result["authored"], 0)
            with self.subTest(dependency=bad):
                doc = copy.deepcopy(self.doc)
                doc["records"][0]["dependencies"] = [
                    {"logical_id": "E2EESA-R-00001", "kind": bad}
                ]
                result = self.inspect(doc)
                self.assertTrue(result["errors"])
                self.assertEqual(result["authored"], 0)

    def test_only_individually_authored_records_count(self):
        r = self.inspect()
        self.assertEqual(r["errors"], [])
        self.assertEqual((r["total"], r["projected"], r["authored"]), (2, 2, 1))
        self.assertEqual(r["independently_authenticated_reviewed"], 0)

    def test_empty_registry_does_not_fake_coverage(self):
        r = self.inspect(doc={"schema_version": "0.1", "analysis_version": "0.1.0", "records": []})
        self.assertEqual(r["authored"], 0)
        self.assertEqual(r["projected"], 2)

    def test_orphan_and_stale_paragraphs_fail(self):
        r = copy.deepcopy(self.doc)
        r["records"][0]["requirement_id"] = "REQ-" + "0" * 64
        self.assertIn("orphaned", " ".join(self.inspect(r)["errors"]))
        r = copy.deepcopy(self.doc)
        r["records"][0]["text_digest"] = E
        self.assertIn("stale analysis", " ".join(self.inspect(r)["errors"]))

    def test_supporting_registry_changes_invalidate_authored_state(self):
        changed = {"registry/threat-model.json": "sha256:" + "0" * 64}
        r = self.inspect(basis=changed)
        self.assertEqual(r["authored"], 0)
        self.assertIn("context", " ".join(r["errors"]))

    def test_boilerplate_is_not_authored_analysis(self):
        r = copy.deepcopy(self.doc)
        r["records"][0]["rationale"] = "Broad document rationale."
        self.assertEqual(self.inspect(r)["authored"], 0)
        self.assertTrue(self.inspect(r)["errors"])

    def test_typed_dependencies_bind_correct_content_version(self):
        second = copy.deepcopy(self.first)
        second.update({"logical_id": "E2EESA-R-00002", "requirement_id": R2, "text_digest": E,
                       "rationale": "This independently analyzes replay prevention for the exact accepted message state and remote recipient key.",
                       "dependencies": [{"logical_id": "E2EESA-R-00001", "kind": "requires"}]})
        self.rebuild(second, [{"logical_id": "E2EESA-R-00001", "kind": "requires", "text_digest": D}])
        doc = {**self.doc, "records": [self.first, second]}
        self.assertEqual(self.inspect(doc)["authored"], 2)
        broken = copy.deepcopy(doc)
        broken["records"][1]["dependencies"][0]["kind"] = "undocumented-prose-link"
        self.assertTrue(self.inspect(broken)["errors"])

    def test_review_attestation_not_trusted_without_external_verifier(self):
        r = copy.deepcopy(self.doc)
        entry = r["records"][0]
        entry["review"] = {
            "reviewer_id": "independent-expert", "reviewer_organization_id": "other-organization",
            "accepted_context_digest": entry["context_digest"], "attestation_ref": "signed-attestation",
        }
        self.assertEqual(self.inspect(r)["review_recorded"], 1)
        self.assertEqual(self.inspect(r)["independently_authenticated_reviewed"], 0)
        self.assertEqual(self.inspect(r, verifier=lambda review, row: True)
                         ["independently_authenticated_reviewed"], 1)
        r["records"][0]["review"]["accepted_context_digest"] = E
        self.assertTrue(self.inspect(r)["errors"])

    def test_self_review_never_counts(self):
        r = copy.deepcopy(self.doc)
        entry = r["records"][0]
        entry["review"] = {
            "reviewer_id": entry["author_id"], "reviewer_organization_id": "own-organization",
            "accepted_context_digest": entry["context_digest"], "attestation_ref": "signed-attestation",
        }
        self.assertTrue(self.inspect(r, verifier=lambda review, row: True)["errors"])
        self.assertEqual(self.inspect(r, verifier=lambda review, row: True)
                         ["independently_authenticated_reviewed"], 0)

    def test_repository_baseline_explicitly_pending(self):
        r = a.validate_repository(ROOT)
        self.assertEqual(r["errors"], [])
        self.assertGreater(r["total"], 0)
        self.assertEqual(r["authored"], 0)
        self.assertEqual(r["independently_authenticated_reviewed"], 0)


if __name__ == "__main__":
    unittest.main()
