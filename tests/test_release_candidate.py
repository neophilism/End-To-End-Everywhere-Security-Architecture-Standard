from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/"scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0,str(SCRIPTS))

import release_candidate  # noqa: E402


class ReleaseCandidateTests(unittest.TestCase):
    def load(self,rel):
        return json.loads((ROOT/rel).read_text(encoding="utf-8"))

    def test_release_version_is_rc2_development(self):
        policy=self.load("registry/release-candidate.json")
        self.assertEqual(policy["release_version"],"0.9.0-rc.2-dev")
        self.assertEqual((ROOT/"VERSION").read_text(encoding="utf-8").strip(),"0.9.0-rc.2-dev")

    def test_historical_candidate_bytes_are_verified(self):
        self.assertEqual(release_candidate.validate_historical_candidates(ROOT, self.load("registry/release-candidate.json")), [])

    def test_original_anchor_cannot_be_removed(self):
        policy=self.load("registry/release-candidate.json")
        policy["historical_candidates"]=[]
        self.assertTrue(release_candidate.validate_historical_candidates(ROOT,policy))

    def test_changed_historical_manifest_is_rejected(self):
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "release/archive").mkdir(parents=True)
            policy = self.load("registry/release-candidate.json")
            anchor = self.load(policy["historical_candidates"][0])
            for path in [policy["historical_candidates"][0], anchor["manifest_path"], anchor["archive_path"]]:
                shutil.copyfile(ROOT / path, target / path)
            (target / anchor["manifest_path"]).write_text("{}")
            self.assertTrue(release_candidate.validate_historical_candidates(target, policy))

    def test_basis_version_is_deliberately_frozen(self):
        policy=self.load("registry/release-candidate.json")
        self.assertEqual(policy["basis_standard_version"],"0.1.0-dev")
        self.assertEqual(self.load("profiles/catalog.json")["standard_version"],"0.1.0-dev")
        self.assertEqual(self.load("registry/cryptographic-algorithms.json")["standard_version"],"0.1.0-dev")
        self.assertEqual(self.load("registry/integration-contracts.json")["standard_version"],"0.1.0-dev")

    def test_candidate_release_validation_passes(self):
        self.assertEqual(release_candidate.validate_release(ROOT),[])

    def test_manifest_matches_frozen_tree_exactly(self):
        policy=self.load("registry/release-candidate.json")
        stored=self.load(policy["manifest_path"])
        generated=release_candidate.build_manifest(ROOT,policy)
        self.assertEqual(stored,generated)
        self.assertEqual(stored["file_count"],len(stored["files"]))
        self.assertGreater(stored["file_count"],100)
        self.assertTrue(stored["tree_digest"].startswith("sha256:"))
        self.assertTrue(all(len(item["git_blob_sha"])==40 for item in stored["files"]))

    def test_manifest_paths_are_unique_sorted_and_existing(self):
        policy=self.load("registry/release-candidate.json")
        manifest=self.load(policy["manifest_path"])
        paths=[x["path"] for x in manifest["files"]]
        self.assertEqual(paths,sorted(paths))
        self.assertEqual(len(paths),len(set(paths)))
        for rel in paths:
            self.assertTrue((ROOT/rel).is_file(),rel)

    def test_release_manifest_excludes_self_and_policy(self):
        policy=self.load("registry/release-candidate.json")
        manifest=self.load(policy["manifest_path"])
        paths={x["path"] for x in manifest["files"]}
        self.assertNotIn(policy["manifest_path"],paths)
        self.assertNotIn("registry/release-candidate.json",paths)

    def test_catalog_complete_fixture_freeze(self):
        catalog=self.load("profiles/catalog.json")
        fixture=self.load("fixtures/reference-architectures/manifest.json")
        catalog_refs={
            f"{x['profile_id']}@{x['profile_version']}"
            for x in catalog["profiles"]
        }
        fixture_refs={x["profile_ref"] for x in fixture["entries"]}
        self.assertEqual(catalog_refs,fixture_refs)

    def test_production_interoperability_pair_space_is_complete_size(self):
        fixture=self.load("fixtures/reference-architectures/manifest.json")
        production=[
            x["profile_ref"] for x in fixture["entries"]
            if x["disposition"]=="production-positive"
        ]
        self.assertEqual(len(production),58)
        self.assertEqual(len(production)*(len(production)-1)//2,1653)

    def test_release_surface_contains_core_candidate_layers(self):
        policy=self.load("registry/release-candidate.json")
        manifest=self.load(policy["manifest_path"])
        paths={x["path"] for x in manifest["files"]}
        required={
            "profiles/catalog.json",
            "registry/cryptographic-algorithms.json",
            "registry/conformance.json",
            "registry/integration-contracts.json",
            "registry/external-standards.json",
            "registry/security-rationale-rules.json",
            "scripts/conformance_engine.py",
            "scripts/compatibility_solver.py",
            "scripts/interoperability_suite.py",
            "scripts/standards_crosswalk.py",
            "scripts/security_rationale.py",
            "spec/integration-contracts.md",
            "spec/standards-crosswalk.md",
            "spec/security-rationale-corpus.md",
            ".github/workflows/validate.yml",
        }
        self.assertTrue(required<=paths,sorted(required-paths))

    def test_release_policy_declares_all_candidate_gates(self):
        policy=self.load("registry/release-candidate.json")
        self.assertEqual(
            set(policy["required_release_gates"]),
            {
                "repository-validation",
                "catalog-complete-reference-fixtures",
                "production-interoperability-matrix",
                "six-project-integration-contracts",
                "complete-standards-crosswalk",
                "complete-security-rationale",
            },
        )


if __name__=="__main__":
    unittest.main()
