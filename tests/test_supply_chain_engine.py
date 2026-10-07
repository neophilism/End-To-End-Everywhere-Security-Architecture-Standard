import base64
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import supply_chain_engine as engine
from assurance_common import digest, load_json


class SupplyChainTests(unittest.TestCase):
    def pair(self, name="spdx"):
        return (load_json(ROOT / f"fixtures/supply-chain/policies/{name}.json"),
                load_json(ROOT / f"fixtures/supply-chain/evidence/{name}.json"))

    def validate(self, p, e):
        return engine.validate_release(p, e, load_json(ROOT / "profiles/catalog.json"))

    def reject(self, path, value):
        p, e = self.pair(); node = e
        for key in path[:-1]: node = node[key]
        node[path[-1]] = value
        self.assertTrue(self.validate(p, e), (path, value))

    def mutate_statement(self, callback):
        p, e = self.pair()
        statement = json.loads(base64.b64decode(e["provenance_envelope"]["payload"]))
        callback(statement)
        e["provenance_envelope"]["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()
        self.assertTrue(self.validate(p, e))

    def test_supported_sbom_profiles_and_fixtures(self):
        for name in ("spdx", "cyclonedx"): self.assertEqual(self.validate(*self.pair(name)), [])
        self.assertEqual(engine.validate_repository(ROOT, load_json(ROOT / "profiles/catalog.json")), [])

    def test_wrong_subject_source_builder_and_parameters(self):
        self.mutate_statement(lambda s:s["subject"][0]["digest"].update(sha256="0"*64))
        self.mutate_statement(lambda s:s["predicate"]["runDetails"]["builder"].update(id="attacker"))
        self.mutate_statement(lambda s:s["predicate"]["buildDefinition"]["externalParameters"].update(source_commit="0"*40))
        self.mutate_statement(lambda s:s["predicate"]["buildDefinition"]["externalParameters"].update(unsafe_option=True))

    def test_provenance_material_completeness(self):
        self.mutate_statement(lambda s:s["predicate"]["buildDefinition"]["resolvedDependencies"].pop())
        self.reject(["inventory", 0, "dependency_ids"], ["missing-package"])
        self.reject(["complete_transitive_inventory"], False)

    def test_no_floating_dependency_versions(self):
        for version in ("latest", "3.13", "*", "main"):
            self.reject(["inventory", 1, "version"], version)

    def test_sbom_subject_and_inventory_bindings(self):
        self.reject(["sbom", "subject_digest"], "sha256:"+"0"*64)
        self.reject(["sbom", "component_ids"], ["release-source"])
        self.reject(["sbom", "inventory_digest"], "sha256:"+"0"*64)
        self.reject(["sbom_format_verified"], False)

    def test_signature_threshold_and_identity(self):
        self.reject(["verified_signer_ids"], ["attacker"])
        self.reject(["provenance_authenticated"], False)
        self.reject(["signature_verified"], False)
        self.reject(["provenance_envelope", "signatures", 0, "sig"], "!!!!")
        p, e = self.pair(); e["provenance_envelope"]["signatures"].append(e["provenance_envelope"]["signatures"][0].copy())
        self.assertTrue(self.validate(p, e))

    def test_dsse_malformed_payload_and_duplicate_json_keys(self):
        for value in ("!!!!", base64.b64encode(b'{"_type":"a","_type":"b"}').decode(), base64.b64encode(b'null').decode()):
            self.reject(["provenance_envelope", "payload"], value)
        self.reject(["provenance_envelope", "payloadType"], "text/plain")

    def test_rebuild_independence_and_equal_bytes(self):
        self.reject(["reproduction", "operator_id"], "release-operator")
        self.reject(["reproduction", "builder_id"], "https://builders.example/release")
        self.reject(["reproduction", "byte_identical"], False)
        self.reject(["reproduction", "artifact_digest"], "sha256:"+"0"*64)

    def test_slsa_levels_cannot_be_raised_without_evidence(self):
        self.reject(["hosted_builder"], False)
        self.reject(["platform_generated_provenance"], False)
        p, e = self.pair(); e["claimed_slsa_build_level"] = 3; e["unforgeable_provenance"] = False
        self.assertTrue(self.validate(p, e))

    def test_build_timing_and_missing_reports(self):
        self.mutate_statement(lambda s:s["predicate"]["runDetails"]["metadata"].update(finishedOn="2026-10-09T00:00:00Z"))
        self.mutate_statement(lambda s:s["predicate"]["runDetails"]["metadata"].update(startedOn="2026-10-08T00:00:00Z"))
        self.reject(["report_refs"], [])

    def test_hash_verifier_uses_actual_bytes(self):
        self.assertEqual(engine.artifact_digest(b"abc"), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertNotEqual(engine.artifact_digest(b"abc"), engine.artifact_digest(b"abd"))
        self.reject(["report_refs"], ["sha256:"+"a"*64+"\n"])


if __name__ == "__main__": unittest.main()
