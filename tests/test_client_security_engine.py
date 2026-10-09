import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import client_security_engine as engine
from assurance_common import digest, load_json, shape


class ClientSecurityTests(unittest.TestCase):
    def load(self, rel):
        return load_json(ROOT / rel)

    def pair(self, name="native"):
        return (self.load(f"fixtures/client-security/policies/{name}.json"),
                self.load(f"fixtures/client-security/evidence/{name}.json"))

    def validate(self, policy, evidence):
        return engine.validate_client(policy, evidence, self.load("fixtures/profiles/development-catalog.json"))

    def mutate(self, path, value, name="native"):
        p, e = self.pair(name)
        dest = e
        for key in path[:-1]:
            dest = dest[key]
        dest[path[-1]] = value
        self.assertTrue(self.validate(p, e), (name, path, value))

    def test_valid_profiles_and_repository_fixtures(self):
        self.assertEqual(engine.validate_repository(ROOT, self.load("fixtures/profiles/development-catalog.json")), [])
        for name in ("native", "web", "verified-web"):
            self.assertEqual(self.validate(*self.pair(name)), [])

    def test_policy_binding_and_product_scope(self):
        for field, value in (("product_id", "other"), ("product_version", "2.0"), ("platform", "other"), ("profile_ref", "client-web-hardened@0.1.0"), ("policy_digest", "sha256:" + "0" * 64)):
            with self.subTest(field=field): self.mutate([field], value)

    def test_rollback_and_freeze(self):
        self.mutate(["release", "sequence"], 8)
        self.mutate(["release", "metadata_expires_at"], "2026-10-06T00:00:00Z")
        self.mutate(["observed_at"], "2026-02-30T22:40:20Z")

    def test_manifest_and_transparency_bindings(self):
        self.mutate(["release", "manifest", "version"], "9.0")
        self.mutate(["release", "executable_paths"], ["untracked.js"])
        self.mutate(["transparency", "entry_digest"], "sha256:" + "0" * 64)
        self.mutate(["transparency", "checkpoint_sequence"], 1)
        self.mutate(["transparency", "operator_id"], "messenger-operator")

    def test_unknown_signer_missing_witness_and_reports(self):
        self.mutate(["release", "signer_id"], "attacker")
        self.mutate(["transparency", "witness_ids"], [])
        self.mutate(["report_refs"], [])

    def test_unknown_fields_and_boolean_confusion_fail_closed(self):
        p, e = self.pair(); e["runtime"]["escape_hatch"] = True
        self.assertTrue(self.validate(p, e))
        for v in ("true", 1, None): self.mutate(["release", "signature_verified"], v)

    def test_runtime_controls_cannot_be_disabled(self):
        for field in ("all_executables_covered", "signature_verified", "update_metadata_verified", "trust_root_rotation_verified"):
            with self.subTest(field=field): self.mutate(["release", field], False)
        self.mutate(["runtime", "authenticated_local_secret_storage"], False)
        self.mutate(["runtime", "debug_interfaces_disabled"], False)

    def test_csp_overrides_and_unsafe_sources(self):
        p, e = self.pair("web"); baseline = e["runtime"]["web"]["csp"]
        for suffix in ("; script-src-elem *", "; SCRIPT-SRC-ELEM *", "; script-src-attr 'unsafe-inline'", "; script-src 'unsafe-eval'", "; connect-src https://*.example"):
            self.mutate(["runtime", "web", "csp"], baseline + suffix, "web")

    def test_web_origin_and_secret_boundaries(self):
        for field, value in (("origin", "https://attacker.example"), ("mixed_content", True), ("third_party_code_in_secret_context", True), ("plaintext_secrets_in_web_storage", True), ("service_workers_manifest_bound", False)):
            with self.subTest(field=field): self.mutate(["runtime", "web", field], value, "web")

    def test_verified_bootstrap_must_be_independent_and_gate_execution(self):
        for field, value in (("bootstrap_operator_id", "messenger-operator"), ("bootstrap_trust_source", "origin"), ("verification_before_execution", False), ("fail_closed_on_manifest_mismatch", False)):
            with self.subTest(field=field): self.mutate(["runtime", "web", field], value, "verified-web")

    def test_web_cannot_overclaim_origin_independence(self):
        p, e = self.pair("web"); p["claims_origin_independent_execution"] = True
        e["policy_digest"] = digest(p)
        self.assertTrue(self.validate(p, e))
        self.mutate(["runtime", "web", "claims_malicious_origin_prevention"], True, "web")

    def test_profile_lifecycle_and_missing_evidence(self):
        p, e = self.pair(); catalog = self.load("fixtures/profiles/development-catalog.json")
        for profile in catalog["profiles"]:
            if profile["profile_id"] == "client-native-signed": profile["status"] = "prohibited"
        self.assertTrue(engine.validate_client(p, e, catalog))
        for v in (None, [], {}, "invalid"):
            self.assertTrue(self.validate(p, v))

    def test_common_schema_rejects_unsupported_keywords_and_integer_bools(self):
        self.assertTrue(shape(True, {"type": "integer"}))
        self.assertTrue(shape({}, {"type": "object", "allOf": []}))
        self.assertTrue(shape(["same", "same"], {"type": "array", "uniqueItems": True}))

    def test_duplicate_json_keys_and_nan_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "evidence.json"
            for data in ('{"a": 1, "a": 2}', '{"a": NaN}'):
                p.write_text(data)
                with self.assertRaises(ValueError): load_json(p)

    def test_manifest_path_traversal_rejected_even_when_rehashed(self):
        p, e = self.pair()
        e["release"]["manifest"]["artifacts"][0]["path"] = "../outside.bin"
        e["release"]["executable_paths"] = ["../outside.bin"]
        e["release"]["artifact_digest"] = digest(e["release"]["manifest"])
        e["transparency"]["entry_digest"] = e["release"]["artifact_digest"]
        self.assertTrue(self.validate(p, e))


if __name__ == "__main__":
    unittest.main()
