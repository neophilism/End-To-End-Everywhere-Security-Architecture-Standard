from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import server_trust_engine as engine
from assurance_common import digest, load_json


class ServerTrustTests(unittest.TestCase):
    def pair(self, name="live"):
        return (load_json(ROOT / f"fixtures/server-trust/policies/{name}.json"),
                load_json(ROOT / f"fixtures/server-trust/evidence/{name}.json"))

    def validate(self, p, e):
        return engine.validate_deployment(p, e, load_json(ROOT / "fixtures/profiles/development-catalog.json"))

    def reject(self, path, value, name="live"):
        p, e = self.pair(name); node = e
        for key in path[:-1]: node = node[key]
        node[path[-1]] = value
        self.assertTrue(self.validate(p, e), (path, value))

    def test_valid_inventory_and_deletion(self):
        for name in ("live", "deleted"): self.assertEqual(self.validate(*self.pair(name)), [])
        self.assertEqual(engine.validate_repository(ROOT, load_json(ROOT / "fixtures/profiles/development-catalog.json")), [])

    def test_service_plaintext_keys_and_enrollment_are_prohibited(self):
        for field in ("application_plaintext_access", "application_key_access", "backup_recovery_key_access", "can_authorize_e2ee_devices", "logs_application_content"):
            with self.subTest(field=field): self.reject(["components", 0, field], True)

    def test_key_separation_and_purpose_restriction(self):
        self.reject(["components", 0, "service_keys", 0, "shared_with_application_e2ee"], True)
        self.reject(["components", 0, "service_keys", 0, "purpose"], "message-key")
        self.reject(["storage_credentials_separate_from_e2ee"], False)

    def test_exhaustive_unique_component_inventory(self):
        self.reject(["assessed_component_ids"], ["ingress-relay"])
        p, e = self.pair(); e["components"].append(e["components"][0].copy())
        self.assertTrue(self.validate(p, e))
        self.reject(["objects", 0, "component_id"], "unassessed-store")

    def test_client_recipient_set_must_be_complete(self):
        for devices in (["device-one"], ["device-one", "attacker"], ["device-one", "device-one"]):
            self.reject(["objects", 0, "recipient_device_ids"], devices)

    def test_derivatives_indexes_and_locator_keys(self):
        self.reject(["objects", 0, "derivatives_encrypted"], False)
        self.reject(["objects", 0, "plaintext_search_index"], True)
        self.reject(["objects", 0, "keys_in_locator"], True)
        self.reject(["objects", 0, "object_locator"], "https://store.example/#secret-key")

    def test_expired_objects_must_be_purged(self):
        self.reject(["objects", 0, "deleted_at"], None, "deleted")
        self.reject(["objects", 0, "deleted_at"], "2026-10-07T22:01:00Z", "deleted")
        self.reject(["objects", 0, "deleted_at"], "2026-10-05T00:00:00Z", "deleted")

    def test_retention_limits_and_future_creation(self):
        self.reject(["objects", 0, "expires_at"], "2026-10-10T22:00:00Z")
        self.reject(["objects", 0, "created_at"], "2026-10-08T22:00:00Z")
        self.reject(["objects", 0, "created_at"], "2026-13-07T22:00:00Z")

    def test_metadata_allowlist_is_enforced(self):
        self.reject(["components", 0, "metadata_fields"], ["message-text"])
        p, e = self.pair(); p["allowed_metadata_fields"] = ["expiry"]
        e["policy_digest"] = digest(p)
        self.assertTrue(self.validate(p, e))

    def test_policy_invariants_and_scope_binding(self):
        for field in ("require_no_application_key_access", "require_client_recipient_authorization"):
            p, e = self.pair(); p[field] = False; e["policy_digest"] = digest(p)
            self.assertTrue(self.validate(p, e))
        self.reject(["policy_digest"], "sha256:" + "0" * 64)
        self.reject(["product_version"], "other")

    def test_malformed_evidence_and_missing_reports(self):
        self.reject(["report_refs"], [])
        self.reject(["components", 0, "application_key_access"], "false")
        p, e = self.pair(); e["objects"][0]["allow_plaintext"] = False
        self.assertTrue(self.validate(p, e))
        self.assertTrue(self.validate(p, {}))


if __name__ == "__main__": unittest.main()
