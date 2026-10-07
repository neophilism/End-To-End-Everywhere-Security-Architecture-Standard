import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import telemetry_engine as engine
from assurance_common import digest, load_json


class TelemetryTests(unittest.TestCase):
    def pair(self, name="diagnostics"):
        return (load_json(ROOT / f"fixtures/telemetry/policies/{name}.json"),
                load_json(ROOT / f"fixtures/telemetry/evidence/{name}.json"))

    def validate(self, p, e):
        return engine.validate_telemetry(p, e, load_json(ROOT / "profiles/catalog.json"))

    def reject(self, path, value, name="diagnostics", rehash=False):
        p, e = self.pair(name); node = e
        for key in path[:-1]: node = node[key]
        node[path[-1]] = value
        if rehash: e["dp"]["ledger_digest"] = digest(e["dp"]["releases"])
        self.assertTrue(self.validate(p, e), (path, value))

    def test_all_profiles_and_adversarial_fixtures(self):
        for name in ("none", "diagnostics", "dp-aggregate"): self.assertEqual(self.validate(*self.pair(name)), [])
        self.assertEqual(engine.validate_repository(ROOT, load_json(ROOT / "profiles/catalog.json")), [])

    def test_no_export_profile_rejects_collection(self):
        self.reject(["collector_enabled"], True, "none")
        self.reject(["max_durable_age_seconds"], 1, "none")

    def test_consent_and_privacy_invariants(self):
        for field in ("consent_granted", "withdrawal_honored", "no_plaintext_or_secrets", "no_personal_identifiers", "no_raw_crash_dumps", "privacy_controls_tested", "ip_stripped_before_collection"):
            with self.subTest(field=field): self.reject([field], False)
        self.reject(["stable_pseudonyms"], True)
        self.reject(["cross_product_joining"], True)
        self.reject(["claims_network_anonymity"], True)

    def test_unknown_free_form_payload_is_rejected(self):
        p, e = self.pair(); e["events"][0]["exception_text"] = "secret token"
        self.assertTrue(self.validate(p, e))
        self.reject(["events", 0, "event_code"], "unreviewed-event")
        self.reject(["events", 0, "value_bucket"], "identifier")

    def test_retention_and_policy_binding(self):
        self.reject(["max_durable_age_seconds"], 86401)
        self.reject(["policy_digest"], "sha256:" + "0" * 64)
        self.reject(["product_id"], "other")

    def test_default_opt_in_is_forbidden_even_with_rebound_policy(self):
        p, e = self.pair(); p["enabled_by_default"] = True; e["policy_digest"] = digest(p)
        self.assertTrue(self.validate(p, e))

    def test_privacy_budget_exact_boundary_and_exhaustion(self):
        p, e = self.pair("dp-aggregate")
        e["dp"]["releases"][0].update(epsilon_micros=800000, noise_scale_denominator=800000)
        e["dp"]["ledger_digest"] = digest(e["dp"]["releases"])
        self.assertEqual(self.validate(p, e), [])
        e["dp"]["releases"][0].update(epsilon_micros=800001, noise_scale_denominator=800001)
        e["dp"]["ledger_digest"] = digest(e["dp"]["releases"])
        self.assertTrue(any("budget exceeded" in x for x in self.validate(p, e)))

    def test_lifetime_ledger_rollback_duplicates_and_reset(self):
        self.reject(["dp", "previous_release_count"], 3, "dp-aggregate")
        self.reject(["dp", "budget_reset_on_update"], True, "dp-aggregate")
        self.reject(["dp", "all_prior_releases_included"], False, "dp-aggregate")
        self.reject(["dp", "releases", 1, "release_id"], "aggregate-1", "dp-aggregate", True)
        self.reject(["dp", "accounting_domain"], "new-budget-domain", "dp-aggregate")

    def test_mechanism_parameters_and_sampler_evidence(self):
        for field, value in (("delta_ppb", 1), ("sensitivity", 0), ("contribution_upper", 10), ("epsilon_micros", True), ("noise_scale_denominator", 1), ("fresh_noise", False), ("noise_mechanism_verified", False)):
            with self.subTest(field=field): self.reject(["dp", "releases", 0, field], value, "dp-aggregate", True)

    def test_small_cohorts_and_time_ordering(self):
        self.reject(["dp", "releases", 0, "distinct_users"], 19, "dp-aggregate", True)
        self.reject(["dp", "releases", 1, "published_at"], "2026-10-09T00:00:00Z", "dp-aggregate", True)
        self.reject(["dp", "releases", 1, "published_at"], "2026-10-05T00:00:00Z", "dp-aggregate", True)

    def test_central_collector_claim_is_honest(self):
        self.reject(["dp", "claims_collector_cannot_observe_inputs"], True, "dp-aggregate")
        self.reject(["events"], self.pair()[1]["events"], "dp-aggregate")
        self.reject(["dp"], None, "dp-aggregate")

    def test_missing_reports_and_malformed_records(self):
        self.reject(["report_refs"], [])
        self.reject(["no_plaintext_or_secrets"], "true")
        p, e = self.pair(); del e["withdrawal_honored"]
        self.assertTrue(self.validate(p, e))


if __name__ == "__main__": unittest.main()
