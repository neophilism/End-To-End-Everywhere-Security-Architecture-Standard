from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import secure_development_engine as engine
from assurance_common import digest, load_json


class DevelopmentTests(unittest.TestCase):
    def pair(self, name="clean"):
        return (load_json(ROOT / f"fixtures/secure-development/policies/{name}.json"),
                load_json(ROOT / f"fixtures/secure-development/evidence/{name}.json"))

    def validate(self, p, e):
        return engine.validate_release(p, e, load_json(ROOT / "fixtures/profiles/development-catalog.json"))

    def reject(self, path, value, name="clean"):
        p, e = self.pair(name); node = e
        for key in path[:-1]: node = node[key]
        node[path[-1]] = value
        self.assertTrue(self.validate(p, e), (path, value))

    def test_clean_and_fixed_release_fixtures(self):
        for name in ("clean", "remediated"): self.assertEqual(self.validate(*self.pair(name)), [])
        self.assertEqual(engine.validate_repository(ROOT, load_json(ROOT / "fixtures/profiles/development-catalog.json")), [])

    def test_controls_are_complete_unique_and_nonwaivable(self):
        p, e = self.pair(); e["controls"].pop(); self.assertTrue(self.validate(p, e))
        p, e = self.pair(); e["controls"].append(e["controls"][0].copy()); self.assertTrue(self.validate(p, e))
        for status in ("not-applicable", "waived", "failed"):
            self.reject(["controls", 0, "status"], status)

    def test_self_review_and_release_authorizer_separation(self):
        self.reject(["reviewer_ids"], ["contributor"])
        self.reject(["release_authorizer_ids"], ["release-owner"])
        self.reject(["release_authorizer_ids"], ["release-owner", "other-owner"])
        self.reject(["reviews_approved"], False)

    def test_exact_source_binding(self):
        self.reject(["reviewed_source_digest"], "sha256:" + "0" * 64)
        self.reject(["gates", 0, "source_digest"], "sha256:" + "0" * 64)
        self.reject(["policy_digest"], "sha256:" + "0" * 64)

    def test_skipped_failed_and_stale_gates(self):
        for status in ("skipped", "failed", "cancelled"): self.reject(["gates", 0, "status"], status)
        self.reject(["gates", 0, "completed_at"], "2026-10-01T00:00:00Z")
        self.reject(["gates", 0, "completed_at"], "2026-10-08T00:00:00Z")
        p, e = self.pair(); e["gates"].pop(); self.assertTrue(self.validate(p, e))

    def test_qualified_cryptographic_review_and_classification(self):
        self.reject(["qualified_crypto_review"], False)
        self.reject(["security_change_classification_reviewed"], False)

    def test_fixed_findings_require_current_source_and_retest(self):
        self.reject(["findings", 0, "retest_report_ref"], None, "remediated")
        self.reject(["findings", 0, "remediation_source_digest"], "sha256:" + "0" * 64, "remediated")
        self.reject(["findings", 0, "status"], "open", "remediated")

    def accepted_pair(self, severity="medium"):
        p, e = self.pair("remediated")
        e["findings"][0].update(severity=severity, status="accepted", accepted_by="security-reviewer",
                                acceptance_expires_at="2026-10-08T00:00:00Z", rationale="assessed compensating control")
        return p, e

    def test_high_and_critical_findings_cannot_be_waived(self):
        for severity in ("high", "critical"):
            self.assertTrue(self.validate(*self.accepted_pair(severity)))

    def test_low_risk_acceptance_requires_independent_unexpired_approval(self):
        self.assertEqual(self.validate(*self.accepted_pair()), [])
        for field, value in (("accepted_by", "contributor"), ("acceptance_expires_at", None), ("acceptance_expires_at", "2026-10-06T00:00:00Z"), ("rationale", "")):
            p, e = self.accepted_pair(); e["findings"][0][field] = value
            self.assertTrue(self.validate(p, e))

    def test_policy_cannot_drop_controls_or_gates(self):
        for field in ("required_control_ids", "required_gate_ids"):
            p, e = self.pair(); p[field].pop(); e["policy_digest"] = digest(p)
            self.assertTrue(self.validate(p, e))

    def test_type_confusion_unknowns_and_reports(self):
        self.reject(["reviews_approved"], 1)
        self.reject(["report_refs"], [])
        p, e = self.pair(); e["gates"][0]["allow_failure"] = True
        self.assertTrue(self.validate(p, e))


if __name__ == "__main__": unittest.main()
