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

import certification_lifecycle  # noqa: E402


class CertificationLifecycleTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/certification-lifecycle.json")

    def case(self) -> dict:
        return self.load("fixtures/certification-lifecycle/valid/basic-certified.json")

    def validate(self, case: dict, *, as_of: str = "2026-10-07T16:00:00Z"):
        return certification_lifecycle.validate_case(case, self.registry(), as_of=as_of)

    def test_registry_is_valid(self) -> None:
        self.assertEqual(certification_lifecycle.validate_registry(self.registry()), [])

    def test_basic_certification_path_is_valid(self) -> None:
        result = self.validate(self.case())
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.state, "certified")
        self.assertEqual(
            result.current_evidence_bundle_digest,
            "sha256:" + "a" * 64,
        )

    def test_direct_state_skip_fails(self) -> None:
        case = self.case()
        case["events"][1]["from_state"] = "submitted"
        case["events"][1]["to_state"] = "certified"
        case["events"][1]["event_type"] = "approve"
        case["events"][1]["actor_role"] = "decision-maker"
        errors = self.validate(case).errors
        self.assertTrue(any("illegal transition" in e for e in errors))

    def test_duplicate_event_id_fails(self) -> None:
        case = self.case()
        case["events"][1]["event_id"] = case["events"][0]["event_id"]
        errors = self.validate(case).errors
        self.assertTrue(any("duplicate event_id" in e for e in errors))

    def test_timestamp_regression_fails(self) -> None:
        case = self.case()
        case["events"][2]["occurred_at"] = "2026-10-07T13:00:00Z"
        errors = self.validate(case).errors
        self.assertTrue(any("decreases relative to previous event" in e for e in errors))

    def test_decision_maker_cannot_be_applicant(self) -> None:
        case = self.case()
        case["events"][4]["actor_id"] = "vendor-applicant"
        errors = self.validate(case).errors
        self.assertTrue(any("must not be an applicant actor" in e for e in errors))

    def test_decision_maker_cannot_be_evaluator(self) -> None:
        case = self.case()
        case["events"][4]["actor_id"] = "evaluator-one"
        errors = self.validate(case).errors
        self.assertTrue(any("must not be an evaluator" in e for e in errors))

    def test_approval_must_use_bundle_advanced_to_decision(self) -> None:
        case = self.case()
        case["events"][4]["evidence_bundle_digest"] = "sha256:" + "b" * 64
        errors = self.validate(case).errors
        self.assertTrue(any("approval bundle differs" in e for e in errors))

    def test_validity_window_must_be_future_and_ordered(self) -> None:
        case = self.case()
        case["events"][4]["surveillance_due_at"] = "2028-01-01T00:00:00Z"
        errors = self.validate(case).errors
        self.assertTrue(any("must not exceed certificate expiry" in e for e in errors))

    def test_overdue_surveillance_invalidates_current_certification(self) -> None:
        result = self.validate(self.case(), as_of="2027-05-01T00:00:00Z")
        self.assertFalse(result.valid)
        self.assertTrue(any("overdue surveillance" in e for e in result.errors))

    def test_expired_active_certification_fails(self) -> None:
        result = self.validate(self.case(), as_of="2027-11-01T00:00:00Z")
        self.assertFalse(result.valid)
        self.assertTrue(any("expired as of validation time" in e for e in result.errors))

    def test_future_event_relative_to_as_of_fails(self) -> None:
        result = self.validate(self.case(), as_of="2026-10-07T15:00:00Z")
        self.assertFalse(result.valid)
        self.assertTrue(any("events after validation as_of time" in e for e in result.errors))

    def test_surveillance_pass_refreshes_due_without_extending_expiry(self) -> None:
        case = self.case()
        digest = "sha256:" + "c" * 64
        case["events"].extend([
            {
                "event_id":"event-06-surveillance","event_type":"begin-surveillance",
                "actor_id":"surveillance-one","actor_role":"surveillance-reviewer",
                "occurred_at":"2027-03-01T12:00:00Z","from_state":"certified","to_state":"surveillance-review",
                "reason":None,"evidence_bundle_digest":digest,
                "certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            },
            {
                "event_id":"event-07-pass","event_type":"surveillance-pass",
                "actor_id":"surveillance-one","actor_role":"surveillance-reviewer",
                "occurred_at":"2027-03-02T12:00:00Z","from_state":"surveillance-review","to_state":"certified",
                "reason":None,"evidence_bundle_digest":None,
                "certificate_expires_at":"2027-10-07T15:30:00Z",
                "surveillance_due_at":"2027-08-01T00:00:00Z","artifacts":[]
            }
        ])
        result = self.validate(case, as_of="2027-03-03T00:00:00Z")
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.surveillance_due_at, "2027-08-01T00:00:00Z")

    def test_surveillance_pass_cannot_extend_certificate_expiry(self) -> None:
        case = self.case()
        digest = "sha256:" + "c" * 64
        case["events"].extend([
            {
                "event_id":"event-06-surveillance","event_type":"begin-surveillance",
                "actor_id":"surveillance-one","actor_role":"surveillance-reviewer",
                "occurred_at":"2027-03-01T12:00:00Z","from_state":"certified","to_state":"surveillance-review",
                "reason":None,"evidence_bundle_digest":digest,
                "certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            },
            {
                "event_id":"event-07-pass","event_type":"surveillance-pass",
                "actor_id":"surveillance-one","actor_role":"surveillance-reviewer",
                "occurred_at":"2027-03-02T12:00:00Z","from_state":"surveillance-review","to_state":"certified",
                "reason":None,"evidence_bundle_digest":None,
                "certificate_expires_at":"2028-10-07T15:30:00Z",
                "surveillance_due_at":"2027-08-01T00:00:00Z","artifacts":[]
            }
        ])
        errors=self.validate(case,as_of="2027-03-03T00:00:00Z").errors
        self.assertTrue(any("must preserve current certificate expiry" in e for e in errors))

    def test_renewal_must_approve_reviewed_bundle(self) -> None:
        case = self.case()
        reviewed = "sha256:" + "c" * 64
        case["events"].extend([
            {
                "event_id":"event-06-renewal","event_type":"begin-renewal",
                "actor_id":"surveillance-one","actor_role":"surveillance-reviewer",
                "occurred_at":"2027-09-01T12:00:00Z","from_state":"certified","to_state":"renewal-review",
                "reason":None,"evidence_bundle_digest":reviewed,
                "certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            },
            {
                "event_id":"event-07-renew","event_type":"renew",
                "actor_id":"decision-maker-two","actor_role":"decision-maker",
                "occurred_at":"2027-09-02T12:00:00Z","from_state":"renewal-review","to_state":"certified",
                "reason":None,"evidence_bundle_digest":"sha256:"+"d"*64,
                "certificate_expires_at":"2028-09-02T12:00:00Z",
                "surveillance_due_at":"2028-03-02T12:00:00Z","artifacts":[]
            }
        ])
        errors=self.validate(case,as_of="2027-09-03T00:00:00Z").errors
        self.assertTrue(any("renewal bundle differs" in e for e in errors))

    def test_renewal_corrective_action_returns_to_renewal_review(self) -> None:
        case = self.case()
        reviewed = "sha256:" + "c" * 64
        updated = "sha256:" + "d" * 64
        case["events"].extend([
            {
                "event_id":"event-06-renewal","event_type":"begin-renewal",
                "actor_id":"surveillance-one","actor_role":"surveillance-reviewer",
                "occurred_at":"2027-09-01T12:00:00Z","from_state":"certified","to_state":"renewal-review",
                "reason":None,"evidence_bundle_digest":reviewed,
                "certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            },
            {
                "event_id":"event-07-fix","event_type":"renewal-corrective-action",
                "actor_id":"surveillance-one","actor_role":"surveillance-reviewer",
                "occurred_at":"2027-09-01T13:00:00Z","from_state":"renewal-review","to_state":"corrective-action",
                "reason":"Update evidence","evidence_bundle_digest":None,
                "certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            },
            {
                "event_id":"event-08-fixed","event_type":"corrective-action-submitted",
                "actor_id":"vendor-applicant","actor_role":"applicant",
                "occurred_at":"2027-09-02T10:00:00Z","from_state":"corrective-action","to_state":"renewal-review",
                "reason":None,"evidence_bundle_digest":updated,
                "certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            }
        ])
        result=self.validate(case,as_of="2027-09-02T11:00:00Z")
        self.assertTrue(result.valid,result.errors)
        self.assertEqual(result.state,"renewal-review")

    def test_appeal_reviewer_cannot_be_adverse_decision_actor(self) -> None:
        case=self.case()
        case["events"]=case["events"][:-1]
        case["events"].append({
            "event_id":"event-05-deny","event_type":"deny","actor_id":"decision-maker-one",
            "actor_role":"decision-maker","occurred_at":"2026-10-07T15:30:00Z",
            "from_state":"decision-review","to_state":"denied","reason":"Insufficient evidence",
            "evidence_bundle_digest":None,"certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
        })
        case["events"].extend([
            {
                "event_id":"event-06-appeal","event_type":"open-appeal","actor_id":"vendor-applicant",
                "actor_role":"applicant","occurred_at":"2026-10-07T16:00:00Z",
                "from_state":"denied","to_state":"appeal-review","reason":None,
                "evidence_bundle_digest":None,"certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            },
            {
                "event_id":"event-07-remand","event_type":"appeal-remanded","actor_id":"decision-maker-one",
                "actor_role":"appeal-reviewer","occurred_at":"2026-10-07T17:00:00Z",
                "from_state":"appeal-review","to_state":"decision-review","reason":"Reconsider",
                "evidence_bundle_digest":None,"certificate_expires_at":None,"surveillance_due_at":None,"artifacts":[]
            }
        ])
        errors=self.validate(case,as_of="2026-10-07T18:00:00Z").errors
        self.assertTrue(any("appeal reviewer must not be adverse decision actor" in e for e in errors))

    def test_registry_forbids_direct_reinstatement_from_revoked(self) -> None:
        registry=copy.deepcopy(self.registry())
        registry["transitions"].append({
            "event_type":"reinstate","from_state":"revoked","to_state":"certified",
            "actor_role":"decision-maker","requires_reason":True,
            "requires_evidence_bundle":True,"requires_validity_window":True
        })
        errors=certification_lifecycle.validate_registry(registry)
        self.assertTrue(any("must not permit direct reinstatement from revoked" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
