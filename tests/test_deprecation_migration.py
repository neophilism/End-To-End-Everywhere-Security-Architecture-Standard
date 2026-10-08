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

import crypto_registry  # noqa: E402
import deprecation_migration  # noqa: E402
import profile_engine  # noqa: E402


class DeprecationMigrationTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/deprecation-migration.json")

    def crypto(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("profiles/catalog.json")

    def plan(self, name: str) -> dict:
        plan=self.load(f"fixtures/deprecation-migration/valid/{name}-plan.json")
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        return plan

    def case(self, name: str, plan: dict | None=None) -> dict:
        plan=plan or self.plan(name)
        case=self.load(f"fixtures/deprecation-migration/valid/{name}-case.json")
        case["plan_digest"]=plan["plan_digest"]
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        return case

    def validate_plan(self, plan: dict):
        return deprecation_migration.validate_plan(
            plan,self.registry(),self.crypto(),self.catalog()
        )

    def validate_case(self, case: dict, plan: dict, as_of: str | None=None):
        return deprecation_migration.validate_case(
            case,plan,self.registry(),self.crypto(),self.catalog(),as_of=as_of
        )

    def test_registry_is_valid(self) -> None:
        self.assertEqual(deprecation_migration.validate_registry(self.registry()),[])

    def test_planned_migration_plan_is_valid(self) -> None:
        plan=self.plan("planned")
        self.assertEqual(self.validate_plan(plan),[])
        self.assertEqual(
            deprecation_migration.known_dependents(
                plan["asset"],self.crypto(),self.catalog()
            ),
            [
                ("suite","SUITE-HPKE-X25519-HKDF-SHA256-AES128GCM"),
                ("suite","SUITE-HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305"),
            ],
        )

    def test_emergency_migration_plan_is_valid(self) -> None:
        plan=self.plan("emergency")
        self.assertEqual(self.validate_plan(plan),[])
        self.assertEqual(
            deprecation_migration.known_dependents(
                plan["asset"],self.crypto(),self.catalog()
            ),
            [
                ("suite","SUITE-HPKE-P256-HKDF-SHA256-AES128GCM"),
                ("suite","SUITE-HPKE-X25519-HKDF-SHA256-AES128GCM"),
            ],
        )

    def test_plan_digest_tamper_fails(self) -> None:
        plan=self.plan("planned")
        plan["plan_digest"]="sha256:"+"9"*64
        errors=self.validate_plan(plan)
        self.assertTrue(any("plan_digest does not match" in e for e in errors))

    def test_current_status_must_match_registry(self) -> None:
        plan=self.plan("planned")
        plan["current_status"]="allowed"
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("current_status mismatch" in e for e in errors))

    def test_planned_migration_requires_replacement(self) -> None:
        plan=self.plan("planned")
        plan["replacement"]=None
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("planned migration requires replacement" in e for e in errors))

    def test_replacement_must_use_same_algorithm_category(self) -> None:
        plan=self.plan("planned")
        plan["replacement"]={"kind":"algorithm","id":"ALG-SHA384"}
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("same registry category" in e for e in errors))

    def test_active_exploitation_requires_emergency_mode(self) -> None:
        plan=self.plan("planned")
        plan["reason"]["reason_class"]="active-exploitation"
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("requires emergency mode" in e for e in errors))

    def test_emergency_migration_disables_fallback(self) -> None:
        plan=self.plan("emergency")
        plan["fallback_policy"]="bounded-until-new-use-stop"
        plan["controls"]["fallback_telemetry"]=True
        plan["evidence"].append({
            "evidence_id":"fallback",
            "evidence_type":"fallback-telemetry",
            "evidence_digest":"sha256:"+"1"*64,
            "reference":"https://example.org/fallback"
        })
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("emergency migration must disable fallback" in e for e in errors))

    def test_bounded_fallback_requires_downgrade_protection(self) -> None:
        plan=self.plan("planned")
        plan["controls"]["downgrade_protection"]=False
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("requires downgrade protection" in e for e in errors))

    def test_bounded_fallback_requires_telemetry_evidence(self) -> None:
        plan=self.plan("planned")
        plan["evidence"]=[
            item for item in plan["evidence"]
            if item["evidence_type"]!="fallback-telemetry"
        ]
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("fallback-telemetry evidence" in e for e in errors))

    def test_historical_processing_requires_isolation_and_audit(self) -> None:
        plan=self.plan("emergency")
        plan["controls"]["isolated_legacy_processing"]=False
        plan["controls"]["audited_legacy_processing"]=False
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("must be isolated" in e for e in errors))
        self.assertTrue(any("must be audited" in e for e in errors))

    def test_configuration_rollback_must_remain_blocked(self) -> None:
        plan=self.plan("planned")
        plan["controls"]["configuration_rollback_blocked"]=False
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("block configuration rollback" in e for e in errors))

    def test_plan_must_cover_every_known_dependent(self) -> None:
        plan=self.plan("planned")
        plan["dependents"]=plan["dependents"][:1]
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("omits known registry dependents" in e for e in errors))

    def test_planned_timeline_is_monotonic(self) -> None:
        plan=self.plan("planned")
        plan["timeline"]["replacement_available_at"]="2026-11-20T00:00:00Z"
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("planned timeline must satisfy" in e for e in errors))

    def test_emergency_prohibition_is_immediate_at_effective_time(self) -> None:
        plan=self.plan("emergency")
        plan["timeline"]["prohibit_at"]="2026-10-08T06:00:00Z"
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("prohibit at effective_at" in e for e in errors))

    def test_planned_case_is_valid_and_complete(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        result=self.validate_case(case,plan,"2027-01-01T00:00:00Z")
        self.assertTrue(result.valid,result.errors+result.overdue)
        self.assertEqual(result.lifecycle_status,"prohibited")
        self.assertEqual(len(result.completed_dependents),2)

    def test_emergency_case_is_valid_and_complete(self) -> None:
        plan=self.plan("emergency")
        case=self.case("emergency",plan)
        result=self.validate_case(case,plan,"2026-10-10T00:00:00Z")
        self.assertTrue(result.valid,result.errors+result.overdue)
        self.assertEqual(result.lifecycle_status,"prohibited")
        self.assertEqual(len(result.completed_dependents),2)

    def test_case_digest_tamper_fails(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        case["case_digest"]="sha256:"+"9"*64
        result=self.validate_case(case,plan)
        self.assertFalse(result.valid)
        self.assertTrue(any("case_digest does not match" in e for e in result.errors))

    def test_case_plan_digest_substitution_fails(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        case["plan_digest"]="sha256:"+"9"*64
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan)
        self.assertFalse(result.valid)
        self.assertTrue(any("plan_digest mismatch" in e for e in result.errors))

    def test_late_planned_events_fail(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        replacement=next(e for e in case["events"] if e["event_type"]=="replacement-available")
        replacement["occurred_at"]="2026-10-21T00:00:00Z"
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan)
        self.assertFalse(result.valid)
        self.assertTrue(any("after plan deadline" in e for e in result.errors))

    def test_incomplete_planned_case_reports_overdue_obligations(self) -> None:
        plan=self.plan("planned")
        case={
            "schema_version":"0.1",
            "case_id":"incomplete",
            "plan_id":plan["plan_id"],
            "plan_digest":plan["plan_digest"],
            "events":[
                {
                    "event_id":"activate",
                    "event_type":"activate-plan",
                    "occurred_at":"2026-10-15T00:00:00Z",
                    "dependent_id":None,
                    "evidence_digest":"sha256:"+"1"*64,
                    "reference":"https://example.org/activate"
                }
            ],
            "case_digest":""
        }
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan,"2026-11-21T00:00:00Z")
        self.assertFalse(result.valid)
        self.assertIn("replacement availability is overdue",result.overdue)
        self.assertIn("new-use stop is overdue",result.overdue)

    def test_emergency_post_review_is_due_within_24_hours(self) -> None:
        plan=self.plan("emergency")
        case=self.case("emergency",plan)
        case["events"]=[
            event for event in case["events"]
            if event["event_type"]!="post-emergency-review"
        ]
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan,"2026-10-09T06:00:00Z")
        self.assertFalse(result.valid)
        self.assertIn("post-emergency review is overdue",result.overdue)

    def test_late_emergency_review_fails(self) -> None:
        plan=self.plan("emergency")
        case=self.case("emergency",plan)
        review=next(e for e in case["events"] if e["event_type"]=="post-emergency-review")
        review["occurred_at"]="2026-10-09T06:00:00Z"
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan)
        self.assertFalse(result.valid)
        self.assertTrue(any("exceeded 24-hour" in e for e in result.errors))

    def test_lifecycle_events_cannot_move_backward(self) -> None:
        plan=self.plan("emergency")
        case=self.case("emergency",plan)
        case["events"].insert(1,{
            "event_id":"bad-activate",
            "event_type":"activate-plan",
            "occurred_at":"2026-10-08T05:14:00Z",
            "dependent_id":None,
            "evidence_digest":"sha256:"+"1"*64,
            "reference":"https://example.org/bad"
        })
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan)
        self.assertFalse(result.valid)
        self.assertTrue(any("move backward" in e for e in result.errors))

    def test_complete_event_requires_all_dependents_when_checked(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        case["events"]=[
            event for event in case["events"]
            if event.get("dependent_id")!="SUITE-HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305"
        ]
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan,"2027-01-01T00:00:00Z")
        self.assertFalse(result.valid)
        self.assertTrue(any("cannot complete with unresolved dependents" in e for e in result.errors))

    def test_planned_new_use_is_denied_after_stop(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        self.assertTrue(deprecation_migration.operation_allowed(
            plan,case,operation="new-security-use",as_of="2026-11-01T00:00:00Z"
        ))
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,operation="new-security-use",as_of="2026-11-16T00:00:00Z"
        ))
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,operation="negotiate",as_of="2026-11-16T00:00:00Z"
        ))

    def test_migration_only_policy_allows_only_pre_cutoff_conversion(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        self.assertTrue(deprecation_migration.operation_allowed(
            plan,case,
            operation="migration-transform",
            as_of="2026-12-01T00:00:00Z",
            material_created_at="2026-11-01T00:00:00Z"
        ))
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,
            operation="historical-read-verify",
            as_of="2026-12-01T00:00:00Z",
            material_created_at="2026-11-01T00:00:00Z"
        ))
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,
            operation="migration-transform",
            as_of="2026-12-01T00:00:00Z",
            material_created_at="2026-11-16T00:00:00Z"
        ))
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,
            operation="migration-transform",
            as_of="2026-12-16T00:00:00Z",
            material_created_at="2026-11-01T00:00:00Z"
        ))

    def test_emergency_historical_read_is_bounded_and_not_new_use(self) -> None:
        plan=self.plan("emergency")
        case=self.case("emergency",plan)
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,operation="new-security-use",as_of="2026-10-08T06:00:00Z"
        ))
        self.assertTrue(deprecation_migration.operation_allowed(
            plan,case,
            operation="historical-read-verify",
            as_of="2026-10-20T00:00:00Z",
            material_created_at="2026-10-01T00:00:00Z"
        ))
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,
            operation="historical-read-verify",
            as_of="2026-10-20T00:00:00Z",
            material_created_at="2026-10-09T00:00:00Z"
        ))
        self.assertFalse(deprecation_migration.operation_allowed(
            plan,case,
            operation="migration-transform",
            as_of="2026-10-20T00:00:00Z",
            material_created_at="2026-10-01T00:00:00Z"
        ))

    def test_deprecated_algorithm_projection_weakens_dependent_suites(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        case["events"]=case["events"][:1]
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        crypto,catalog,errors=deprecation_migration.project_registries(
            plan,case,self.crypto(),self.catalog()
        )
        self.assertEqual(errors,[])
        algorithm=next(x for x in crypto["algorithms"] if x["id"]==plan["asset"]["id"])
        self.assertEqual(algorithm["status"],"deprecated")
        suites=[
            x for x in crypto["suites"]
            if plan["asset"]["id"] in x["algorithm_ids"]
        ]
        self.assertTrue(suites)
        self.assertTrue(all(x["status"]=="deprecated" for x in suites))
        self.assertEqual(crypto_registry.validate_registry(crypto),[])
        self.assertEqual(profile_engine.validate_catalog(catalog),[])

    def test_prohibited_algorithm_projection_removes_invalid_live_suites(self) -> None:
        plan=self.plan("planned")
        case=self.case("planned",plan)
        crypto,catalog,errors=deprecation_migration.project_registries(
            plan,case,self.crypto(),self.catalog()
        )
        self.assertEqual(errors,[])
        algorithm=next(x for x in crypto["algorithms"] if x["id"]==plan["asset"]["id"])
        self.assertEqual(algorithm["status"],"prohibited")
        self.assertIn("status_reason",algorithm)
        self.assertFalse(any(
            plan["asset"]["id"] in suite["algorithm_ids"]
            for suite in crypto["suites"]
        ))
        self.assertEqual(crypto_registry.validate_registry(crypto),[])
        self.assertEqual(profile_engine.validate_catalog(catalog),[])

    def test_emergency_projection_removes_suites_with_prohibited_component(self) -> None:
        plan=self.plan("emergency")
        case=self.case("emergency",plan)
        crypto,_catalog,errors=deprecation_migration.project_registries(
            plan,case,self.crypto(),self.catalog()
        )
        self.assertEqual(errors,[])
        self.assertFalse(any(
            "ALG-AES-128-GCM" in suite["algorithm_ids"]
            for suite in crypto["suites"]
        ))
        self.assertEqual(crypto_registry.validate_registry(crypto),[])

    def profile_plan(self) -> dict:
        plan={
            "schema_version":"0.1",
            "plan_id":"example-profile-retirement",
            "asset":{"kind":"profile","id":"example-choice-a@0.1.0"},
            "mode":"planned",
            "strategy":"scheduled-cutover",
            "reason":{
                "reason_class":"ecosystem-migration",
                "summary":"Illustrative retirement of an example profile.",
                "evidence_digest":"sha256:"+"1"*64,
                "reference":"https://example.org/profile-retirement/reason",
                "detected_at":"2026-10-20T00:00:00Z"
            },
            "current_status":"recommended",
            "terminal_status":"prohibited",
            "replacement":{"kind":"profile","id":"example-choice-b@0.1.0"},
            "legacy_processing_policy":"hard-cutoff",
            "fallback_policy":"disabled",
            "controls":{
                "downgrade_protection":True,
                "fallback_telemetry":False,
                "historical_cutoff_at":None,
                "isolated_legacy_processing":False,
                "audited_legacy_processing":False,
                "configuration_rollback_blocked":True
            },
            "timeline":{
                "effective_at":"2026-11-01T00:00:00Z",
                "replacement_available_at":"2026-11-01T00:00:00Z",
                "new_use_stop_at":"2026-12-01T00:00:00Z",
                "legacy_processing_stop_at":None,
                "prohibit_at":"2026-12-01T00:00:00Z"
            },
            "dependents":[{
                "kind":"profile",
                "id":"example-addon-requires-a@0.1.0",
                "action":"update-requirement",
                "replacement_id":"example-choice-b@0.1.0",
                "owner":"example-profile-owner",
                "deadline_at":"2026-11-25T00:00:00Z",
                "evidence_digest":"sha256:"+"2"*64,
                "reference":"https://example.org/profile-retirement/dependent"
            }],
            "evidence":[
                {"evidence_id":"replacement","evidence_type":"replacement-verification","evidence_digest":"sha256:"+"3"*64,"reference":"https://example.org/profile-retirement/replacement"},
                {"evidence_id":"test","evidence_type":"migration-test","evidence_digest":"sha256:"+"4"*64,"reference":"https://example.org/profile-retirement/test"},
                {"evidence_id":"impact","evidence_type":"dependent-impact","evidence_digest":"sha256:"+"5"*64,"reference":"https://example.org/profile-retirement/impact"}
            ],
            "approvals":[
                {"approver_id":"security","role":"security-reviewer","approved_at":"2026-10-31T10:00:00Z","evidence_digest":"sha256:"+"6"*64,"reference":"https://example.org/profile-retirement/security"},
                {"approver_id":"owner","role":"profile-owner","approved_at":"2026-10-31T11:00:00Z","evidence_digest":"sha256:"+"7"*64,"reference":"https://example.org/profile-retirement/owner"}
            ],
            "plan_digest":""
        }
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        return plan

    def test_profile_dependency_is_discovered_and_must_be_covered(self) -> None:
        plan=self.profile_plan()
        self.assertIn(
            ("profile","example-addon-requires-a@0.1.0"),
            deprecation_migration.known_dependents(
                plan["asset"],self.crypto(),self.catalog()
            )
        )
        self.assertEqual(self.validate_plan(plan),[])
        plan["dependents"]=[]
        plan["plan_digest"]=deprecation_migration.compute_plan_digest(plan)
        errors=self.validate_plan(plan)
        self.assertTrue(any("omits known registry dependents" in e for e in errors))

    def test_profile_projection_uses_existing_lifecycle_status(self) -> None:
        plan=self.profile_plan()
        case={
            "schema_version":"0.1",
            "case_id":"profile-retirement-case",
            "plan_id":plan["plan_id"],
            "plan_digest":plan["plan_digest"],
            "events":[
                {"event_id":"a","event_type":"activate-plan","occurred_at":"2026-11-01T00:00:00Z","dependent_id":None,"evidence_digest":"sha256:"+"8"*64,"reference":"https://example.org/a"},
                {"event_id":"b","event_type":"replacement-available","occurred_at":"2026-11-01T00:01:00Z","dependent_id":None,"evidence_digest":"sha256:"+"9"*64,"reference":"https://example.org/b"},
                {"event_id":"c","event_type":"dependent-migrated","occurred_at":"2026-11-20T00:00:00Z","dependent_id":"example-addon-requires-a@0.1.0","evidence_digest":"sha256:"+"a"*64,"reference":"https://example.org/c"},
                {"event_id":"d","event_type":"stop-new-use","occurred_at":"2026-12-01T00:00:00Z","dependent_id":None,"evidence_digest":"sha256:"+"b"*64,"reference":"https://example.org/d"},
                {"event_id":"e","event_type":"prohibit","occurred_at":"2026-12-01T00:00:00Z","dependent_id":None,"evidence_digest":"sha256:"+"c"*64,"reference":"https://example.org/e"},
                {"event_id":"f","event_type":"complete","occurred_at":"2026-12-01T00:01:00Z","dependent_id":None,"evidence_digest":"sha256:"+"d"*64,"reference":"https://example.org/f"}
            ],
            "case_digest":""
        }
        case["case_digest"]=deprecation_migration.compute_case_digest(case)
        result=self.validate_case(case,plan,"2026-12-02T00:00:00Z")
        self.assertTrue(result.valid,result.errors+result.overdue)
        _crypto,catalog,errors=deprecation_migration.project_registries(
            plan,case,self.crypto(),self.catalog()
        )
        self.assertEqual(errors,[])
        profile=next(
            item for item in catalog["profiles"]
            if item["profile_id"]=="example-choice-a"
            and item["profile_version"]=="0.1.0"
        )
        self.assertEqual(profile["status"],"prohibited")
        self.assertEqual(profile_engine.validate_catalog(catalog),[])


if __name__ == "__main__":
    unittest.main()
