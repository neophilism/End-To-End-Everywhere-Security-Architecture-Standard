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

import research_profile_registry  # noqa: E402
import research_promotion  # noqa: E402


class ResearchPromotionTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def promotion_registry(self) -> dict:
        return self.load("registry/research-promotion.json")

    def research_registry(self) -> dict:
        return self.load("registry/research-profile-registry.json")

    def threat_registry(self) -> dict:
        return self.load("registry/threat-model.json")

    def property_registry(self) -> dict:
        return self.load("registry/security-properties.json")

    def algorithm_registry(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def candidate_entry(self) -> dict:
        entry=self.load("fixtures/research-promotion/valid/candidate-research-entry.json")
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        return entry

    def candidate_record(self, entry: dict | None=None) -> dict:
        entry=entry or self.candidate_entry()
        record=self.load("fixtures/research-promotion/valid/candidate-record.json")
        record["source_research"]["entry_digest"]=entry["entry_digest"]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        return record

    def validate(
        self,
        record: dict,
        entry: dict,
        catalog: dict | None=None,
        previous: dict | None=None,
    ):
        return research_promotion.validate_promotion(
            record,
            entry,
            self.research_registry(),
            self.promotion_registry(),
            self.threat_registry(),
            self.property_registry(),
            self.algorithm_registry(),
            catalog or self.catalog(),
            previous_record=previous,
        )

    def mature_entry(self, *, three_impls: bool=False, two_replications: bool=False) -> dict:
        entry=self.candidate_entry()
        entry["revision"]=2
        entry["previous_entry_digest"]=entry["entry_digest"]
        entry["updated_at"]="2026-11-15T00:00:00Z"
        entry["implementations"].append({
            "implementation_id":"hybrid-independent",
            "maturity":"independent",
            "source_reference":"https://independent.example/hybrid/source",
            "source_digest":"sha256:"+"e"*64,
            "language_runtime":"Go example implementation",
            "build_reference":"https://independent.example/hybrid/build",
            "limitations":["Independent example implementation; promotion evidence still required."],
            "production_use_prohibited":True,
        })
        experiment=entry["experiments"][0]
        experiment["replication_status"]="independent"
        experiment["replication_evidence_digest"]="sha256:"+"f"*64
        experiment["replication_reference"]="https://replication.example/hybrid/replication-1"
        if three_impls:
            entry["implementations"].append({
                "implementation_id":"hybrid-third",
                "maturity":"independent",
                "source_reference":"https://third.example/hybrid/source",
                "source_digest":"sha256:"+"1"*64,
                "language_runtime":"C example implementation",
                "build_reference":"https://third.example/hybrid/build",
                "limitations":["Third independent example implementation."],
                "production_use_prohibited":True,
            })
        if two_replications:
            entry["experiments"].append({
                "experiment_id":"hybrid-negative-vector-run-2",
                "hypothesis_ids":["hybrid-transcript-binding"],
                "methodology_digest":"sha256:"+"2"*64,
                "methodology_reference":"https://replication-two.example/method",
                "test_vector_ids":["hybrid-negative-vectors"],
                "implementation_ids":["hybrid-independent"],
                "environment_digest":"sha256:"+"3"*64,
                "environment_reference":"https://replication-two.example/environment",
                "outcome":"supported",
                "result_digest":"sha256:"+"4"*64,
                "result_reference":"https://replication-two.example/result",
                "executed_at":"2026-11-14T20:00:00Z",
                "replication_status":"independent",
                "replication_evidence_digest":"sha256:"+"5"*64,
                "replication_reference":"https://replication-two.example/evidence",
            })
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        return entry

    def implementation_evidence(self, entry: dict) -> list[dict]:
        org_by_id={
            "hybrid-prototype":"org-research",
            "hybrid-independent":"org-implementation-b",
            "hybrid-third":"org-implementation-c",
        }
        items=[]
        for index, implementation in enumerate(entry["implementations"]):
            implementation_id=implementation["implementation_id"]
            if implementation["maturity"]=="concept":
                continue
            org=org_by_id[implementation_id]
            items.append({
                "evidence_id":f"implementation-{index+1}",
                "evidence_type":"implementation-provenance",
                "evidence_digest":"sha256:"+format(index+10,"064x"),
                "reference":implementation["source_reference"],
                "producer_organization_id":org,
                "independent_from_submitter":org!="org-research",
                "created_at":"2026-11-15T01:00:00Z",
                "details":{
                    "implementation_id":implementation_id,
                    "source_digest":implementation["source_digest"],
                },
            })
        return items

    def review(self, suffix: str, org: str, when: str="2026-11-15T02:00:00Z") -> dict:
        return {
            "evidence_id":f"review-{suffix}",
            "evidence_type":"independent-security-review",
            "evidence_digest":"sha256:"+((suffix.encode().hex()+"a"*64)[:64]),
            "reference":f"https://{org}.example/review/{suffix}",
            "producer_organization_id":org,
            "independent_from_submitter":True,
            "created_at":when,
            "details":{"status":"pass"},
        }

    def replication(self, suffix: str, org: str, experiment: dict, when: str="2026-11-15T03:00:00Z") -> dict:
        return {
            "evidence_id":f"replication-{suffix}",
            "evidence_type":"independent-replication",
            "evidence_digest":"sha256:"+((("b"+suffix).encode().hex()+"b"*64)[:64]),
            "reference":experiment["replication_reference"],
            "producer_organization_id":org,
            "independent_from_submitter":True,
            "created_at":when,
            "details":{
                "experiment_id":experiment["experiment_id"],
                "replication_evidence_digest":experiment["replication_evidence_digest"],
            },
        }

    def interop(self, suffix: str, impl_ids: list[str], when: str="2026-11-15T04:00:00Z") -> dict:
        return {
            "evidence_id":f"interop-{suffix}",
            "evidence_type":"interoperability",
            "evidence_digest":"sha256:"+((("c"+suffix).encode().hex()+"c"*64)[:64]),
            "reference":f"https://interop.example/{suffix}",
            "producer_organization_id":"org-interop-lab",
            "independent_from_submitter":True,
            "created_at":when,
            "details":{"implementation_ids":impl_ids},
        }

    def deployment(self, suffix: str, org: str, when: str="2026-11-15T05:00:00Z") -> dict:
        return {
            "evidence_id":f"deployment-{suffix}",
            "evidence_type":"operational-deployment",
            "evidence_digest":"sha256:"+((("d"+suffix).encode().hex()+"d"*64)[:64]),
            "reference":f"https://{org}.example/deployment/{suffix}",
            "producer_organization_id":org,
            "independent_from_submitter":org!="org-research",
            "created_at":when,
            "details":{"deployment_id":f"deployment-{suffix}"},
        }

    def public_review(self) -> dict:
        return {
            "evidence_id":"public-review-30-days",
            "evidence_type":"public-review",
            "evidence_digest":"sha256:"+"6"*64,
            "reference":"https://example.org/public-review",
            "producer_organization_id":"org-standards",
            "independent_from_submitter":True,
            "created_at":"2026-11-16T00:00:00Z",
            "details":{
                "started_at":"2026-10-10T00:00:00Z",
                "ended_at":"2026-11-15T00:00:00Z",
                "public_review_reference":"https://example.org/public-review/thread",
                "disposition_digest":"sha256:"+"7"*64,
                "disposition_reference":"https://example.org/public-review/disposition",
            },
        }

    def external_standard(self, target_ref: str, when: str="2026-11-15T06:00:00Z") -> dict:
        return {
            "evidence_id":"external-standard-final",
            "evidence_type":"recognized-external-standard",
            "evidence_digest":"sha256:"+"8"*64,
            "reference":"https://standards.example/final",
            "producer_organization_id":"org-external-standards-body",
            "independent_from_submitter":True,
            "created_at":when,
            "details":{
                "status":"final",
                "standards_body":"Example Standards Body",
                "designation":"EXAMPLE-STD-1",
                "specification_digest":"sha256:"+"9"*64,
                "specification_reference":"https://standards.example/spec-1",
                "target_profile_ref":target_ref,
            },
        }

    def formal(self, properties: list[str]) -> dict:
        return {
            "evidence_id":"formal-proof-one",
            "evidence_type":"formal-verification",
            "evidence_digest":"sha256:"+"a"*64,
            "reference":"https://formal.example/proof/1",
            "producer_organization_id":"org-formal-lab",
            "independent_from_submitter":True,
            "created_at":"2026-11-15T06:30:00Z",
            "details":{"covered_property_ids":properties},
        }

    def approvals(self, count: int, when: str) -> list[dict]:
        orgs=["org-research","org-review-a","org-review-b","org-standards","org-review-c"]
        result=[]
        for index in range(count):
            result.append({
                "approver_id":f"approver-{index+1}",
                "organization_id":orgs[index],
                "role":"promotion-reviewer",
                "approved_at":when,
                "approval_evidence_digest":"sha256:"+format(index+40,"064x"),
                "reference":f"https://approvals.example/{index+1}",
            })
        return result

    def recommended_record(
        self,
        path: str,
        entry: dict,
        candidate: dict,
        candidate_catalog: dict,
    ) -> dict:
        record=copy.deepcopy(candidate)
        record["sequence"]=2
        record["previous_promotion_record_digest"]=candidate["promotion_record_digest"]
        record["source_research"]={
            "entry_id":entry["entry_id"],
            "entry_version":entry["entry_version"],
            "entry_digest":entry["entry_digest"],
        }
        record["source_state"]="candidate"
        record["target_state"]="recommended"
        record["gate_profile_ref"]=f"promotion-recommended-{path}@0.1.0"
        record["requested_at"]="2026-11-20T00:00:00Z"
        record["prior_state_effective_at"]=candidate["decision"]["decided_at"]
        record["target_profile"]["status"]="recommended"
        record["target_profile"]["notes"]=f"Illustrative Recommended projection via {path}."
        evidence=self.implementation_evidence(entry)
        evidence.append(self.review("a","org-review-a"))
        impl_ids=[item["implementation_id"] for item in entry["implementations"]]
        evidence.append(self.interop("one",impl_ids[:2]))
        if path=="implementation-led":
            evidence.append(self.review("b","org-review-b"))
            evidence.append(self.replication("one","org-replication-a",entry["experiments"][0]))
            evidence.append(self.deployment("one","org-deploy-a"))
            evidence.append(self.public_review())
        elif path=="formal-led":
            evidence.append(self.replication("one","org-replication-a",entry["experiments"][0]))
            evidence.append(self.formal(record["target_profile"]["security_properties"]))
            evidence.append(self.public_review())
        elif path=="external-standard-led":
            evidence.append(self.external_standard(
                f"{record['target_profile']['profile_id']}@{record['target_profile']['profile_version']}"
            ))
        else:
            raise AssertionError(path)
        record["evidence"]=evidence
        record["approvals"]=self.approvals(3,"2026-11-20T12:00:00Z")
        record["decision"]={
            "status":"approved",
            "decided_at":"2026-11-21T00:00:00Z",
            "rationale":f"Recommended {path} gate satisfied.",
        }
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        return record

    def required_entry(self) -> dict:
        entry=self.mature_entry(three_impls=True,two_replications=True)
        entry["revision"]=3
        entry["previous_entry_digest"]="sha256:"+"e"*64
        entry["updated_at"]="2027-05-20T00:00:00Z"
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        return entry

    def required_record(
        self,
        path: str,
        entry: dict,
        recommended: dict,
    ) -> dict:
        record=copy.deepcopy(recommended)
        record["sequence"]=3
        record["previous_promotion_record_digest"]=recommended["promotion_record_digest"]
        record["source_research"]={
            "entry_id":entry["entry_id"],
            "entry_version":entry["entry_version"],
            "entry_digest":entry["entry_digest"],
        }
        record["source_state"]="recommended"
        record["target_state"]="required"
        record["gate_profile_ref"]=f"promotion-required-{path}@0.1.0"
        record["prior_state_effective_at"]=recommended["decision"]["decided_at"]
        if path=="operational-maturity":
            record["requested_at"]="2027-05-30T00:00:00Z"
        else:
            record["requested_at"]="2027-03-01T00:00:00Z"
        record["target_profile"]["status"]="recommended"
        record["target_profile"]["notes"]=f"Illustrative Required projection via {path}."
        evidence=self.implementation_evidence(entry)
        evidence.extend([
            self.review("a","org-review-a","2027-02-01T00:00:00Z"),
            self.review("b","org-review-b","2027-02-02T00:00:00Z"),
        ])
        impl_ids=[item["implementation_id"] for item in entry["implementations"]]
        evidence.extend([
            self.interop("one",impl_ids[:2],"2027-02-03T00:00:00Z"),
            self.interop("two",impl_ids[1:3],"2027-02-04T00:00:00Z"),
        ])
        if path=="operational-maturity":
            evidence.extend([
                self.replication("one","org-replication-a",entry["experiments"][0],"2027-02-05T00:00:00Z"),
                self.replication("two","org-replication-b",entry["experiments"][1],"2027-02-06T00:00:00Z"),
                self.deployment("one","org-deploy-a","2027-02-07T00:00:00Z"),
                self.deployment("two","org-deploy-b","2027-02-08T00:00:00Z"),
                self.deployment("three","org-deploy-c","2027-02-09T00:00:00Z"),
            ])
            decided="2027-05-31T00:00:00Z"
            approval_when="2027-05-30T12:00:00Z"
        elif path=="standards-deployment":
            evidence.extend([
                self.deployment("one","org-deploy-a","2027-02-07T00:00:00Z"),
                self.deployment("two","org-deploy-b","2027-02-08T00:00:00Z"),
                self.external_standard(
                    f"{record['target_profile']['profile_id']}@{record['target_profile']['profile_version']}",
                    "2027-02-10T00:00:00Z",
                ),
            ])
            decided="2027-03-02T00:00:00Z"
            approval_when="2027-03-01T12:00:00Z"
        else:
            raise AssertionError(path)
        record["evidence"]=evidence
        record["approvals"]=self.approvals(4,approval_when)
        record["decision"]={
            "status":"approved",
            "decided_at":decided,
            "rationale":f"Required {path} gate satisfied.",
        }
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        return record

    def test_promotion_registry_is_valid_and_exposes_all_paths(self) -> None:
        registry=self.promotion_registry()
        self.assertEqual(research_promotion.validate_registry(registry),[])
        paths={(item["target_state"],item["path"]) for item in registry["gate_profiles"]}
        self.assertIn(("candidate","candidate-baseline"),paths)
        self.assertIn(("recommended","implementation-led"),paths)
        self.assertIn(("recommended","formal-assurance-led"),paths)
        self.assertIn(("recommended","external-standard-led"),paths)
        self.assertIn(("required","operational-maturity"),paths)
        self.assertIn(("required","standards-and-deployment"),paths)

    def test_candidate_promotion_is_valid(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        result=self.validate(record,entry)
        self.assertTrue(result.valid,result.errors)
        self.assertTrue(result.eligible,result.gate_failures)
        projected=next(
            item for item in result.projected_catalog["profiles"]
            if item["profile_id"]=="pairwise-example-hybrid-research"
        )
        self.assertEqual(projected["status"],"provisional")

    def test_candidate_profile_cannot_be_recommended_early(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        record["target_profile"]["status"]="recommended"
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("status must be provisional" in e for e in result.errors))

    def test_state_skipping_is_rejected(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        record["target_state"]="recommended"
        record["gate_profile_ref"]="promotion-recommended-implementation-led@0.1.0"
        record["target_profile"]["status"]="recommended"
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("is not allowed" in e for e in result.errors))

    def test_same_org_review_cannot_claim_independence(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        review=next(item for item in record["evidence"] if item["evidence_type"]=="independent-security-review")
        review["producer_organization_id"]="org-research"
        review["independent_from_submitter"]=True
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("cannot be independent" in e for e in result.errors))

    def test_approved_candidate_with_missing_review_fails_closed(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        record["evidence"]=[
            item for item in record["evidence"]
            if item["evidence_type"]!="independent-security-review"
        ]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertFalse(result.eligible)
        self.assertTrue(any("security-review" in e for e in result.gate_failures))

    def test_pending_under_gated_request_is_structurally_valid_but_not_eligible(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        record["evidence"]=[]
        record["approvals"]=[]
        record["decision"]={
            "status":"pending",
            "decided_at":None,
            "rationale":"Evidence collection is still in progress.",
        }
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertTrue(result.valid,result.errors)
        self.assertFalse(result.eligible)
        self.assertTrue(result.gate_failures)

    def test_promotion_critical_inconclusive_hypothesis_blocks_approval(self) -> None:
        entry=self.candidate_entry()
        entry["experiments"][0]["outcome"]="inconclusive"
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        record=self.candidate_record(entry)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("latest outcome is inconclusive" in e for e in result.gate_failures))

    def test_nonblocking_inconclusive_hypothesis_can_remain_visible(self) -> None:
        entry=self.candidate_entry()
        entry["experiments"][0]["outcome"]="inconclusive"
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        record=self.candidate_record(entry)
        record["hypothesis_dispositions"][0]={
            "hypothesis_id":"hybrid-transcript-binding",
            "promotion_role":"non-blocking",
            "rationale":"The Candidate profile does not claim the property under this unresolved experimental condition.",
        }
        record["target_profile"]["security_properties"]=[
            "SP-CONFIDENTIALITY","SP-PQ-CONFIDENTIALITY"
        ]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertTrue(result.valid,result.errors)
        self.assertTrue(result.eligible,result.gate_failures)

    def test_unreconciled_experimental_property_blocks_promotion(self) -> None:
        entry=self.candidate_entry()
        entry["security_properties"]["experimental_properties"]=[{
            "id":"EXP-SP-EXAMPLE",
            "name":"Example",
            "definition":"Experimental property used only to exercise reconciliation."
        }]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        record=self.candidate_record(entry)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("missing experimental identifiers" in e for e in result.errors))

    def test_reconciled_experimental_property_must_map_to_known_property(self) -> None:
        entry=self.candidate_entry()
        entry["security_properties"]["experimental_properties"]=[{
            "id":"EXP-SP-EXAMPLE",
            "name":"Example",
            "definition":"Experimental property."
        }]
        entry["entry_digest"]=research_profile_registry.compute_entry_digest(entry)
        record=self.candidate_record(entry)
        record["reconciliation"]=[{
            "kind":"security-property",
            "experimental_id":"EXP-SP-EXAMPLE",
            "disposition":"promoted",
            "production_id":"SP-NOT-REGISTERED",
            "rationale":"Invalid mapping for adversarial test."
        }]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("production security property ID is unknown" in e for e in result.errors))

    def test_open_critical_finding_blocks_candidate(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        record["findings"]=[{
            "finding_id":"critical-one",
            "severity":"critical",
            "status":"open",
            "summary":"Unresolved critical issue.",
            "evidence_digest":None,
            "reference":None,
        }]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("critical finding critical-one is open" in e for e in result.gate_failures))

    def test_accepted_blocker_is_never_enough(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        record["findings"]=[{
            "finding_id":"blocker-one",
            "severity":"blocker",
            "status":"accepted",
            "summary":"Attempted blocker risk acceptance.",
            "evidence_digest":"sha256:"+"f"*64,
            "reference":"https://example.org/risk-acceptance",
        }]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("blocker finding blocker-one must be resolved" in e for e in result.gate_failures))

    def test_all_three_recommended_paths_are_executable(self) -> None:
        entry=self.mature_entry()
        candidate_entry=self.candidate_entry()
        candidate=self.candidate_record(candidate_entry)
        candidate_result=self.validate(candidate,candidate_entry)
        self.assertTrue(candidate_result.valid,candidate_result.errors)
        candidate_catalog=candidate_result.projected_catalog

        for path in ("implementation-led","formal-led","external-standard-led"):
            with self.subTest(path=path):
                record=self.recommended_record(path,entry,candidate,candidate_catalog)
                result=self.validate(record,entry,candidate_catalog,candidate)
                self.assertTrue(result.valid,result.errors)
                self.assertTrue(result.eligible,result.gate_failures)
                projected=next(
                    item for item in result.projected_catalog["profiles"]
                    if item["profile_id"]=="pairwise-example-hybrid-research"
                )
                self.assertEqual(projected["status"],"recommended")

    def test_formal_led_requires_coverage_of_all_claimed_properties(self) -> None:
        entry=self.mature_entry()
        candidate_entry=self.candidate_entry()
        candidate=self.candidate_record(candidate_entry)
        candidate_result=self.validate(candidate,candidate_entry)
        record=self.recommended_record(
            "formal-led",entry,candidate,candidate_result.projected_catalog
        )
        formal=next(item for item in record["evidence"] if item["evidence_type"]=="formal-verification")
        formal["details"]["covered_property_ids"]=["SP-CONFIDENTIALITY"]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry,candidate_result.projected_catalog,candidate)
        self.assertFalse(result.valid)
        self.assertTrue(any("lacks formal coverage" in e for e in result.gate_failures))

    def test_implementation_led_reviews_must_come_from_distinct_external_orgs(self) -> None:
        entry=self.mature_entry()
        candidate_entry=self.candidate_entry()
        candidate=self.candidate_record(candidate_entry)
        candidate_result=self.validate(candidate,candidate_entry)
        record=self.recommended_record(
            "implementation-led",entry,candidate,candidate_result.projected_catalog
        )
        reviews=[item for item in record["evidence"] if item["evidence_type"]=="independent-security-review"]
        reviews[1]["producer_organization_id"]=reviews[0]["producer_organization_id"]
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry,candidate_result.projected_catalog,candidate)
        self.assertFalse(result.valid)
        self.assertTrue(any("security-review organizations" in e for e in result.gate_failures))

    def test_public_review_duration_cannot_be_shortened(self) -> None:
        entry=self.mature_entry()
        candidate_entry=self.candidate_entry()
        candidate=self.candidate_record(candidate_entry)
        candidate_result=self.validate(candidate,candidate_entry)
        record=self.recommended_record(
            "implementation-led",entry,candidate,candidate_result.projected_catalog
        )
        public=next(item for item in record["evidence"] if item["evidence_type"]=="public-review")
        public["details"]["started_at"]="2026-11-01T00:00:00Z"
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry,candidate_result.projected_catalog,candidate)
        self.assertFalse(result.valid)
        self.assertTrue(any("public-review days" in e for e in result.gate_failures))

    def test_external_standard_must_be_final_and_match_target_profile(self) -> None:
        entry=self.mature_entry()
        candidate_entry=self.candidate_entry()
        candidate=self.candidate_record(candidate_entry)
        candidate_result=self.validate(candidate,candidate_entry)
        record=self.recommended_record(
            "external-standard-led",entry,candidate,candidate_result.projected_catalog
        )
        standard=next(item for item in record["evidence"] if item["evidence_type"]=="recognized-external-standard")
        standard["details"]["status"]="draft"
        standard["details"]["target_profile_ref"]="wrong@0.1.0"
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry,candidate_result.projected_catalog,candidate)
        self.assertFalse(result.valid)
        self.assertTrue(any("must have final status" in e for e in result.errors))
        self.assertTrue(any("target_profile_ref mismatch" in e for e in result.errors))

    def recommended_for_required(self):
        entry=self.mature_entry()
        candidate_entry=self.candidate_entry()
        candidate=self.candidate_record(candidate_entry)
        candidate_result=self.validate(candidate,candidate_entry)
        recommended=self.recommended_record(
            "implementation-led",entry,candidate,candidate_result.projected_catalog
        )
        recommended_result=self.validate(
            recommended,entry,candidate_result.projected_catalog,candidate
        )
        self.assertTrue(recommended_result.valid,recommended_result.errors)
        return candidate,recommended,recommended_result.projected_catalog

    def test_both_required_paths_are_executable(self) -> None:
        _candidate,recommended,recommended_catalog=self.recommended_for_required()
        entry=self.required_entry()
        for path in ("operational-maturity","standards-deployment"):
            with self.subTest(path=path):
                record=self.required_record(path,entry,recommended)
                result=self.validate(
                    record,entry,recommended_catalog,recommended
                )
                self.assertTrue(result.valid,result.errors)
                self.assertTrue(result.eligible,result.gate_failures)
                projected=next(
                    item for item in result.projected_catalog["profiles"]
                    if item["profile_id"]=="pairwise-example-hybrid-research"
                )
                self.assertEqual(projected["status"],"recommended")

    def test_required_operational_path_enforces_180_day_dwell(self) -> None:
        _candidate,recommended,recommended_catalog=self.recommended_for_required()
        entry=self.required_entry()
        record=self.required_record("operational-maturity",entry,recommended)
        record["requested_at"]="2027-02-01T00:00:00Z"
        record["decision"]["decided_at"]="2027-02-02T00:00:00Z"
        record["approvals"]=self.approvals(4,"2027-02-01T12:00:00Z")
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry,recommended_catalog,recommended)
        self.assertFalse(result.valid)
        self.assertTrue(any("days in prior state" in e for e in result.gate_failures))

    def test_required_standards_path_enforces_90_day_dwell(self) -> None:
        _candidate,recommended,recommended_catalog=self.recommended_for_required()
        entry=self.required_entry()
        record=self.required_record("standards-deployment",entry,recommended)
        record["requested_at"]="2026-12-01T00:00:00Z"
        record["decision"]["decided_at"]="2026-12-02T00:00:00Z"
        record["approvals"]=self.approvals(4,"2026-12-01T12:00:00Z")
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry,recommended_catalog,recommended)
        self.assertFalse(result.valid)
        self.assertTrue(any("days in prior state" in e for e in result.gate_failures))

    def test_previous_promotion_digest_substitution_fails(self) -> None:
        entry=self.mature_entry()
        candidate_entry=self.candidate_entry()
        candidate=self.candidate_record(candidate_entry)
        candidate_result=self.validate(candidate,candidate_entry)
        record=self.recommended_record(
            "implementation-led",entry,candidate,candidate_result.projected_catalog
        )
        record["previous_promotion_record_digest"]="sha256:"+"9"*64
        record["promotion_record_digest"]=research_promotion.compute_promotion_record_digest(record)
        result=self.validate(record,entry,candidate_result.projected_catalog,candidate)
        self.assertFalse(result.valid)
        self.assertTrue(any("previous_promotion_record_digest mismatch" in e for e in result.errors))

    def test_promotion_record_digest_tamper_fails(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        record["promotion_record_digest"]="sha256:"+"9"*64
        result=self.validate(record,entry)
        self.assertFalse(result.valid)
        self.assertTrue(any("promotion_record_digest does not match" in e for e in result.errors))

    def test_approved_records_project_promotion_registry_state(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        result=self.validate(record,entry)
        self.assertTrue(result.valid,result.errors)
        registry=research_promotion.project_promotion_registry(
            self.promotion_registry(),record
        )
        self.assertEqual(
            research_promotion.validate_promotion_registry_state(
                registry,[record]
            ),[]
        )
        item=registry["promoted_profiles"][0]
        self.assertEqual(item["lifecycle_state"],"candidate")
        self.assertEqual(
            item["profile_ref"],
            "pairwise-example-hybrid-research@0.1.0",
        )

    def test_promotion_registry_state_digest_substitution_fails(self) -> None:
        entry=self.candidate_entry()
        record=self.candidate_record(entry)
        registry=research_promotion.project_promotion_registry(
            self.promotion_registry(),record
        )
        registry["promoted_profiles"][0]["promotion_record_digest"]="sha256:"+"9"*64
        errors=research_promotion.validate_promotion_registry_state(
            registry,[record]
        )
        self.assertTrue(any("state mismatch" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
