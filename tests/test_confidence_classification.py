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

import confidence_classification  # noqa: E402
import observatory_evidence  # noqa: E402


class ConfidenceClassificationTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/confidence-classification.json")

    def bundle(self) -> dict:
        bundle=self.load("fixtures/observatory-evidence/valid/bundle.json")
        bundle["agents"].append({
            "agent_id":"agent-human-reviewer",
            "agent_type":"person",
            "name":"Example Human Reviewer",
            "version":None,
            "identity_ref":"https://example.org/reviewers/human-1"
        })
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        return bundle

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/confidence-classification/valid/{name}-policy.json")

    def record(self, name: str, bundle: dict | None=None) -> dict:
        bundle=bundle or self.bundle()
        record=self.load(f"fixtures/confidence-classification/valid/{name}-record.json")
        record["source_bundle_digest"]=bundle["bundle_digest"]
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        return record

    def validate(self, name: str, record: dict | None=None, policy: dict | None=None, bundle: dict | None=None):
        bundle=bundle or self.bundle()
        policy=policy or self.policy(name)
        record=record or self.record(name,bundle)
        return confidence_classification.validate_record(
            record,policy,bundle,self.registry()
        )

    def test_registry_is_valid(self) -> None:
        self.assertEqual(
            confidence_classification.validate_registry(self.registry()),[]
        )

    def test_all_example_policies_are_valid(self) -> None:
        for name in ("human","automated","mixed-weighted"):
            with self.subTest(name=name):
                self.assertEqual(
                    confidence_classification.validate_policy(
                        self.policy(name),self.registry()
                    ),[]
                )

    def test_human_record_is_valid(self) -> None:
        self.assertEqual(self.validate("human"),[])

    def test_automated_calibrated_record_is_valid(self) -> None:
        self.assertEqual(self.validate("automated"),[])

    def test_mixed_weighted_record_is_valid(self) -> None:
        self.assertEqual(self.validate("mixed-weighted"),[])

    def test_unknown_target_fails(self) -> None:
        bundle=self.bundle()
        record=self.record("human",bundle)
        record["target"]["id"]="event-missing"
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("human",record=record,bundle=bundle)
        self.assertTrue(any("unknown event" in e for e in errors))

    def test_unknown_citation_fails(self) -> None:
        bundle=self.bundle()
        record=self.record("human",bundle)
        record["evidence_citation_ids"]=["citation-missing"]
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("human",record=record,bundle=bundle)
        self.assertTrue(any("unknown citations" in e for e in errors))

    def test_citations_must_be_sorted(self) -> None:
        bundle=self.bundle()
        bundle["citations"].append({
            "citation_id":"citation-a",
            "entity_id":"entity-source-001",
            "locator_kind":"section",
            "locator_value":"A",
            "excerpt_digest":None,
            "note":None
        })
        bundle["manifest_digest"]=observatory_evidence.compute_manifest_digest(bundle)
        bundle["bundle_digest"]=observatory_evidence.compute_bundle_digest(bundle)
        record=self.record("human",bundle)
        record["evidence_citation_ids"]=["citation-source-lines","citation-a"]
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("human",record=record,bundle=bundle)
        self.assertTrue(any("evidence_citation_ids must be lexically sorted" in e for e in errors))

    def test_human_assessment_requires_person_agent(self) -> None:
        bundle=self.bundle()
        record=self.record("human",bundle)
        record["human_assessment"]["agent_id"]="agent-fetcher"
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("human",record=record,bundle=bundle)
        self.assertTrue(any("human assessment agent must be PR 34 person agent" in e for e in errors))

    def test_automated_assessment_requires_software_or_service_agent(self) -> None:
        bundle=self.bundle()
        record=self.record("automated",bundle)
        record["automated_assessment"]["agent_id"]="agent-human-reviewer"
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("automated",record=record,bundle=bundle)
        self.assertTrue(any("software/service agent" in e for e in errors))

    def test_human_policy_cannot_allow_calibrated_probability(self) -> None:
        policy=self.policy("human")
        policy["allowed_assessment_confidence_models"]=[
            "dimensional-ordinal","calibrated-probability"
        ]
        policy["max_calibration_age_days"]=30
        errors=confidence_classification.validate_policy(policy,self.registry())
        self.assertTrue(any("must not allow calibrated-probability" in e for e in errors))

    def test_calibration_must_bind_exact_model_digest(self) -> None:
        bundle=self.bundle()
        record=self.record("automated",bundle)
        record["automated_assessment"]["confidence"]["calibration"]["model_digest"]="sha256:"+"9"*64
        record["final_confidence"]=copy.deepcopy(record["automated_assessment"]["confidence"])
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("automated",record=record,bundle=bundle)
        self.assertTrue(any("calibration model_digest does not match" in e for e in errors))

    def test_calibration_cannot_postdate_assessment(self) -> None:
        bundle=self.bundle()
        record=self.record("automated",bundle)
        record["automated_assessment"]["confidence"]["calibration"]["evaluated_at"]="2026-10-08T00:00:00Z"
        record["final_confidence"]=copy.deepcopy(record["automated_assessment"]["confidence"])
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("automated",record=record,bundle=bundle)
        self.assertTrue(any("calibration cannot postdate assessment" in e for e in errors))

    def test_stale_calibration_fails(self) -> None:
        bundle=self.bundle()
        policy=self.policy("automated")
        policy["max_calibration_age_days"]=1
        record=self.record("automated",bundle)
        errors=self.validate("automated",record=record,policy=policy,bundle=bundle)
        self.assertTrue(any("calibration evidence is stale" in e for e in errors))

    def test_brier_score_range_is_enforced(self) -> None:
        bundle=self.bundle()
        record=self.record("automated",bundle)
        record["automated_assessment"]["confidence"]["calibration"]["brier_score_millionths"]=1000001
        record["final_confidence"]=copy.deepcopy(record["automated_assessment"]["confidence"])
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("automated",record=record,bundle=bundle)
        self.assertTrue(any("Brier score millionths" in e for e in errors))

    def test_automated_record_must_bind_model_configuration(self) -> None:
        bundle=self.bundle()
        record=self.record("automated",bundle)
        record["automated_assessment"]["classifier"]["configuration_digest"]="not-a-digest"
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("automated",record=record,bundle=bundle)
        self.assertTrue(any("configuration_digest must be sha256" in e for e in errors))

    def test_stix_confidence_is_not_marked_probability_in_registry(self) -> None:
        descriptor=next(
            item for item in self.registry()["confidence_models"]
            if item["id"]=="stix-0-100"
        )
        self.assertFalse(descriptor["probability"])

    def test_weighted_policy_weights_must_sum_to_100(self) -> None:
        policy=self.policy("mixed-weighted")
        policy["mixed_resolution"]["human_weight_percent"]=70
        errors=confidence_classification.validate_policy(policy,self.registry())
        self.assertTrue(any("must sum to 100" in e for e in errors))

    def test_weighted_result_is_deterministic(self) -> None:
        bundle=self.bundle()
        record=self.record("mixed-weighted",bundle)
        record["final_confidence"]["value"]=75
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("mixed-weighted",record=record,bundle=bundle)
        self.assertTrue(any("must equal deterministic value 76" in e for e in errors))

    def test_weighted_strategy_requires_stix_inputs(self) -> None:
        bundle=self.bundle()
        record=self.record("mixed-weighted",bundle)
        record["human_assessment"]["confidence"]={
            "model":"dimensional-ordinal",
            "level":"high",
            "source_reliability":"strong",
            "evidence_directness":"strong",
            "corroboration":"strong",
            "freshness":"strong",
            "conflicting_evidence":"none",
            "rationale":"Test"
        }
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("mixed-weighted",record=record,bundle=bundle)
        self.assertTrue(any("requires STIX 0-100 confidence from both assessments" in e for e in errors))

    def test_weighted_label_disagreement_must_escalate(self) -> None:
        bundle=self.bundle()
        record=self.record("mixed-weighted",bundle)
        record["automated_assessment"]["labels"]=["different-label"]
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("mixed-weighted",record=record,bundle=bundle)
        self.assertTrue(any("disagreement must resolve to needs-review" in e for e in errors))

    def test_weighted_disagreement_needs_review_is_valid(self) -> None:
        bundle=self.bundle()
        record=self.record("mixed-weighted",bundle)
        record["automated_assessment"]["labels"]=["different-label"]
        record["status"]="needs-review"
        record["final_labels"]=[]
        record["final_confidence"]=None
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        self.assertEqual(self.validate("mixed-weighted",record=record,bundle=bundle),[])

    def test_human_final_disagreement_requires_override_reason(self) -> None:
        bundle=self.bundle()
        policy=self.policy("mixed-weighted")
        policy["policy_id"]="example-human-final-mixed"
        policy["mixed_resolution"]={
            "strategy":"human-final",
            "consensus_confidence_source":None,
            "human_weight_percent":None,
            "automated_weight_percent":None
        }
        record=self.record("mixed-weighted",bundle)
        record["automated_assessment"]["labels"]=["different-label"]
        record["mixed_resolution"]={
            "strategy":"human-final",
            "confidence_source":None,
            "human_weight_percent":None,
            "automated_weight_percent":None,
            "override_reason":None
        }
        record["final_confidence"]=copy.deepcopy(record["human_assessment"]["confidence"])
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("mixed-weighted",record=record,policy=policy,bundle=bundle)
        self.assertTrue(any("requires override/disagreement rationale" in e for e in errors))

    def test_human_final_disagreement_with_reason_is_valid(self) -> None:
        bundle=self.bundle()
        policy=self.policy("mixed-weighted")
        policy["policy_id"]="example-human-final-mixed"
        policy["mixed_resolution"]={
            "strategy":"human-final",
            "consensus_confidence_source":None,
            "human_weight_percent":None,
            "automated_weight_percent":None
        }
        record=self.record("mixed-weighted",bundle)
        record["automated_assessment"]["labels"]=["different-label"]
        record["mixed_resolution"]={
            "strategy":"human-final",
            "confidence_source":None,
            "human_weight_percent":None,
            "automated_weight_percent":None,
            "override_reason":"The reviewer found direct cited evidence that the automated classifier missed."
        }
        record["final_confidence"]=copy.deepcopy(record["human_assessment"]["confidence"])
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        self.assertEqual(
            self.validate("mixed-weighted",record=record,policy=policy,bundle=bundle),[]
        )

    def test_consensus_disagreement_has_no_final_result(self) -> None:
        bundle=self.bundle()
        policy=self.policy("mixed-weighted")
        policy["policy_id"]="example-consensus-mixed"
        policy["mixed_resolution"]={
            "strategy":"consensus",
            "consensus_confidence_source":"human",
            "human_weight_percent":None,
            "automated_weight_percent":None
        }
        record=self.record("mixed-weighted",bundle)
        record["automated_assessment"]["labels"]=["different-label"]
        record["mixed_resolution"]={
            "strategy":"consensus",
            "confidence_source":"human",
            "human_weight_percent":None,
            "automated_weight_percent":None,
            "override_reason":None
        }
        record["status"]="needs-review"
        record["final_labels"]=[]
        record["final_confidence"]=None
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        self.assertEqual(
            self.validate("mixed-weighted",record=record,policy=policy,bundle=bundle),[]
        )

    def test_consensus_agreement_copies_configured_confidence_source(self) -> None:
        bundle=self.bundle()
        policy=self.policy("mixed-weighted")
        policy["policy_id"]="example-consensus-mixed"
        policy["mixed_resolution"]={
            "strategy":"consensus",
            "consensus_confidence_source":"automated",
            "human_weight_percent":None,
            "automated_weight_percent":None
        }
        record=self.record("mixed-weighted",bundle)
        record["mixed_resolution"]={
            "strategy":"consensus",
            "confidence_source":"automated",
            "human_weight_percent":None,
            "automated_weight_percent":None,
            "override_reason":None
        }
        record["final_confidence"]=copy.deepcopy(record["automated_assessment"]["confidence"])
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        self.assertEqual(
            self.validate("mixed-weighted",record=record,policy=policy,bundle=bundle),[]
        )

    def test_needs_review_cannot_publish_final_result(self) -> None:
        bundle=self.bundle()
        record=self.record("mixed-weighted",bundle)
        record["status"]="needs-review"
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("mixed-weighted",record=record,bundle=bundle)
        self.assertTrue(any("must not publish final" in e for e in errors))

    def test_classification_digest_tamper_fails(self) -> None:
        bundle=self.bundle()
        record=self.record("human",bundle)
        record["classification_digest"]="sha256:"+"9"*64
        errors=self.validate("human",record=record,bundle=bundle)
        self.assertTrue(any("classification_digest does not match" in e for e in errors))

    def test_source_bundle_digest_substitution_fails(self) -> None:
        bundle=self.bundle()
        record=self.record("human",bundle)
        record["source_bundle_digest"]="sha256:"+"9"*64
        record["classification_digest"]=confidence_classification.compute_classification_digest(record)
        errors=self.validate("human",record=record,bundle=bundle)
        self.assertTrue(any("source_bundle_digest mismatch" in e for e in errors))

    def test_revision_chain_is_valid(self) -> None:
        bundle=self.bundle()
        previous=self.record("human",bundle)
        current=copy.deepcopy(previous)
        current["revision"]=2
        current["previous_record_digest"]=previous["classification_digest"]
        current["created_at"]="2026-10-07T23:00:00Z"
        current["human_assessment"]["confidence"]["rationale"]="Updated after a second review of the same cited evidence."
        current["final_confidence"]=copy.deepcopy(current["human_assessment"]["confidence"])
        current["classification_digest"]=confidence_classification.compute_classification_digest(current)
        self.assertEqual(
            confidence_classification.validate_revision_chain(
                current,previous,self.policy("human"),bundle,self.registry()
            ),[]
        )

    def test_revision_chain_rejects_wrong_predecessor(self) -> None:
        bundle=self.bundle()
        previous=self.record("human",bundle)
        current=copy.deepcopy(previous)
        current["revision"]=2
        current["previous_record_digest"]="sha256:"+"9"*64
        current["created_at"]="2026-10-07T23:00:00Z"
        current["classification_digest"]=confidence_classification.compute_classification_digest(current)
        errors=confidence_classification.validate_revision_chain(
            current,previous,self.policy("human"),bundle,self.registry()
        )
        self.assertTrue(any("previous_record_digest mismatch" in e for e in errors))

    def test_revision_chain_preserves_target_and_taxonomy(self) -> None:
        bundle=self.bundle()
        previous=self.record("human",bundle)
        current=copy.deepcopy(previous)
        current["revision"]=2
        current["previous_record_digest"]=previous["classification_digest"]
        current["target"]={"kind":"entity","id":"entity-source-001"}
        current["created_at"]="2026-10-07T23:00:00Z"
        current["classification_digest"]=confidence_classification.compute_classification_digest(current)
        errors=confidence_classification.validate_revision_chain(
            current,previous,self.policy("human"),bundle,self.registry()
        )
        self.assertTrue(any("must preserve target" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
