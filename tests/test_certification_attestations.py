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

import certification_attestations  # noqa: E402
import formal_verification  # noqa: E402


class CertificationAttestationTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def attestation_registry(self) -> dict:
        return self.load("registry/certification-attestations.json")

    def crypto_registry(self) -> dict:
        return self.load("registry/cryptographic-algorithms.json")

    def lifecycle_registry(self) -> dict:
        return self.load("registry/certification-lifecycle.json")

    def evidence_registry(self) -> dict:
        return self.load("registry/certification-evidence.json")

    def assurance_registry(self) -> dict:
        return self.load("registry/assurance-levels.json")

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def property_ids(self) -> set[str]:
        return {x["id"] for x in self.load("registry/security-properties.json")["properties"]}

    def threat_ids(self) -> set[str]:
        return {x["id"] for x in self.load("registry/threat-model.json")["threats"]}

    def plan(self) -> dict:
        return self.load("fixtures/assurance/valid/a3-plan.json")

    def evidence_bundle(self, plan: dict) -> dict:
        bundle=self.load("fixtures/certification-evidence/valid/a3-bundle.json")
        bundle["assurance_plan_digest"]=formal_verification.canonical_digest(plan)
        bundle["configuration_digest"]=formal_verification.canonical_digest(plan["configuration"])
        return bundle

    def lifecycle(self, bundle_digest: str) -> dict:
        case=self.load("fixtures/certification-lifecycle/valid/basic-certified.json")
        for event in case["events"]:
            if event["event_type"] in {"submit","advance-to-decision","approve"}:
                event["evidence_bundle_digest"]=bundle_digest
        return case

    def classical_policy(self) -> dict:
        return self.load("fixtures/certification-attestations/valid/signing-policy-classical.json")

    def dual_policy(self) -> dict:
        return self.load("fixtures/certification-attestations/valid/signing-policy-dual.json")

    def prepared_attestation(self, *, dual: bool=False):
        plan=self.plan()
        bundle=self.evidence_bundle(plan)
        bundle_digest=certification_attestations.canonical_digest(bundle)
        lifecycle=self.lifecycle(bundle_digest)
        lifecycle_digest=certification_attestations.canonical_digest(lifecycle)
        policy=self.dual_policy() if dual else self.classical_policy()
        record=self.load("fixtures/certification-attestations/valid/attestation.json")
        payload=record["payload"]
        payload["assurance_plan_digest"]=formal_verification.canonical_digest(plan)
        payload["configuration_digest"]=formal_verification.canonical_digest(plan["configuration"])
        payload["evidence_bundle_digest"]=bundle_digest
        payload["lifecycle_digest"]=lifecycle_digest
        payload["issuer_id"]=policy["issuer_id"]
        payload["signing_policy_id"]=policy["policy_id"]
        if dual:
            record["envelopes"]=[
                {
                    "envelope_id":"envelope-classical",
                    "format":"jws-compact",
                    "serialized_envelope":"TEST-ENVELOPE-ED25519",
                    "payload_digest":""
                },
                {
                    "envelope_id":"envelope-pq",
                    "format":"cose-sign1",
                    "serialized_envelope":"TEST-ENVELOPE-MLDSA65",
                    "payload_digest":""
                }
            ]
        digest=certification_attestations.canonical_digest(payload)
        record["payload_digest"]=digest
        for envelope in record["envelopes"]:
            envelope["payload_digest"]=digest
        return record,policy,lifecycle,bundle,plan

    def fake_verifier(self,envelope,payload_bytes,policy,payload_type):
        marker=envelope["serialized_envelope"]
        if marker in {"TEST-ENVELOPE-ED25519","TEST-STATUS-ED25519"}:
            return [{"key_id":"cert-ed25519-2026","algorithm_id":"ALG-ED25519"}]
        if marker=="TEST-ENVELOPE-MLDSA65":
            return [{"key_id":"cert-mldsa65-2026","algorithm_id":"ALG-ML-DSA-65"}]
        return []

    def validate_attestation(self, record, policy, lifecycle, bundle, plan, verifier=None):
        return certification_attestations.validate_attestation(
            record,policy,self.attestation_registry(),self.crypto_registry(),
            lifecycle,self.lifecycle_registry(),bundle,plan,self.evidence_registry(),
            self.assurance_registry(),self.catalog(),self.property_ids(),self.threat_ids(),
            verifier or self.fake_verifier,as_of="2026-10-07T21:30:00Z",
        )

    def prepared_status(self):
        attestation,policy,lifecycle,bundle,plan=self.prepared_attestation()
        record=self.load("fixtures/certification-attestations/valid/status.json")
        payload=record["payload"]
        payload["lifecycle_digest"]=certification_attestations.canonical_digest(lifecycle)
        payload["evidence_bundle_digest"]=certification_attestations.canonical_digest(bundle)
        payload["issuer_id"]=policy["issuer_id"]
        payload["signing_policy_id"]=policy["policy_id"]
        digest=certification_attestations.canonical_digest(payload)
        record["payload_digest"]=digest
        for envelope in record["envelopes"]:
            envelope["payload_digest"]=digest
        return record,policy,lifecycle

    def test_attestation_registry_is_valid(self) -> None:
        self.assertEqual(
            certification_attestations.validate_attestation_registry(
                self.attestation_registry(),self.crypto_registry()
            ),[]
        )

    def test_classical_signing_policy_is_valid(self) -> None:
        self.assertEqual(
            certification_attestations.validate_signing_policy(
                self.classical_policy(),self.attestation_registry(),self.crypto_registry()
            ),[]
        )

    def test_complete_classical_attestation_is_valid(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        self.assertEqual(self.validate_attestation(record,policy,lifecycle,bundle,plan),[])

    def test_complete_dual_classical_pq_attestation_is_valid(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation(dual=True)
        self.assertEqual(self.validate_attestation(record,policy,lifecycle,bundle,plan),[])

    def test_dual_policy_rejects_missing_pq_signature(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation(dual=True)
        record["envelopes"]=record["envelopes"][:1]
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("post-quantum signature threshold not met" in e for e in errors))

    def test_missing_crypto_backend_fails_closed(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        errors=certification_attestations.validate_attestation(
            record,policy,self.attestation_registry(),self.crypto_registry(),
            lifecycle,self.lifecycle_registry(),bundle,plan,self.evidence_registry(),
            self.assurance_registry(),self.catalog(),self.property_ids(),self.threat_ids(),
            None,as_of="2026-10-07T21:30:00Z",
        )
        self.assertTrue(any("cryptographic verifier backend is required" in e for e in errors))

    def test_tampered_payload_digest_fails(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        record["payload"]["product_version"]="2.0.0"
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("payload_digest does not match canonical payload" in e for e in errors))
        self.assertTrue(any("product_version does not match certified scope" in e for e in errors))

    def test_evidence_bundle_substitution_fails(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        record["payload"]["evidence_bundle_digest"]="sha256:"+"9"*64
        record["payload_digest"]=certification_attestations.canonical_digest(record["payload"])
        for envelope in record["envelopes"]:
            envelope["payload_digest"]=record["payload_digest"]
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("evidence_bundle_digest does not match certified scope" in e for e in errors))

    def test_lifecycle_bundle_must_equal_validated_evidence_bundle(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        lifecycle["events"][-1]["evidence_bundle_digest"]="sha256:"+"9"*64
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("current evidence bundle digest does not match" in e for e in errors))

    def test_unsupported_claim_cannot_be_published(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        record["payload"]["claims"].append({
            "property_id":"SP-INTEGRITY","status":"supported",
            "threat_ids":["TM-NET-ACTIVE"],"limitations":[]
        })
        record["payload"]["claims"]=sorted(record["payload"]["claims"],key=lambda x:(x["property_id"],x["status"],tuple(x["threat_ids"]),tuple(x["limitations"])))
        record["payload_digest"]=certification_attestations.canonical_digest(record["payload"])
        for envelope in record["envelopes"]:
            envelope["payload_digest"]=record["payload_digest"]
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("claims does not match certified scope" in e for e in errors))

    def test_unsorted_set_semantics_fail(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        record["payload"]["effective_profile_refs"]=list(reversed(record["payload"]["effective_profile_refs"]))
        record["payload_digest"]=certification_attestations.canonical_digest(record["payload"])
        for envelope in record["envelopes"]:
            envelope["payload_digest"]=record["payload_digest"]
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("effective_profile_refs must be lexically sorted" in e for e in errors))

    def test_unauthorized_key_returned_by_backend_fails(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        def bad_verifier(envelope,payload_bytes,policy,payload_type):
            return [{"key_id":"not-authorized","algorithm_id":"ALG-ED25519"}]
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan,bad_verifier)
        self.assertTrue(any("unknown or unauthorized key" in e for e in errors))
        self.assertTrue(any("signature threshold not met" in e for e in errors))

    def test_revoked_key_cannot_count(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        policy["trusted_keys"][0]["status"]="revoked"
        policy["trusted_keys"][0]["status_effective_at"]="2026-10-07T15:00:00Z"
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("key is not valid" in e for e in errors))

    def test_retired_key_can_validate_historical_pre_retirement_signature(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        policy["trusted_keys"][0]["status"]="retired"
        policy["trusted_keys"][0]["status_effective_at"]="2027-01-01T00:00:00Z"
        self.assertEqual(self.validate_attestation(record,policy,lifecycle,bundle,plan),[])

    def test_retired_key_cannot_sign_after_retirement(self) -> None:
        record,policy,lifecycle,bundle,plan=self.prepared_attestation()
        policy["trusted_keys"][0]["status"]="retired"
        policy["trusted_keys"][0]["status_effective_at"]="2026-10-07T15:45:00Z"
        errors=self.validate_attestation(record,policy,lifecycle,bundle,plan)
        self.assertTrue(any("key is not valid" in e for e in errors))

    def test_status_statement_zero_is_valid(self) -> None:
        record,policy,lifecycle=self.prepared_status()
        errors=certification_attestations.validate_status_statement(
            record,policy,self.attestation_registry(),self.crypto_registry(),
            lifecycle,self.lifecycle_registry(),self.fake_verifier,
            highest_sequence=0,as_of="2026-10-07T21:30:00Z",
        )
        self.assertEqual(errors,[])

    def test_status_sequence_rollback_fails(self) -> None:
        record,policy,lifecycle=self.prepared_status()
        errors=certification_attestations.validate_status_statement(
            record,policy,self.attestation_registry(),self.crypto_registry(),
            lifecycle,self.lifecycle_registry(),self.fake_verifier,
            highest_sequence=1,as_of="2026-10-07T21:30:00Z",
        )
        self.assertTrue(any("status sequence rollback detected" in e for e in errors))

    def test_chained_status_requires_previous_digest(self) -> None:
        previous,policy,lifecycle=self.prepared_status()
        current=copy.deepcopy(previous)
        current["payload"]["statement_id"]="example-status-1"
        current["payload"]["sequence"]=1
        current["payload"]["previous_status_digest"]="sha256:"+"9"*64
        current["payload_digest"]=certification_attestations.canonical_digest(current["payload"])
        current["envelopes"][0]["payload_digest"]=current["payload_digest"]
        errors=certification_attestations.validate_status_statement(
            current,policy,self.attestation_registry(),self.crypto_registry(),
            lifecycle,self.lifecycle_registry(),self.fake_verifier,
            previous_record=previous,highest_sequence=0,as_of="2026-10-07T21:30:00Z",
        )
        self.assertTrue(any("does not bind previous accepted status payload" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
