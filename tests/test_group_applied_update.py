"""AUD-15 applied-epoch and PQ group claim mutation tests."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import group_applied_update as applied


class AppliedGroupUpdateTests(unittest.TestCase):
    def load(self, name):
        return json.loads((ROOT/name).read_text(encoding="utf-8"))

    def setup_case(self, kind="mls"):
        policy=self.load(f"fixtures/group/policies/{kind}.json")
        event=self.load(f"fixtures/group/membership/valid/{kind}.json")
        checkpoint=self.load(f"fixtures/group/messages/valid/{kind}.json")
        rec={
            "schema_version":"0.1",
            "group_id":event["group_id"],
            "profile_ref":policy["profile_ref"],
            "previous_epoch":event["previous_epoch"],
            "applied_epoch":event["new_epoch"],
            "operation_kind":applied.KINDS[policy["profile_ref"]],
            "commit_status":"applied",
            "prior_state_digest":"sha256:"+"a"*64,
            "applied_state_digest":"sha256:"+"b"*64,
            "membership_digest":applied.membership_commitment(event["new_member_device_ids"]),
            "authorizer_evidence_ref":"authorized-previous-member",
            "transition_proof_ref":"authenticated-applied-change",
            "commit_digest":"",
            "claims_post_quantum_group_confidentiality":False,
        }
        rec["commit_digest"]=applied.commit_digest(rec)
        trust={
            "group_id":rec["group_id"],
            "previous_epoch":rec["previous_epoch"],
            "previous_state_digest":rec["prior_state_digest"],
            "independently_verified_commit_digest":rec["commit_digest"],
        }
        return [policy,event,checkpoint,rec,trust,
            self.load("registry/group-protocols.json"),
            self.load("registry/cryptographic-algorithms.json"),
            self.load("fixtures/profiles/development-catalog.json")]

    def evaluate(self,case):
        return applied.evaluate(*case)

    def test_all_three_existing_group_architectures(self):
        for kind in ("mls","sender","pairwise"):
            with self.subTest(kind=kind):
                result=self.evaluate(self.setup_case(kind))
                self.assertTrue(result["consistent"],result)
                self.assertFalse(result["cryptographically_verified"])

    def test_proposed_or_not_yet_applied_commit_cannot_certify(self):
        for state in ("proposed","queued","rejected",""):
            c=self.setup_case()
            c[3]["commit_status"]=state
            self.assertEqual(self.evaluate(c)["reason"],"proposal-or-queued-update-is-not-committed")

    def test_mutated_group_epoch_or_commit_kind_rejected(self):
        for field,value in (("applied_epoch",2**31),("previous_epoch",False),
                            ("operation_kind","fake-mls-commit")):
            c=self.setup_case()
            c[3][field]=value
            self.assertFalse(self.evaluate(c)["consistent"])

    def test_same_secret_state_does_not_count_as_new_epoch(self):
        c=self.setup_case()
        c[3]["applied_state_digest"]=c[3]["prior_state_digest"]
        self.assertEqual(self.evaluate(c)["reason"],"no-new-keyed-group-state")

    def test_stale_source_or_modified_commit_is_rejected(self):
        c=self.setup_case()
        c[3]["transition_proof_ref"]="different-proof"
        self.assertEqual(self.evaluate(c)["reason"],"tampered-group-update-receipt")
        c=self.setup_case()
        c[4]["independently_verified_commit_digest"]="sha256:"+"0"*64
        self.assertEqual(self.evaluate(c)["reason"],"independent-group-state-or-commit-anchor-mismatch")

    def test_missing_trusted_prior_state_rejected(self):
        c=self.setup_case()
        c[4]={}
        self.assertEqual(self.evaluate(c)["reason"],"missing-independent-prior-state-and-commit-anchor")

    def test_member_set_replacement_rejected(self):
        c=self.setup_case()
        c[3]["membership_digest"]="sha256:"+"f"*64
        self.assertEqual(self.evaluate(c)["reason"],"committed-recipient-set-mismatch")

    def test_pairwise_post_quantum_component_cannot_imply_group_pq(self):
        c=self.setup_case("pairwise")
        c[3]["claims_post_quantum_group_confidentiality"]=True
        self.assertEqual(self.evaluate(c)["reason"],"unsupported-group-post-quantum-claim")
        c=self.setup_case("mls")
        c[3]["claims_post_quantum_group_confidentiality"]=True
        self.assertFalse(self.evaluate(c)["consistent"])

    def test_invalid_prior_group_or_message_evidence_rejected(self):
        c=self.setup_case()
        c[2]["epoch"]+=1
        self.assertEqual(self.evaluate(c)["reason"],"invalid-group-epoch-membership-or-message")

    def test_no_unknown_fields(self):
        c=self.setup_case()
        c[3]["server_claimed_verified"]=True
        self.assertEqual(self.evaluate(c)["reason"],"missing-applied-transition-receipt")


if __name__=="__main__":
    unittest.main()
