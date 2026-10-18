"""AUD-23.1: actual independent Python/Node canonical group update digests."""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import group_applied_update as group

@unittest.skipUnless(shutil.which("node"),"node required for cross-runtime corpus")
class CrossRuntimeGroupUpdate(unittest.TestCase):
    def node(self,kind,value):
        output=subprocess.check_output(
            ["node",str(ROOT/"reference/canonicalization/group-update.mjs"),kind],
            input=json.dumps(value,ensure_ascii=False).encode("utf-8"),timeout=12)
        return output.decode("ascii").strip()

    def test_member_set_permutation_and_explicit_domain(self):
        members=["user-three","user-one","user-two"]
        digest=group.membership_commitment(members)
        self.assertEqual(digest,self.node("members",members))
        self.assertEqual(digest,self.node("members",list(reversed(members))))
        self.assertNotEqual(digest,self.node("members",["user-one"]))

    def test_applied_receipt_bytes_identical_across_languages(self):
        rec={
            "schema_version":"0.1",
            "group_id":"alpha-room",
            "profile_ref":"group-mls-rfc9420@0.1.0",
            "previous_epoch":53,
            "applied_epoch":54,
            "operation_kind":"mls-applied-commit",
            "commit_status":"applied",
            "prior_state_digest":"sha256:"+"a"*64,
            "applied_state_digest":"sha256:"+"b"*64,
            "membership_digest":group.membership_commitment(["alice-1","bob-3"]),
            "authorizer_evidence_ref":"trusted-admin",
            "transition_proof_ref":"verified-mls-update-path",
            "commit_digest":"",
            "claims_post_quantum_group_confidentiality":False,
        }
        exact=group.commit_digest(rec)
        self.assertEqual(exact,self.node("receipt",rec))
        rec["applied_epoch"]+=1
        self.assertNotEqual(exact,self.node("receipt",rec))
        self.assertEqual(group.commit_digest(rec),self.node("receipt",rec))

    def test_distinct_domains_cannot_alias_same_json_bytes(self):
        example=["alice","bob"]
        self.assertNotEqual(
            group.membership_commitment(example),
            "sha256:"+__import__("hashlib").sha256(
                b"E2EESA-GROUP-APPLIED-COMMIT-v1\x00"+
                __import__("canonical_serialization").canonical_bytes(sorted(example))
            ).hexdigest()
        )

    def test_node_rejects_invalid_member_list(self):
        for malformed in ([], ["alice","alice"], [{"id":"alice"}], [""]):
            with self.assertRaises(subprocess.CalledProcessError):
                self.node("members",malformed)


if __name__=="__main__":
    unittest.main()
