"""AUD-12 authenticated backup-generation transitions cannot pass on salt changes."""
from __future__ import annotations
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import backup_generation_rotation as g

def h(char):
    return "sha256:" + char * 64


class AuthenticatedRotationTests(unittest.TestCase):
    def setUp(self):
        self.old = {
            "schema_version": "0.1", "identity_id": "identity-alice",
            "profile_ref": "backup-user-secret@0.1.0", "backup_id": "backup-one",
            "generation": 1, "recovery_credential_epoch": 1,
            "bdek_id": "key-one", "bdek_commitment": h("1"),
            "encrypted_content_digest": h("2"), "inner_recovery_wrap_digest": h("3"),
            "argon2_salt_digest": h("4"), "content_aead_algorithm_id": "aead-aesgcm",
        }
        self.new = {**self.old, "generation": 2, "recovery_credential_epoch": 2,
                    "bdek_id": "key-two", "bdek_commitment": h("5"),
                    "encrypted_content_digest": h("6"), "inner_recovery_wrap_digest": h("7"),
                    "argon2_salt_digest": h("8")}
        self.evidence = {
            "fresh_bdek_generation_evidence_ref": "actual-keygen-test",
            "independent_distinct_key_check_ref": "actual-independent-key-test",
            "new_ciphertext_aead_test_ref": "actual-ciphertext-aead-test",
            "new_credential_decryption_test_ref": "actual-new-credential-test",
            "old_credential_rejection_test_ref": "actual-old-credential-rejection",
            "old_snapshots_may_remain_decryptable": True,
            "generated_bdek_random_bits": 256,
            "hardware_budget_release_evidence_ref": None,
        }

    def auth(self, old=None, new=None):
        old = old or self.old
        new = new or self.new
        a = g.manifest_digest(old)
        b = g.manifest_digest(new)
        return {
            "old_generation_digest": a,
            "new_generation_digest": b,
            "authorization_context_digest": g.transition_digest(a, b),
            "verified_identity_authority_evidence_ref": "signed-endpoint-authority",
        }

    def check(self, old=None, new=None, auth=None, evidence=None, floor=None):
        old = old or self.old
        new = new or self.new
        return g.evaluate_transition(
            old, new, auth if auth is not None else self.auth(),
            evidence if evidence is not None else self.evidence,
            trusted_previous_digest=floor if floor is not None else g.manifest_digest(self.old)
        )

    def test_valid_metadata_still_does_not_claim_cryptographic_proof(self):
        r = self.check()
        self.assertTrue(r["policy_consistent"], r)
        self.assertFalse(r["release_ready"])
        self.assertFalse(r["cryptographic_testing_verified"])
        self.assertIn("verify-old-credential-cannot-decrypt-new-ciphertext", r["required_external_checks"])

    def test_salt_only_change_is_not_rotation(self):
        x = copy.deepcopy(self.old)
        x["argon2_salt_digest"] = h("8")
        self.assertEqual(self.check(new=x)["reason"], "nonmonotonic-generation-or-credential-epoch")
        x.update({"generation": 2, "recovery_credential_epoch": 2})
        self.assertEqual(self.check(new=x)["reason"], "fresh-backup-key-not-demonstrated")

    def test_same_key_commitment_rejected_even_with_new_key_id(self):
        x = copy.deepcopy(self.new)
        x["bdek_commitment"] = self.old["bdek_commitment"]
        self.assertEqual(self.check(new=x)["reason"], "fresh-backup-key-not-demonstrated")

    def test_new_ciphertext_and_wrap_evidence_required(self):
        x = copy.deepcopy(self.new)
        x["inner_recovery_wrap_digest"] = self.old["inner_recovery_wrap_digest"]
        self.assertEqual(self.check(new=x)["reason"], "new-credential-envelope-and-ciphertext-required")
        x = copy.deepcopy(self.new)
        x["encrypted_content_digest"] = self.old["encrypted_content_digest"]
        self.assertEqual(self.check(new=x)["reason"], "new-credential-envelope-and-ciphertext-required")

    def test_reject_wrong_credential_or_identity_epoch(self):
        x = copy.deepcopy(self.new); x["generation"] = 3
        self.assertEqual(self.check(new=x)["reason"], "nonmonotonic-generation-or-credential-epoch")
        x = copy.deepcopy(self.new); x["identity_id"] = "identity-mallory"
        self.assertEqual(self.check(new=x)["reason"], "unapproved-identity-profile-or-algorithm-transition")

    def test_old_floor_and_replayed_authority_rejected(self):
        self.assertEqual(self.check(floor=h("9"))["reason"],
                         "independent-previous-generation-checkpoint-mismatch")
        a = self.auth()
        a["new_generation_digest"] = h("0")
        self.assertEqual(self.check(auth=a)["reason"], "unauthenticated-or-stale-generation-transition")
        a = self.auth()
        a["verified_identity_authority_evidence_ref"] = None
        self.assertEqual(self.check(auth=a)["reason"], "unauthenticated-or-stale-generation-transition")

    def test_old_secret_negative_decrypt_reference_required(self):
        x = copy.deepcopy(self.evidence)
        x["old_credential_rejection_test_ref"] = None
        self.assertEqual(self.check(evidence=x)["reason"], "missing-actual-crypto-test-reference")
        x = copy.deepcopy(self.evidence)
        x["generated_bdek_random_bits"] = 128
        self.assertEqual(self.check(evidence=x)["reason"], "insufficient-reported-bdek-entropy")

    def test_retained_old_ciphertext_claim_cannot_be_suppressed(self):
        x = copy.deepcopy(self.evidence)
        x["old_snapshots_may_remain_decryptable"] = False
        self.assertEqual(self.check(evidence=x)["reason"],
                         "retained-ciphertext-limitation-must-be-disclosed")

    def test_hardware_profile_needs_separate_budget_evidence(self):
        self.old["profile_ref"] = "backup-hardware-assisted@0.1.0"
        self.new["profile_ref"] = "backup-hardware-assisted@0.1.0"
        r = self.check(auth=self.auth(), floor=g.manifest_digest(self.old))
        self.assertEqual(r["reason"], "missing-attested-hardware-budget-evidence")
        x = copy.deepcopy(self.evidence)
        x["hardware_budget_release_evidence_ref"] = "attested-budget-release-record"
        r = self.check(evidence=x, auth=self.auth(), floor=g.manifest_digest(self.old))
        self.assertTrue(r["policy_consistent"])
        self.assertFalse(r["release_ready"])

    def test_local_vault_is_not_same_as_hosted_backup_rotation(self):
        x = copy.deepcopy(self.new)
        x["profile_ref"] = "secret-software-vault@0.1.0"
        self.assertIn("not a server-hosted", self.check(new=x)["reason"])


if __name__ == "__main__":
    unittest.main()
