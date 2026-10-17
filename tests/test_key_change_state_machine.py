"""AUD-09.2 key-change journal and queued delivery security regressions."""
from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import key_change_state_machine as m
import key_verification_engine as verification


class ChangeStateTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"schema_version": "0.1", "policy_id": "example-policy", "mode": "strict-reverification"}
        self.a = "a" * 64
        self.b = "b" * 64
        self.c = "c" * 64
        self.state = m.new_state(peer_id="bob", initial_subject_digest=self.a, policy=self.policy)
        self.head = m.inspect_state(self.state, self.policy)["head"]

    def observed(self, target=None, classification="unverified-change", evidence=None):
        self.state = m.observe(self.state, self.policy, accepted_subject_digest=target or self.b,
                               classification=classification, authority_evidence_ref=evidence, trusted_head=self.head)
        self.head = m.inspect_state(self.state, self.policy)["head"]

    def decision(self, **kw):
        return m.send_decision(self.state, self.policy, target_subject_digest=kw.pop("subject", self.b),
                               trusted_head=kw.pop("head", self.head), **kw)

    def test_unverified_peer_change_produces_notice_and_blocks(self):
        self.observed()
        info = m.inspect_state(self.state, self.policy)
        self.assertEqual(info["trust"], "unverified")
        self.assertEqual(info["notices"][0]["message_key"], "security.unverified-key-change")
        self.assertFalse(self.decision()["allowed"])

    def test_strict_acknowledgement_cannot_send(self):
        self.observed()
        self.state = m.acknowledge(self.state, self.policy, noticed_change_sequence=1, trusted_head=self.head)
        self.head = m.inspect_state(self.state, self.policy)["head"]
        self.assertFalse(self.decision()["allowed"])

    def test_acknowledged_policy_can_send_with_visible_unverified_status(self):
        self.policy["mode"] = "acknowledge-change"
        self.observed()
        self.state = m.acknowledge(self.state, self.policy, noticed_change_sequence=1, trusted_head=self.head)
        self.head = m.inspect_state(self.state, self.policy)["head"]
        result = self.decision()
        self.assertTrue(result["allowed"])
        self.assertTrue(result["requires_visible_notice"])
        self.assertEqual(result["trust"], "unverified")

    def test_replacement_blocks_in_both_modes(self):
        for mode in ("strict-reverification", "acknowledge-change"):
            with self.subTest(mode=mode):
                self.setUp()
                self.policy["mode"] = mode
                self.observed(classification="identity-replacement")
                self.state = m.acknowledge(self.state, self.policy, noticed_change_sequence=1, trusted_head=self.head)
                self.head = m.inspect_state(self.state, self.policy)["head"]
                self.assertFalse(self.decision()["allowed"])

    def test_forged_authorized_subordinate_evidence_rejected(self):
        with self.assertRaises(ValueError):
            self.observed(classification="authorized-subordinate")
        self.observed(classification="authorized-subordinate", evidence="trusted-transition")
        self.assertEqual(m.inspect_state(self.state, self.policy)["change_class"], "authorized-subordinate")

    def test_tampered_event_and_rollback_fail(self):
        self.observed()
        original = copy.deepcopy(self.state)
        self.state["events"][0]["change_class"] = "identity-replacement"
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            m.inspect_state(self.state, self.policy)
        self.state = original
        self.assertFalse(self.decision(head=m._genesis(self.state))["allowed"])

    def test_out_of_order_and_missing_events_fail(self):
        self.observed()
        self.observed(self.c)
        self.state["events"].pop(0)
        with self.assertRaises(ValueError):
            m.inspect_state(self.state, self.policy)

    def test_queue_cannot_silently_reencrypt_or_resurrect(self):
        self.observed()
        self.assertEqual(self.decision(queued_subject_digest=self.a, queued_revision=0)["reason"], "queued-recipient-mismatch")
        self.observed(self.a)
        self.assertEqual(self.decision(subject=self.a, queued_subject_digest=self.a, queued_revision=0)["reason"],
                         "queued-content-requires-fresh-authorization")

    def test_stale_acknowledgement_rejected(self):
        self.observed()
        self.observed(self.c)
        with self.assertRaises(ValueError):
            m.acknowledge(self.state, self.policy, noticed_change_sequence=1, trusted_head=self.head)

    def test_manual_verification_integrates_existing_engine(self):
        family = "account"
        load = lambda name: json.loads((ROOT / name).read_text(encoding="utf-8"))
        vp = load(f"fixtures/verification/policies/{family}.json")
        alice = load(f"fixtures/verification/snapshots/{family}/alice.json")
        bob = load(f"fixtures/verification/snapshots/{family}/bob.json")
        crypto = load("registry/cryptographic-algorithms.json")
        catalog = load("fixtures/profiles/development-catalog.json")
        subject = verification.subject_digest(vp, alice, bob).hex()
        state = m.new_state(peer_id="bob", initial_subject_digest=subject, policy=self.policy)
        head = m.inspect_state(state, self.policy)["head"]
        record = verification.create_manual_record(record_id="fresh-comparison", verification_method="qr",
            user_confirmed=True, policy=vp, first_snapshot=alice, second_snapshot=bob,
            crypto_registry=crypto, profile_catalog=catalog)
        args = dict(trusted_head=head, record=record, verification_policy=vp,
            first_snapshot=alice, second_snapshot=bob, crypto_registry=crypto, profile_catalog=catalog)
        state = m.confirm_manual_verification(state, self.policy, **args)
        head = m.inspect_state(state, self.policy)["head"]
        self.assertTrue(m.send_decision(state, self.policy, target_subject_digest=subject, trusted_head=head)["allowed"])
        with self.assertRaisesRegex(ValueError, "replay"):
            m.confirm_manual_verification(state, self.policy, **{**args, "trusted_head": head})
        changed = load(f"fixtures/verification/snapshots/{family}/bob-root-changed.json")
        new_subject = verification.subject_digest(vp, alice, changed).hex()
        state = m.observe(state, self.policy, accepted_subject_digest=new_subject,
                          classification="identity-replacement", trusted_head=head)
        head = m.inspect_state(state, self.policy)["head"]
        self.assertFalse(m.send_decision(state, self.policy, target_subject_digest=new_subject, trusted_head=head)["allowed"])
        with self.assertRaises(ValueError):
            m.confirm_manual_verification(state, self.policy, **{**args, "trusted_head": head})


if __name__ == "__main__":
    unittest.main()
