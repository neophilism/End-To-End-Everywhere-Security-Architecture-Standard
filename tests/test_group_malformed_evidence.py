"""AUD-19.1: fail closed on nested/unhashable untrusted group evidence."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import group_e2ee_engine as group


class MalformedGroupEvidenceTests(unittest.TestCase):
    def load(self, name):
        return json.loads((ROOT/name).read_text(encoding="utf-8"))

    def policy(self):
        return self.load("fixtures/group/policies/mls.json")

    def event(self):
        return self.load("fixtures/group/membership/valid/mls.json")

    def message(self):
        return self.load("fixtures/group/messages/valid/mls.json")

    def case(self, policy=None, event=None, checkpoint=None):
        return group.validate_group_case(
            self.policy() if policy is None else policy,
            self.event() if event is None else event,
            self.message() if checkpoint is None else checkpoint,
            self.load("registry/group-protocols.json"),
            self.load("registry/cryptographic-algorithms.json"),
            self.load("fixtures/profiles/development-catalog.json"),
        )

    def test_valid_baseline_still_passes(self):
        self.assertEqual(self.case(), [])

    def test_unhashable_member_arrays_and_nulls_return_errors(self):
        for field in ("previous_member_device_ids", "added_member_device_ids",
                      "removed_member_device_ids", "new_member_device_ids"):
            for malformed in (None, [{"device_id": "nested"}], [[1]], {"id": "dict"}):
                with self.subTest(field=field, malformed=repr(malformed)):
                    event=self.event()
                    event[field]=malformed
                    errors=self.case(event=event)
                    self.assertTrue(errors, (field,malformed))
                    self.assertTrue(any(field in e for e in errors),errors)

    def test_unhashable_authorizer_type_is_rejected(self):
        for malformed in ([], {}, ["server"], {"pretend": "device"}):
            event=self.event()
            event["verified_membership_authorizers"]=[{"type":malformed,"id":"alice-phone"}]
            errors=self.case(event=event)
            self.assertTrue(any("invalid authorizer type" in e for e in errors),errors)

    def test_unhashable_or_invalid_sender_is_rejected(self):
        for sender in (None, [], {}, ["alice-phone"], 3):
            checkpoint=self.message()
            checkpoint["sender_device_id"]=sender
            errors=self.case(checkpoint=checkpoint)
            self.assertTrue(errors)

    def test_invalid_member_and_recipient_evidence_does_not_crash_crosscheck(self):
        for field in ("current_member_device_ids","recipient_device_ids"):
            for malformed in (None, [{"id": "nested"}], [["bob-phone"]]):
                checkpoint=self.message()
                checkpoint[field]=malformed
                errors=self.case(checkpoint=checkpoint)
                self.assertTrue(errors)

    def test_bad_policy_ids_do_not_crash_index_lookup(self):
        for field in ("profile_ref","protocol_id","mls_cipher_suite_id"):
            for malformed in ([], {}, ["group-mls-rfc9420@0.1.0"], None):
                policy=self.policy()
                policy[field]=malformed
                errors=self.case(policy=policy)
                self.assertTrue(errors, (field,malformed))

    def test_invalid_registry_enums_do_not_crash(self):
        for field in ("status","architecture"):
            registry=self.load("registry/group-protocols.json")
            registry["protocols"][0][field]=[]
            errors=group.validate_protocol_registry(registry)
            self.assertTrue(errors)
        registry=self.load("registry/group-protocols.json")
        registry["mls_cipher_suites"][0]["status"]={}
        self.assertTrue(group.validate_protocol_registry(registry))

    def test_nonobject_membership_and_checkpoint_fail_closed(self):
        for malformed in ([],None,{"unexpected":"field"}):
            self.assertTrue(group.validate_membership_event(self.policy(),malformed))
            self.assertTrue(group.validate_message_checkpoint(self.policy(),malformed))


if __name__=="__main__":
    unittest.main()
