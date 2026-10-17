"""AUD-10: fail-closed protected endpoint disclosure boundaries."""
from __future__ import annotations

import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import endpoint_egress_engine as e

FP = "sha256:" + "a" * 64


class EndpointEgressTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "schema_version": "0.1", "policy_id": "endpoint-data-egress",
            "flows": [{
                "flow_id": "message-export",
                "source_class": "protected",
                "e2ee_profile_ref": "capsule-test@0.1.0",
                "endpoint_recipients": [{"recipient_id": "recipient-bob", "key_fingerprint": FP}],
                "metadata_exposures": [{
                    "destination_id": "relay-main",
                    "permitted_fields": ["ciphertext-size", "delivery-time"]
                }],
                "public_destinations": [],
                "explicit_disclosures": [{
                    "authorization_id": "share-a", "purpose_id": "publish-report",
                    "selected_content_ids": ["note-one", "note-two"],
                    "recipient_ids": ["report-office"], "output_kinds": ["plaintext", "preview"],
                    "expires_at_epoch": 200,
                }],
            }]
        }
        self.base = {
            "event_id": "event-one", "flow_id": "message-export",
            "phase": "success", "output_kind": "ciphertext",
            "content_ids": ["note-one"], "destination_id": "relay-main",
            "recipient_id": "recipient-bob",
            "recipient_key_fingerprint": FP,
            "e2ee_profile_ref": "capsule-test@0.1.0",
            "encryption_scope": "e2ee-recipient", "metadata_fields": ["ciphertext-size"],
            "authorization_id": None, "purpose_id": None, "event_epoch": 100
        }

    def decision(self, **changes):
        event = copy.deepcopy(self.base)
        event.update(changes)
        return e.evaluate_event(self.policy, event)

    def disclose(self, **changes):
        event = copy.deepcopy(self.base)
        event.update({
            "event_id": "disclosure-one", "phase": "user-action", "output_kind": "plaintext",
            "content_ids": ["note-one", "note-two"],
            "destination_id": "report-office", "recipient_id": "report-office",
            "recipient_key_fingerprint": None, "e2ee_profile_ref": None,
            "encryption_scope": "none", "metadata_fields": [],
            "authorization_id": "share-a", "purpose_id": "publish-report",
        })
        event.update(changes)
        return event

    def test_ciphertext_to_named_recipient_and_relay(self):
        self.assertTrue(self.decision()["allowed"])
        self.assertTrue(self.decision(destination_id="recipient-bob", metadata_fields=[])["allowed"])
        for phase in ("success", "failure", "crash", "retry", "analytics", "background"):
            with self.subTest(phase=phase):
                self.assertTrue(self.decision(phase=phase)["allowed"])

    def test_reject_provider_key_and_wrong_profile(self):
        self.assertFalse(self.decision(encryption_scope="provider-key")["allowed"])
        self.assertFalse(self.decision(recipient_key_fingerprint="sha256:" + "b" * 64)["allowed"])
        self.assertFalse(self.decision(e2ee_profile_ref="capsule-weak@0.1.0")["allowed"])
        self.assertFalse(self.decision(recipient_id="provider-service")["allowed"])
        self.assertFalse(self.decision(destination_id="unlisted-provider")["allowed"])

    def test_metadata_leakage_must_be_explicit(self):
        self.assertEqual(self.decision(metadata_fields=["packet-count"])["reason"], "undeclared-metadata-leakage")
        self.assertTrue(self.decision(output_kind="protocol-metadata", recipient_id=None,
            recipient_key_fingerprint=None, e2ee_profile_ref=None, encryption_scope="none",
            metadata_fields=["delivery-time"])["allowed"])
        self.assertFalse(self.decision(output_kind="protocol-metadata", recipient_id=None,
            recipient_key_fingerprint=None, e2ee_profile_ref=None, encryption_scope="none",
            metadata_fields=["routing-token"])["allowed"])

    def test_derived_exports_denied_from_all_automatic_paths(self):
        for phase in ("success", "failure", "crash", "retry", "analytics", "background"):
            for kind in e.DERIVED:
                with self.subTest(phase=phase, kind=kind):
                    result = e.evaluate_event(self.policy, self.disclose(
                        output_kind=kind, phase=phase))
                    self.assertEqual(result["reason"], "automatic-content-derived-export")

    def test_explicit_finite_user_selection(self):
        self.assertEqual(e.evaluate_event(self.policy, self.disclose()),
                         {"allowed": True, "reason": "finite-user-selected-disclosure"})
        self.assertEqual(e.evaluate_event(self.policy, self.disclose(
            content_ids=["note-three"]))["reason"], "disclosure-scope-mismatch")
        self.assertEqual(e.evaluate_event(self.policy, self.disclose(
            content_ids=["note-one"]))["reason"], "disclosure-scope-mismatch")
        self.assertEqual(e.evaluate_event(self.policy, self.disclose(
            event_epoch=201))["reason"], "disclosure-scope-mismatch")

    def test_rejected_recipient_relabeling(self):
        for changes in (
            {"destination_id": "unlisted-service", "recipient_id": "unlisted-service"},
            {"destination_id": "report-office", "recipient_id": "relay-main"},
            {"purpose_id": "unrelated-purpose"},
            {"output_kind": "embedding"},
            {"authorization_id": None},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(e.evaluate_event(self.policy, self.disclose(**changes))["allowed"])

    def test_intentional_disclosure_never_satisfied_by_provider_encryption(self):
        self.assertFalse(e.evaluate_event(self.policy, self.disclose(
            encryption_scope="provider-key"))["allowed"])
        self.assertFalse(e.evaluate_event(self.policy, self.disclose(
            encryption_scope="e2ee-recipient"))["allowed"])

    def test_batch_detects_replay_and_spent_intentional_selection(self):
        result = e.evaluate_batch(self.policy, [self.disclose()])
        self.assertTrue(result["allowed"])
        self.assertEqual(result["new_spent_authorization_ids"], ["share-a"])
        repeated = e.evaluate_batch(self.policy, [self.disclose(), self.disclose(
            event_id="disclosure-two")])
        self.assertFalse(repeated["allowed"])
        self.assertEqual(repeated["results"][1]["reason"], "spent-disclosure-authorization")
        spent = e.evaluate_batch(self.policy, [self.disclose()], spent_authorization_ids=["share-a"])
        self.assertEqual(spent["results"][0]["reason"], "spent-disclosure-authorization")
        replay = e.evaluate_batch(self.policy, [self.base, copy.deepcopy(self.base)])
        self.assertEqual(replay["results"][1]["reason"], "replayed-egress-event-id")

    def test_invalid_events_fail_closed(self):
        for changes in (
            {"output_kind": "other"},
            {"flow_id": "unlisted-flow"},
            {"metadata_fields": ["plaintext-data"]},
            {"content_ids": []},
            {"event_epoch": True},
            {"encryption_scope": "provider-key"},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(self.decision(**changes)["allowed"])
        malformed = copy.deepcopy(self.base)
        malformed["unknown_field"] = "x"
        self.assertEqual(e.evaluate_event(self.policy, malformed)["reason"], "malformed-event")

    def test_public_data_does_not_inherit_private_policy(self):
        public = {
            "flow_id": "public-catalog", "source_class": "public",
            "e2ee_profile_ref": None, "endpoint_recipients": [],
            "metadata_exposures": [], "explicit_disclosures": [],
            "public_destinations": ["catalog-site"],
        }
        policy = copy.deepcopy(self.policy)
        policy["flows"].append(public)
        event = {**self.base, "flow_id": "public-catalog", "output_kind": "public-data",
                 "recipient_id": None, "recipient_key_fingerprint": None,
                 "e2ee_profile_ref": None, "encryption_scope": "none", "metadata_fields": [],
                 "destination_id": "catalog-site"}
        self.assertTrue(e.evaluate_event(policy, event)["allowed"])
        event["destination_id"] = "private-index"
        self.assertFalse(e.evaluate_event(policy, event)["allowed"])

    def test_policy_guards_future_content_and_wildcards(self):
        changed = copy.deepcopy(self.policy)
        changed["flows"][0]["explicit_disclosures"][0]["selected_content_ids"] = ["*"]
        with self.assertRaises(ValueError):
            e.validate_policy(changed)
        changed = copy.deepcopy(self.policy)
        changed["flows"][0]["explicit_disclosures"][0]["recipient_ids"] = []
        with self.assertRaises(ValueError):
            e.validate_policy(changed)


if __name__ == "__main__":
    unittest.main()
