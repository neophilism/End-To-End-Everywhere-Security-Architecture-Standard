from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "real_time_media_engine.py"

spec = importlib.util.spec_from_file_location("real_time_media_engine", MODULE_PATH)
real_time_media_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = real_time_media_engine
spec.loader.exec_module(real_time_media_engine)


class RealTimeMediaEngineTests(unittest.TestCase):
    def load(self, rel: str) -> dict:
        return json.loads((ROOT / rel).read_text(encoding="utf-8"))

    def registry(self) -> dict:
        return self.load("registry/real-time-media.json")

    def catalog(self) -> dict:
        return self.load("fixtures/profiles/development-catalog.json")

    def policy(self, name: str) -> dict:
        return self.load(f"fixtures/media/policies/{name}.json")

    def session(self, name: str) -> dict:
        return self.load(f"fixtures/media/sessions/{name}.json")

    def frame(self, name: str) -> dict:
        return self.load(f"fixtures/media/frames/{name}.json")

    def checkpoint(self, name: str) -> dict:
        return self.load(f"fixtures/media/checkpoints/{name}.json")

    def test_registry_pins_rfc9605_and_cipher_suite_policy(self) -> None:
        self.assertEqual(real_time_media_engine.validate_registry(self.registry()), [])
        suites = {x["id"]: x for x in self.registry()["cipher_suites"]}
        self.assertEqual(suites["0x0005"]["status"], "recommended")
        self.assertEqual(suites["0x0003"]["status"], "prohibited")
        self.assertEqual(suites["0x0005"]["nt"], 16)

    def test_two_media_profiles_are_registered(self) -> None:
        refs = {
            f"{p['profile_id']}@{p['profile_version']}"
            for p in self.catalog()["profiles"]
            if p["family_id"] == "real-time-media"
        }
        self.assertEqual(refs, set(real_time_media_engine.PROFILE_MODES))

    def test_sender_and_mls_policies_pass(self) -> None:
        for name in ("sender-keys", "mls"):
            with self.subTest(name=name):
                self.assertEqual(
                    real_time_media_engine.validate_policy(
                        self.policy(name), self.registry(), self.catalog()
                    ),
                    [],
                )

    def test_prohibited_32_bit_tag_suite_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy("sender-keys"))
        policy["cipher_suite_id"] = "0x0003"
        errors = real_time_media_engine.validate_policy(
            policy, self.registry(), self.catalog()
        )
        self.assertTrue(any("prohibited" in e for e in errors), errors)

    def test_mls_profile_requires_mls_control_plane(self) -> None:
        policy = copy.deepcopy(self.policy("mls"))
        policy["control_profile_ref"] = "group-sender-key-aead@0.1.0"
        errors = real_time_media_engine.validate_policy(
            policy, self.registry(), self.catalog()
        )
        self.assertTrue(any("requires group-mls-rfc9420" in e for e in errors), errors)

    def test_valid_sessions_pass(self) -> None:
        for name in ("sender-keys", "mls"):
            with self.subTest(name=name):
                self.assertEqual(
                    real_time_media_engine.validate_session(
                        self.policy(name), self.session(name),
                        self.registry(), self.catalog()
                    ),
                    [],
                )

    def test_sfu_cannot_observe_plaintext_or_base_keys(self) -> None:
        evidence = self.session("mls")
        evidence["sfu_observed_media_plaintext"] = True
        errors = real_time_media_engine.validate_session(
            self.policy("mls"), evidence, self.registry(), self.catalog()
        )
        self.assertTrue(any("sfu_observed_media_plaintext" in e for e in errors), errors)

        evidence = self.session("mls")
        evidence["sfu_observed_base_keys"] = True
        errors = real_time_media_engine.validate_session(
            self.policy("mls"), evidence, self.registry(), self.catalog()
        )
        self.assertTrue(any("sfu_observed_base_keys" in e for e in errors), errors)

    def test_recording_bot_must_be_policy_allowed_and_authorized(self) -> None:
        evidence = self.session("mls")
        evidence["recording_bot_present"] = True
        evidence["recording_bot_authorized_participant"] = True
        errors = real_time_media_engine.validate_session(
            self.policy("mls"), evidence, self.registry(), self.catalog()
        )
        self.assertTrue(any("recording bot is prohibited" in e for e in errors), errors)

        policy = copy.deepcopy(self.policy("mls"))
        policy["allow_media_recording_bot"] = True
        evidence["recording_bot_authorized_participant"] = False
        errors = real_time_media_engine.validate_session(
            policy, evidence, self.registry(), self.catalog()
        )
        self.assertTrue(any("explicitly authorized" in e for e in errors), errors)

    def test_valid_membership_events_pass(self) -> None:
        cases = (
            ("sender-keys", "sender-join.json"),
            ("mls", "mls-remove-compromised.json"),
        )
        for policy_name, filename in cases:
            with self.subTest(policy=policy_name):
                event = self.load(f"fixtures/media/membership/{filename}")
                self.assertEqual(
                    real_time_media_engine.validate_membership_event(
                        self.policy(policy_name), event,
                        self.registry(), self.catalog()
                    ),
                    [],
                )

    def test_membership_change_requires_rekey_before_media_resume(self) -> None:
        event = self.load("fixtures/media/membership/sender-join.json")
        event["keys_rotated_before_media_resume"] = False
        errors = real_time_media_engine.validate_membership_event(
            self.policy("sender-keys"), event, self.registry(), self.catalog()
        )
        self.assertTrue(any("keys_rotated_before_media_resume" in e for e in errors), errors)

    def test_joiner_cannot_receive_prior_epoch_keys(self) -> None:
        event = self.load("fixtures/media/membership/sender-join.json")
        event["new_joiner_received_prior_epoch_keys"] = True
        errors = real_time_media_engine.validate_membership_event(
            self.policy("sender-keys"), event, self.registry(), self.catalog()
        )
        self.assertTrue(any("must not receive prior epoch" in e for e in errors), errors)

    def test_compromised_removal_requires_exclusion_and_authenticated_mls_commit(self) -> None:
        event = self.load("fixtures/media/membership/mls-remove-compromised.json")
        event["departed_devices_excluded_from_new_keys"] = False
        errors = real_time_media_engine.validate_membership_event(
            self.policy("mls"), event, self.registry(), self.catalog()
        )
        self.assertTrue(any("departed_devices_excluded" in e for e in errors), errors)

        event = self.load("fixtures/media/membership/mls-remove-compromised.json")
        event["mls_commit_authenticated"] = False
        errors = real_time_media_engine.validate_membership_event(
            self.policy("mls"), event, self.registry(), self.catalog()
        )
        self.assertTrue(any("MLS membership commit" in e for e in errors), errors)

    def test_rejoin_cannot_reuse_old_sender_key(self) -> None:
        event = self.load("fixtures/media/membership/sender-join.json")
        event["event_type"] = "rejoin"
        event["rejoining_device_reused_old_sender_key"] = True
        errors = real_time_media_engine.validate_membership_event(
            self.policy("sender-keys"), event, self.registry(), self.catalog()
        )
        self.assertTrue(any("must not reuse its old sender key" in e for e in errors), errors)

    def test_exact_rfc9605_mls_kid_construction(self) -> None:
        self.assertEqual(
            real_time_media_engine.expected_mls_kid(
                epoch=7, sender_index=1, group_size=3, epoch_bits=16, context=0
            ),
            65543,
        )

    def test_valid_sender_and_mls_frames_pass_with_checkpoints(self) -> None:
        for name in ("sender", "mls"):
            policy_name = "sender-keys" if name == "sender" else "mls"
            with self.subTest(name=name):
                self.assertEqual(
                    real_time_media_engine.validate_frame(
                        self.policy(policy_name),
                        self.frame(name),
                        self.registry(),
                        self.catalog(),
                        self.checkpoint(name),
                    ),
                    [],
                )

    def test_wrong_mls_kid_is_rejected(self) -> None:
        frame = self.frame("mls")
        frame["kid"] += 1
        errors = real_time_media_engine.validate_frame(
            self.policy("mls"), frame, self.registry(), self.catalog()
        )
        self.assertTrue(any("MLS construction" in e for e in errors), errors)

    def test_ctr_replay_is_rejected(self) -> None:
        frame = self.frame("sender")
        frame["ctr"] = 41
        errors = real_time_media_engine.validate_frame(
            self.policy("sender-keys"), frame, self.registry(), self.catalog(),
            self.checkpoint("sender")
        )
        self.assertTrue(any("replay/CTR rollback" in e for e in errors), errors)

    def test_explicit_replay_flag_is_rejected(self) -> None:
        frame = self.frame("sender")
        frame["kid_ctr_previously_seen"] = True
        errors = real_time_media_engine.validate_frame(
            self.policy("sender-keys"), frame, self.registry(), self.catalog()
        )
        self.assertTrue(any("kid_ctr_previously_seen must be false" in e for e in errors), errors)

    def test_new_epoch_requires_new_base_key(self) -> None:
        frame = self.frame("sender")
        frame["media_epoch"] = 2
        frame["kid"] = 102
        frame["ctr"] = 0
        errors = real_time_media_engine.validate_frame(
            self.policy("sender-keys"), frame, self.registry(), self.catalog(),
            self.checkpoint("sender")
        )
        self.assertTrue(any("new media epoch must rotate sender base key" in e for e in errors), errors)

    def test_media_epoch_rollback_is_rejected(self) -> None:
        checkpoint = self.checkpoint("sender")
        checkpoint["media_epoch"] = 2
        frame = self.frame("sender")
        errors = real_time_media_engine.validate_frame(
            self.policy("sender-keys"), frame, self.registry(), self.catalog(),
            checkpoint
        )
        self.assertTrue(any("media epoch rollback" in e for e in errors), errors)

    def test_sender_base_key_cannot_be_shared_by_multiple_senders(self) -> None:
        frame = self.frame("sender")
        frame["base_key_reused_by_multiple_senders"] = True
        errors = real_time_media_engine.validate_frame(
            self.policy("sender-keys"), frame, self.registry(), self.catalog()
        )
        self.assertTrue(any("base_key_reused_by_multiple_senders" in e for e in errors), errors)

    def test_plaintext_cannot_be_released_before_sframe_authentication(self) -> None:
        frame = self.frame("mls")
        frame["plaintext_released_before_authentication"] = True
        errors = real_time_media_engine.validate_frame(
            self.policy("mls"), frame, self.registry(), self.catalog()
        )
        self.assertTrue(any("plaintext_released_before_authentication" in e for e in errors), errors)

    def test_checkpoint_projection(self) -> None:
        frame = self.frame("mls")
        checkpoint = real_time_media_engine.checkpoint_from_frame(frame)
        self.assertEqual(real_time_media_engine.validate_checkpoint(checkpoint), [])
        self.assertEqual(checkpoint["max_ctr"], 200)
        self.assertEqual(checkpoint["kid"], 65543)


if __name__ == "__main__":
    unittest.main()
