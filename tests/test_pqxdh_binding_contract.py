"""AUD-14.1 pinned PQXDH wire and transcript mutation regressions."""
from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pqxdh_binding_contract as binding


def sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class PqxdhBindingTests(unittest.TestCase):
    def setUp(self):
        self.ik_a = b"\x05" + bytes.fromhex("aa" * 32)
        self.ik_b = b"\x05" + bytes.fromhex("bb" * 32)
        self.pq = b"\x11" + bytes.fromhex("ab" * 128)
        self.ct = bytes.fromhex("01" * 128)
        self.record = {
            "schema_version": "0.1",
            "profile_ref": "pairwise-pqxdh-triple-ratchet@0.1.0",
            "initialization_protocol_id": binding.PQXDH_REVISION,
            "braid_component_revision": binding.BRAID_REVISION,
            "ad_convention": binding.AD_CONVENTION,
            "kem_algorithm_id": "ALG-ML-KEM-768",
            "encoded_initiator_identity_hex": self.ik_a.hex(),
            "encoded_responder_identity_hex": self.ik_b.hex(),
            "encoded_pq_prekey_hex": self.pq.hex(),
            "kem_ciphertext_hex": self.ct.hex(),
            "associated_data_hex": (self.ik_a + self.ik_b).hex(),
        }
        self.trusted = {
            "profile_ref": self.record["profile_ref"],
            "ad_convention": binding.AD_CONVENTION,
            "kem_algorithm_id": "ALG-ML-KEM-768",
            "initiator_identity_sha256": sha(self.ik_a),
            "responder_identity_sha256": sha(self.ik_b),
            "pq_prekey_sha256": sha(self.pq),
            "kem_ciphertext_sha256": sha(self.ct),
        }

    def result(self, record=None, trusted=None):
        return binding.validate(self.record if record is None else record,
                                self.trusted if trusted is None else trusted)

    def test_pinned_ad_exact_bytes_and_true_limits(self):
        self.assertEqual(binding.published_ad_for_mlk(self.ik_a, self.ik_b).hex(),
                         "05" + "aa" * 32 + "05" + "bb" * 32)
        self.assertTrue(self.result()["consistent"])
        self.assertFalse(self.result()["cryptographically_verified"])

    def test_pqxdh_double_does_not_require_braid(self):
        r = copy.deepcopy(self.record)
        r["profile_ref"] = "pairwise-pqxdh-double-ratchet@0.1.0"
        r["braid_component_revision"] = None
        t = copy.deepcopy(self.trusted)
        t["profile_ref"] = r["profile_ref"]
        self.assertTrue(self.result(r, t)["consistent"])

    def test_wrong_pqxdh_or_braid_revision_rejected(self):
        for name, value in (
            ("initialization_protocol_id", "PROTO-PQXDH-R2"),
            ("braid_component_revision", "MLKEM-BRAID-R2"),
            ("braid_component_revision", None),
        ):
            r = copy.deepcopy(self.record)
            r[name] = value
            with self.subTest(field=name, value=value):
                self.assertFalse(self.result(r)["consistent"])

    def test_explicit_new_wire_version_needed_for_extra_binding(self):
        r = copy.deepcopy(self.record)
        r["associated_data_hex"] += self.pq.hex()
        self.assertEqual(self.result(r)["reason"], "pqxdh-associated-data-mismatch")
        r = copy.deepcopy(self.record)
        r["ad_convention"] = "pqxdh-r3-extra-pqpk-v2"
        self.assertEqual(self.result(r)["reason"], "unapproved-wire-binding-convention")

    def test_wrong_prekey_and_ciphertext_rejected(self):
        for field in ("encoded_pq_prekey_hex", "kem_ciphertext_hex"):
            with self.subTest(field=field):
                r = copy.deepcopy(self.record)
                r[field] = ("00" if r[field][:2] != "00" else "ff") + r[field][2:]
                self.assertEqual(self.result(r)["reason"], "untrusted-key-or-ciphertext-substitution")

    def test_swapped_identity_keys_rejected(self):
        r = copy.deepcopy(self.record)
        r["encoded_initiator_identity_hex"], r["encoded_responder_identity_hex"] = (
            r["encoded_responder_identity_hex"], r["encoded_initiator_identity_hex"]
        )
        self.assertEqual(self.result(r)["reason"], "untrusted-key-or-ciphertext-substitution")

    def test_wrong_kem_and_profile_rejected(self):
        for field, value in (
            ("kem_algorithm_id", "ALG-ML-KEM-512"),
            ("profile_ref", "pairwise-x3dh-double-ratchet@0.1.0"),
            ("profile_ref", "pairwise-pqxdh-spqr@0.1.0"),
        ):
            with self.subTest(field=field, value=value):
                r = copy.deepcopy(self.record)
                r[field] = value
                self.assertFalse(self.result(r)["consistent"])

    def test_missing_trust_and_malformed_bytes_fail_closed(self):
        for bad in ({}, {"profile_ref": self.record["profile_ref"]}):
            self.assertFalse(self.result(trusted=bad)["consistent"])
        self.assertFalse(binding.validate(self.record, None)["consistent"])
        for field, val in (
            ("encoded_pq_prekey_hex", "00f"),
            ("encoded_pq_prekey_hex", "0xabcdef"),
            ("encoded_pq_prekey_hex", ""),
            ("encoded_initiator_identity_hex", []),
            ("associated_data_hex", "AA"),
        ):
            with self.subTest(field=field):
                r = copy.deepcopy(self.record)
                r[field] = val
                self.assertEqual(self.result(r)["reason"], "invalid-wire-bytes")

    def test_claim_fields_cannot_bypass_exact_contract(self):
        r = copy.deepcopy(self.record)
        r["verified"] = True
        self.assertEqual(self.result(r)["reason"], "malformed-binding-record")
        r = copy.deepcopy(self.record)
        r.pop("kem_ciphertext_hex")
        self.assertEqual(self.result(r)["reason"], "malformed-binding-record")

    def test_status_cannot_infer_real_kem_authentication(self):
        result = self.result()
        self.assertTrue(result["consistent"])
        self.assertFalse(result["cryptographically_verified"])


if __name__ == "__main__":
    unittest.main()
