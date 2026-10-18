"""AUD-12.2: reject malformed/bool backup parameters rather than treating true as 1."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import backup_recovery_engine as backup


class StrictGenerationTypesTests(unittest.TestCase):
    def load(self,rel):
        return json.loads((ROOT/rel).read_text(encoding="utf-8"))

    def envelope(self):
        return self.load("fixtures/recovery/user-envelope-gen1.json")

    def args(self):
        return (
            self.load("fixtures/recovery/policies/user.json"),
            self.load("registry/cryptographic-algorithms.json"),
            self.load("fixtures/profiles/development-catalog.json"),
        )

    def test_baseline_valid_envelope(self):
        errors=backup.validate_envelope(*self.args()[:1], self.envelope(), *self.args()[1:])
        self.assertEqual(errors,[])

    def test_invalid_backup_entropy_reports_error_not_exception(self):
        for value in (True,False,None,256.0,"256",{},[],0,255):
            with self.subTest(value=value):
                env=self.envelope();env["backup_data_key_random_bits"]=value
                errors=backup.validate_envelope(self.args()[0],env,*self.args()[1:])
                self.assertTrue(any("256 random bits" in e for e in errors),errors)

    def test_bad_chunk_counts_rejected(self):
        for value in (True,False,None,"8",8.0,{},[],0):
            with self.subTest(value=value):
                env=self.envelope();env["ciphertext_chunk_count"]=value
                errors=backup.validate_envelope(self.args()[0],env,*self.args()[1:])
                self.assertTrue(any("ciphertext_chunk_count" in e for e in errors),errors)

    def test_bool_generation_never_advances_counter(self):
        old=self.envelope()
        new=self.load("fixtures/recovery/user-envelope-gen2.json")
        self.assertEqual(backup.validate_generation_transition(old,new),[])
        old["generation"]=True
        errs=backup.validate_generation_transition(old,new)
        self.assertTrue(any("exactly one" in e for e in errs),errs)
        old=self.envelope()
        new["generation"]=True
        self.assertTrue(backup.validate_generation_transition(old,new))

    def test_nonpositive_and_nonintegral_generation_rejected(self):
        for p,n in ((0,1),(-1,0),(1,2.0),(1,"2"),(None,2)):
            with self.subTest(old=p,new=n):
                old=self.envelope();new=self.load("fixtures/recovery/user-envelope-gen2.json")
                old["generation"]=p;new["generation"]=n
                self.assertTrue(backup.validate_generation_transition(old,new))


if __name__=="__main__":
    unittest.main()
