import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import canonical_serialization as c
import formal_verification, conformance_engine

class CanonicalTests(unittest.TestCase):
    def test_unicode_owners_agree(self):
        obj={'claim':'café','n':1}
        self.assertEqual(formal_verification.canonical_digest(obj),conformance_engine.canonical_digest(obj))
        self.assertEqual(c.canonical_bytes(obj), b'{"claim":"caf\xc3\xa9","n":1}')
    def test_utf16_key_order(self):
        self.assertEqual(c.canonical_bytes({'\ue000':1,'\U00010000':2}),'{"𐀀":2,"":1}'.encode())
    def test_reject_invalid_input(self):
        for text in ['{"x":1,"x":2}','1.5','NaN','Infinity','9007199254740992','"\\ud800"']:
            with self.subTest(text=text),self.assertRaises(ValueError):c.parse_json(text)
    def test_arrays_are_ordered_and_sets_explicit(self):
        x={'events':[2,1],'members':['z','a']}
        y=c.preprocess_sets(x,paths=[('members',)])
        self.assertEqual(y,{'events':[2,1],'members':['a','z']})
        self.assertEqual(x['members'],['z','a'])
    def test_historical_schemes_remain_different_and_explicit(self):
        x={'name':'é'}
        self.assertNotEqual(c.legacy_bytes(x,scheme='legacy-python-ascii-v0'),c.legacy_bytes(x,scheme='legacy-python-utf8-v0'))
        with self.assertRaises(ValueError):c.bytes_for_scheme(x,scheme='unknown')
    def test_decimal_adapter_is_exact(self):
        x=c.external_decimal_model(0.1)
        self.assertEqual(x['value'],'0.1000000000000000055511151231257827021181583404541015625')
        with self.assertRaises(ValueError):c.canonical_bytes(0.1)
