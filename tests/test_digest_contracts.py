import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import digest_contracts as d

class DigestContractsTests(unittest.TestCase):
    def payload(self):
        return {'schema_version':'0.1','identity_id':'alice','sequence':0,'account_root_key':None,'devices':[],'retired_key_ids':[]}
    def test_domain_and_algorithm_separation(self):
        p=self.payload();c='identity-state-record@1.0.0'
        a=d.input_bytes(c,p)
        b=d.input_bytes(c,p,purpose='signature',signature_algorithm='ed25519',profile_ref='identity-account-root@0.1.0')
        self.assertNotEqual(a,b)
        self.assertNotEqual(b,d.input_bytes(c,p,purpose='signature',signature_algorithm='ml-dsa-65',profile_ref='identity-account-root@0.1.0'))
    def test_unknown_fields_versions_and_contracts_fail(self):
        c='identity-state-record@1.0.0'
        for p in [dict(self.payload(),extra=1),dict(self.payload(),schema_version='0.2'),{'schema_version':'0.1'}]:
            with self.assertRaises(ValueError):d.digest(c,p)
        with self.assertRaises(ValueError):d.digest('unknown',self.payload())
    def test_ordered_history_is_bound(self):
        a=self.payload();a['devices']=[{'id':'a'},{'id':'b'}];b=dict(a,devices=list(reversed(a['devices'])))
        self.assertNotEqual(d.digest('identity-state-record@1.0.0',a),d.digest('identity-state-record@1.0.0',b))
    def test_legacy_is_explicit(self):
        p={'name':'é'}
        self.assertNotEqual(d.legacy_digest(p,scheme='legacy-python-ascii-v0'),d.legacy_digest(p,scheme='legacy-python-utf8-v0'))
