import json,sys,subprocess,unittest,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import canonical_serialization as canonical,digest_contracts

@unittest.skipUnless(shutil.which('node'),'Independent JavaScript runtime required for release interoperability gate')
class CrossLanguageBytesTests(unittest.TestCase):
    def node(self,arg,payload):return bytes.fromhex(subprocess.check_output(['node',str(ROOT/'reference/canonicalization/canonical.mjs'),arg],input=json.dumps(payload,ensure_ascii=False).encode()).decode())
    def test_golden_canonical_bytes(self):
        vectors=[{'é':'café','𐀀':1,'':2},{'events':[2,1],'members':['z','a']},{'integer':2**53-1,'negative':-(2**53-1),'bool':True,'null':None},{'2':'second','10':'tenth','1':'first'},{'controls':'\b\f\n\r\t\x00','slashes':'\\"','unicode':'e\u0301é'}]
        for value in vectors:self.assertEqual(canonical.canonical_bytes(value),self.node('canonical',value))
    def test_signature_and_digest_inputs(self):
        payload={'schema_version':'0.1','identity_id':'é','sequence':0,'account_root_key':None,'devices':[],'retired_key_ids':[]};contract='identity-state-record@1.0.0'
        for options in [{},{'purpose':'signature','signature_algorithm':'ed25519','profile_ref':'identity-account-root@0.1.0'}]:
            self.assertEqual(digest_contracts.input_bytes(contract,payload,**options),self.node(str(ROOT/'registry/digest-contracts.json'),{'contract_id':contract,'payload':payload,'options':options}))
