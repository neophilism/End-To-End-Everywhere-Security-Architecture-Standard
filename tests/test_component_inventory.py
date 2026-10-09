import copy,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import component_inventory as inv

def fixture():
    return {'schema_version':'0.2','product_id':'mixed-app','source_digest':'sha256:'+'a'*64,'artifact_digest':'sha256:'+'b'*64,'evidence_refs':['source-build-inventory'],
      'components':[{'component_id':'client','product_class':'protected-content-library','capabilities':['offline'],'profile_refs':[],'inventory_flow_ids':['private-file'],'host_obligations':[]}],
      'flows':[{'flow_id':'private-file','component_id':'client','operation':'local-storage','data_class':'protected','recipient_ids':['alice'],'key_authority_ids':['alice'],'profile_refs':[],'networked':False}]}

class InventoryTests(unittest.TestCase):
    def catalog(self):return json.loads((ROOT/'profiles/catalog.json').read_text())
    def observations(self,m):return {'source_digest':m['source_digest'],'artifact_digest':m['artifact_digest'],'flows':copy.deepcopy(m['flows']),'completeness_evidence_ref':'source-build-inventory'}
    def test_declaration_is_not_its_own_evidence(self):
        r=inv.validate_inventory(fixture(),catalog=self.catalog());self.assertTrue(r['valid']);self.assertFalse(r['inventory_supported'])
    def test_omitted_demonstrated_protected_flow_fails(self):
        m=fixture();o=self.observations(m);m['flows']=[];m['components'][0]['inventory_flow_ids']=[];m['components'][0]['product_class']='development-process-only'
        self.assertFalse(inv.validate_inventory(m,catalog=self.catalog(),trusted_observations=o)['valid'])
    def test_process_label_cannot_waive_protected_content(self):
        m=fixture();m['components'][0]['product_class']='development-process-only'
        self.assertFalse(inv.validate_inventory(m,catalog=self.catalog())['valid'])
    def test_wrong_build_and_unknown_class_fail(self):
        m=fixture();o=self.observations(m);o['artifact_digest']='sha256:'+'c'*64
        self.assertFalse(inv.validate_inventory(m,catalog=self.catalog(),trusted_observations=o)['valid'])
        m['components'][0]['product_class']='unknown';self.assertFalse(inv.validate_inventory(m,catalog=self.catalog())['valid'])
    def test_bound_inventory_can_support_applicability(self):
        m=fixture();self.assertTrue(inv.validate_inventory(m,catalog=self.catalog(),trusted_observations=self.observations(m))['inventory_supported'])
