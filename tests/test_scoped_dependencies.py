import copy,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import profile_engine as p, profile_dependencies as deps, compatibility_solver as solver
from test_component_inventory import fixture

class ScopedDependencyTests(unittest.TestCase):
    def load(self,path):return json.loads((ROOT/path).read_text())
    def catalog(self):return self.load('profiles/catalog.json')
    def base(self):return ['identity-account-root@0.1.0','secret-platform-keystore@0.1.0','client-native-signed@0.1.0','transport-tls13-classical@0.1.0']
    def resolve(self,refs):
        c=self.catalog();return p.resolve_configuration(c,{'schema_version':'0.1','configuration_id':'case','standard_version':c['standard_version'],'selected_profiles':refs,'accepted_nondefault_statuses':[]})
    def test_seven_forbidden_family_audit_cases_are_unsatisfiable(self):
        cases=[('pairwise-pqxdh-triple-ratchet',['identity-architecture','key-verification','key-transparency','secret-storage','client-security','server-trust','transport-security']),('group-sender-key-aead',['pairwise-e2ee','identity-architecture']),('group-pairwise-fanout',['pairwise-e2ee']),('backup-hardware-assisted',['identity-architecture']),('attachment-chunked-aead',['pairwise-e2ee','group-e2ee']),('kt-third-party-auditing',['key-verification','identity-architecture']),('media-sframe-sender-keys',['pairwise-e2ee','group-e2ee'])]
        for ref,forbidden in cases:
            r={'schema_version':'0.1','request_id':'audit-case','standard_version':self.catalog()['standard_version'],'mode':'production','required_family_ids':[],'forbidden_family_ids':forbidden,'desired_property_ids':[],'pinned_profile_refs':[ref+'@0.1.0'],'excluded_profile_refs':[],'max_solutions':1,'enforce_required_promotions':True,'request_digest':''};r['request_digest']=solver.compute_request_digest(r)
            result=solver.solve(r,catalog=self.catalog(),solver_registry=self.load('registry/compatibility-solver.json'),property_registry=self.load('registry/security-properties.json'),promotion_registry=self.load('registry/research-promotion.json'),conformance_registry=self.load('registry/conformance.json'))
            with self.subTest(ref=ref):self.assertEqual(result['status'],'unsatisfiable');self.assertTrue(result['search_exhaustive'])
    def test_valid_channel_alternatives_remain_available(self):
        for channel in ['pairwise-x3dh-double-ratchet@0.1.0','group-mls-rfc9420@0.1.0']:
            r=self.resolve(self.base()+['attachment-chunked-aead@0.1.0',channel]);self.assertTrue(r.valid,r.errors)
    def test_account_root_exact_dependency(self):
        self.assertFalse(self.resolve(['verify-account-root@0.1.0']).valid)
        self.assertTrue(self.resolve(['verify-account-root@0.1.0','identity-account-root@0.1.0']).valid)
    def test_other_component_cannot_launder_parent_channel(self):
        m=fixture();c=m['components'][0];c['profile_refs']=self.base()+['attachment-chunked-aead@0.1.0'];m['flows'][0]['profile_refs']=c['profile_refs']
        other={'component_id':'other','product_class':'protected-content-library','capabilities':[],'profile_refs':['pairwise-x3dh-double-ratchet@0.1.0'],'inventory_flow_ids':[],'host_obligations':[]};m['components'].append(other)
        self.assertTrue(any('DEP-AUTHENTICATED-PARENT-CHANNEL' in x for x in deps.inventory_errors(m,self.catalog(),{})))
    def test_other_flow_cannot_launder_parent_channel(self):
        m=fixture();c=m['components'][0];c['profile_refs']=self.base()+['attachment-chunked-aead@0.1.0','pairwise-x3dh-double-ratchet@0.1.0'];m['flows'][0]['profile_refs']=self.base()+['attachment-chunked-aead@0.1.0']
        self.assertTrue(any('DEP-AUTHENTICATED-PARENT-CHANNEL' in x for x in deps.inventory_errors(m,self.catalog(),{})))
    def test_malformed_dependency_operator_fails_catalog_validation(self):
        c=self.catalog();c['profiles'][0]['dependency_rules']=[{'requirement_id':'bad','scope':'same-component','requires':{'any_of':[]}}]
        self.assertTrue(p.validate_catalog(c))
