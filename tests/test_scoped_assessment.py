import copy,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import scoped_assessment as assess
from test_component_inventory import fixture

class ScopedAssessmentTests(unittest.TestCase):
    def bind(self,r):r['request_digest']=assess.request_digest(r);return r
    def request(self):
        return self.bind({'schema_version':'0.2','assessment_id':'test-assessment','evaluated_at':'2026-10-09T23:00:00Z','policy':'configuration','standard_lock':assess.standard_lock(),'inventory':fixture(),'claims':[],'request_digest':''})
    def claim(self):return {'claim_id':'content','claim_domain':'protected-content','flow_id':'private-file','property_id':'SP-CONFIDENTIALITY','threat_ids':['service-provider'],'profile_refs':[],'evidence_refs':[]}
    def messaging(self,r,group=False):
        refs=['identity-account-root@0.1.0','secret-platform-keystore@0.1.0','client-native-signed@0.1.0','transport-tls13-classical@0.1.0','verify-account-root@0.1.0','pairwise-pqxdh-triple-ratchet@0.1.0']
        if group:refs.append('group-mls-rfc9420@0.1.0')
        component=r['inventory']['components'][0];component['profile_refs']=refs;component['product_class']='messaging-endpoint';component['capabilities']=['groups'] if group else []
        flow=r['inventory']['flows'][0];flow['operation']='group-message' if group else 'direct-message';flow['networked']=True;flow['profile_refs']=refs
        return self.bind(r)
    def test_configuration_pass_is_not_certification(self):
        result=assess.evaluate(self.request());self.assertEqual(result['verdict'],'pass');self.assertEqual(result['result_class'],'configuration');self.assertFalse(result['production_certification_eligible']);self.assertFalse(result['inventory_supported'])
    def test_illustrative_and_tls_only_content_claims_fail(self):
        for ref in ['foundation-baseline@0.1.0','transport-tls13-classical@0.1.0']:
            r=self.request();r['inventory']['components'][0]['profile_refs']=[ref];r['inventory']['flows'][0]['profile_refs']=[ref];r['claims']=[dict(self.claim(),profile_refs=[ref])]
            result=assess.evaluate(self.bind(r));self.assertEqual(result['verdict'],'fail');self.assertFalse(result['production_certification_eligible'])
    def test_pairwise_pq_cannot_certify_classical_group(self):
        r=self.messaging(self.request(),True);r['policy']='candidate';r['claims']=[dict(self.claim(),property_id='SP-PQ-CONFIDENTIALITY',profile_refs=['pairwise-pqxdh-triple-ratchet@0.1.0'])]
        result=assess.evaluate(self.bind(r));self.assertEqual(result['verdict'],'fail');self.assertTrue(result['configuration_valid'])
    def test_reference_or_absent_evidence_cannot_pass_implementation(self):
        r=self.messaging(self.request());r['policy']='production';r['claims']=[dict(self.claim(),profile_refs=['pairwise-pqxdh-triple-ratchet@0.1.0'],evidence_refs=['mock'])]
        result=assess.evaluate(self.bind(r),verified_evidence={'mock':{'provider_kind':'mock'}});self.assertEqual(result['verdict'],'indeterminate');self.assertEqual(result['claims'][0]['status'],'indeterminate')
    def test_wrong_lock_and_request_digest_fail(self):
        r=self.request();r['standard_lock']['release_version']='1.0.0';self.assertEqual(assess.evaluate(self.bind(r))['verdict'],'fail')
        r=self.request();r['assessment_id']='mutated';self.assertEqual(assess.evaluate(r)['verdict'],'fail')
    def test_applicant_cannot_inject_trusted_assessor_fields(self):
        r=self.request();r['trusted_observations']={'flows':r['inventory']['flows']};self.assertEqual(assess.evaluate(r)['verdict'],'fail')
    def candidate_case(self, policy, admission, provider_kind=None):
        import tempfile, shutil
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            shutil.copytree(ROOT,root,dirs_exist_ok=True,ignore=shutil.ignore_patterns('.git','__pycache__'))
            path=root/'profiles/catalog.json';catalog=json.loads(path.read_text())
            profile=copy.deepcopy(next(p for p in catalog['profiles'] if p['profile_id']=='pairwise-pqxdh-triple-ratchet'))
            profile['profile_id']='candidate-test';profile['status']='provisional';catalog['profiles'].append(profile);path.write_text(json.dumps(catalog))
            r=self.messaging(self.request());r['policy']=policy
            for x in [r['inventory']['components'][0],r['inventory']['flows'][0]]:
                x['profile_refs']=[p if p!='pairwise-pqxdh-triple-ratchet@0.1.0' else 'candidate-test@0.1.0' for p in x['profile_refs']]
            import release_candidate
            policy=assess.load(root/'registry/release-candidate.json')
            (root/policy['manifest_path']).write_text(json.dumps(release_candidate.build_manifest(root,policy)))
            r['standard_lock']=assess.standard_lock(root)
            if admission is not None:
                admission={**admission,'profile_ref':'candidate-test@0.1.0','profile_digest':assess.c.canonical_digest(profile)}
            evidence={}
            if provider_kind is not None and admission:
                evidence={'entry':{'provider_kind':provider_kind,'result':'pass','profile_digest':admission['profile_digest'],'promotion_record_digest':admission['record_digest'],'provenance_reference':'test-adapter-output'}}
            return assess.evaluate(self.bind(r),root=root,candidate_admissions={'candidate-test@0.1.0':admission} if admission else {},verified_evidence=evidence)

    def test_provisional_opt_in_without_candidate_record_fails(self):
        result=self.candidate_case('candidate',None)
        self.assertEqual(result['verdict'],'fail');self.assertIn('PR38 Candidate admission',' '.join(result['errors']))

    def test_candidate_record_with_incomplete_evidence_fails(self):
        admission={'lifecycle_state':'candidate','validation_errors':[],'gate_failures':[],'record_digest':'sha256:'+'a'*64,'record_reference':'fixture','entry_evidence_refs':['missing']}
        result=self.candidate_case('candidate',admission)
        self.assertEqual(result['verdict'],'fail');self.assertIn('PR38 Candidate admission',' '.join(result['errors']))

    def test_provisional_profile_cannot_use_production_policy(self):
        result=self.candidate_case('production',None)
        self.assertEqual(result['verdict'],'fail');self.assertFalse(result['production_certification_eligible'])

    def test_mock_candidate_entry_evidence_is_rejected(self):
        admission={'lifecycle_state':'candidate','validation_errors':[],'gate_failures':[],'record_digest':'sha256:'+'a'*64,'record_reference':'fixture','entry_evidence_refs':['entry']}
        self.assertEqual(self.candidate_case('candidate',admission,'mock')['verdict'],'fail')

    def test_validated_admission_does_not_finalize_development_basis(self):
        admission={'lifecycle_state':'candidate','validation_errors':[],'gate_failures':[],'record_digest':'sha256:'+'a'*64,'record_reference':'fixture','entry_evidence_refs':['entry']}
        result=self.candidate_case('candidate',admission,'real-provider')
        self.assertEqual(result['errors'],[])
        self.assertEqual(result['verdict'],'indeterminate')
        self.assertFalse(result['production_certification_eligible'])

    def test_bad_nested_types_fail_without_claims(self):
        for key,value in [('product_class',[]),('component_id',{}),('capabilities',[{}])]:
            r=self.request();r['inventory']['components'][0][key]=value
            self.assertEqual(assess.evaluate(self.bind(r))['verdict'],'fail')
