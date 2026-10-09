"""Active assessment: declaration, implementation evidence and release approval stay separate."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from datetime import datetime,timezone
import canonical_serialization as c
import component_inventory
import profile_dependencies
import profile_engine
import digest_contracts
import release_candidate

ROOT=Path(__file__).resolve().parents[1]
CONTENT={'SP-CONFIDENTIALITY','SP-FORWARD-SECRECY','SP-POST-COMPROMISE-SECURITY','SP-PQ-CONFIDENTIALITY'}
CARRIERS={'direct-message':'pairwise-e2ee','group-message':'group-e2ee','attachment':'attachment-encryption','media':'real-time-media','backup':'backup-recovery'}

def load(path):return c.parse_json(path.read_text())

def parse_time(text):return datetime.strptime(text,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)

def standard_lock(root=ROOT):
    policy=load(root/'registry/release-candidate.json');manifest=load(root/policy['manifest_path'])
    if manifest!=release_candidate.build_manifest(root,policy):raise ValueError('standard manifest differs from evaluated source tree')
    return {'release_version':policy['release_version'],'tree_digest':manifest['tree_digest'],'profile_catalog_digest':c.canonical_digest(load(root/'profiles/catalog.json')),'serialization_scheme':c.SCHEME,'digest_scheme':digest_contracts.DIGEST_SCHEME}

def request_digest(request):return digest_contracts.digest('scoped-assessment-request-record@1.0.0',request)

def candidate_admission_complete(admission, ref, profile, verified_evidence):
    if not isinstance(admission,dict):return False
    profile_digest=c.canonical_digest(profile)
    if admission.get('profile_ref')!=ref or admission.get('profile_digest')!=profile_digest or admission.get('lifecycle_state')!='candidate':return False
    if admission.get('validation_errors')!=[] or admission.get('gate_failures')!=[]:return False
    if not isinstance(admission.get('record_digest'),str) or not component_inventory.DIGEST.fullmatch(admission['record_digest']):return False
    if not isinstance(admission.get('record_reference'),str) or not admission['record_reference']:return False
    refs=admission.get('entry_evidence_refs')
    if not isinstance(refs,list) or not refs or not all(isinstance(x,str) for x in refs):return False
    for evidence_ref in refs:
        evidence=verified_evidence.get(evidence_ref)
        if not isinstance(evidence,dict) or evidence.get('provider_kind')!='real-provider' or evidence.get('result')!='pass':return False
        if evidence.get('profile_digest')!=profile_digest or evidence.get('promotion_record_digest')!=admission['record_digest'] or not evidence.get('provenance_reference'):return False
    return True

def evaluate(request, *, root=ROOT, trusted_observations=None, verified_evidence=None, candidate_admissions=None):
    """Evidence/admissions are validated outputs of trusted assessor adapters.

    They are deliberately not applicant-controlled request fields. Adapters must verify
    provenance and signatures using their trust policy; these reference tests do not
    establish that an injected test verifier is a real runtime or independent reviewer.
    """
    errors=[];limitations=[];claims=[]
    verified_evidence=verified_evidence or {};candidate_admissions=candidate_admissions or {}
    fields={'schema_version','assessment_id','evaluated_at','policy','standard_lock','inventory','claims','request_digest'}
    try:
        if not isinstance(request,dict) or set(request)!=fields:raise ValueError('assessment request fields mismatch')
        if request['schema_version']!='0.2':raise ValueError('assessment schema version must be 0.2')
        if not isinstance(request['assessment_id'],str) or not request['assessment_id']:raise ValueError('assessment id must be nonempty')
        now=parse_time(request['evaluated_at'])
        if request['policy'] not in {'configuration','candidate','production'}:raise ValueError('unknown assessment policy')
        if request['request_digest']!=request_digest(request):raise ValueError('assessment request digest mismatch')
        if request['standard_lock']!=standard_lock(root):raise ValueError('assessment standard lock mismatch')
        if not isinstance(request['claims'],list):raise ValueError('claims must be an array')
    except (ValueError,KeyError,TypeError) as exc:
        return {'schema_version':'0.2','verdict':'fail','result_class':'configuration','production_certification_eligible':False,'errors':[str(exc)],'limitations':[],'claims':[]}
    catalog=load(root/'profiles/catalog.json');profiles={profile_engine.profile_ref(x):x for x in catalog['profiles']}
    inventory=request['inventory'];iv=component_inventory.validate_inventory(inventory,catalog=catalog,trusted_observations=trusted_observations)
    errors.extend(iv['errors']);limitations.extend(iv['limitations'])
    resolutions=[]
    if iv['valid']:
        for component in inventory['components']:
            config={'schema_version':'0.1','configuration_id':component['component_id'],'standard_version':catalog['standard_version'],'selected_profiles':component['profile_refs'],'accepted_nondefault_statuses':['provisional'] if request['policy']=='candidate' else []}
            resolution=profile_engine.resolve_configuration(catalog,config);errors.extend(component['component_id']+': '+x for x in resolution.errors)
            resolutions.append({'component_id':component['component_id'],'configuration_valid':resolution.valid,'effective_profile_refs':resolution.effective_profiles})
            for ref in resolution.effective_profiles:
                profile=profiles[ref]
                if profile['status']=='provisional':
                    admission=candidate_admissions.get(ref)
                    complete=candidate_admission_complete(admission,ref,profile,verified_evidence)
                    if request['policy']!='candidate' or not complete:errors.append(ref+': exact PR38 Candidate admission and entry evidence required')
                elif profile['status'] not in {'recommended','allowed'}:errors.append(ref+': profile not eligible for active policy')
        errors.extend(profile_dependencies.inventory_errors(inventory,catalog,iv['required_families']))
    configuration_valid=not errors
    declared_flows=inventory.get('flows',[]) if isinstance(inventory,dict) else []
    flowmap={x['flow_id']:x for x in declared_flows if isinstance(x,dict) and isinstance(x.get('flow_id'),str)} if isinstance(declared_flows,list) else {}
    seen=set()
    for claim in request['claims']:
        claimfields={'claim_id','claim_domain','flow_id','property_id','threat_ids','profile_refs','evidence_refs'}
        status='pass';reasons=[]
        if not isinstance(claim,dict) or set(claim)!=claimfields:
            errors.append('claim fields mismatch');continue
        if not all(isinstance(claim[k],str) and claim[k] for k in ['claim_id','flow_id','property_id']):
            errors.append('claim identifiers must be nonempty strings');continue
        if not isinstance(claim['claim_domain'],str) or claim['claim_domain'] not in {'protected-content','component','process'}:
            errors.append('unknown claim domain');continue
        if not isinstance(claim['claim_id'],str) or claim['claim_id'] in seen:errors.append('duplicate/invalid claim id');continue
        seen.add(claim['claim_id']);flow=flowmap.get(claim['flow_id'])
        for key in ['threat_ids','profile_refs','evidence_refs']:
            if not isinstance(claim[key],list) or not all(isinstance(x,str) for x in claim[key]):reasons.append('invalid claim '+key)
        if flow is None:reasons.append('claim has no declared flow')
        elif not reasons:
            if set(claim['profile_refs'])-set(flow['profile_refs']):reasons.append('claim profiles not bound to flow')
            carrier=CARRIERS.get(flow['operation'])
            providers=[profiles[x] for x in claim['profile_refs'] if x in profiles and claim['property_id'] in profiles[x]['security_properties'] and (claim['claim_domain']!='protected-content' or profiles[x]['family_id']==carrier) and (claim['claim_domain']!='process' or profiles[x]['family_id'] in {'secure-development','software-supply-chain','security-verification','formal-verification'})]
            if not providers:reasons.append('property lacks an operation-specific architecture provider')
            if claim['claim_domain']=='protected-content' and flow['data_class']!='protected':reasons.append('protected-content claim on public/disclosed flow')
            if not claim['threat_ids']:reasons.append('claim threat scope missing')
            if request['policy']=='configuration':reasons.append('configuration-only policy cannot publish implementation claims')
        if reasons:status='fail';errors.extend(claim['claim_id']+': '+x for x in reasons)
        else:
            if not iv['inventory_supported']:status='indeterminate';reasons.append('inventory assessment evidence pending')
            if not claim['evidence_refs']:status='indeterminate';reasons.append('runtime evidence missing')
            for ref in claim['evidence_refs']:
                e=verified_evidence.get(ref)
                try:
                    bound=isinstance(e,dict) and e['source_digest']==inventory['source_digest'] and e['artifact_digest']==inventory['artifact_digest'] and e['flow_id']==claim['flow_id'] and e['claim_domain']==claim['claim_domain'] and claim['property_id'] in e['property_ids'] and set(claim['profile_refs']).issubset(e['profile_refs']) and set(claim['threat_ids']).issubset(e['threat_ids']) and e['provider_kind']=='real-provider' and e['result']=='pass' and parse_time(e['verified_at'])<=now<=parse_time(e['valid_until']) and e['content_digest'] and e['provenance_reference']
                except (KeyError,TypeError,ValueError):bound=False
                if not bound:status='indeterminate';reasons.append(ref+': missing, stale, mock or mismatched evidence')
        claims.append({**claim,'status':status,'reasons':reasons})
    result_class='configuration' if request['policy']=='configuration' else 'protected-content' if any(x.get('claim_domain')=='protected-content' for x in request['claims'] if isinstance(x,dict)) else 'process' if iv['valid'] and all(x['product_class']=='development-process-only' for x in inventory['components']) else 'component'
    policy=load(root/'registry/release-candidate.json')
    if request['policy']!='configuration' and policy.get('development_state')!='frozen-candidate':limitations.append('Standard basis is development; frozen Candidate and independent review gates remain pending.')
    if request['policy']!='configuration' and not claims:limitations.append('No supported implementation claims were supplied.')
    verdict='fail' if errors else 'indeterminate' if any(x['status']!='pass' for x in claims) or (request['policy']!='configuration' and (not iv['inventory_supported'] or policy.get('development_state')!='frozen-candidate' or not claims)) else 'pass'
    result={'schema_version':'0.2','assessment_id':request['assessment_id'],'request_digest':request['request_digest'],'standard_lock':request['standard_lock'],'verdict':verdict,'result_class':result_class,'configuration_valid':configuration_valid,'inventory_supported':iv['inventory_supported'],'components':resolutions,'claims':claims,'production_certification_eligible':False,'independent_review_state':'pending','deployment_state':'not-assessed','errors':sorted(set(errors)),'limitations':limitations,'result_digest':''}
    result['result_digest']=digest_contracts.digest('scoped-assessment-result-record@1.0.0',result)
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('request',type=Path);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:result=evaluate(load(args.request),root=args.root)
    except (OSError,ValueError,TypeError,KeyError) as exc:print(json.dumps({'verdict':'fail','errors':[str(exc)]}));return 3
    print(json.dumps(result,indent=2));return {'pass':0,'fail':1,'indeterminate':2}[result['verdict']]
if __name__=='__main__':raise SystemExit(main())
