"""Reproduce three core demonstrations against preserved rc.1 and the active tooling."""
from __future__ import annotations
import json,sys,tempfile,tarfile,subprocess,hashlib
from pathlib import Path
import release_candidate
ROOT=Path(__file__).resolve().parents[1]
CHILD=r'''
import sys,json
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root/'scripts'))
import compatibility_solver as solver, e2eesa_conformance as cli, conformance_engine as engine, formal_verification as formal
load=lambda p:json.loads((root/p).read_text())
inputs=cli.load_standard_inputs(root)
plan=load('fixtures/conformance/valid/production-assurance-plan.json');bundle=load('fixtures/conformance/valid/production-certification-bundle.json');bundle['assurance_plan_digest']=formal.canonical_digest(plan);bundle['configuration_digest']=formal.canonical_digest(plan['configuration']);req=cli.bind_request(load('fixtures/conformance/valid/production-request.json'),plan,bundle,inputs)
result=engine.evaluate_conformance(req,plan,bundle,**inputs)
loadargs={'catalog':load('profiles/catalog.json'),'solver_registry':load('registry/compatibility-solver.json'),'property_registry':load('registry/security-properties.json'),'promotion_registry':load('registry/research-promotion.json'),'conformance_registry':load('registry/conformance.json')}
cases=[('pairwise-pqxdh-triple-ratchet',['identity-architecture','key-verification','key-transparency','secret-storage','client-security','server-trust','transport-security']),('group-sender-key-aead',['pairwise-e2ee','identity-architecture']),('group-pairwise-fanout',['pairwise-e2ee']),('backup-hardware-assisted',['identity-architecture']),('attachment-chunked-aead',['pairwise-e2ee','group-e2ee']),('kt-third-party-auditing',['key-verification','identity-architecture']),('media-sframe-sender-keys',['pairwise-e2ee','group-e2ee'])]
out=[]
for profile,forbidden in cases:
 r={'schema_version':'0.1','request_id':'audit-case','standard_version':loadargs['catalog']['standard_version'],'mode':'production','required_family_ids':[],'forbidden_family_ids':forbidden,'desired_property_ids':[],'pinned_profile_refs':[profile+'@0.1.0'],'excluded_profile_refs':[],'max_solutions':5,'enforce_required_promotions':True,'request_digest':''};r['request_digest']=solver.compute_request_digest(r);s=solver.solve(r,**loadargs);out.append({'profile':profile+'@0.1.0','forbidden_families':forbidden,'status':s['status'],'solution_count':s['total_solution_count'],'exhaustive':s['search_exhaustive']})
x={'claim':'café','count':1}
print(json.dumps({'legacy_configuration':{'verdict':result['verdict'],'production_certification_eligible':result['production_certification_eligible'],'claim_scope':result['claim_scope']},'dependency_cases':out,'unicode_digest_mismatch':formal.canonical_digest(x)!=engine.canonical_digest(x)},ensure_ascii=False))
'''

def reproduce():
    policy=release_candidate.load_json(ROOT,'registry/release-candidate.json')
    errors=release_candidate.validate_historical_candidates(ROOT,policy)
    if errors:raise ValueError('; '.join(errors))
    anchor=release_candidate.load_json(ROOT,policy['historical_candidates'][0])
    with tempfile.TemporaryDirectory() as directory:
        base=Path(directory)
        with tarfile.open(ROOT/anchor['archive_path']) as archive:
            for entry in archive.getmembers():
                path=Path(entry.name)
                if path.is_absolute() or '..' in path.parts or not entry.isfile():raise ValueError('unsafe historical path')
                dest=base/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(archive.extractfile(entry).read())
        old=json.loads(subprocess.check_output([sys.executable,'-c',CHILD,str(base)],text=True))
    current=json.loads(subprocess.check_output([sys.executable,'-c',CHILD,str(ROOT)],text=True))
    verified=old['legacy_configuration']['production_certification_eligible'] and not current['legacy_configuration']['production_certification_eligible'] and current['legacy_configuration']['claim_scope']=='configuration-diagnostic' and old['unicode_digest_mismatch'] and not current['unicode_digest_mismatch'] and all(x['status']=='solutions' and x['solution_count']==2 for x in old['dependency_cases']) and all(x['status']=='unsatisfiable' and x['exhaustive'] for x in current['dependency_cases'])
    return {'schema_version':'0.1','evidence_origin':'locally-reproduced; independent expert review remains pending','audited_commit':anchor['source_commit'],'historical_tree_digest':anchor['tree_digest'],'baseline':old,'corrected':current,'regression_verified':verified,'tested_source_file_digests':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ['scripts/formal_verification.py','scripts/conformance_engine.py','scripts/compatibility_solver.py','scripts/profile_engine.py','scripts/profile_dependencies.py','scripts/canonical_serialization.py']}}
if __name__=='__main__':
    result=reproduce();print(json.dumps(result,indent=2));raise SystemExit(0 if result['regression_verified'] else 1)
