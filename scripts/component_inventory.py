"""Evidence-backed, component/flow applicability for active assessments."""
from __future__ import annotations
import re
from pathlib import Path
import canonical_serialization as canonical
import profile_engine

ROOT=Path(__file__).resolve().parents[1]
DIGEST=re.compile(r'^sha256:[0-9a-f]{64}$')
OPERATIONS={'direct-message','group-message','attachment','media','backup','local-storage','public-data','business-processing'}
PROTECTED_OPERATIONS={'direct-message','group-message','attachment','media','backup','local-storage'}


def product_classes(root=ROOT):
    return canonical.parse_json((root/'registry/product-classes.json').read_text())


def validate_inventory(manifest, *, catalog, trusted_observations=None, classes=None):
    """Trusted observations come from the assessor adapter, never from applicant JSON.

    Passing declaration validation alone establishes configuration consistency only.
    No scanner, observer identity or completeness proof is invented by this function.
    """
    errors=[]; limitations=[]
    try: canonical.canonical_bytes(manifest)
    except (ValueError,TypeError) as exc:return {'valid':False,'inventory_supported':False,'errors':[str(exc)],'limitations':[],'required_families':{}}
    required={'schema_version','product_id','source_digest','artifact_digest','components','flows','evidence_refs'}
    if not isinstance(manifest,dict) or set(manifest)!=required:
        return {'valid':False,'inventory_supported':False,'errors':['inventory fields mismatch'],'limitations':[],'required_families':{}}
    if manifest['schema_version']!='0.2':errors.append('inventory schema version must be 0.2')
    for k in ['source_digest','artifact_digest']:
        if not isinstance(manifest[k],str) or not DIGEST.fullmatch(manifest[k]) or manifest[k]=='sha256:'+'0'*64:errors.append('invalid '+k)
    classes=classes or product_classes();classmap={x['class_id']:x for x in classes['classes']}
    if not isinstance(manifest['components'],list) or not manifest['components']:errors.append('components must be nonempty')
    if not isinstance(manifest['flows'],list):errors.append('flows must be an array')
    if not isinstance(manifest['evidence_refs'],list) or not all(isinstance(x,str) for x in manifest['evidence_refs']):errors.append('evidence_refs must be strings')
    if errors:return {'valid':False,'inventory_supported':False,'errors':errors,'limitations':[],'required_families':{}}
    components={};flows={};requirements={}
    for component in manifest['components']:
        fields={'component_id','product_class','capabilities','profile_refs','inventory_flow_ids','host_obligations'}
        if not isinstance(component,dict) or set(component)!=fields:errors.append('component fields mismatch');continue
        cid=component['component_id']
        if not isinstance(cid,str) or not cid or cid in components:errors.append('duplicate/invalid component id');continue
        rule=classmap.get(component['product_class'])
        if rule is None:errors.append(cid+': unknown product class');continue
        for key in ['capabilities','profile_refs','inventory_flow_ids']:
            arr=component[key]
            if not isinstance(arr,list) or not all(isinstance(x,str) for x in arr) or len(arr)!=len(set(arr)):errors.append(cid+': invalid '+key)
        if not isinstance(component['host_obligations'],list):errors.append(cid+': host obligations must be an array')
        if errors:continue
        unknown=set(component['capabilities'])-set(classes['capabilities'])
        if unknown:errors.append(cid+': unknown capability')
        requirements[cid]=set(rule['mandatory_families'])
        for capability in component['capabilities']:requirements[cid].update(rule['capability_families'].get(capability,[]))
        components[cid]=component
    profiles={profile_engine.profile_ref(x):x for x in catalog['profiles']}
    for flow in manifest['flows']:
        fields={'flow_id','component_id','operation','data_class','recipient_ids','key_authority_ids','profile_refs','networked'}
        if not isinstance(flow,dict) or set(flow)!=fields:errors.append('flow fields mismatch');continue
        fid=flow['flow_id'];cid=flow['component_id']
        if not isinstance(fid,str) or not fid or fid in flows or cid not in components:errors.append('invalid flow/component binding');continue
        if flow['operation'] not in OPERATIONS or flow['data_class'] not in {'protected','public','intentionally-disclosed'}:errors.append(fid+': unsupported flow classification')
        for key in ['recipient_ids','key_authority_ids','profile_refs']:
            arr=flow[key]
            if not isinstance(arr,list) or not all(isinstance(x,str) and x for x in arr) or len(arr)!=len(set(arr)):errors.append(fid+': invalid '+key)
        if not isinstance(flow['networked'],bool):errors.append(fid+': networked must be boolean')
        if errors:continue
        component=components[cid];rule=classmap[component['product_class']]
        if fid not in component['inventory_flow_ids']:errors.append(fid+': absent from owning inventory')
        if set(flow['profile_refs'])-set(component['profile_refs']):errors.append(fid+': profiles not bound to component')
        if flow['data_class']=='protected':
            if not rule['allows_protected_content']:errors.append(cid+': class cannot handle protected content')
            if not flow['recipient_ids'] or not flow['key_authority_ids']:errors.append(fid+': protected recipient/key authorities required')
            if rule['endpoint']:requirements[cid].update(['identity-architecture','secret-storage','client-security'])
        if flow['networked']:requirements[cid].add('transport-security')
        flows[fid]=flow
    for cid,component in components.items():
        if set(component['inventory_flow_ids'])!={f for f,x in flows.items() if x['component_id']==cid}:errors.append(cid+': inventory flow set mismatch')
        if any(ref not in profiles for ref in component['profile_refs']):errors.append(cid+': unknown/illustrative profile')
    supported=False
    if trusted_observations is None:
        limitations.append('Inventory is declared only; trusted source/build observations and completeness assessment are pending.')
    else:
        if trusted_observations.get('source_digest')!=manifest['source_digest'] or trusted_observations.get('artifact_digest')!=manifest['artifact_digest']:errors.append('inventory evidence source/build mismatch')
        observed=trusted_observations.get('flows')
        if not isinstance(observed,list):errors.append('trusted observed flows missing')
        else:
            observedmap={x.get('flow_id'):x for x in observed if isinstance(x,dict)}
            if len(observedmap)!=len(observed) or set(observedmap)!=set(flows):errors.append('omitted/duplicate/contradicted observed flow')
            for fid,flow in flows.items():
                if observedmap.get(fid)!=flow:errors.append(fid+': observed flow contradicts inventory')
        if not trusted_observations.get('completeness_evidence_ref') or trusted_observations.get('completeness_evidence_ref') not in manifest['evidence_refs']:errors.append('inventory completeness evidence not bound')
        supported=not errors
    return {'valid':not errors,'inventory_supported':supported,'errors':sorted(set(errors)),'limitations':limitations,'required_families':{k:sorted(v) for k,v in requirements.items()}}
