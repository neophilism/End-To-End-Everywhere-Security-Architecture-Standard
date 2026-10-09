"""Typed all-of / any-of constraints with exact profile or family leaves."""
from __future__ import annotations


def leaves(node):
    if not isinstance(node,dict):return []
    if 'family_id' in node or 'profile_ref' in node:return [node]
    return [leaf for key in ['all_of','any_of'] for child in node.get(key,[]) for leaf in leaves(child)]


def validate_node(node, families, profiles):
    if not isinstance(node,dict) or len(node)!=1:return ['dependency node must have exactly one typed operator']
    key,value=next(iter(node.items()))
    if key=='family_id':return [] if isinstance(value,str) and value in families else ['unknown dependency family']
    if key=='profile_ref':return [] if isinstance(value,str) and value in profiles else ['unknown exact dependency profile']
    if key not in {'all_of','any_of'} or not isinstance(value,list) or not value:return ['invalid dependency operator']
    return [error for child in value for error in validate_node(child,families,profiles)]


def validate_rules(rules, families, profiles):
    if not isinstance(rules,list):return ['dependency rules must be an array']
    errors=[];ids=set()
    for rule in rules:
        if not isinstance(rule,dict) or set(rule)!={'requirement_id','scope','requires'}:errors.append('dependency rule fields mismatch');continue
        rid=rule['requirement_id']
        if not isinstance(rid,str) or not rid or rid in ids:errors.append('duplicate/invalid dependency requirement id')
        else:ids.add(rid)
        if rule['scope'] not in {'same-component','same-flow'}:errors.append('unsupported dependency scope')
        errors.extend(validate_node(rule['requires'],families,profiles))
    return errors


def satisfied(node, refs, families):
    if 'family_id' in node:return node['family_id'] in families
    if 'profile_ref' in node:return node['profile_ref'] in refs
    if 'all_of' in node:return all(satisfied(x,refs,families) for x in node['all_of'])
    if 'any_of' in node:return any(satisfied(x,refs,families) for x in node['any_of'])
    return False


def configuration_errors(profiles, effective):
    families={profiles[ref]['family_id'] for ref in effective if ref in profiles}
    return [ref+': '+rule['requirement_id']+' unsatisfied '+rule['scope']+' dependency'
            for ref in sorted(effective) for rule in profiles[ref].get('dependency_rules',[])
            if not satisfied(rule['requires'],effective,families)]


def family_universe(profiles, active_families):
    found=set(active_families)
    while True:
        added=set()
        for profile in profiles.values():
            if profile['family_id'] not in found:continue
            for rule in profile.get('dependency_rules',[]):
                for leaf in leaves(rule['requires']):
                    if 'family_id' in leaf:added.add(leaf['family_id'])
                    elif leaf['profile_ref'] in profiles:added.add(profiles[leaf['profile_ref']]['family_id'])
        if added.issubset(found):return found
        found.update(added)


def inventory_errors(manifest, catalog, required_families):
    profiles={x['profile_id']+'@'+x['profile_version']:x for x in catalog['profiles']}
    components={x['component_id']:x for x in manifest['components']};flows={x['flow_id']:x for x in manifest['flows']}
    errors=[]
    for cid,component in components.items():
        selected=set(component['profile_refs']);familyset={profiles[x]['family_id'] for x in selected if x in profiles}
        if set(required_families.get(cid,[]))-familyset:errors.append(cid+': missing class/capability mandatory families')
        for fid in component['inventory_flow_ids']:
            flow=flows[fid];flowrefs=set(flow['profile_refs']);hostrefs=set()
            for obligation in component['host_obligations']:
                fields={'flow_id','host_component_id','host_flow_id','requirement_id','integration_evidence_ref'}
                if not isinstance(obligation,dict) or set(obligation)!=fields:errors.append(cid+': invalid host obligation');continue
                if obligation['flow_id']!=fid:continue
                host=flows.get(obligation['host_flow_id'])
                if host is None or host['component_id']!=obligation['host_component_id'] or obligation['integration_evidence_ref'] not in manifest['evidence_refs']:errors.append(fid+': unbound host integration');continue
                if set(host['recipient_ids'])!=set(flow['recipient_ids']) or set(host['key_authority_ids'])!=set(flow['key_authority_ids']):errors.append(fid+': unrelated host recipient/key boundary');continue
                hostrefs.update(host['profile_refs'])
            for ref in sorted(flowrefs):
                if ref not in profiles:continue
                for rule in profiles[ref].get('dependency_rules',[]):
                    available=selected if rule['scope']=='same-component' else flowrefs
                    # A reusable library may discharge only its named obligation.
                    named=any(isinstance(x,dict) and x.get('flow_id')==fid and x.get('requirement_id')==rule['requirement_id'] for x in component['host_obligations'])
                    if named:available=available|hostrefs
                    fam={profiles[x]['family_id'] for x in available if x in profiles}
                    if not satisfied(rule['requires'],available,fam):errors.append(fid+': '+rule['requirement_id']+' unsatisfied scoped dependency')
    return sorted(set(errors))
