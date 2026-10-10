"""Exact, domain-separated, versioned digest/signature input contracts."""
from __future__ import annotations
import hashlib
from pathlib import Path
import canonical_serialization as canonical

DIGEST_SCHEME = 'e2eesa-sha256-domain-v1'
ROOT = Path(__file__).resolve().parents[1]


def registry(root=ROOT):
    return canonical.parse_json((root/'registry/digest-contracts.json').read_text())


def input_bytes(contract_id, payload, *, purpose='digest', signature_algorithm=None, profile_ref=None, contracts=None):
    entries = (contracts or registry())['contracts']
    match = next((x for x in entries if x['contract_id']==contract_id),None)
    if match is None: raise ValueError('unknown digest contract')
    if not isinstance(payload,dict): raise ValueError('contract payload must be an object')
    fields=set(payload); allowed=set(match['included_fields'])|set(match['excluded_fields'])
    if fields-allowed: raise ValueError('unknown contract fields: '+','.join(sorted(fields-allowed)))
    if set(match['required_fields'])-fields: raise ValueError('missing contract fields')
    if payload.get('schema_version')!=match['payload_schema_version']: raise ValueError('payload schema version mismatch')
    if purpose not in {'digest','signature'}: raise ValueError('unknown input purpose')
    if purpose=='signature':
        if not signature_algorithm or not profile_ref: raise ValueError('signature algorithm and exact profile required')
        if '@' not in profile_ref: raise ValueError('signature profile must be version-pinned')
    elif signature_algorithm is not None or profile_ref is not None: raise ValueError('signature metadata in digest context')
    header={'contract_id':contract_id,'contract_version':'1.0.0','serialization_scheme':canonical.SCHEME,
            'digest_scheme':DIGEST_SCHEME,'purpose':purpose,'signature_algorithm':signature_algorithm,'profile_ref':profile_ref}
    data={k:payload[k] for k in match['included_fields'] if k in payload}
    return b'E2EESA\x00'+canonical.canonical_bytes(header)+b'\x00'+canonical.canonical_bytes(data)


def digest(contract_id,payload,**kwargs):
    return 'sha256:'+hashlib.sha256(input_bytes(contract_id,payload,**kwargs)).hexdigest()


def verify_digest(contract_id,payload,expected,**kwargs):
    return digest(contract_id,payload,**kwargs)==expected


def legacy_digest(payload,*,scheme):
    return 'sha256:'+hashlib.sha256(canonical.legacy_bytes(payload,scheme=scheme)).hexdigest()
