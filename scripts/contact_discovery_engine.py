#!/usr/bin/env python3
"""Semantic validator for E2EESA contact-discovery profiles."""

from __future__ import annotations
import argparse, json, re
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PROFILE_MODES = {
    "contact-exact-handle@0.1.0":"exact-handle",
    "contact-voprf-directory@0.1.0":"voprf",
    "contact-attested-private-set@0.1.0":"confidential-compute",
}

def load_json(path: Path) -> dict[str, Any]:
    value=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value

def _profiles(catalog):
    return {f"{p.get('profile_id')}@{p.get('profile_version')}":p for p in catalog.get("profiles",[]) if isinstance(p,dict)}

def validate_registry(registry:dict[str,Any],source="contact discovery registry")->list[str]:
    errors=[]
    required={"schema_version","registry_version","standard_version","mechanisms","voprf_suites"}
    if set(registry)!=required:
        missing=sorted(required-registry.keys()); extra=sorted(set(registry)-required)
        if missing: errors.append(f"{source}: missing fields: {', '.join(missing)}")
        if extra: errors.append(f"{source}: unknown fields: {', '.join(extra)}")
    if registry.get("schema_version")!="0.1": errors.append(f"{source}: schema_version must be 0.1")
    mechanisms=registry.get("mechanisms",[])
    ids=[m.get("id") for m in mechanisms if isinstance(m,dict)]
    for required_id in ("CONTACT-EXACT-HANDLE-1","CONTACT-VOPRF-RFC9497","CONTACT-ATTESTED-PRIVATE-SET-1"):
        if required_id not in ids: errors.append(f"{source}: missing required mechanism {required_id}")
    if len(ids)!=len(set(ids)): errors.append(f"{source}: duplicate mechanism ids")
    suites=registry.get("voprf_suites",[])
    suite={s.get("id"):s for s in suites if isinstance(s,dict)}.get("VOPRF-RISTRETTO255-SHA512")
    if not suite:
        errors.append(f"{source}: missing VOPRF-RISTRETTO255-SHA512")
    else:
        if suite.get("mode")!="VOPRF" or suite.get("mode_value")!="0x01":
            errors.append(f"{source}: RFC 9497 suite must use VOPRF mode 0x01")
        if suite.get("ciphersuite_identifier")!="ristretto255-SHA512":
            errors.append(f"{source}: unexpected RFC 9497 ciphersuite identifier")
    return sorted(set(errors))

def validate_policy(policy,registry,catalog,source="contact discovery policy")->list[str]:
    errors=[]
    profile_ref=policy.get("profile_ref"); mode=PROFILE_MODES.get(profile_ref)
    if policy.get("schema_version")!="0.1": errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(policy.get("policy_id"),str) or not ID_RE.fullmatch(policy.get("policy_id","")):
        errors.append(f"{source}: invalid policy_id")
    if mode is None: errors.append(f"{source}: unsupported profile_ref")
    else:
        p=_profiles(catalog).get(profile_ref)
        if not p or p.get("family_id")!="contact-discovery":
            errors.append(f"{source}: profile_ref is not a registered contact-discovery profile")
    if policy.get("registry_version")!=registry.get("registry_version"):
        errors.append(f"{source}: registry_version does not match registry")
    for field in ("discoverability_opt_in_required","return_only_matches"):
        if policy.get(field) is not True: errors.append(f"{source}: {field} must be true")
    for field in ("raw_address_book_upload_allowed","raw_identifier_hash_upload_allowed","host_plaintext_access_allowed","query_persistence_allowed"):
        if policy.get(field) is not False: errors.append(f"{source}: {field} must be false")
    for field in ("max_batch_size","max_queries_per_account_per_day"):
        v=policy.get(field)
        if not isinstance(v,int) or isinstance(v,bool) or v<1: errors.append(f"{source}: {field} must be positive")
    if not isinstance(policy.get("normalization_profile_id"),str):
        errors.append(f"{source}: normalization_profile_id must be versioned")

    if mode=="exact-handle":
        if policy.get("exact_query_required") is not True: errors.append(f"{source}: exact-handle profile requires exact query")
        if policy.get("max_batch_size")!=1: errors.append(f"{source}: exact-handle profile max_batch_size must be 1")
        for field in ("voprf_required","directory_epoch_required","directory_snapshot_authentication_required","confidential_compute_required","attestation_required","measurement_allowlist_required","encrypted_channel_to_trusted_boundary_required","memory_zeroization_required"):
            if policy.get(field) is not False: errors.append(f"{source}: exact-handle profile must set {field}=false")
        for field in ("voprf_suite_id","voprf_public_key_id"):
            if policy.get(field) is not None: errors.append(f"{source}: exact-handle profile must set {field} to null")

    if mode=="voprf":
        if policy.get("exact_query_required") is not False: errors.append(f"{source}: VOPRF profile must allow batched contact discovery")
        for field in ("voprf_required","directory_epoch_required","directory_snapshot_authentication_required"):
            if policy.get(field) is not True: errors.append(f"{source}: VOPRF profile requires {field}=true")
        if policy.get("voprf_suite_id")!="VOPRF-RISTRETTO255-SHA512":
            errors.append(f"{source}: VOPRF profile must use registered RFC 9497 suite")
        if not isinstance(policy.get("voprf_public_key_id"),str): errors.append(f"{source}: VOPRF public key id required")
        for field in ("confidential_compute_required","attestation_required","measurement_allowlist_required","encrypted_channel_to_trusted_boundary_required","memory_zeroization_required"):
            if policy.get(field) is not False: errors.append(f"{source}: VOPRF profile must set {field}=false")

    if mode=="confidential-compute":
        if policy.get("exact_query_required") is not False: errors.append(f"{source}: confidential-compute profile must allow batched discovery")
        for field in ("confidential_compute_required","attestation_required","measurement_allowlist_required","encrypted_channel_to_trusted_boundary_required","memory_zeroization_required"):
            if policy.get(field) is not True: errors.append(f"{source}: confidential-compute profile requires {field}=true")
        for field in ("voprf_required","directory_epoch_required","directory_snapshot_authentication_required"):
            if policy.get(field) is not False: errors.append(f"{source}: confidential-compute profile must set {field}=false")
        for field in ("voprf_suite_id","voprf_public_key_id"):
            if policy.get(field) is not None: errors.append(f"{source}: confidential-compute profile must set {field} to null")
    return sorted(set(errors))

def validate_evidence(policy,evidence,registry,catalog,source="contact discovery evidence")->list[str]:
    errors=validate_policy(policy,registry,catalog)
    if errors: return errors
    mode=PROFILE_MODES[policy["profile_ref"]]
    if evidence.get("schema_version")!="0.1": errors.append(f"{source}: schema_version must be 0.1")
    if evidence.get("profile_ref")!=policy.get("profile_ref"): errors.append(f"{source}: profile_ref does not match policy")
    if not isinstance(evidence.get("event_id"),str) or not ID_RE.fullmatch(evidence.get("event_id","")): errors.append(f"{source}: invalid event_id")
    q=evidence.get("query_count"); n=evidence.get("normalized_identifier_count")
    if not isinstance(q,int) or q<1 or q>policy["max_batch_size"]: errors.append(f"{source}: query_count exceeds policy")
    if not isinstance(n,int) or n<1 or n!=q: errors.append(f"{source}: normalized_identifier_count must equal query_count")
    if evidence.get("discoverability_policy_enforced") is not True: errors.append(f"{source}: discoverability opt-in policy must be enforced")
    if evidence.get("raw_address_book_sent_to_service") is not False: errors.append(f"{source}: raw address book upload is prohibited")
    if evidence.get("raw_identifier_hashes_sent_to_service") is not False: errors.append(f"{source}: raw or unkeyed identifier hash upload is prohibited")
    if evidence.get("only_matching_registered_entries_returned") is not True: errors.append(f"{source}: discovery may return only matching discoverable entries")
    if evidence.get("query_persisted_after_completion") is not False: errors.append(f"{source}: query identifiers must not persist after completion")
    rc=evidence.get("result_count")
    if not isinstance(rc,int) or rc<0 or (isinstance(q,int) and rc>q): errors.append(f"{source}: invalid result_count")

    if mode=="exact-handle":
        if evidence.get("exact_user_supplied_query") is not True: errors.append(f"{source}: exact-handle query must be explicitly user supplied")
        if evidence.get("service_observed_query_identifiers") is not True: errors.append(f"{source}: exact-handle evidence must not falsely claim hidden explicit query")
        for field in ("voprf_blinded_inputs_verified","voprf_proof_verified","directory_snapshot_authenticated","online_query_budget_enforced","confidential_compute_used","attestation_verified","measurement_authorized","encrypted_channel_terminated_inside_trusted_boundary","query_memory_zeroized"):
            if evidence.get(field) is not False: errors.append(f"{source}: exact-handle evidence must set {field}=false")
        if evidence.get("voprf_public_key_id") is not None or evidence.get("directory_epoch") is not None or evidence.get("directory_snapshot_version") is not None:
            errors.append(f"{source}: exact-handle evidence must not claim VOPRF directory state")

    if mode=="voprf":
        if evidence.get("service_observed_query_identifiers") is not False: errors.append(f"{source}: VOPRF server must not learn query identifiers")
        if evidence.get("service_observed_query_outputs") is not False: errors.append(f"{source}: VOPRF server must not learn finalized query outputs")
        if evidence.get("voprf_blinded_inputs_verified") is not True: errors.append(f"{source}: blinded VOPRF inputs required")
        if evidence.get("voprf_proof_verified") is not True: errors.append(f"{source}: VOPRF proof must verify")
        if evidence.get("voprf_public_key_id")!=policy.get("voprf_public_key_id"): errors.append(f"{source}: VOPRF public key id mismatch")
        if not isinstance(evidence.get("directory_epoch"),int) or evidence.get("directory_epoch")<1: errors.append(f"{source}: valid directory epoch required")
        if evidence.get("directory_snapshot_authenticated") is not True: errors.append(f"{source}: directory snapshot must authenticate")
        if not isinstance(evidence.get("directory_snapshot_version"),int) or evidence.get("directory_snapshot_version")<1: errors.append(f"{source}: valid directory snapshot version required")
        if evidence.get("online_query_budget_enforced") is not True: errors.append(f"{source}: online VOPRF enumeration budget must be enforced")
        for field in ("confidential_compute_used","attestation_verified","measurement_authorized","encrypted_channel_terminated_inside_trusted_boundary","query_memory_zeroized"):
            if evidence.get(field) is not False: errors.append(f"{source}: VOPRF evidence must set {field}=false")

    if mode=="confidential-compute":
        if evidence.get("service_observed_query_identifiers") is not False: errors.append(f"{source}: host/service must not observe plaintext query identifiers")
        if evidence.get("confidential_compute_used") is not True: errors.append(f"{source}: confidential compute required")
        if evidence.get("attestation_verified") is not True: errors.append(f"{source}: remote attestation must verify")
        if evidence.get("measurement_authorized") is not True: errors.append(f"{source}: measured code must be authorized")
        if evidence.get("encrypted_channel_terminated_inside_trusted_boundary") is not True: errors.append(f"{source}: encrypted query channel must terminate inside trusted boundary")
        if evidence.get("host_observed_plaintext_identifiers") is not False: errors.append(f"{source}: untrusted host must not observe plaintext identifiers")
        if evidence.get("query_memory_zeroized") is not True: errors.append(f"{source}: query memory zeroization must be evidenced")
        for field in ("voprf_blinded_inputs_verified","voprf_proof_verified","directory_snapshot_authenticated","online_query_budget_enforced"):
            if evidence.get(field) is not False: errors.append(f"{source}: confidential-compute evidence must set {field}=false")
        if evidence.get("voprf_public_key_id") is not None or evidence.get("directory_epoch") is not None or evidence.get("directory_snapshot_version") is not None:
            errors.append(f"{source}: confidential-compute evidence must not claim VOPRF directory state")
    return sorted(set(errors))

def main()->int:
    parser=argparse.ArgumentParser(description="Validate E2EESA contact discovery evidence.")
    parser.add_argument("policy",type=Path); parser.add_argument("evidence",type=Path)
    parser.add_argument("registry",type=Path); parser.add_argument("profile_catalog",type=Path)
    args=parser.parse_args()
    try:
        errors=validate_evidence(load_json(args.policy),load_json(args.evidence),load_json(args.registry),load_json(args.profile_catalog))
    except (OSError,json.JSONDecodeError,ValueError) as exc:
        print(json.dumps({"valid":False,"errors":[str(exc)]},indent=2,sort_keys=True)); return 1
    print(json.dumps({"valid":not errors,"errors":errors},indent=2,sort_keys=True))
    return 0 if not errors else 1

if __name__=="__main__":
    raise SystemExit(main())
