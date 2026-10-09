#!/usr/bin/env python3
"""Run seeded malformed-input and semantic property checks on reference tooling.

This is bounded mutational testing, not coverage-guided fuzzing, formal proof,
production wire-protocol testing or an independent product assessment.
"""
from __future__ import annotations
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random

import attachment_encryption_engine
import client_security_engine
import server_trust_engine
import telemetry_engine
import secure_development_engine
import supply_chain_engine
import verification_engine
from assurance_common import digest, load_json

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ("client-security", "native", client_security_engine.validate_client),
    ("server-trust", "live", server_trust_engine.validate_deployment),
    ("telemetry", "dp-aggregate", telemetry_engine.validate_telemetry),
    ("secure-development", "clean", secure_development_engine.validate_release),
    ("supply-chain", "spdx", supply_chain_engine.validate_release),
    ("verification", "combined", verification_engine.validate_assessment),
]


def leaves(value, prefix=()):
    if isinstance(value, dict) and value:
        for key, item in value.items(): yield from leaves(item, prefix+(key,))
    elif isinstance(value, list) and value:
        for i, item in enumerate(value): yield from leaves(item, prefix+(i,))
    else: yield prefix


def load_pair(root, name, variant):
    return (load_json(root/f"fixtures/{name}/policies/{variant}.json"),
            load_json(root/f"fixtures/{name}/evidence/{variant}.json"))


def run_campaign(seed=20261007, iterations=1000, root=ROOT):
    if type(seed) is not int or type(iterations) is not int or not 1 <= iterations <= 100000:
        raise ValueError("seed/iterations must be integers; iterations range is 1..100000")
    rng=random.Random(seed)
    catalog=load_json(root/"fixtures/profiles/development-catalog.json")
    pairs=[load_pair(root,name,variant) for name,variant,validator in TARGETS]
    failures=[]; mutated=0; properties=0
    def failure(label, i, kind):
        if len(failures)<10:failures.append({"check":label,"iteration":i,"failure":kind})
    for index,(name,variant,validator) in enumerate(TARGETS):
        policy,evidence=pairs[index]
        if validator(policy,evidence,catalog,root=root):
            failure(name,0,"baseline fixture rejected")
    for i in range(iterations):
        index=rng.randrange(len(TARGETS)); name,variant,validator=TARGETS[index]
        policy,reference=pairs[index]; mutated_evidence=copy.deepcopy(reference)
        if i % 3 == 0:
            mutated_evidence=rng.choice([None,[],True,42,"unparsed-json",{}])
        else:
            path=rng.choice(list(leaves(mutated_evidence)))
            node=mutated_evidence
            for key in path[:-1]:node=node[key]
            node[path[-1]]={"unexpected-shape":i}
        try:
            if not validator(policy,mutated_evidence,catalog,root=root):
                failure(name,i,"malformed evidence accepted")
        except Exception as exc:
            failure(name,i,type(exc).__name__)
        mutated+=1
        # Semantic properties exercise real validators, independent of schema mutation.
        sp,se=copy.deepcopy(pairs[1]); se["objects"][0]["recipient_device_ids"].append(f"attacker-{i}")
        if not server_trust_engine.validate_deployment(sp,se,catalog,root=root):
            failure("recipient-authorization",i,"unauthorized recipient accepted")
        properties+=1
        tp,te=copy.deepcopy(pairs[2]); eps=[rng.randint(1,1000000),rng.randint(1,1000000)]
        for release,amount in zip(te["dp"]["releases"],eps):
            release["epsilon_micros"]=release["noise_scale_denominator"]=amount
        te["dp"]["ledger_digest"]=digest(te["dp"]["releases"])
        errors=telemetry_engine.validate_telemetry(tp,te,catalog,root=root)
        if bool(errors) != (sum(eps)>tp["lifetime_epsilon_micros"]):
            failure("dp-composition",i,"privacy-budget decision mismatch")
        properties+=1
    manifest=load_json(root/"fixtures/attachments/manifest.json")
    start=rng.randrange(2**64)
    counters=[(start+i)%(2**64) for i in range(iterations)]
    nonces=[attachment_encryption_engine.expected_nonce_hex(manifest,counter) for counter in counters]
    if len(set(nonces))!=len(counters) or any(len(n)!=24 for n in nonces):
        failure("attachment-nonce",0,"nonce collision or wrong width")
    properties+=len(counters)
    for counter in (-1,2**64):
        try:
            attachment_encryption_engine.expected_nonce_hex(manifest,counter)
            failure("attachment-nonce",counter,"out-of-range counter accepted")
        except ValueError:pass
    inputs={}
    for directory in ("scripts","tests","schemas","registry","fixtures","profiles","spec","adr"):
        for path in sorted((root/directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py",".json",".md"}:
                inputs[str(path.relative_to(root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    return {"schema_version":"0.1","report_type":"reference-security-checks","seed":seed,"iterations":iterations,
            "observed_at":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"input_inventory_digest":digest(inputs),
            "malformed_input_cases":mutated,"semantic_property_cases":properties,"passed":not failures,
            "failures":failures,"independent_assessment":False,
            "limitations":["bounded seeded mutations", "reference evidence validators only", "no cryptographic/wire-protocol proof"]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed",type=int,default=20261007)
    parser.add_argument("--iterations",type=int,default=1000)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    try:report=run_campaign(args.seed,args.iterations)
    except (ValueError,OSError) as exc:parser.error(str(exc))
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:report[k] for k in ("passed","seed","iterations","malformed_input_cases","semantic_property_cases","failures")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":raise SystemExit(main())
