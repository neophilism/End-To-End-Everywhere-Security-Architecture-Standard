#!/usr/bin/env python3
"""Security rationale corpus generator for E2EESA PR 47."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import standards_crosswalk


def canonical_digest(value):
    return standards_crosswalk.canonical_digest(value)


def validate_rules(rules_doc, root, threat_registry, property_registry):
    errors=[]
    if rules_doc.get("schema_version") != "0.1":
        errors.append("security rationale rules schema_version must be 0.1")
    rules=rules_doc.get("rules",[])
    if not isinstance(rules,list) or not rules:
        errors.append("security rationale rules must be non-empty")
        return errors
    known_threats={x.get("id") for x in threat_registry.get("threats",[]) if isinstance(x,dict)}
    known_scenarios={x.get("id") for x in threat_registry.get("composite_scenarios",[]) if isinstance(x,dict)}
    known_props={x.get("id") for x in property_registry.get("properties",[]) if isinstance(x,dict)}
    seen=set()
    for i,rule in enumerate(rules):
        prefix=f"security rationale rules[{i}]"
        if not isinstance(rule,dict):
            errors.append(prefix+" must be an object")
            continue
        doc=rule.get("document_path")
        if not isinstance(doc,str) or not doc.startswith("spec/"):
            errors.append(prefix+".document_path must point into spec/")
            continue
        if doc in seen:
            errors.append("duplicate security rationale rule for "+doc)
        seen.add(doc)
        if not isinstance(rule.get("rationale"),str) or not rule["rationale"].strip():
            errors.append(doc+" rationale must be non-empty")
        evidence=rule.get("evidence_expectations")
        if not isinstance(evidence,list) or not evidence or len(evidence)!=len(set(evidence)):
            errors.append(doc+" evidence_expectations must be unique and non-empty")
        threats=rule.get("threat_ids")
        scenarios=rule.get("composite_scenario_ids")
        props=rule.get("security_property_ids")
        if not isinstance(threats,list) or len(threats)!=len(set(threats)):
            errors.append(doc+" threat_ids must be a unique array")
            threats=[]
        if not isinstance(scenarios,list) or len(scenarios)!=len(set(scenarios)):
            errors.append(doc+" composite_scenario_ids must be a unique array")
            scenarios=[]
        if not isinstance(props,list) or not props or len(props)!=len(set(props)):
            errors.append(doc+" security_property_ids must be unique and non-empty")
            props=[]
        bad=sorted(set(threats)-known_threats)
        if bad:
            errors.append(doc+" unknown threats: "+", ".join(bad))
        bad=sorted(set(scenarios)-known_scenarios)
        if bad:
            errors.append(doc+" unknown composite scenarios: "+", ".join(bad))
        bad=sorted(set(props)-known_props)
        if bad:
            errors.append(doc+" unknown security properties: "+", ".join(bad))
    expected={p.relative_to(root).as_posix() for p in standards_crosswalk.spec_documents(root)}
    missing=sorted(expected-seen)
    stale=sorted(seen-expected)
    if missing:
        errors.append("security rationale rules missing spec documents: "+", ".join(missing))
    if stale:
        errors.append("security rationale rules reference missing spec documents: "+", ".join(stale))
    return sorted(set(errors))


def build_report(root, rationale_rules, threat_registry, property_registry, standards_catalog, crosswalk_rules):
    errors=validate_rules(rationale_rules,root,threat_registry,property_registry)
    crosswalk_errors=standards_crosswalk.validate(standards_catalog,crosswalk_rules,root)
    errors.extend(crosswalk_errors)
    if errors:
        raise ValueError("; ".join(sorted(set(errors))))
    crosswalk=standards_crosswalk.build_report(root,standards_catalog,crosswalk_rules)
    rules={x["document_path"]:x for x in rationale_rules["rules"]}
    records=[]
    by_doc=Counter(); by_threat=Counter(); by_prop=Counter(); by_evidence=Counter()
    for req in crosswalk["requirements"]:
        rule=rules[req["document_path"]]
        record={
            "requirement_id":req["requirement_id"],
            "document_path":req["document_path"],
            "text":req["text"],
            "text_digest":req["text_digest"],
            "keywords":req["keywords"],
            "rationale":rule["rationale"],
            "threat_ids":sorted(rule["threat_ids"]),
            "composite_scenario_ids":sorted(rule["composite_scenario_ids"]),
            "security_property_ids":sorted(rule["security_property_ids"]),
            "evidence_expectations":sorted(rule["evidence_expectations"]),
            "external_coverage":req["coverage"],
            "external_relations":req["relations"],
            "no_direct_analog_reason":req["no_direct_analog_reason"],
        }
        record["rationale_record_digest"]=canonical_digest(record)
        records.append(record)
        by_doc[req["document_path"]]+=1
        for x in rule["threat_ids"]: by_threat[x]+=1
        for x in rule["security_property_ids"]: by_prop[x]+=1
        for x in rule["evidence_expectations"]: by_evidence[x]+=1
    report={
        "schema_version":"0.1",
        "rationale_version":rationale_rules["rationale_version"],
        "crosswalk_report_digest":crosswalk["report_digest"],
        "requirement_count":len(records),
        "rationale_count":len(records),
        "coverage_percent_basis_points":10000 if records else 0,
        "per_document_counts":dict(sorted(by_doc.items())),
        "per_threat_counts":dict(sorted(by_threat.items())),
        "per_property_counts":dict(sorted(by_prop.items())),
        "per_evidence_class_counts":dict(sorted(by_evidence.items())),
        "records":records,
        "report_digest":"",
    }
    report["report_digest"]=canonical_digest({k:v for k,v in report.items() if k!="report_digest"})
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[1])
    p.add_argument("--output",type=Path)
    a=p.parse_args(); root=a.root.resolve()
    load=lambda rel: json.loads((root/rel).read_text(encoding="utf-8"))
    report=build_report(root,load("registry/security-rationale-rules.json"),load("registry/threat-model.json"),load("registry/security-properties.json"),load("registry/external-standards.json"),load("registry/standards-crosswalk-rules.json"))
    rendered=json.dumps(report,indent=2,ensure_ascii=False,sort_keys=True)+"\n"
    if a.output: a.output.write_text(rendered,encoding="utf-8")
    else: print(rendered,end="")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
