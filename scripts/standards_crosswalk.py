#!/usr/bin/env python3
"""Requirement-by-requirement standards crosswalk for E2EESA PR 46."""

from __future__ import annotations

import canonical_serialization

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

NORMATIVE_RE = re.compile(r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY)\b")


def canonical_digest(value):
    return canonical_serialization.canonical_digest(value)


def spec_documents(root):
    return sorted(p for p in (root / "spec").glob("*.md") if p.name != "README.md")


def extract_requirements_from_text(document_path, text):
    out = []
    paragraph = []
    in_fence = False

    def flush():
        nonlocal paragraph
        if not paragraph:
            return
        normalized = " ".join(" ".join(paragraph).split())
        paragraph = []
        if not normalized or normalized.startswith("#"):
            return
        keywords = sorted(set(NORMATIVE_RE.findall(normalized)))
        if not keywords:
            return
        basis = (document_path + chr(0) + normalized).encode("utf-8")
        out.append({
            "requirement_id": "REQ-" + hashlib.sha256(basis).hexdigest(),
            "document_path": document_path,
            "keywords": keywords,
            "text": normalized,
            "text_digest": canonical_digest(normalized),
        })

    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("```"):
            flush()
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not s:
            flush()
            continue
        if s.startswith("#"):
            flush()
            continue
        paragraph.append(s)
    flush()
    return out


def extract_requirements(root):
    out = []
    for path in spec_documents(root):
        rel = path.relative_to(root).as_posix()
        out.extend(extract_requirements_from_text(rel, path.read_text(encoding="utf-8")))
    return sorted(out, key=lambda x: (x["document_path"], x["requirement_id"]))


def validate(catalog, rules_doc, root):
    errors = []
    standards = catalog.get("standards", [])
    standard_ids = [x.get("id") for x in standards if isinstance(x, dict)]
    if catalog.get("schema_version") != "0.1":
        errors.append("external standards catalog schema_version must be 0.1")
    if not standards or len(standard_ids) != len(set(standard_ids)):
        errors.append("external standards catalog IDs must be unique and non-empty")
    for item in standards:
        if not isinstance(item, dict):
            errors.append("external standard entry must be an object")
            continue
        for field in ("id","organization","designation","title","status","reference_uri"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                errors.append("external standard missing " + field)
        if isinstance(item.get("reference_uri"), str) and not item["reference_uri"].startswith("https://"):
            errors.append("external standard reference_uri must use https")

    rules = rules_doc.get("rules", [])
    if rules_doc.get("schema_version") != "0.1":
        errors.append("crosswalk rules schema_version must be 0.1")
    rule_docs = []
    for rule in rules:
        if not isinstance(rule, dict):
            errors.append("crosswalk rule must be an object")
            continue
        doc = rule.get("document_path")
        rule_docs.append(doc)
        rels = rule.get("relations")
        rationale = rule.get("no_direct_analog_reason")
        if not isinstance(rels, list):
            errors.append(str(doc) + " relations must be an array")
            continue
        if rels and rationale is not None:
            errors.append(str(doc) + " cannot have relations and no-direct-analog rationale")
        if not rels and (not isinstance(rationale, str) or not rationale.strip()):
            errors.append(str(doc) + " requires no-direct-analog rationale")
        seen = set()
        for rel in rels:
            sid = rel.get("standard_id") if isinstance(rel, dict) else None
            if sid not in standard_ids:
                errors.append(str(doc) + " references unknown standard " + str(sid))
            if sid in seen:
                errors.append(str(doc) + " duplicates standard " + str(sid))
            seen.add(sid)
            if not isinstance(rel, dict) or rel.get("relation") not in {"direct","contextual"}:
                errors.append(str(doc) + " has invalid relation")
            if not isinstance(rel, dict) or not isinstance(rel.get("scope_note"), str) or not rel["scope_note"].strip():
                errors.append(str(doc) + " relation scope_note must be non-empty")

    if len(rule_docs) != len(set(rule_docs)):
        errors.append("crosswalk document rules must be unique")
    expected = {p.relative_to(root).as_posix() for p in spec_documents(root)}
    actual = set(rule_docs)
    missing = sorted(expected - actual)
    stale = sorted(actual - expected)
    if missing:
        errors.append("crosswalk rules missing current spec documents: " + ", ".join(missing))
    if stale:
        errors.append("crosswalk rules reference missing spec documents: " + ", ".join(stale))
    return sorted(set(errors))


def build_report(root, catalog, rules_doc):
    errors = validate(catalog, rules_doc, root)
    if errors:
        raise ValueError("; ".join(errors))
    rules = {x["document_path"]: x for x in rules_doc["rules"]}
    standards = {x["id"]: x for x in catalog["standards"]}
    records = []
    by_doc = Counter()
    by_org = Counter()
    no_direct = 0
    for req in extract_requirements(root):
        rule = rules[req["document_path"]]
        relations = [dict(x) for x in rule["relations"]]
        if relations:
            coverage = "external-related"
            rationale = None
            for rel in relations:
                by_org[standards[rel["standard_id"]]["organization"]] += 1
        else:
            coverage = "no-direct-analog"
            rationale = rule["no_direct_analog_reason"]
            no_direct += 1
        records.append({**req, "coverage": coverage, "relations": relations, "no_direct_analog_reason": rationale})
        by_doc[req["document_path"]] += 1
    report = {
        "schema_version": "0.1",
        "crosswalk_version": rules_doc["crosswalk_version"],
        "standard_catalog_digest": canonical_digest(catalog),
        "rule_set_digest": canonical_digest(rules_doc),
        "requirement_count": len(records),
        "covered_requirement_count": len(records),
        "coverage_percent_basis_points": 10000 if records else 0,
        "coverage_kind": "document-rule-projection",
        "projected_coverage_percent_basis_points": 10000 if records else 0,
        "individually_authored_coverage_percent_basis_points": 0,
        "independently_reviewed_coverage_percent_basis_points": 0,
        "no_direct_analog_count": no_direct,
        "per_document_requirement_counts": dict(sorted(by_doc.items())),
        "per_organization_relation_counts": dict(sorted(by_org.items())),
        "requirements": records,
        "report_digest": "",
    }
    report["report_digest"] = canonical_digest({k:v for k,v in report.items() if k != "report_digest"})
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    catalog = json.loads((root / "registry/external-standards.json").read_text(encoding="utf-8"))
    rules = json.loads((root / "registry/standards-crosswalk-rules.json").read_text(encoding="utf-8"))
    report = build_report(root, catalog, rules)
    rendered = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
