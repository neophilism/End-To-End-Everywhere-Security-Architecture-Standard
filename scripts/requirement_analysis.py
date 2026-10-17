#!/usr/bin/env python3
"""AUD-21: requirement-level authored analysis and review provenance.

Old document-wide rationale projection is not independently authored analysis.
Review JSON, signatures or AI self-review cannot establish independent human
review unless a trusted external attestation verifier authenticates them.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Callable

import canonical_serialization
import standards_crosswalk

ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LOGICAL = re.compile(r"^E2EESA-R-[0-9]{5}$")
HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
REQ = re.compile(r"^REQ-[0-9a-f]{64}$")
DEPENDENCIES = {"requires", "one-of", "excludes"}
FIELDS = {
    "logical_id", "requirement_id", "document_path", "text_digest",
    "author_id", "rationale", "threat_ids", "security_property_ids",
    "evidence_expectations", "external_standard_ids",
    "dependencies", "context_digest", "review",
}
REVIEW_FIELDS = {
    "reviewer_id", "reviewer_organization_id", "accepted_context_digest",
    "attestation_ref",
}


def _id(x: Any) -> bool:
    return isinstance(x, str) and ID.fullmatch(x) is not None


def _hash(x: Any) -> bool:
    return isinstance(x, str) and HASH.fullmatch(x) is not None


def _ids(value: Any, nonempty: bool = False) -> bool:
    return isinstance(value, list) and (not nonempty or bool(value)) and all(
        isinstance(v, str) and bool(v) for v in value
    ) and len(value) == len(set(value))


def current_context_digest(
    row: dict[str, Any], requirement: dict[str, Any],
    dependency_digests: list[dict[str, Any]], source_basis: dict[str, str],
) -> str:
    """Exact source and supporting-registry basis; no review status included."""
    context = {
        "domain": "E2EESA-AUD21-REQUIREMENT-ANALYSIS-v1",
        "logical_id": row["logical_id"],
        "requirement_id": requirement["requirement_id"],
        "document_path": requirement["document_path"],
        "text_digest": requirement["text_digest"],
        "rationale": row["rationale"],
        "threat_ids": sorted(row["threat_ids"]),
        "security_property_ids": sorted(row["security_property_ids"]),
        "evidence_expectations": sorted(row["evidence_expectations"]),
        "external_standard_ids": sorted(row["external_standard_ids"]),
        "dependency_digests": sorted(dependency_digests,
                                     key=lambda x: (x["logical_id"], x["kind"])),
        "source_basis": source_basis,
    }
    return canonical_serialization.canonical_digest(context)


def source_basis(root: Path) -> dict[str, str]:
    return {
        path: canonical_serialization.canonical_digest(
            json.loads((root / path).read_text(encoding="utf-8"))
        )
        for path in (
            "registry/threat-model.json",
            "registry/security-properties.json",
            "registry/external-standards.json",
            "registry/standards-crosswalk-rules.json",
        )
    }


def check_analyses(
    doc: dict[str, Any], requirements: list[dict[str, Any]],
    threats: set[str], properties: set[str], standards: set[str],
    basis: dict[str, str],
    *,
    authenticated_review: Callable[[dict[str, Any], dict[str, Any]], bool] | None = None,
    document_rationales: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate overlays and compute separate, defensible coverage denominators."""
    errors: list[str] = []
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "analysis_version", "records"}:
        return {"errors": ["invalid analysis registry shape"], "total": len(requirements),
                "projected": len(requirements), "authored": 0, "review_recorded": 0,
                "independently_authenticated_reviewed": 0}
    if doc["schema_version"] != "0.1" or doc["analysis_version"] != "0.1.0":
        errors.append("unsupported requirement-analysis registry version")
    rows = doc["records"]
    if not isinstance(rows, list):
        rows = []
        errors.append("analysis registry records must be a list")

    req_by_id = {r["requirement_id"]: r for r in requirements}
    logical: dict[str, dict[str, Any]] = {}
    claimed_reqs: set[str] = set()

    for index, row in enumerate(rows):
        prefix = f"analysis records[{index}]"
        if not isinstance(row, dict) or set(row) != FIELDS:
            errors.append(prefix + ": missing/unknown fields")
            continue
        lid = row["logical_id"]
        rid = row["requirement_id"]
        if not isinstance(lid, str) or LOGICAL.fullmatch(lid) is None or lid in logical:
            errors.append(prefix + ": invalid/duplicate logical id")
            continue
        logical[lid] = row
        if not isinstance(rid, str) or REQ.fullmatch(rid) is None or rid not in req_by_id:
            errors.append(prefix + ": orphaned or invalid requirement reference")
            continue
        if rid in claimed_reqs:
            errors.append(prefix + ": duplicate authored requirement")
        claimed_reqs.add(rid)
        req = req_by_id[rid]
        if row["document_path"] != req["document_path"] or row["text_digest"] != req["text_digest"]:
            errors.append(prefix + ": stale analysis: requirement text or document changed")
        if not _id(row["author_id"]):
            errors.append(prefix + ": invalid author")
        rationale = row["rationale"]
        if not isinstance(rationale, str) or len(rationale.strip()) < 60:
            errors.append(prefix + ": individually authored rationale must be substantive")
        if document_rationales and rationale == document_rationales.get(req["document_path"]):
            errors.append(prefix + ": copied document-wide rationale is a projection, not authored analysis")
        for field, known in (("threat_ids", threats), ("security_property_ids", properties),
                             ("external_standard_ids", standards)):
            if not _ids(row[field], nonempty=field != "external_standard_ids"):
                errors.append(prefix + f": {field} invalid")
            elif set(row[field]) - known:
                errors.append(prefix + f": {field} contains unknown ids")
        if not _ids(row["evidence_expectations"], nonempty=True):
            errors.append(prefix + ": missing unique evidence expectations")
        if not isinstance(row["dependencies"], list):
            errors.append(prefix + ": dependencies must be a typed list")

    valid_authored = 0
    review_recorded = 0
    independently_reviewed = 0
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != FIELDS:
            continue
        rid = row["requirement_id"]
        if rid not in req_by_id or row["logical_id"] not in logical:
            continue
        prefix = f"analysis records[{index}]"
        dependencies = row["dependencies"]
        dep_digests: list[dict[str, Any]] = []
        dep_keys: set[tuple[str, str]] = set()
        if not isinstance(dependencies, list):
            continue
        for dep in dependencies:
            if not isinstance(dep, dict) or set(dep) != {"logical_id", "kind"}:
                errors.append(prefix + ": malformed dependency")
                continue
            target = dep["logical_id"]
            kind = dep["kind"]
            if (not isinstance(target, str) or target not in logical
                    or target == row["logical_id"] or kind not in DEPENDENCIES):
                errors.append(prefix + ": unresolved or invalid typed dependency")
                continue
            key = (target, kind)
            if key in dep_keys:
                errors.append(prefix + ": duplicate typed dependency")
                continue
            dep_keys.add(key)
            target_req = req_by_id.get(logical[target].get("requirement_id"))
            if target_req is None:
                errors.append(prefix + ": dependency requirement is absent")
                continue
            dep_digests.append({"logical_id": target, "kind": kind,
                                "text_digest": target_req["text_digest"]})

        # Refuse to treat an overlay as current merely because its prose still
        # happens to be present: supporting registry and dependency digest changes
        # also invalidate its authored and review evidence.
        try:
            expected = current_context_digest(row, req_by_id[rid], dep_digests, basis)
        except (ValueError, TypeError, KeyError):
            errors.append(prefix + ": context cannot be derived")
            continue
        if row["context_digest"] != expected:
            errors.append(prefix + ": stale analysis or supporting dependency context")
            continue
        if any(x.startswith(prefix) for x in errors):
            continue
        valid_authored += 1
        review = row["review"]
        if review is None:
            continue
        if not isinstance(review, dict) or set(review) != REVIEW_FIELDS:
            errors.append(prefix + ": malformed review provenance")
            continue
        if (not _id(review["reviewer_id"]) or not _id(review["reviewer_organization_id"])
                or review["reviewer_id"] == row["author_id"]
                or not _id(review["attestation_ref"])
                or review["accepted_context_digest"] != expected):
            errors.append(prefix + ": stale, unauthenticated, or self-review record")
            continue
        review_recorded += 1
        if authenticated_review is not None and authenticated_review(review, row) is True:
            independently_reviewed += 1

    return {
        "errors": sorted(set(errors)),
        "total": len(requirements),
        "projected": len(requirements),
        "authored": valid_authored,
        "review_recorded": review_recorded,
        "independently_authenticated_reviewed": independently_reviewed,
        "note": "Document-level projections are not authored or independently reviewed requirement analysis.",
    }


def validate_repository(root: Path) -> dict[str, Any]:
    doc = json.loads((root / "registry/requirement-analyses.json").read_text(encoding="utf-8"))
    threats = json.loads((root / "registry/threat-model.json").read_text(encoding="utf-8"))
    props = json.loads((root / "registry/security-properties.json").read_text(encoding="utf-8"))
    standards = json.loads((root / "registry/external-standards.json").read_text(encoding="utf-8"))
    rationales = json.loads((root / "registry/security-rationale-rules.json").read_text(encoding="utf-8"))
    return check_analyses(
        doc, standards_crosswalk.extract_requirements(root),
        {r["id"] for r in threats["threats"]},
        {r["id"] for r in props["properties"]},
        {r["id"] for r in standards["standards"]},
        source_basis(root),
        document_rationales={r["document_path"]: r["rationale"] for r in rationales["rules"]},
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = validate_repository(args.root)
    print(json.dumps(result, sort_keys=True))
    if result["errors"]:
        raise SystemExit(1)
