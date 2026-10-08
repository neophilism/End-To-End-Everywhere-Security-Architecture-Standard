#!/usr/bin/env python3
"""Normalize standalone independent-review artifacts into the combined package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "review"
if str(REVIEW) not in sys.path:
    sys.path.insert(0, str(REVIEW))

import validate_review

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DOMAINS = {
    "cryptography-protocols",
    "implementation-security",
    "supply-chain-development",
    "privacy-metadata-recovery",
    "conformance-standards",
}
CANDIDATE = {
    "release_version": "0.9.0-rc.1",
    "tree_digest": (
        "sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c"
        "551083f5f5189491370ce2a2"
    ),
    "file_count": 645,
}


def load_object(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def source_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(
        path
        for path in directory.glob("*.json")
        if path.is_file()
    )


def validate_source_attestation(data: dict, path: Path) -> list[str]:
    errors: list[str] = []
    required_strings = (
        "reviewer_id",
        "reviewer_name",
        "organization_id",
        "organization_name",
        "relationship_disclosure",
        "review_started_at",
        "review_completed_at",
        "overall_conclusion",
    )
    if data.get("schema_version") != "0.1":
        errors.append(f"{path}: schema_version must be 0.1")
    for field in required_strings:
        if not isinstance(data.get(field), str) or not data[field].strip():
            errors.append(f"{path}: {field} must be non-empty")
    if data.get("independent_from_maintainers") is not True:
        errors.append(f"{path}: reviewer must be independent from maintainers")
    if data.get("candidate") != CANDIDATE:
        errors.append(f"{path}: candidate identity mismatch")

    for field in ("expertise", "methods_used", "areas_emphasized"):
        value = data.get(field)
        if (
            not isinstance(value, list)
            or not value
            or len(value) != len(set(value))
            or any(not isinstance(item, str) or not item for item in value)
        ):
            errors.append(f"{path}: {field} must be a unique non-empty string array")

    limits = data.get("scope_limitations")
    if (
        not isinstance(limits, list)
        or len(limits) != len(set(limits))
        or any(not isinstance(item, str) or not item for item in limits)
    ):
        errors.append(f"{path}: scope_limitations must be a unique string array")

    domains = data.get("domains")
    if (
        not isinstance(domains, list)
        or not domains
        or len(domains) != len(set(domains))
        or not set(domains).issubset(DOMAINS)
    ):
        errors.append(f"{path}: domains are invalid")

    finding_ids = data.get("finding_ids")
    if (
        not isinstance(finding_ids, list)
        or len(finding_ids) != len(set(finding_ids))
        or any(not isinstance(item, str) or not item for item in finding_ids)
    ):
        errors.append(f"{path}: finding_ids must be a unique string array")

    final_acceptance = data.get("final_acceptance")
    final_tree = data.get("final_reviewed_tree_digest")
    if final_acceptance not in {None, True, False}:
        errors.append(f"{path}: final_acceptance must be true, false, or null")
    if final_acceptance is True:
        if not isinstance(final_tree, str) or not SHA256_RE.fullmatch(final_tree):
            errors.append(
                f"{path}: accepted final tree requires a sha256 final_reviewed_tree_digest"
            )
    elif final_tree is not None:
        errors.append(
            f"{path}: final_reviewed_tree_digest must remain null until final acceptance"
        )
    return errors


def validate_source_finding(data: dict, path: Path) -> list[str]:
    errors: list[str] = []
    if data.get("candidate") != CANDIDATE:
        errors.append(f"{path}: candidate identity mismatch")
    if not isinstance(data.get("failure_scenario"), str) or not data["failure_scenario"].strip():
        errors.append(f"{path}: failure_scenario must be non-empty")
    refs = data.get("supporting_references")
    if (
        not isinstance(refs, list)
        or any(not isinstance(item, str) or not item for item in refs)
    ):
        errors.append(f"{path}: supporting_references must be a string array")
    return errors


def normalized_reviewer(data: dict, path: Path) -> dict:
    digest = raw_digest(path)
    accepted = data.get("final_acceptance") is True
    return {
        "reviewer_id": data["reviewer_id"],
        "organization_id": data["organization_id"],
        "independent_from_maintainers": True,
        "domains": sorted(data["domains"]),
        "attestation_digest": digest,
        "attestation_reference": path.relative_to(ROOT).as_posix(),
        "final_reviewed_tree_digest": (
            data["final_reviewed_tree_digest"] if accepted else None
        ),
        "final_acceptance_digest": digest if accepted else None,
        "final_acceptance_reference": (
            path.relative_to(ROOT).as_posix() if accepted else None
        ),
    }


def normalized_finding(data: dict, path: Path) -> dict:
    keep = (
        "finding_id",
        "reviewer_id",
        "severity",
        "title",
        "analysis",
        "failure_scenario",
        "affected_requirement_ids",
        "affected_paths",
        "recommendation",
        "supporting_references",
        "status",
        "disposition_rationale",
        "fix_reference",
        "reviewer_acceptance",
    )
    result = {field: data.get(field) for field in keep}
    result["source_finding_digest"] = raw_digest(path)
    result["source_finding_reference"] = path.relative_to(ROOT).as_posix()
    return result


def build_package(current: dict) -> tuple[dict, list[str]]:
    errors: list[str] = []
    attestations: list[tuple[dict, Path]] = []
    findings: list[tuple[dict, Path]] = []

    for path in source_files(REVIEW / "attestations"):
        try:
            data = load_object(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        source_errors = validate_source_attestation(data, path)
        errors.extend(source_errors)
        if not source_errors:
            attestations.append((data, path))

    for path in source_files(REVIEW / "findings"):
        try:
            data = load_object(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        source_errors = validate_source_finding(data, path)
        errors.extend(source_errors)
        if not source_errors:
            findings.append((data, path))

    reviewer_ids = [data["reviewer_id"] for data, _ in attestations]
    if len(reviewer_ids) != len(set(reviewer_ids)):
        errors.append("duplicate reviewer_id across source attestations")

    finding_ids = [data.get("finding_id") for data, _ in findings]
    if len(finding_ids) != len(set(finding_ids)):
        errors.append("duplicate finding_id across source findings")

    known_reviewers = set(reviewer_ids)
    findings_by_reviewer: dict[str, set[str]] = {
        reviewer_id: set() for reviewer_id in known_reviewers
    }
    for data, path in findings:
        reviewer_id = data.get("reviewer_id")
        if reviewer_id not in known_reviewers:
            errors.append(f"{path}: finding references unknown reviewer_id {reviewer_id}")
            continue
        findings_by_reviewer[reviewer_id].add(data["finding_id"])

    for data, path in attestations:
        declared = set(data.get("finding_ids", []))
        actual = findings_by_reviewer.get(data["reviewer_id"], set())
        if declared != actual:
            errors.append(
                f"{path}: finding_ids do not match source findings "
                f"(declared={sorted(declared)}, actual={sorted(actual)})"
            )

    reviewers = sorted(
        (normalized_reviewer(data, path) for data, path in attestations),
        key=lambda item: item["reviewer_id"],
    )
    normalized_findings = sorted(
        (normalized_finding(data, path) for data, path in findings),
        key=lambda item: item["finding_id"],
    )

    completion = current.get("completion")
    if not isinstance(completion, dict):
        completion = {
            "review_complete": False,
            "completed_at": None,
            "summary_digest": None,
            "summary_reference": None,
            "final_reviewed_tree_digest": None,
            "final_reviewed_commit": None,
        }

    if completion.get("review_complete") is True:
        status = current.get("status")
    elif not reviewers:
        status = "awaiting-review"
    elif any(item.get("status") == "open" for item in normalized_findings):
        status = "findings-open"
    else:
        status = "review-in-progress"

    package = {
        "schema_version": "0.1",
        "review_id": current.get(
            "review_id", "e2eesa-0-9-independent-review"
        ),
        "candidate": CANDIDATE,
        "status": status,
        "reviewers": reviewers,
        "findings": normalized_findings,
        "completion": completion,
    }

    errors.extend(validate_review.validate_package(package, ROOT))
    if completion.get("review_complete") is True:
        errors.extend(validate_review.completion_errors(package, ROOT))
    return package, sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="write the normalized combined review package",
    )
    args = parser.parse_args()

    package_path = REVIEW / "independent-review.json"
    current = load_object(package_path)
    package, errors = build_package(current)
    if errors:
        for error in errors:
            print("ERROR:", error)
        return 1

    rendered = json.dumps(
        package, indent=2, ensure_ascii=False, sort_keys=False
    ) + "\n"

    if args.write:
        package_path.write_text(rendered, encoding="utf-8")
        print("Wrote", package_path.relative_to(ROOT))
        print("reviewers:", len(package["reviewers"]))
        print("findings:", len(package["findings"]))
        print("status:", package["status"])
        return 0

    existing = package_path.read_text(encoding="utf-8")
    if existing != rendered:
        print(
            "ERROR: combined review package differs from deterministic "
            "normalization. Run: python review/ingest_review.py --write"
        )
        return 1

    print("Combined review package matches standalone source artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
