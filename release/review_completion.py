#!/usr/bin/env python3
"""Create and validate the immutable review-completion receipt for 1.0 promotion."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "review"
if str(REVIEW) not in sys.path:
    sys.path.insert(0, str(REVIEW))

import validate_review

RECEIPT_PATH = ROOT / "release" / "review-completion-receipt.json"
PACKAGE_PATH = ROOT / "review" / "independent-review.json"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(str(path) + " must contain a JSON object")
    return value


def receipt_core(receipt: dict) -> dict:
    return {
        key: value
        for key, value in receipt.items()
        if key != "receipt_digest"
    }


def build_receipt(package: dict) -> dict:
    reviewers = [
        item
        for item in package.get("reviewers", [])
        if isinstance(item, dict)
    ]
    organizations = sorted(
        {
            item.get("organization_id")
            for item in reviewers
            if isinstance(item.get("organization_id"), str)
        }
    )
    domains = sorted(
        {
            domain
            for item in reviewers
            for domain in item.get("domains", [])
            if isinstance(domain, str)
        }
    )
    findings = [
        item
        for item in package.get("findings", [])
        if isinstance(item, dict)
    ]
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    completion = package["completion"]
    receipt = {
        "schema_version": "0.1",
        "source_candidate_digest": (
            "sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2"
        ),
        "review_package_digest": file_digest(PACKAGE_PATH),
        "final_reviewed_tree_digest": completion["final_reviewed_tree_digest"],
        "final_reviewed_commit": completion["final_reviewed_commit"],
        "review_summary_digest": completion["summary_digest"],
        "review_summary_reference": completion["summary_reference"],
        "reviewer_count": len(reviewers),
        "organization_count": len(organizations),
        "review_domains": domains,
        "finding_counts_by_severity": dict(sorted(severity_counts.items())),
        "receipt_digest": "",
    }
    receipt["receipt_digest"] = canonical_digest(receipt_core(receipt))
    return receipt


def write_receipt() -> dict:
    package = load_json(PACKAGE_PATH)
    errors = validate_review.completion_errors(package, ROOT)
    if errors:
        raise ValueError(
            "independent review completion gate failed: " + "; ".join(errors)
        )
    receipt = build_receipt(package)
    RECEIPT_PATH.write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return receipt


def validate_receipt() -> list[str]:
    errors: list[str] = []
    if not RECEIPT_PATH.is_file():
        return ["review completion receipt is missing"]

    try:
        receipt = load_json(RECEIPT_PATH)
        package = load_json(PACKAGE_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [str(exc)]

    if receipt.get("schema_version") != "0.1":
        errors.append("review completion receipt schema_version must be 0.1")

    expected_receipt_digest = canonical_digest(receipt_core(receipt))
    if receipt.get("receipt_digest") != expected_receipt_digest:
        errors.append("review completion receipt digest mismatch")

    if receipt.get("review_package_digest") != file_digest(PACKAGE_PATH):
        errors.append("review package differs from the completion receipt")

    completion = package.get("completion")
    if not isinstance(completion, dict) or completion.get("review_complete") is not True:
        errors.append("review package no longer records review_complete=true")
        completion = {}

    if package.get("status") != "ready-for-1.0":
        errors.append("review package no longer has ready-for-1.0 status")

    comparisons = {
        "final_reviewed_tree_digest": completion.get("final_reviewed_tree_digest"),
        "final_reviewed_commit": completion.get("final_reviewed_commit"),
        "review_summary_digest": completion.get("summary_digest"),
        "review_summary_reference": completion.get("summary_reference"),
    }
    for field, expected in comparisons.items():
        if receipt.get(field) != expected:
            errors.append(
                "review completion receipt field mismatch: " + field
            )

    rebuilt = build_receipt(package)
    for field in (
        "reviewer_count",
        "organization_count",
        "review_domains",
        "finding_counts_by_severity",
    ):
        if receipt.get(field) != rebuilt.get(field):
            errors.append(
                "review completion receipt aggregate mismatch: " + field
            )

    if receipt.get("source_candidate_digest") != (
        "sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2"
    ):
        errors.append("review completion receipt source candidate mismatch")

    return sorted(set(errors))


def main() -> int:
    try:
        receipt = write_receipt()
    except ValueError as exc:
        print("ERROR:", exc)
        return 1
    print("Wrote", RECEIPT_PATH.relative_to(ROOT))
    print("receipt_digest:", receipt["receipt_digest"])
    print("review_package_digest:", receipt["review_package_digest"])
    print("final_reviewed_tree_digest:", receipt["final_reviewed_tree_digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
