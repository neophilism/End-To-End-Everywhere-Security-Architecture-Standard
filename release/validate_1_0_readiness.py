#!/usr/bin/env python3
"""E2EESA 1.0 release-readiness gate.

Default mode is strict and blocks until the external independent review is complete.
Use --engineering-only to verify that development is otherwise ready while review is pending.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
REVIEW = ROOT / "review"
for path in (SCRIPTS, REVIEW):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import release_candidate
import validate_review


EXPECTED_CANDIDATE_DIGEST = "sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2"


def load_json(rel: str) -> dict:
    value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(rel + " must contain a JSON object")
    return value


def engineering_errors() -> list[str]:
    errors: list[str] = []
    readiness = load_json("release/1.0.0-readiness.json")
    candidate_manifest = load_json("release/0.9.0-rc.1-manifest.json")
    review_package = load_json("review/independent-review.json")

    if readiness.get("target_release") != "1.0.0":
        errors.append("readiness target_release must be 1.0.0")
    if readiness.get("engineering_status") not in {
        "ready-except-independent-review",
        "review-fixes-in-progress",
        "ready-for-final-promotion",
        "released",
    }:
        errors.append("invalid engineering_status")

    source = readiness.get("source_candidate", {})
    if source.get("tree_digest") != EXPECTED_CANDIDATE_DIGEST:
        errors.append("readiness source candidate digest mismatch")
    if source.get("file_count") != 645:
        errors.append("readiness source candidate file_count mismatch")
    if candidate_manifest.get("tree_digest") != EXPECTED_CANDIDATE_DIGEST:
        errors.append("stored 0.9 candidate digest mismatch")
    if candidate_manifest.get("file_count") != 645:
        errors.append("stored 0.9 candidate file_count mismatch")

    internal = readiness.get("internal_gates")
    if not isinstance(internal, list) or not internal:
        errors.append("internal_gates must be non-empty")
    else:
        ids: set[str] = set()
        for gate in internal:
            if not isinstance(gate, dict):
                errors.append("internal gate must be an object")
                continue
            gate_id = gate.get("gate_id")
            if not isinstance(gate_id, str) or not gate_id:
                errors.append("internal gate_id must be non-empty")
            elif gate_id in ids:
                errors.append("duplicate internal gate " + gate_id)
            else:
                ids.add(gate_id)
            if gate.get("status") != "passed":
                errors.append("internal engineering gate is not passed: " + str(gate_id))
            if not isinstance(gate.get("evidence"), str) or not gate["evidence"]:
                errors.append("internal gate lacks evidence: " + str(gate_id))

    package_errors = validate_review.validate_package(review_package, ROOT)
    errors.extend("review package: " + error for error in package_errors)

    review_complete = (
        isinstance(review_package.get("completion"), dict)
        and review_package["completion"].get("review_complete") is True
    )
    engineering_status = readiness.get("engineering_status")

    if not review_complete and engineering_status != "review-fixes-in-progress":
        candidate_errors = release_candidate.validate_release(ROOT)
        errors.extend("candidate: " + error for error in candidate_errors)
    elif engineering_status == "review-fixes-in-progress":
        if review_package.get("status") not in {
            "review-in-progress",
            "findings-open",
        }:
            errors.append(
                "review-fixes-in-progress requires review package status "
                "review-in-progress or findings-open"
            )

    return sorted(set(errors))


def external_review_errors() -> list[str]:
    package = load_json("review/independent-review.json")
    return validate_review.completion_errors(package, ROOT)


def readiness_errors(*, engineering_only: bool) -> list[str]:
    errors = engineering_errors()
    if not engineering_only:
        review_errors = external_review_errors()
        errors.extend("external review: " + error for error in review_errors)

        readiness = load_json("release/1.0.0-readiness.json")
        if not review_errors:
            if readiness.get("external_review_status") != "complete":
                errors.append(
                    "external review is complete but readiness external_review_status is not complete"
                )
            if readiness.get("engineering_status") not in {
                "ready-for-final-promotion",
                "released",
            }:
                errors.append(
                    "completed review requires engineering_status ready-for-final-promotion or released"
                )
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--engineering-only",
        action="store_true",
        help="allow the independent-review gate to remain pending",
    )
    args = parser.parse_args()

    errors = readiness_errors(engineering_only=args.engineering_only)
    if errors:
        for error in errors:
            print("ERROR:", error)
        if not args.engineering_only:
            print()
            print(
                "BLOCKED_EXTERNAL_REVIEW: engineering may continue, but final "
                "E2EESA 1.0 promotion requires the independent review package "
                "to pass review/validate_review.py --require-complete."
            )
        return 1

    if args.engineering_only:
        print(
            "E2EESA 1.0 engineering readiness passed. Independent expert review "
            "remains an external final-release gate."
        )
    else:
        print("E2EESA 1.0 strict readiness passed. Final promotion is permitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
