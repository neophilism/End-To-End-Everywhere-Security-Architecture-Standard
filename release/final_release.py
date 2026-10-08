#!/usr/bin/env python3
"""Final E2EESA 1.0 content-addressed release manifest and validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "review"
if str(REVIEW) not in sys.path:
    sys.path.insert(0, str(REVIEW))

import review_completion
import requirement_transition


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


def git_blob_sha(data: bytes) -> str:
    header = ("blob " + str(len(data)) + chr(0)).encode("utf-8")
    return hashlib.sha1(header + data).hexdigest()


def load_json(rel: str) -> dict:
    value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(rel + " must contain an object")
    return value


def frozen_paths(policy: dict) -> list[str]:
    config = policy["final_manifest"]
    excluded = set(config["excluded_paths"])
    paths: set[str] = set()

    for rel in config["frozen_top_level_files"]:
        if (ROOT / rel).is_file() and rel not in excluded:
            paths.add(rel)

    for relroot in config["frozen_roots"]:
        base = ROOT / relroot
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(ROOT).as_posix()
            if rel in excluded or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            paths.add(rel)

    for rel in config["additional_files"]:
        if rel not in excluded and (ROOT / rel).is_file():
            paths.add(rel)

    return sorted(paths)


def build_manifest(policy: dict) -> dict:
    entries = []
    for rel in frozen_paths(policy):
        data = (ROOT / rel).read_bytes()
        entries.append(
            {
                "path": rel,
                "size": len(data),
                "git_blob_sha": git_blob_sha(data),
            }
        )
    receipt = load_json("release/review-completion-receipt.json")
    transition = load_json(
        "release/1.0.0-requirement-id-transition.json"
    )
    manifest = {
        "schema_version": "0.1",
        "release_version": "1.0.0",
        "source_candidate_digest": policy["source_candidate"]["tree_digest"],
        "final_reviewed_tree_digest": receipt.get(
            "final_reviewed_tree_digest"
        ),
        "review_summary_digest": receipt.get("review_summary_digest"),
        "review_package_digest": receipt.get("review_package_digest"),
        "review_completion_receipt_digest": receipt.get("receipt_digest"),
        "requirement_transition_report_digest": transition.get(
            "report_digest"
        ),
        "file_count": len(entries),
        "files": entries,
        "tree_digest": canonical_digest(entries),
    }
    return manifest


def residual_pre_1_0_occurrences(policy: dict) -> list[str]:
    old = policy["pre_1_0_standard_version"]
    historical = set(policy["historical_version_paths"])
    hits: list[str] = []

    roots = [
        ".github/workflows",
        "adr",
        "fixtures",
        "profiles",
        "reference",
        "registry",
        "schemas",
        "scripts",
        "spec",
        "tests",
    ]
    top = ["README.md", "VERSION"]

    paths: list[Path] = []
    for relroot in roots:
        base = ROOT / relroot
        if base.exists():
            paths.extend(path for path in base.rglob("*") if path.is_file())
    paths.extend(ROOT / rel for rel in top if (ROOT / rel).is_file())

    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        if rel in historical or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if old in text:
            hits.append(rel)
    return sorted(set(hits))


def validate_final_release() -> list[str]:
    errors: list[str] = []
    policy = load_json("release/1.0.0-finalization.json")
    receipt_errors = review_completion.validate_receipt()
    errors.extend(
        "review completion receipt: " + error
        for error in receipt_errors
    )

    if not receipt_errors:
        receipt = load_json("release/review-completion-receipt.json")
        transition_errors = requirement_transition.validate_report(
            receipt["final_reviewed_tree_digest"]
        )
        errors.extend(
            "requirement transition: " + error
            for error in transition_errors
        )

    readiness = load_json("release/1.0.0-readiness.json")
    if readiness.get("external_review_status") != "complete":
        errors.append("1.0 readiness external_review_status must be complete")
    if readiness.get("engineering_status") not in {
        "ready-for-final-promotion",
        "released",
    }:
        errors.append(
            "1.0 readiness engineering_status must be ready-for-final-promotion or released"
        )

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if version != "1.0.0":
        errors.append("VERSION must equal 1.0.0 for final release")

    residual = residual_pre_1_0_occurrences(policy)
    if residual:
        errors.append(
            "unclassified pre-1.0 standard-version occurrences remain: "
            + ", ".join(residual)
        )

    manifest_path = ROOT / policy["final_manifest"]["path"]
    if not manifest_path.is_file():
        errors.append("final 1.0 manifest is missing")
    else:
        stored = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = build_manifest(policy)
        if stored != expected:
            errors.append("final 1.0 manifest differs from current frozen tree")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()

    policy = load_json("release/1.0.0-finalization.json")
    if args.write_manifest:
        receipt_errors = review_completion.validate_receipt()
        if receipt_errors:
            for error in receipt_errors:
                print("ERROR:", error)
            print(
                "Refusing to write final manifest without a valid "
                "review-completion receipt."
            )
            return 1

        receipt = load_json("release/review-completion-receipt.json")
        transition_errors = requirement_transition.validate_report(
            receipt["final_reviewed_tree_digest"]
        )
        if transition_errors:
            for error in transition_errors:
                print("ERROR:", error)
            print(
                "Refusing to write final manifest without a valid "
                "requirement ID transition report."
            )
            return 1

        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        if version != "1.0.0":
            print("ERROR: VERSION must equal 1.0.0 before final manifest generation.")
            return 1

        residual = residual_pre_1_0_occurrences(policy)
        if residual:
            print(
                "ERROR: unclassified pre-1.0 standard-version occurrences remain: "
                + ", ".join(residual)
            )
            return 1

        readiness = load_json("release/1.0.0-readiness.json")
        if readiness.get("external_review_status") != "complete":
            print("ERROR: external review status must be complete.")
            return 1
        if readiness.get("engineering_status") not in {
            "ready-for-final-promotion",
            "released",
        }:
            print(
                "ERROR: engineering status must be ready-for-final-promotion or released."
            )
            return 1

        manifest = build_manifest(policy)
        path = ROOT / policy["final_manifest"]["path"]
        path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(
            "Wrote", path.relative_to(ROOT),
            "files=", manifest["file_count"],
            "tree_digest=", manifest["tree_digest"],
        )
        return 0

    errors = validate_final_release()
    if errors:
        for error in errors:
            print("ERROR:", error)
        return 1
    print("E2EESA 1.0 final release validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
