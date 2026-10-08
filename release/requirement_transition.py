#!/usr/bin/env python3
"""Build and validate the reviewed-tree -> E2EESA 1.0 requirement ID transition."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import standards_crosswalk

TRANSITION_PATH = ROOT / "release" / "1.0.0-requirement-id-transition.json"


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


def snapshot() -> list[dict]:
    return standards_crosswalk.extract_requirements(ROOT)


def report_core(report: dict) -> dict:
    return {
        key: value
        for key, value in report.items()
        if key != "report_digest"
    }


def build_report(
    before: list[dict],
    *,
    old_version: str,
    new_version: str,
    source_reviewed_tree_digest: str,
) -> dict:
    after = snapshot()
    after_by_key = {
        (item["document_path"], item["text"]): item
        for item in after
    }

    mappings: list[dict] = []
    seen_new: set[str] = set()
    errors: list[str] = []

    for item in before:
        expected_text = item["text"].replace(old_version, new_version)
        target = after_by_key.get((item["document_path"], expected_text))
        if target is None:
            errors.append(
                "requirement transition missing target for "
                + item["requirement_id"]
            )
            continue
        new_id = target["requirement_id"]
        if new_id in seen_new:
            errors.append(
                "requirement transition maps multiple sources to " + new_id
            )
        seen_new.add(new_id)
        mappings.append(
            {
                "document_path": item["document_path"],
                "old_requirement_id": item["requirement_id"],
                "new_requirement_id": new_id,
                "old_text_digest": item["text_digest"],
                "new_text_digest": target["text_digest"],
                "version_literal_changed": item["text"] != expected_text,
            }
        )

    after_ids = {item["requirement_id"] for item in after}
    if seen_new != after_ids:
        missing = sorted(after_ids - seen_new)
        extra = sorted(seen_new - after_ids)
        if missing:
            errors.append(
                "unmapped final requirement IDs: " + ", ".join(missing)
            )
        if extra:
            errors.append(
                "unexpected mapped final requirement IDs: " + ", ".join(extra)
            )

    if errors:
        raise ValueError("; ".join(errors))

    mappings.sort(
        key=lambda item: (
            item["document_path"],
            item["old_requirement_id"],
        )
    )
    report = {
        "schema_version": "0.1",
        "source_reviewed_tree_digest": source_reviewed_tree_digest,
        "source_standard_version": old_version,
        "target_release": "1.0.0",
        "target_standard_version": new_version,
        "mapping_count": len(mappings),
        "changed_requirement_id_count": sum(
            1
            for item in mappings
            if item["old_requirement_id"] != item["new_requirement_id"]
        ),
        "mappings": mappings,
        "report_digest": "",
    }
    report["report_digest"] = canonical_digest(report_core(report))
    return report


def write_report(
    before: list[dict],
    *,
    old_version: str,
    new_version: str,
    source_reviewed_tree_digest: str,
) -> dict:
    report = build_report(
        before,
        old_version=old_version,
        new_version=new_version,
        source_reviewed_tree_digest=source_reviewed_tree_digest,
    )
    TRANSITION_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return report


def validate_report(expected_source_reviewed_tree_digest: str) -> list[str]:
    errors: list[str] = []
    if not TRANSITION_PATH.is_file():
        return ["requirement ID transition report is missing"]

    try:
        report = json.loads(TRANSITION_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [str(exc)]

    if not isinstance(report, dict):
        return ["requirement ID transition report must be an object"]

    if report.get("schema_version") != "0.1":
        errors.append("requirement transition schema_version must be 0.1")
    if report.get("target_release") != "1.0.0":
        errors.append("requirement transition target_release must be 1.0.0")
    if (
        report.get("source_reviewed_tree_digest")
        != expected_source_reviewed_tree_digest
    ):
        errors.append(
            "requirement transition source reviewed tree digest mismatch"
        )

    if report.get("report_digest") != canonical_digest(report_core(report)):
        errors.append("requirement transition report digest mismatch")

    mappings = report.get("mappings")
    if not isinstance(mappings, list):
        errors.append("requirement transition mappings must be an array")
        mappings = []

    if report.get("mapping_count") != len(mappings):
        errors.append("requirement transition mapping_count mismatch")

    current = {
        item["requirement_id"]: item
        for item in snapshot()
    }
    mapped_new: set[str] = set()
    changed_count = 0

    for index, mapping in enumerate(mappings):
        prefix = f"requirement transition mappings[{index}]"
        if not isinstance(mapping, dict):
            errors.append(prefix + " must be an object")
            continue
        new_id = mapping.get("new_requirement_id")
        if not isinstance(new_id, str) or new_id not in current:
            errors.append(prefix + " references unknown final requirement ID")
            continue
        if new_id in mapped_new:
            errors.append(prefix + " duplicates final requirement ID")
        mapped_new.add(new_id)
        if mapping.get("new_text_digest") != current[new_id]["text_digest"]:
            errors.append(prefix + " final text digest mismatch")
        if (
            mapping.get("document_path")
            != current[new_id]["document_path"]
        ):
            errors.append(prefix + " final document_path mismatch")
        if mapping.get("old_requirement_id") != new_id:
            changed_count += 1

    if mapped_new != set(current):
        errors.append(
            "requirement transition does not cover the complete final corpus"
        )
    if report.get("changed_requirement_id_count") != changed_count:
        errors.append(
            "requirement transition changed_requirement_id_count mismatch"
        )

    return sorted(set(errors))
