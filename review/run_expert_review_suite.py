#!/usr/bin/env python3
"""Run the reproducible automated portion of an independent E2EESA review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

CANDIDATE_RELEASE = "0.9.0-rc.1"
CANDIDATE_TREE_DIGEST = "sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2"
CANDIDATE_FILE_COUNT = 645

COMMANDS = [
    {
        "id": "repository-invariants",
        "argv": [sys.executable, "scripts/validate_repo.py"],
        "purpose": "Validate repository-wide E2EESA invariants.",
    },
    {
        "id": "candidate-freeze",
        "argv": [sys.executable, "scripts/release_candidate.py"],
        "purpose": "Verify the exact 0.9.0-rc.1 frozen candidate.",
    },
    {
        "id": "unit-tests",
        "argv": [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        "purpose": "Run the complete repository unit-test suite.",
    },
    {
        "id": "seeded-adversarial-reference-checks",
        "argv": [
            sys.executable,
            "scripts/run_reference_security_checks.py",
            "--seed",
            "20261007",
            "--iterations",
            "1000",
        ],
        "purpose": "Run deterministic seeded adversarial reference checks.",
    },
    {
        "id": "review-package-structure",
        "argv": [sys.executable, "review/validate_review.py"],
        "purpose": "Validate the current review package structure without pretending review is complete.",
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


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


def command_plan() -> list[dict[str, Any]]:
    return [
        {
            "id": item["id"],
            "argv": item["argv"],
            "purpose": item["purpose"],
        }
        for item in COMMANDS
    ]


def run_command(item: dict[str, Any]) -> dict[str, Any]:
    started = utc_now()
    proc = subprocess.run(
        item["argv"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )
    finished = utc_now()
    return {
        "id": item["id"],
        "purpose": item["purpose"],
        "argv": item["argv"],
        "started_at": started,
        "finished_at": finished,
        "return_code": proc.returncode,
        "passed": proc.returncode == 0,
        "stdout_sha256": sha256_text(proc.stdout),
        "stderr_sha256": sha256_text(proc.stderr),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def build_report(reviewer_id: str | None, organization_id: str | None) -> dict[str, Any]:
    started = utc_now()
    results = [run_command(item) for item in COMMANDS]
    report: dict[str, Any] = {
        "schema_version": "0.1",
        "evidence_kind": "automated-review-support",
        "candidate": {
            "release_version": CANDIDATE_RELEASE,
            "tree_digest": CANDIDATE_TREE_DIGEST,
            "file_count": CANDIDATE_FILE_COUNT,
        },
        "reviewer_id": reviewer_id,
        "organization_id": organization_id,
        "started_at": started,
        "finished_at": utc_now(),
        "environment": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "human_review_required": True,
        "human_review_note": (
            "Passing automated checks is supporting evidence only. It does not satisfy "
            "the independent cryptography/protocol, implementation, privacy, supply-chain, "
            "or conformance review requirements."
        ),
        "all_automated_checks_passed": all(item["passed"] for item in results),
        "commands": results,
        "report_digest": "",
    }
    report["report_digest"] = canonical_digest(
        {key: value for key, value in report.items() if key != "report_digest"}
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reviewer-id")
    parser.add_argument("--organization-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Print the commands that would run, without executing them.",
    )
    args = parser.parse_args()

    if args.plan:
        print(json.dumps(
            {
                "candidate_release": CANDIDATE_RELEASE,
                "candidate_tree_digest": CANDIDATE_TREE_DIGEST,
                "commands": command_plan(),
            },
            indent=2,
            ensure_ascii=False,
        ))
        return 0

    report = build_report(args.reviewer_id, args.organization_id)
    rendered = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"

    if args.output:
        output = args.output
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(f"Wrote review evidence: {output.relative_to(ROOT)}")
    else:
        print(rendered, end="")

    print("report_digest:", report["report_digest"])
    return 0 if report["all_automated_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
