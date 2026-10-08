#!/usr/bin/env python3
"""Validate the external expert review package for E2EESA PR 49."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import standards_crosswalk

REQUIRED_DOMAINS = {
    "cryptography-protocols",
    "implementation-security",
    "supply-chain-development",
    "privacy-metadata-recovery",
    "conformance-standards",
}
SEVERITIES = {"blocker", "critical", "high", "medium", "low", "informational"}
BLOCKING_SEVERITIES = {"blocker", "critical", "high"}
FINDING_STATES = {"open", "fixed", "deferred", "rejected"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def known_requirement_ids(root: Path) -> set[str]:
    return {
        item["requirement_id"]
        for item in standards_crosswalk.extract_requirements(root)
    }


def validate_package(package: dict, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    if package.get("schema_version") != "0.1":
        errors.append("review package schema_version must be 0.1")

    candidate = package.get("candidate")
    if not isinstance(candidate, dict):
        errors.append("review candidate must be an object")
    else:
        if candidate.get("release_version") != "0.9.0-rc.1":
            errors.append("review package candidate release_version mismatch")
        if candidate.get("tree_digest") != "sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2":
            errors.append("review package candidate tree_digest mismatch")
        if candidate.get("file_count") != 645:
            errors.append("review package candidate file_count mismatch")

    status = package.get("status")
    if status not in {
        "awaiting-review", "review-in-progress", "findings-open", "ready-for-1.0"
    }:
        errors.append(f"invalid review status {status}")

    reviewers = package.get("reviewers")
    if not isinstance(reviewers, list):
        errors.append("reviewers must be an array")
        reviewers = []

    reviewer_ids: set[str] = set()
    organizations: set[str] = set()
    covered_domains: set[str] = set()
    crypto_reviewers = 0
    for index, reviewer in enumerate(reviewers):
        prefix = f"reviewers[{index}]"
        if not isinstance(reviewer, dict):
            errors.append(f"{prefix} must be an object")
            continue
        reviewer_id = reviewer.get("reviewer_id")
        if not isinstance(reviewer_id, str) or not reviewer_id:
            errors.append(f"{prefix}.reviewer_id must be non-empty")
        elif reviewer_id in reviewer_ids:
            errors.append(f"{prefix} duplicate reviewer_id {reviewer_id}")
        else:
            reviewer_ids.add(reviewer_id)

        organization = reviewer.get("organization_id")
        if not isinstance(organization, str) or not organization:
            errors.append(f"{prefix}.organization_id must be non-empty")
        else:
            organizations.add(organization)

        if reviewer.get("independent_from_maintainers") is not True:
            errors.append(f"{prefix} must be independent from maintainers")

        domains = reviewer.get("domains")
        if (
            not isinstance(domains, list)
            or not domains
            or len(domains) != len(set(domains))
        ):
            errors.append(f"{prefix}.domains must be a unique non-empty array")
            domains = []
        unknown_domains = sorted(set(domains) - REQUIRED_DOMAINS)
        if unknown_domains:
            errors.append(
                f"{prefix} has unknown domains: " + ", ".join(unknown_domains)
            )
        covered_domains.update(set(domains) & REQUIRED_DOMAINS)
        if "cryptography-protocols" in domains:
            crypto_reviewers += 1

        digest = reviewer.get("attestation_digest")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            errors.append(f"{prefix}.attestation_digest must be sha256")
        reference = reviewer.get("attestation_reference")
        if not isinstance(reference, str) or not reference:
            errors.append(f"{prefix}.attestation_reference must be non-empty")

    findings = package.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        findings = []
    finding_ids: set[str] = set()
    known_requirements = known_requirement_ids(root)
    for index, finding in enumerate(findings):
        prefix = f"findings[{index}]"
        if not isinstance(finding, dict):
            errors.append(f"{prefix} must be an object")
            continue
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            errors.append(f"{prefix}.finding_id must be non-empty")
        elif finding_id in finding_ids:
            errors.append(f"{prefix} duplicate finding_id {finding_id}")
        else:
            finding_ids.add(finding_id)

        if finding.get("reviewer_id") not in reviewer_ids:
            errors.append(f"{prefix} references unknown reviewer_id")
        if finding.get("severity") not in SEVERITIES:
            errors.append(f"{prefix} has invalid severity")
        state = finding.get("status")
        if state not in FINDING_STATES:
            errors.append(f"{prefix} has invalid status")

        for field in ("title", "analysis", "recommendation"):
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                errors.append(f"{prefix}.{field} must be non-empty")

        reqs = finding.get("affected_requirement_ids")
        if not isinstance(reqs, list) or len(reqs) != len(set(reqs)):
            errors.append(f"{prefix}.affected_requirement_ids must be unique")
            reqs = []
        unknown_reqs = sorted(set(reqs) - known_requirements)
        if unknown_reqs:
            errors.append(
                f"{prefix} references unknown requirement IDs: "
                + ", ".join(unknown_reqs)
            )

        paths = finding.get("affected_paths")
        if not isinstance(paths, list) or len(paths) != len(set(paths)):
            errors.append(f"{prefix}.affected_paths must be unique")
            paths = []
        for rel in paths:
            if not isinstance(rel, str) or not rel or not (root / rel).exists():
                errors.append(f"{prefix} references missing affected path {rel}")

        rationale = finding.get("disposition_rationale")
        fix_ref = finding.get("fix_reference")
        accepted = finding.get("reviewer_acceptance")
        if state == "open":
            if rationale is not None or fix_ref is not None or accepted is not None:
                errors.append(f"{prefix} open finding must not claim disposition/fix")
        elif state == "fixed":
            if not isinstance(rationale, str) or not rationale.strip():
                errors.append(f"{prefix} fixed finding requires disposition_rationale")
            if not isinstance(fix_ref, str) or not fix_ref:
                errors.append(f"{prefix} fixed finding requires fix_reference")
            if accepted is not True:
                errors.append(f"{prefix} fixed finding requires reviewer_acceptance=true")
        elif state in {"deferred", "rejected"}:
            if not isinstance(rationale, str) or not rationale.strip():
                errors.append(f"{prefix} {state} finding requires disposition_rationale")
            if accepted is not True:
                errors.append(f"{prefix} {state} finding requires reviewer_acceptance=true")

    completion = package.get("completion")
    if not isinstance(completion, dict):
        errors.append("completion must be an object")
    else:
        complete = completion.get("review_complete")
        if not isinstance(complete, bool):
            errors.append("completion.review_complete must be boolean")
        if complete:
            for field in ("completed_at", "summary_digest", "summary_reference"):
                value = completion.get(field)
                if not isinstance(value, str) or not value:
                    errors.append(f"completed review requires {field}")
            if isinstance(completion.get("summary_digest"), str) and not SHA256_RE.fullmatch(completion["summary_digest"]):
                errors.append("completion.summary_digest must be sha256")
        else:
            if any(
                completion.get(field) is not None
                for field in ("completed_at", "summary_digest", "summary_reference")
            ):
                errors.append("incomplete review must not claim completion artifacts")

    return sorted(set(errors))


def completion_errors(package: dict, root: Path = ROOT) -> list[str]:
    errors = validate_package(package, root)
    reviewers = package.get("reviewers", [])
    findings = package.get("findings", [])
    completion = package.get("completion", {})

    independent_reviewers = [
        item for item in reviewers
        if isinstance(item, dict) and item.get("independent_from_maintainers") is True
    ]
    organizations = {
        item.get("organization_id")
        for item in independent_reviewers
        if isinstance(item.get("organization_id"), str)
    }
    domains = {
        domain
        for item in independent_reviewers
        for domain in item.get("domains", [])
        if isinstance(domain, str)
    }

    if len(independent_reviewers) < 3:
        errors.append("PR 49 completion requires at least three independent reviewers")
    if len(organizations) < 2:
        errors.append("PR 49 completion requires at least two independent reviewer organizations")
    missing_domains = sorted(REQUIRED_DOMAINS - domains)
    if missing_domains:
        errors.append(
            "PR 49 completion lacks review domains: " + ", ".join(missing_domains)
        )
    if not any(
        "cryptography-protocols" in item.get("domains", [])
        for item in independent_reviewers
    ):
        errors.append("PR 49 completion requires independent cryptography/protocol review")

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = finding.get("severity")
        state = finding.get("status")
        if severity in BLOCKING_SEVERITIES and state != "fixed":
            errors.append(
                f"blocking finding {finding.get('finding_id')} must be fixed"
            )
        if severity == "medium" and state == "open":
            errors.append(
                f"medium finding {finding.get('finding_id')} must be dispositioned"
            )

    if package.get("status") != "ready-for-1.0":
        errors.append("review package status must be ready-for-1.0")
    if completion.get("review_complete") is not True:
        errors.append("review completion attestation is missing")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--package",
        type=Path,
        default=ROOT / "review" / "independent-review.json",
    )
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()

    package = load_json(args.package)
    errors = (
        completion_errors(package, ROOT)
        if args.require_complete
        else validate_package(package, ROOT)
    )
    if errors:
        for error in errors:
            print("ERROR:", error)
        return 1
    print(
        "Independent review package complete."
        if args.require_complete
        else "Independent review package structurally valid."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
