#!/usr/bin/env python3
"""Plan or apply the E2EESA 0.9 -> 1.0 version promotion.

Dry-run is always allowed when engineering readiness passes.
--apply is review-gated and refuses to mutate the tree until the independent
review package satisfies the PR 49 completion gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release"
REVIEW = ROOT / "review"
SCRIPTS = ROOT / "scripts"
for path in (RELEASE, REVIEW, SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import final_release
import validate_1_0_readiness
import validate_review


TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".py",
    ".yml",
    ".yaml",
    ".sql",
    ".toml",
    ".txt",
}


def load_json(rel: str) -> dict:
    value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(rel + " must contain an object")
    return value


def write_json(rel: str, value: dict) -> None:
    (ROOT / rel).write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def transition_policy() -> dict:
    return load_json("release/1.0.0-finalization.json")


def transition_paths(policy: dict) -> list[Path]:
    historical = set(policy["historical_version_paths"])
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
    paths: set[Path] = set()

    for relroot in roots:
        base = ROOT / relroot
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if (
                path.is_file()
                and path.suffix in TEXT_SUFFIXES
                and "__pycache__" not in path.parts
            ):
                rel = path.relative_to(ROOT).as_posix()
                if rel not in historical:
                    paths.add(path)

    readme = ROOT / "README.md"
    if readme.is_file():
        paths.add(readme)

    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def planned_replacements(policy: dict) -> list[dict]:
    old = policy["pre_1_0_standard_version"]
    new = policy["final_standard_version"]
    plan: list[dict] = []

    for path in transition_paths(policy):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        count = text.count(old)
        if count:
            plan.append(
                {
                    "path": path.relative_to(ROOT).as_posix(),
                    "occurrences": count,
                    "from": old,
                    "to": new,
                }
            )
    return plan


def preflight_promotion(policy: dict) -> list[str]:
    errors: list[str] = []

    version_path = ROOT / "VERSION"
    current_version = (
        version_path.read_text(encoding="utf-8").strip()
        if version_path.is_file()
        else ""
    )
    if current_version != policy["source_candidate"]["release_version"]:
        errors.append(
            "promotion preflight requires VERSION "
            + policy["source_candidate"]["release_version"]
        )

    workflow = (ROOT / ".github/workflows/validate.yml").read_text(
        encoding="utf-8"
    )
    if "Validate 0.9 candidate freeze" not in workflow:
        errors.append("promotion preflight cannot find candidate workflow step")

    validator = (ROOT / "scripts/validate_repo.py").read_text(
        encoding="utf-8"
    )
    if "CANDIDATE_VERSION = re.compile" not in validator:
        errors.append("promotion preflight cannot find candidate VERSION marker")
    if "release_candidate.validate_release(root)" not in validator:
        errors.append("promotion preflight cannot find candidate release gate")
    if "STABLE_VERSION.fullmatch(version)" in validator:
        errors.append("promotion preflight found an already-promoted VERSION gate")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if (
        "E2EESA 0.9 release candidate" not in readme
        or "0.9.0-rc.1" not in readme
    ):
        errors.append("promotion preflight cannot find candidate README status")

    if not (ROOT / "INDEPENDENT-REVIEW-PENDING.md").is_file():
        errors.append("promotion preflight requires the pending-review notice")

    if not planned_replacements(policy):
        errors.append(
            "promotion preflight found no active pre-1.0 standard-version markers"
        )

    return sorted(set(errors))


def patch_repository_version_validation() -> None:
    path = ROOT / "scripts" / "validate_repo.py"
    text = path.read_text(encoding="utf-8")

    if "STABLE_VERSION = re.compile" not in text:
        marker = (
            'CANDIDATE_VERSION = re.compile(r"^0\\.9\\.0-rc\\.[0-9]+$")'
        )
        replacement = (
            marker
            + '\nSTABLE_VERSION = re.compile(r"^1\\.0\\.0$")'
        )
        if marker not in text:
            raise RuntimeError(
                "validate_repo.py candidate version marker not found"
            )
        text = text.replace(marker, replacement)

    old_check = (
        "if not (DEV_VERSION.fullmatch(version) or "
        "CANDIDATE_VERSION.fullmatch(version)):\n"
        '            errors.append("VERSION must use x.y.z-dev or the '
        '0.9.0-rc.N candidate line before 1.0")'
    )
    new_check = (
        "if not (DEV_VERSION.fullmatch(version) or "
        "CANDIDATE_VERSION.fullmatch(version) or "
        "STABLE_VERSION.fullmatch(version)):\n"
        '            errors.append("VERSION must use x.y.z-dev, '
        '0.9.0-rc.N, or 1.0.0")'
    )
    if old_check in text:
        text = text.replace(old_check, new_check)
    elif "STABLE_VERSION.fullmatch(version)" not in text:
        raise RuntimeError(
            "validate_repo.py VERSION acceptance block did not match expected source"
        )

    old_release_gate = '''    errors.extend(
        "release candidate: " + error
        for error in release_candidate.validate_release(root)
    )
'''
    new_release_gate = '''    current_release_version = (
        (root / "VERSION").read_text(encoding="utf-8").strip()
        if (root / "VERSION").is_file()
        else ""
    )
    if current_release_version.startswith("0.9.0-rc."):
        errors.extend(
            "release candidate: " + error
            for error in release_candidate.validate_release(root)
        )
'''
    if old_release_gate in text:
        text = text.replace(old_release_gate, new_release_gate)
    elif 'current_release_version.startswith("0.9.0-rc.")' not in text:
        raise RuntimeError(
            "validate_repo.py release-candidate gate did not match expected source"
        )

    path.write_text(text, encoding="utf-8")


def patch_validation_workflow() -> None:
    path = ROOT / ".github" / "workflows" / "validate.yml"
    text = path.read_text(encoding="utf-8")
    old = '''      - name: Validate 0.9 candidate freeze
        run: python scripts/release_candidate.py
'''
    new = '''      - name: Validate 1.0 final release
        run: python release/final_release.py
'''
    if old not in text:
        raise RuntimeError("0.9 candidate workflow validation step not found")
    path.write_text(text.replace(old, new), encoding="utf-8")


def patch_readme() -> None:
    path = ROOT / "README.md"
    text = path.read_text(encoding="utf-8")
    old = (
        "E2EESA 0.9 release candidate (`0.9.0-rc.1`). The candidate is "
        "frozen for independent expert review before the 1.0 decision. "
        "No profile in this repository should yet be interpreted as an End "
        "To End Everywhere certification claim."
    )
    new = (
        "E2EESA 1.0.0 stable release. The 1.0 release was promoted only "
        "after the independent expert-review gate and final release "
        "validation passed. Conformance to this architecture standard does "
        "not by itself constitute an End To End Everywhere product "
        "certification."
    )
    if old in text:
        text = text.replace(old, new)
    elif "E2EESA 1.0.0 stable release." not in text:
        raise RuntimeError(
            "README candidate status did not match expected source"
        )
    path.write_text(text, encoding="utf-8")


def mark_readiness_complete() -> None:
    readiness = load_json("release/1.0.0-readiness.json")
    readiness["engineering_status"] = "ready-for-final-promotion"
    readiness["external_review_status"] = "complete"
    for gate in readiness.get("external_gates", []):
        if (
            isinstance(gate, dict)
            and gate.get("gate_id") == "independent-expert-review"
        ):
            gate["status"] = "complete"
    write_json("release/1.0.0-readiness.json", readiness)


def replace_review_pending_notice() -> None:
    package = load_json("review/independent-review.json")
    completion = package["completion"]

    pending = ROOT / "INDEPENDENT-REVIEW-PENDING.md"
    if pending.exists():
        pending.unlink()

    complete = ROOT / "INDEPENDENT-REVIEW-COMPLETE.md"
    complete.write_text(
        "# Independent Expert Review Complete\n\n"
        "E2EESA 1.0 promotion is based on a completed independent expert review.\n\n"
        "## Review identity\n\n"
        f"- Final reviewed tree digest: {completion.get('final_reviewed_tree_digest')}\n"
        f"- Final reviewed commit: {completion.get('final_reviewed_commit')}\n"
        f"- Review summary digest: {completion.get('summary_digest')}\n"
        f"- Review summary reference: {completion.get('summary_reference')}\n\n"
        "Detailed reviewer attestations, findings, dispositions, and the "
        "combined review package are retained under the review directory.\n",
        encoding="utf-8",
    )


def generate_release_notes() -> None:
    package = load_json("review/independent-review.json")
    completion = package["completion"]
    reviewers = package.get("reviewers", [])
    organizations = {
        item.get("organization_id")
        for item in reviewers
        if isinstance(item, dict)
    }
    domains = sorted(
        {
            domain
            for item in reviewers
            if isinstance(item, dict)
            for domain in item.get("domains", [])
        }
    )
    findings = [
        item
        for item in package.get("findings", [])
        if isinstance(item, dict)
    ]
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity"))
        counts[severity] = counts.get(severity, 0) + 1

    notes = f"""# E2EESA 1.0.0 Release Notes

## Release status

E2EESA 1.0.0 is the first stable release of the End To End Everywhere
Security Architecture Standard.

## Source candidate

- Candidate: 0.9.0-rc.1
- Candidate digest: sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2

## Independent review

- Independent reviewers: {len(reviewers)}
- Independent organizations: {len(organizations)}
- Review domains: {", ".join(domains)}
- Final reviewed tree digest: {completion.get("final_reviewed_tree_digest")}
- Final reviewed commit: {completion.get("final_reviewed_commit")}
- Review summary digest: {completion.get("summary_digest")}
- Review summary reference: {completion.get("summary_reference")}
- Findings by severity: {json.dumps(counts, sort_keys=True)}

All blocker, critical, and high findings satisfy the PR 49 completion gate.
All medium findings have a reviewer-accepted disposition.

## Final release provenance

The final release manifest is stored at `release/1.0.0-manifest.json`.
Its final tree digest and file count are generated after version promotion.

## Version transition

The E2EESA release version and active `standard_version` basis are 1.0.0.
Independently versioned profile, registry, and schema versions retain their
own versions unless separately changed by an accepted review fix.

## Security and certification boundary

Conformance to E2EESA 1.0.0 does not by itself constitute an End To End
Everywhere product certification. Certification remains scope-, evidence-,
version-, and lifecycle-specific.
"""
    (ROOT / "release" / "1.0.0-RELEASE-NOTES.md").write_text(
        notes, encoding="utf-8"
    )


def apply_promotion(policy: dict) -> None:
    preflight = preflight_promotion(policy)
    if preflight:
        raise RuntimeError(
            "promotion preflight failed: " + "; ".join(preflight)
        )

    engineering = validate_1_0_readiness.engineering_errors()
    if engineering:
        raise RuntimeError(
            "engineering readiness failed: " + "; ".join(engineering)
        )

    package = load_json("review/independent-review.json")
    review_errors = validate_review.completion_errors(package, ROOT)
    if review_errors:
        raise RuntimeError(
            "independent review is incomplete: " + "; ".join(review_errors)
        )

    old = policy["pre_1_0_standard_version"]
    new = policy["final_standard_version"]
    for item in planned_replacements(policy):
        path = ROOT / item["path"]
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace(old, new), encoding="utf-8")

    (ROOT / "VERSION").write_text("1.0.0\n", encoding="utf-8")
    patch_repository_version_validation()
    patch_validation_workflow()
    patch_readme()
    mark_readiness_complete()
    generate_release_notes()
    replace_review_pending_notice()

    residual = final_release.residual_pre_1_0_occurrences(policy)
    if residual:
        raise RuntimeError(
            "promotion left unclassified pre-1.0 version occurrences: "
            + ", ".join(residual)
        )

    manifest = final_release.build_manifest(policy)
    path = ROOT / policy["final_manifest"]["path"]
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    final_errors = final_release.validate_final_release()
    if final_errors:
        raise RuntimeError(
            "post-promotion final release validation failed: "
            + "; ".join(final_errors)
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the promotion; requires completed independent review",
    )
    args = parser.parse_args()

    policy = transition_policy()
    engineering = validate_1_0_readiness.engineering_errors()
    if engineering:
        for error in engineering:
            print("ERROR:", error)
        return 1

    preflight = preflight_promotion(policy)
    if preflight:
        for error in preflight:
            print("ERROR:", error)
        return 1

    plan = planned_replacements(policy)
    print(
        "E2EESA 1.0 promotion plan:",
        len(plan),
        "files contain active",
        policy["pre_1_0_standard_version"],
        "version markers.",
    )
    for item in plan:
        print(
            f"  {item['path']}: {item['occurrences']} replacement(s)"
        )

    if not args.apply:
        review_errors = validate_1_0_readiness.external_review_errors()
        if review_errors:
            print()
            print(
                "PLACEHOLDER_GATE: independent expert review remains pending. "
                "The promotion plan is ready, but no release files were "
                "mutated."
            )
            print(
                "Final apply will unlock automatically after "
                "review/validate_review.py --require-complete passes."
            )
        else:
            print()
            print("Independent review is complete; --apply is permitted.")
        return 0

    try:
        apply_promotion(policy)
    except RuntimeError as exc:
        print("ERROR:", exc)
        return 1

    print(
        "Applied E2EESA 1.0 version promotion and wrote final release "
        "manifest. Run python release/final_release.py and the full "
        "repository validation suite before tagging."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
