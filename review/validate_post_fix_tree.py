#!/usr/bin/env python3
"""Validate a review-fixed E2EESA tree without pretending it is still rc.1."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import release_candidate
import validate_repo

EXPECTED_RC_DRIFT = (
    "release candidate: release candidate frozen-file manifest differs "
    "from working tree"
)


def post_fix_errors(root: Path = ROOT) -> list[str]:
    try:
        errors = validate_repo.validate_repository(root)
    except validate_repo.ValidationError as exc:
        return [str(exc)]

    return sorted(
        error
        for error in errors
        if error != EXPECTED_RC_DRIFT
    )


def current_tree_identity(root: Path = ROOT) -> dict:
    policy = validate_repo.load_json(root / "registry/release-candidate.json")
    return release_candidate.build_manifest(root, policy)


def main() -> int:
    errors = post_fix_errors(ROOT)
    if errors:
        for error in errors:
            print("ERROR:", error)
        return 1

    identity = current_tree_identity(ROOT)
    print("Post-fix repository invariants passed.")
    print(
        "The original rc.1 manifest may differ by design after review fixes; "
        "no other repository invariant failures are permitted."
    )
    print("file_count:", identity["file_count"])
    print("tree_digest:", identity["tree_digest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
