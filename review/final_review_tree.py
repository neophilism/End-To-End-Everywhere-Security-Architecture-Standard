#!/usr/bin/env python3
"""Compute the exact E2EESA standard tree identity for post-fix reviewer acceptance."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import release_candidate


def main() -> int:
    policy = json.loads(
        (ROOT / "registry/release-candidate.json").read_text(encoding="utf-8")
    )
    manifest = release_candidate.build_manifest(ROOT, policy)
    print("release_version:", policy["release_version"])
    print("file_count:", manifest["file_count"])
    print("tree_digest:", manifest["tree_digest"])
    print(
        "Use this tree_digest as completion.final_reviewed_tree_digest and "
        "in every reviewer final acceptance after the fixes have been reviewed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
