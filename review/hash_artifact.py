#!/usr/bin/env python3
"""Print a content-addressed SHA-256 identity for an external review artifact."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()

    if not args.artifact.is_file():
        parser.error("artifact must be an existing file")

    digest = hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    print("sha256:" + digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
