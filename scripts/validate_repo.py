#!/usr/bin/env python3
"""Repository-level validation for E2EESA foundation artifacts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PATHS = [
    "README.md",
    "VERSION",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "spec/README.md",
    "adr/0000-template.md",
    "profiles/README.md",
    "schemas/profile.schema.json",
]

VALID_STATUSES = {
    "recommended",
    "allowed",
    "legacy",
    "deprecated",
    "prohibited",
    "provisional",
    "experimental",
}
VALID_DECISION_CLASSES = {"invariant", "profile-choice", "capability", "experimental"}
PROFILE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
DEV_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-dev$")


class ValidationError(Exception):
    pass


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{path}: top-level JSON value must be an object")
    return value


def validate_string_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and bool(item) for item in value)
        and len(value) == len(set(value))
    )


def validate_profile(data: dict, source: str = "<profile>") -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "profile_id",
        "profile_version",
        "status",
        "decision_class",
        "security_properties",
    }
    missing = sorted(required - data.keys())
    if missing:
        errors.append(f"{source}: missing required fields: {', '.join(missing)}")

    if data.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    profile_id = data.get("profile_id")
    if not isinstance(profile_id, str) or not PROFILE_ID.fullmatch(profile_id):
        errors.append(f"{source}: invalid profile_id")

    version = data.get("profile_version")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        errors.append(f"{source}: invalid profile_version")

    if data.get("status") not in VALID_STATUSES:
        errors.append(f"{source}: invalid status")

    if data.get("decision_class") not in VALID_DECISION_CLASSES:
        errors.append(f"{source}: invalid decision_class")

    if not validate_string_list(data.get("security_properties")):
        errors.append(f"{source}: security_properties must be a unique array of non-empty strings")

    allowed = required | {"requires", "incompatible_with", "notes"}
    extras = sorted(set(data) - allowed)
    if extras:
        errors.append(f"{source}: unknown fields: {', '.join(extras)}")

    for name in ("requires", "incompatible_with"):
        if not validate_string_list(data.get(name, [])):
            errors.append(f"{source}: {name} must be a unique array of non-empty strings")

    if "notes" in data and not isinstance(data["notes"], str):
        errors.append(f"{source}: notes must be a string")

    return errors


def validate_repository(root: Path = ROOT) -> list[str]:
    errors: list[str] = []

    for rel in REQUIRED_PATHS:
        if not (root / rel).is_file():
            errors.append(f"missing required file: {rel}")

    version_path = root / "VERSION"
    if version_path.is_file():
        version = version_path.read_text(encoding="utf-8").strip()
        if not DEV_VERSION.fullmatch(version):
            errors.append("VERSION must use x.y.z-dev during pre-1.0 foundation development")

    schema_path = root / "schemas/profile.schema.json"
    if schema_path.is_file():
        schema = load_json(schema_path)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append("profile schema must declare JSON Schema Draft 2020-12")
        if schema.get("additionalProperties") is not False:
            errors.append("profile schema must reject unknown properties")

    adr_path = root / "adr/0000-template.md"
    if adr_path.is_file():
        adr = adr_path.read_text(encoding="utf-8")
        for heading in (
            "## Context",
            "## Serious alternatives considered",
            "## Decision",
            "## Security consequences",
            "## Compatibility constraints",
            "## Evidence and references",
            "## Reconsideration triggers",
        ):
            if heading not in adr:
                errors.append(f"ADR template missing heading: {heading}")

    valid_dir = root / "fixtures/profiles/valid"
    for path in sorted(valid_dir.glob("*.json")) if valid_dir.exists() else []:
        errors.extend(validate_profile(load_json(path), str(path.relative_to(root))))

    invalid_dir = root / "fixtures/profiles/invalid"
    for path in sorted(invalid_dir.glob("*.json")) if invalid_dir.exists() else []:
        result = validate_profile(load_json(path), str(path.relative_to(root)))
        if not result:
            errors.append(f"{path.relative_to(root)}: invalid fixture unexpectedly passed validation")

    return errors


def main() -> int:
    try:
        errors = validate_repository()
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("E2EESA repository validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
