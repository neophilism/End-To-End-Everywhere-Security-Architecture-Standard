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
    "spec/normative-language.md",
    "spec/terminology.md",
    "adr/0000-template.md",
    "profiles/README.md",
    "schemas/profile.schema.json",
    "schemas/terminology.schema.json",
    "registry/terminology.json",
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


def validate_terminology(data: dict, source: str = "<terminology>") -> list[str]:
    errors: list[str] = []
    allowed_top = {"schema_version", "terms"}
    extras = sorted(set(data) - allowed_top)
    if extras:
        errors.append(f"{source}: unknown top-level fields: {', '.join(extras)}")

    if data.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    terms = data.get("terms")
    if not isinstance(terms, list) or not terms:
        errors.append(f"{source}: terms must be a non-empty array")
        return errors

    seen_ids: set[str] = set()
    seen_terms: set[str] = set()
    allowed_fields = {"id", "term", "definition", "aliases", "notes"}

    for index, entry in enumerate(terms):
        prefix = f"{source}: terms[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix}: term entry must be an object")
            continue

        missing = sorted({"id", "term", "definition"} - entry.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields: {', '.join(missing)}")

        entry_extras = sorted(set(entry) - allowed_fields)
        if entry_extras:
            errors.append(f"{prefix}: unknown fields: {', '.join(entry_extras)}")

        term_id = entry.get("id")
        if not isinstance(term_id, str) or not PROFILE_ID.fullmatch(term_id):
            errors.append(f"{prefix}: invalid id")
        elif term_id in seen_ids:
            errors.append(f"{prefix}: duplicate id: {term_id}")
        else:
            seen_ids.add(term_id)

        term = entry.get("term")
        if not isinstance(term, str) or not term.strip():
            errors.append(f"{prefix}: term must be a non-empty string")
        else:
            folded = term.casefold()
            if folded in seen_terms:
                errors.append(f"{prefix}: duplicate term label: {term}")
            else:
                seen_terms.add(folded)

        definition = entry.get("definition")
        if not isinstance(definition, str) or not definition.strip():
            errors.append(f"{prefix}: definition must be a non-empty string")

        if "aliases" in entry and not validate_string_list(entry["aliases"]):
            errors.append(f"{prefix}: aliases must be a unique array of non-empty strings")

        if "notes" in entry and not isinstance(entry["notes"], str):
            errors.append(f"{prefix}: notes must be a string")

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

    for schema_rel in ("schemas/profile.schema.json", "schemas/terminology.schema.json"):
        schema_path = root / schema_rel
        if schema_path.is_file():
            schema = load_json(schema_path)
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                errors.append(f"{schema_rel}: must declare JSON Schema Draft 2020-12")
            if schema.get("additionalProperties") is not False:
                errors.append(f"{schema_rel}: must reject unknown top-level properties")

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

    normative_path = root / "spec/normative-language.md"
    if normative_path.is_file():
        normative = normative_path.read_text(encoding="utf-8")
        for required_text in ("**Status:** Normative", "RFC 2119", "RFC 8174", "MUST", "SHOULD", "MAY"):
            if required_text not in normative:
                errors.append(f"normative-language.md missing required marker: {required_text}")

    terminology_path = root / "spec/terminology.md"
    if terminology_path.is_file():
        terminology = terminology_path.read_text(encoding="utf-8")
        for heading in (
            "## 1. Actors and system boundaries",
            "## 3. End-to-end encryption",
            "## 5. Security properties",
            "## 6. Compromise and recovery",
            "## 8. Assurance and lifecycle",
            "## 9. Threat-model terms",
        ):
            if heading not in terminology:
                errors.append(f"terminology.md missing required section: {heading}")

    registry_path = root / "registry/terminology.json"
    if registry_path.is_file():
        errors.extend(validate_terminology(load_json(registry_path), "registry/terminology.json"))

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
