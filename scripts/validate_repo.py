#!/usr/bin/env python3
"""Repository-level validation for E2EESA standard artifacts."""

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
    "spec/threat-model.md",
    "adr/0000-template.md",
    "profiles/README.md",
    "schemas/profile.schema.json",
    "schemas/terminology.schema.json",
    "schemas/threat-model.schema.json",
    "registry/terminology.json",
    "registry/threat-model.json",
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
THREAT_CATEGORIES = {
    "network",
    "service",
    "identity",
    "endpoint",
    "physical",
    "insider",
    "software-supply-chain",
    "recovery",
    "storage",
    "hardware",
    "directory",
    "metadata",
    "availability",
    "state",
    "cryptographic-environment",
    "quantum",
}
REQUIRED_THREAT_IDS = {
    "TM-NET-PASSIVE",
    "TM-NET-ACTIVE",
    "TM-SERVICE-READ",
    "TM-SERVICE-ACTIVE",
    "TM-ACCOUNT",
    "TM-CREDENTIAL",
    "TM-ENDPOINT-STATE",
    "TM-ENDPOINT-LIVE",
    "TM-DEVICE-PHYSICAL",
    "TM-INSIDER",
    "TM-UPDATE",
    "TM-SUPPLY-CHAIN",
    "TM-SIGNING-KEY",
    "TM-RECOVERY",
    "TM-BACKUP",
    "TM-HARDWARE",
    "TM-DIRECTORY",
    "TM-METADATA",
    "TM-DOS",
    "TM-ROLLBACK",
    "TM-RNG",
    "TM-CLOCK",
    "TM-QUANTUM-HARVEST",
    "TM-QUANTUM-ACTIVE",
}

PROFILE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
THREAT_ID = re.compile(r"^TM-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
COMPOSITE_ID = re.compile(r"^CS-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
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


def validate_string_list(value: object, *, min_items: int = 0) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
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


def validate_threat_model(data: dict, source: str = "<threat-model>") -> list[str]:
    errors: list[str] = []
    allowed_top = {"schema_version", "threats", "composite_scenarios"}
    extras = sorted(set(data) - allowed_top)
    if extras:
        errors.append(f"{source}: unknown top-level fields: {', '.join(extras)}")

    if data.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    threats = data.get("threats")
    if not isinstance(threats, list) or not threats:
        errors.append(f"{source}: threats must be a non-empty array")
        return errors

    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    allowed_threat_fields = {"id", "name", "category", "description", "capabilities", "notes"}

    for index, threat in enumerate(threats):
        prefix = f"{source}: threats[{index}]"
        if not isinstance(threat, dict):
            errors.append(f"{prefix}: threat entry must be an object")
            continue

        missing = sorted({"id", "name", "category", "description", "capabilities"} - threat.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields: {', '.join(missing)}")

        entry_extras = sorted(set(threat) - allowed_threat_fields)
        if entry_extras:
            errors.append(f"{prefix}: unknown fields: {', '.join(entry_extras)}")

        threat_id = threat.get("id")
        if not isinstance(threat_id, str) or not THREAT_ID.fullmatch(threat_id):
            errors.append(f"{prefix}: invalid threat id")
        elif threat_id in seen_ids:
            errors.append(f"{prefix}: duplicate threat id: {threat_id}")
        else:
            seen_ids.add(threat_id)

        name = threat.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix}: name must be a non-empty string")
        else:
            folded = name.casefold()
            if folded in seen_names:
                errors.append(f"{prefix}: duplicate threat name: {name}")
            else:
                seen_names.add(folded)

        if threat.get("category") not in THREAT_CATEGORIES:
            errors.append(f"{prefix}: invalid category")

        description = threat.get("description")
        if not isinstance(description, str) or not description.strip():
            errors.append(f"{prefix}: description must be a non-empty string")

        if not validate_string_list(threat.get("capabilities"), min_items=1):
            errors.append(f"{prefix}: capabilities must be a unique non-empty array of non-empty strings")

        if "notes" in threat and not isinstance(threat["notes"], str):
            errors.append(f"{prefix}: notes must be a string")

    missing_baseline = sorted(REQUIRED_THREAT_IDS - seen_ids)
    if missing_baseline:
        errors.append(f"{source}: missing baseline threat ids: {', '.join(missing_baseline)}")

    scenarios = data.get("composite_scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        errors.append(f"{source}: composite_scenarios must be a non-empty array")
        return errors

    seen_scenario_ids: set[str] = set()
    seen_scenario_names: set[str] = set()
    allowed_scenario_fields = {"id", "name", "threat_ids", "description"}

    for index, scenario in enumerate(scenarios):
        prefix = f"{source}: composite_scenarios[{index}]"
        if not isinstance(scenario, dict):
            errors.append(f"{prefix}: scenario entry must be an object")
            continue

        missing = sorted({"id", "name", "threat_ids", "description"} - scenario.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields: {', '.join(missing)}")

        entry_extras = sorted(set(scenario) - allowed_scenario_fields)
        if entry_extras:
            errors.append(f"{prefix}: unknown fields: {', '.join(entry_extras)}")

        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not COMPOSITE_ID.fullmatch(scenario_id):
            errors.append(f"{prefix}: invalid scenario id")
        elif scenario_id in seen_scenario_ids:
            errors.append(f"{prefix}: duplicate scenario id: {scenario_id}")
        else:
            seen_scenario_ids.add(scenario_id)

        name = scenario.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix}: name must be a non-empty string")
        else:
            folded = name.casefold()
            if folded in seen_scenario_names:
                errors.append(f"{prefix}: duplicate scenario name: {name}")
            else:
                seen_scenario_names.add(folded)

        threat_ids = scenario.get("threat_ids")
        if not validate_string_list(threat_ids, min_items=2):
            errors.append(f"{prefix}: threat_ids must be a unique array containing at least two threat ids")
        else:
            for threat_id in threat_ids:
                if not THREAT_ID.fullmatch(threat_id):
                    errors.append(f"{prefix}: invalid threat reference: {threat_id}")
                elif threat_id not in seen_ids:
                    errors.append(f"{prefix}: unknown threat reference: {threat_id}")

        description = scenario.get("description")
        if not isinstance(description, str) or not description.strip():
            errors.append(f"{prefix}: description must be a non-empty string")

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

    for schema_rel in (
        "schemas/profile.schema.json",
        "schemas/terminology.schema.json",
        "schemas/threat-model.schema.json",
    ):
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

    threat_model_path = root / "spec/threat-model.md"
    if threat_model_path.is_file():
        threat_model = threat_model_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 2. Protected assets",
            "## 3. Adversary capability classes",
            "## 4. Composite scenarios",
            "## 5. Threat declarations by profiles",
            "## 6. Temporal compromise model",
            "## 10. Quantum scope",
            "TM-ENDPOINT-LIVE",
            "TM-SERVICE-ACTIVE",
            "TM-QUANTUM-HARVEST",
        ):
            if required_text not in threat_model:
                errors.append(f"threat-model.md missing required marker: {required_text}")

    terminology_registry_path = root / "registry/terminology.json"
    if terminology_registry_path.is_file():
        errors.extend(validate_terminology(load_json(terminology_registry_path), "registry/terminology.json"))

    threat_registry_path = root / "registry/threat-model.json"
    if threat_registry_path.is_file():
        errors.extend(validate_threat_model(load_json(threat_registry_path), "registry/threat-model.json"))

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
