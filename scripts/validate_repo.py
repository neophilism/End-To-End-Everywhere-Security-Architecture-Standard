#!/usr/bin/env python3
"""Repository-level validation for E2EESA standard artifacts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import profile_engine

REQUIRED_PATHS = [
    "README.md",
    "VERSION",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "spec/README.md",
    "spec/normative-language.md",
    "spec/terminology.md",
    "spec/threat-model.md",
    "spec/security-properties.md",
    "spec/profile-configuration.md",
    "adr/0000-template.md",
    "profiles/README.md",
    "schemas/profile.schema.json",
    "schemas/terminology.schema.json",
    "schemas/threat-model.schema.json",
    "schemas/security-properties.schema.json",
    "schemas/security-property-claim.schema.json",
    "schemas/profile-catalog.schema.json",
    "schemas/configuration.schema.json",
    "registry/terminology.json",
    "registry/threat-model.json",
    "registry/security-properties.json",
    "profiles/catalog.json",
    "scripts/profile_engine.py",
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
SECURITY_PROPERTY_CATEGORIES = {
    "content",
    "identity",
    "protocol",
    "state",
    "evidence",
    "metadata",
    "availability",
    "recovery",
    "storage",
    "software-supply-chain",
    "post-quantum",
}
CLAIM_DIMENSIONS = {
    "scope",
    "assets",
    "threats",
    "composite_scenarios",
    "temporal_phases",
    "assumptions",
    "limitations",
    "conditions",
    "identity_granularity",
    "healing_event",
    "exposure_window",
    "evidence_model",
}
CLAIM_STATES = {"provided", "conditional", "not-claimed", "not-applicable"}
TEMPORAL_PHASES = {
    "steady-state",
    "pre-compromise",
    "during-compromise",
    "post-compromise-pre-healing",
    "post-healing",
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
REQUIRED_SECURITY_PROPERTY_IDS = {
    "SP-CONFIDENTIALITY",
    "SP-INTEGRITY",
    "SP-MESSAGE-AUTHENTICITY",
    "SP-PEER-AUTHENTICATION",
    "SP-AUTHORIZATION-INTEGRITY",
    "SP-FORWARD-SECRECY",
    "SP-POST-COMPROMISE-SECURITY",
    "SP-KEY-CONSISTENCY",
    "SP-DOWNGRADE-RESISTANCE",
    "SP-REPLAY-RESISTANCE",
    "SP-ROLLBACK-RESISTANCE",
    "SP-DENIABILITY",
    "SP-NON-REPUDIATION",
    "SP-METADATA-MINIMIZATION",
    "SP-METADATA-CONFIDENTIALITY",
    "SP-UNLINKABILITY",
    "SP-AVAILABILITY",
    "SP-RECOVERY-CONFIDENTIALITY",
    "SP-BACKUP-CONFIDENTIALITY",
    "SP-SOFTWARE-INTEGRITY",
    "SP-BUILD-PROVENANCE",
    "SP-PQ-CONFIDENTIALITY",
    "SP-PQ-AUTHENTICATION",
}

PROFILE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
THREAT_ID = re.compile(r"^TM-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
COMPOSITE_ID = re.compile(r"^CS-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
PROPERTY_ID = re.compile(r"^SP-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
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


def validate_profile(
    data: dict,
    source: str = "<profile>",
    known_property_ids: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "profile_id",
        "profile_version",
        "family_id",
        "status",
        "decision_class",
        "security_properties",
        "requires_profile_refs",
        "incompatible_profile_refs",
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

    family_id = data.get("family_id")
    if not isinstance(family_id, str) or not PROFILE_ID.fullmatch(family_id):
        errors.append(f"{source}: invalid family_id")

    if data.get("status") not in VALID_STATUSES:
        errors.append(f"{source}: invalid status")

    if data.get("decision_class") not in VALID_DECISION_CLASSES:
        errors.append(f"{source}: invalid decision_class")

    properties = data.get("security_properties")
    if not validate_string_list(properties):
        errors.append(f"{source}: security_properties must be a unique array of non-empty strings")
    elif isinstance(properties, list):
        for property_id in properties:
            if not PROPERTY_ID.fullmatch(property_id):
                errors.append(f"{source}: invalid security property id: {property_id}")
            elif known_property_ids is not None and property_id not in known_property_ids:
                errors.append(f"{source}: unknown security property id: {property_id}")

    for field_name in ("requires_profile_refs", "incompatible_profile_refs"):
        values = data.get(field_name)
        if not validate_string_list(values):
            errors.append(f"{source}: {field_name} must be a unique array of non-empty strings")
        elif isinstance(values, list):
            for value in values:
                if profile_engine.parse_profile_ref(value) is None:
                    errors.append(f"{source}: malformed exact profile reference in {field_name}: {value}")

    allowed = required | {"notes"}
    extras = sorted(set(data) - allowed)
    if extras:
        errors.append(f"{source}: unknown fields: {', '.join(extras)}")

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


def validate_security_properties(data: dict, source: str = "<security-properties>") -> list[str]:
    errors: list[str] = []
    allowed_top = {"schema_version", "properties"}
    extras = sorted(set(data) - allowed_top)
    if extras:
        errors.append(f"{source}: unknown top-level fields: {', '.join(extras)}")

    if data.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    properties = data.get("properties")
    if not isinstance(properties, list) or not properties:
        errors.append(f"{source}: properties must be a non-empty array")
        return errors

    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    allowed_fields = {"id", "name", "category", "definition", "required_claim_dimensions", "notes"}

    for index, prop in enumerate(properties):
        prefix = f"{source}: properties[{index}]"
        if not isinstance(prop, dict):
            errors.append(f"{prefix}: property entry must be an object")
            continue

        missing = sorted({"id", "name", "category", "definition", "required_claim_dimensions"} - prop.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields: {', '.join(missing)}")

        entry_extras = sorted(set(prop) - allowed_fields)
        if entry_extras:
            errors.append(f"{prefix}: unknown fields: {', '.join(entry_extras)}")

        property_id = prop.get("id")
        if not isinstance(property_id, str) or not PROPERTY_ID.fullmatch(property_id):
            errors.append(f"{prefix}: invalid property id")
        elif property_id in seen_ids:
            errors.append(f"{prefix}: duplicate property id: {property_id}")
        else:
            seen_ids.add(property_id)

        name = prop.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix}: name must be a non-empty string")
        else:
            folded = name.casefold()
            if folded in seen_names:
                errors.append(f"{prefix}: duplicate property name: {name}")
            else:
                seen_names.add(folded)

        if prop.get("category") not in SECURITY_PROPERTY_CATEGORIES:
            errors.append(f"{prefix}: invalid category")

        definition = prop.get("definition")
        if not isinstance(definition, str) or not definition.strip():
            errors.append(f"{prefix}: definition must be a non-empty string")

        dimensions = prop.get("required_claim_dimensions")
        if not validate_string_list(dimensions, min_items=1):
            errors.append(f"{prefix}: required_claim_dimensions must be a unique non-empty array")
        elif isinstance(dimensions, list):
            unknown_dimensions = sorted(set(dimensions) - CLAIM_DIMENSIONS)
            if unknown_dimensions:
                errors.append(f"{prefix}: unknown claim dimensions: {', '.join(unknown_dimensions)}")
            for baseline_dimension in ("scope", "assets", "threats"):
                if baseline_dimension not in dimensions:
                    errors.append(f"{prefix}: required_claim_dimensions must include {baseline_dimension}")

        if "notes" in prop and not isinstance(prop["notes"], str):
            errors.append(f"{prefix}: notes must be a string")

    missing_baseline = sorted(REQUIRED_SECURITY_PROPERTY_IDS - seen_ids)
    if missing_baseline:
        errors.append(f"{source}: missing baseline security property ids: {', '.join(missing_baseline)}")

    return errors


def validate_security_claim(
    data: dict,
    property_registry: dict,
    threat_registry: dict,
    source: str = "<security-claim>",
) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "property_id",
        "state",
        "scope",
        "assets",
        "threat_ids",
        "temporal_phases",
        "assumptions",
        "limitations",
    }
    allowed = required | {
        "composite_scenario_ids",
        "conditions",
        "identity_granularity",
        "healing_event",
        "exposure_window",
        "evidence_model",
        "notes",
    }

    missing = sorted(required - data.keys())
    if missing:
        errors.append(f"{source}: missing required fields: {', '.join(missing)}")

    extras = sorted(set(data) - allowed)
    if extras:
        errors.append(f"{source}: unknown fields: {', '.join(extras)}")

    if data.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")

    properties = {
        prop.get("id"): prop
        for prop in property_registry.get("properties", [])
        if isinstance(prop, dict) and isinstance(prop.get("id"), str)
    }
    threats = {
        threat.get("id")
        for threat in threat_registry.get("threats", [])
        if isinstance(threat, dict) and isinstance(threat.get("id"), str)
    }
    scenarios = {
        scenario.get("id")
        for scenario in threat_registry.get("composite_scenarios", [])
        if isinstance(scenario, dict) and isinstance(scenario.get("id"), str)
    }

    property_id = data.get("property_id")
    if not isinstance(property_id, str) or not PROPERTY_ID.fullmatch(property_id):
        errors.append(f"{source}: invalid property_id")
        prop = None
    else:
        prop = properties.get(property_id)
        if prop is None:
            errors.append(f"{source}: unknown property_id: {property_id}")

    state = data.get("state")
    if state not in CLAIM_STATES:
        errors.append(f"{source}: invalid claim state")

    scope = data.get("scope")
    if not isinstance(scope, str) or not scope.strip():
        errors.append(f"{source}: scope must be a non-empty string")

    assets = data.get("assets")
    if not validate_string_list(assets, min_items=1):
        errors.append(f"{source}: assets must be a unique non-empty array of non-empty strings")

    threat_ids = data.get("threat_ids")
    minimum_threats = 1 if state in {"provided", "conditional", "not-claimed"} else 0
    if not validate_string_list(threat_ids, min_items=minimum_threats):
        errors.append(f"{source}: threat_ids must be a unique array with the required threat coverage")
    elif isinstance(threat_ids, list):
        for threat_id in threat_ids:
            if not THREAT_ID.fullmatch(threat_id):
                errors.append(f"{source}: invalid threat reference: {threat_id}")
            elif threat_id not in threats:
                errors.append(f"{source}: unknown threat reference: {threat_id}")

    composite_ids = data.get("composite_scenario_ids", [])
    if not validate_string_list(composite_ids):
        errors.append(f"{source}: composite_scenario_ids must be a unique array of non-empty strings")
    elif isinstance(composite_ids, list):
        for scenario_id in composite_ids:
            if not COMPOSITE_ID.fullmatch(scenario_id):
                errors.append(f"{source}: invalid composite scenario reference: {scenario_id}")
            elif scenario_id not in scenarios:
                errors.append(f"{source}: unknown composite scenario reference: {scenario_id}")

    temporal_phases = data.get("temporal_phases")
    if not validate_string_list(temporal_phases, min_items=1):
        errors.append(f"{source}: temporal_phases must be a unique non-empty array")
    elif isinstance(temporal_phases, list):
        unknown_phases = sorted(set(temporal_phases) - TEMPORAL_PHASES)
        if unknown_phases:
            errors.append(f"{source}: unknown temporal phases: {', '.join(unknown_phases)}")

    for list_field in ("assumptions", "limitations", "conditions"):
        if list_field in data and not validate_string_list(data.get(list_field, [])):
            errors.append(f"{source}: {list_field} must be a unique array of non-empty strings")

    if state == "conditional" and not validate_string_list(data.get("conditions"), min_items=1):
        errors.append(f"{source}: conditional claim must include at least one condition")

    for field in ("identity_granularity", "healing_event", "exposure_window", "evidence_model"):
        if field in data:
            value = data[field]
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{source}: {field} must be a non-empty string")

    if "notes" in data and not isinstance(data["notes"], str):
        errors.append(f"{source}: notes must be a string")

    if prop is not None and state in {"provided", "conditional"}:
        dimensions = prop.get("required_claim_dimensions", [])
        dimension_to_field = {
            "scope": "scope",
            "assets": "assets",
            "threats": "threat_ids",
            "composite_scenarios": "composite_scenario_ids",
            "temporal_phases": "temporal_phases",
            "assumptions": "assumptions",
            "limitations": "limitations",
            "conditions": "conditions",
            "identity_granularity": "identity_granularity",
            "healing_event": "healing_event",
            "exposure_window": "exposure_window",
            "evidence_model": "evidence_model",
        }
        for dimension in dimensions:
            field = dimension_to_field.get(dimension)
            if field is None:
                errors.append(f"{source}: property requires unsupported claim dimension: {dimension}")
                continue
            if field not in data:
                errors.append(f"{source}: property {property_id} requires claim field: {field}")
                continue
            value = data[field]
            if dimension in {"scope", "identity_granularity", "healing_event", "exposure_window", "evidence_model"}:
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{source}: property {property_id} requires non-empty {field}")
            elif dimension in {"assets", "threats", "composite_scenarios", "temporal_phases", "conditions"}:
                if not validate_string_list(value, min_items=1):
                    errors.append(f"{source}: property {property_id} requires non-empty {field}")
            elif dimension in {"assumptions", "limitations"}:
                if not validate_string_list(value):
                    errors.append(f"{source}: property {property_id} requires explicit {field} array")

    if property_id in {"SP-FORWARD-SECRECY", "SP-POST-COMPROMISE-SECURITY"} and isinstance(temporal_phases, list):
        if temporal_phases == ["steady-state"]:
            errors.append(f"{source}: {property_id} requires compromise-aware temporal phases")

    if property_id == "SP-POST-COMPROMISE-SECURITY" and state in {"provided", "conditional"}:
        if isinstance(temporal_phases, list) and "post-healing" not in temporal_phases:
            errors.append(f"{source}: PCS claim must include post-healing temporal phase")

    if property_id == "SP-PQ-CONFIDENTIALITY" and state in {"provided", "conditional"}:
        if isinstance(threat_ids, list) and not ({"TM-QUANTUM-HARVEST", "TM-QUANTUM-ACTIVE"} & set(threat_ids)):
            errors.append(f"{source}: post-quantum confidentiality must cover a quantum threat")

    if property_id == "SP-PQ-AUTHENTICATION" and state in {"provided", "conditional"}:
        if isinstance(threat_ids, list) and "TM-QUANTUM-ACTIVE" not in threat_ids:
            errors.append(f"{source}: post-quantum authentication must cover TM-QUANTUM-ACTIVE")

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
        "schemas/security-properties.schema.json",
        "schemas/security-property-claim.schema.json",
        "schemas/profile-catalog.schema.json",
        "schemas/configuration.schema.json",
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

    security_properties_path = root / "spec/security-properties.md"
    if security_properties_path.is_file():
        security_properties = security_properties_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 1. Claim model",
            "## 3. Temporal phases",
            "SP-CONFIDENTIALITY",
            "SP-FORWARD-SECRECY",
            "SP-POST-COMPROMISE-SECURITY",
            "SP-METADATA-CONFIDENTIALITY",
            "SP-PQ-CONFIDENTIALITY",
            "## 5. Relationships between properties",
            "## 12. Fail-closed interpretation",
        ):
            if required_text not in security_properties:
                errors.append(f"security-properties.md missing required marker: {required_text}")

    terminology_registry_path = root / "registry/terminology.json"
    if terminology_registry_path.is_file():
        errors.extend(validate_terminology(load_json(terminology_registry_path), "registry/terminology.json"))

    threat_registry_path = root / "registry/threat-model.json"
    threat_registry = load_json(threat_registry_path) if threat_registry_path.is_file() else {}
    if threat_registry:
        errors.extend(validate_threat_model(threat_registry, "registry/threat-model.json"))

    property_registry_path = root / "registry/security-properties.json"
    property_registry = load_json(property_registry_path) if property_registry_path.is_file() else {}
    if property_registry:
        errors.extend(validate_security_properties(property_registry, "registry/security-properties.json"))

    profile_catalog_path = root / "profiles/catalog.json"
    profile_catalog = load_json(profile_catalog_path) if profile_catalog_path.is_file() else {}
    if profile_catalog:
        known_property_ids_for_catalog = {
            prop.get("id")
            for prop in property_registry.get("properties", [])
            if isinstance(prop, dict) and isinstance(prop.get("id"), str)
        }
        errors.extend(
            profile_engine.validate_catalog(
                profile_catalog,
                known_property_ids=known_property_ids_for_catalog,
            )
        )

    known_property_ids = {
        prop.get("id")
        for prop in property_registry.get("properties", [])
        if isinstance(prop, dict) and isinstance(prop.get("id"), str)
    }

    valid_config_dir = root / "fixtures/configurations/valid"
    for path in sorted(valid_config_dir.glob("*.json")) if valid_config_dir.exists() else []:
        result = profile_engine.resolve_configuration(
            profile_catalog,
            load_json(path),
            known_property_ids=known_property_ids,
        )
        if not result.valid:
            errors.append(
                f"{path.relative_to(root)}: valid configuration failed resolution: "
                + "; ".join(result.errors)
            )

    invalid_config_dir = root / "fixtures/configurations/invalid"
    for path in sorted(invalid_config_dir.glob("*.json")) if invalid_config_dir.exists() else []:
        result = profile_engine.resolve_configuration(
            profile_catalog,
            load_json(path),
            known_property_ids=known_property_ids,
        )
        if result.valid:
            errors.append(
                f"{path.relative_to(root)}: invalid configuration unexpectedly resolved"
            )

    valid_dir = root / "fixtures/profiles/valid"
    for path in sorted(valid_dir.glob("*.json")) if valid_dir.exists() else []:
        errors.extend(
            validate_profile(
                load_json(path),
                str(path.relative_to(root)),
                known_property_ids=known_property_ids,
            )
        )

    invalid_dir = root / "fixtures/profiles/invalid"
    for path in sorted(invalid_dir.glob("*.json")) if invalid_dir.exists() else []:
        result = validate_profile(
            load_json(path),
            str(path.relative_to(root)),
            known_property_ids=known_property_ids,
        )
        if not result:
            errors.append(f"{path.relative_to(root)}: invalid fixture unexpectedly passed validation")

    valid_claim_dir = root / "fixtures/security-claims/valid"
    for path in sorted(valid_claim_dir.glob("*.json")) if valid_claim_dir.exists() else []:
        errors.extend(
            validate_security_claim(
                load_json(path),
                property_registry,
                threat_registry,
                str(path.relative_to(root)),
            )
        )

    invalid_claim_dir = root / "fixtures/security-claims/invalid"
    for path in sorted(invalid_claim_dir.glob("*.json")) if invalid_claim_dir.exists() else []:
        result = validate_security_claim(
            load_json(path),
            property_registry,
            threat_registry,
            str(path.relative_to(root)),
        )
        if not result:
            errors.append(f"{path.relative_to(root)}: invalid security claim fixture unexpectedly passed validation")

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
