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
import crypto_registry
import negotiation_engine
import identity_device_engine
import pairwise_session_engine
import group_e2ee_engine
import key_verification_engine
import key_transparency_engine
import backup_recovery_engine
import metadata_privacy_engine
import contact_discovery_engine

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
    "spec/cryptographic-registry.md",
    "spec/negotiation-downgrade.md",
    "spec/identity-device-architecture.md",
    "spec/pairwise-e2ee.md",
    "spec/group-e2ee.md",
    "spec/key-verification.md",
    "spec/key-transparency.md",
    "spec/backup-recovery.md",
    "spec/metadata-privacy.md",
    "spec/contact-discovery.md",
    "adr/0011-contact-discovery.md",
    "adr/0010-metadata-privacy.md",
    "adr/0009-backup-recovery.md",
    "adr/0008-key-transparency.md",
    "adr/0007-key-verification.md",
    "adr/0006-group-e2ee-profiles.md",
    "adr/0005-pairwise-e2ee-profiles.md",
    "adr/0004-identity-device-architecture.md",
    "adr/0000-template.md",
    "profiles/README.md",
    "schemas/profile.schema.json",
    "schemas/terminology.schema.json",
    "schemas/threat-model.schema.json",
    "schemas/security-properties.schema.json",
    "schemas/security-property-claim.schema.json",
    "schemas/profile-catalog.schema.json",
    "schemas/configuration.schema.json",
    "schemas/cryptographic-algorithm-registry.schema.json",
    "schemas/negotiation-policy.schema.json",
    "schemas/negotiation-evidence.schema.json",
    "schemas/identity-policy.schema.json",
    "schemas/identity-state.schema.json",
    "schemas/identity-event.schema.json",
    "schemas/pairwise-protocol-registry.schema.json",
    "schemas/pairwise-policy.schema.json",
    "schemas/pairwise-handshake-evidence.schema.json",
    "schemas/pairwise-message-checkpoint.schema.json",
    "schemas/group-protocol-registry.schema.json",
    "schemas/group-policy.schema.json",
    "schemas/group-membership-event.schema.json",
    "schemas/group-message-checkpoint.schema.json",
    "schemas/key-verification-policy.schema.json",
    "schemas/key-verification-snapshot.schema.json",
    "schemas/key-verification-record.schema.json",
    "schemas/key-transparency-protocol-registry.schema.json",
    "schemas/key-transparency-policy.schema.json",
    "schemas/key-transparency-evidence.schema.json",
    "schemas/key-transparency-checkpoint.schema.json",
    "schemas/backup-recovery-policy.schema.json",
    "schemas/backup-envelope-evidence.schema.json",
    "schemas/recovery-evidence.schema.json",
    "schemas/no-backup-evidence.schema.json",
    "schemas/metadata-privacy-registry.schema.json",
    "schemas/metadata-privacy-policy.schema.json",
    "schemas/metadata-delivery-evidence.schema.json",
    "schemas/contact-discovery-registry.schema.json",
    "schemas/contact-discovery-policy.schema.json",
    "schemas/contact-discovery-evidence.schema.json",
    "registry/terminology.json",
    "registry/threat-model.json",
    "registry/security-properties.json",
    "registry/cryptographic-algorithms.json",
    "registry/pairwise-protocols.json",
    "registry/group-protocols.json",
    "registry/key-transparency-protocols.json",
    "registry/metadata-privacy-mechanisms.json",
    "registry/contact-discovery-mechanisms.json",
    "profiles/catalog.json",
    "scripts/profile_engine.py",
    "scripts/crypto_registry.py",
    "scripts/negotiation_engine.py",
    "scripts/identity_device_engine.py",
    "scripts/pairwise_session_engine.py",
    "scripts/group_e2ee_engine.py",
    "scripts/key_verification_engine.py",
    "scripts/key_transparency_engine.py",
    "scripts/backup_recovery_engine.py",
    "scripts/metadata_privacy_engine.py",
    "scripts/contact_discovery_engine.py",
    "fixtures/negotiation/policy.json",
    "fixtures/negotiation/valid/baseline.json",
    "fixtures/identity/policies/cross-signing.json",
    "fixtures/identity/states/cross-signing.json",
    "fixtures/identity/valid/cross-sign-enroll.json",
    "fixtures/pairwise/policies/triple.json",
    "fixtures/pairwise/handshakes/valid/triple.json",
    "fixtures/pairwise/checkpoints/valid/triple.json",
    "fixtures/group/policies/mls.json",
    "fixtures/group/membership/valid/mls.json",
    "fixtures/group/messages/valid/mls.json",
    "fixtures/verification/policies/account.json",
    "fixtures/verification/policies/devices.json",
    "fixtures/verification/snapshots/account/alice.json",
    "fixtures/verification/snapshots/account/bob.json",
    "fixtures/verification/snapshots/devices/alice.json",
    "fixtures/verification/snapshots/devices/bob.json",
    "fixtures/transparency/policies/contact.json",
    "fixtures/transparency/policies/audit.json",
    "fixtures/transparency/policies/manager.json",
    "fixtures/transparency/contact-first.json",
    "fixtures/transparency/audit-first.json",
    "fixtures/transparency/manager-first.json",
    "fixtures/transparency/base-checkpoint.json",
    "fixtures/recovery/policies/none.json",
    "fixtures/recovery/policies/user.json",
    "fixtures/recovery/policies/hardware.json",
    "fixtures/recovery/no-backup.json",
    "fixtures/recovery/user-envelope-gen1.json",
    "fixtures/recovery/user-envelope-gen2.json",
    "fixtures/recovery/hardware-envelope.json",
    "fixtures/recovery/user-recovery.json",
    "fixtures/recovery/hardware-recovery.json",
    "fixtures/metadata/policies/minimized.json",
    "fixtures/metadata/policies/sender-hidden.json",
    "fixtures/metadata/policies/relay.json",
    "fixtures/metadata/evidence/minimized.json",
    "fixtures/metadata/evidence/sender-hidden.json",
    "fixtures/metadata/evidence/relay.json",
    "fixtures/contact-discovery/policies/exact.json",
    "fixtures/contact-discovery/policies/voprf.json",
    "fixtures/contact-discovery/policies/attested.json",
    "fixtures/contact-discovery/evidence/exact.json",
    "fixtures/contact-discovery/evidence/voprf.json",
    "fixtures/contact-discovery/evidence/attested.json",
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
        "schemas/cryptographic-algorithm-registry.schema.json",
        "schemas/negotiation-policy.schema.json",
        "schemas/negotiation-evidence.schema.json",
        "schemas/identity-policy.schema.json",
        "schemas/identity-state.schema.json",
        "schemas/identity-event.schema.json",
        "schemas/pairwise-protocol-registry.schema.json",
        "schemas/pairwise-policy.schema.json",
        "schemas/pairwise-handshake-evidence.schema.json",
        "schemas/pairwise-message-checkpoint.schema.json",
        "schemas/group-protocol-registry.schema.json",
        "schemas/group-policy.schema.json",
        "schemas/group-membership-event.schema.json",
        "schemas/group-message-checkpoint.schema.json",
        "schemas/key-verification-policy.schema.json",
        "schemas/key-verification-snapshot.schema.json",
        "schemas/key-verification-record.schema.json",
        "schemas/key-transparency-protocol-registry.schema.json",
        "schemas/key-transparency-policy.schema.json",
        "schemas/key-transparency-evidence.schema.json",
        "schemas/key-transparency-checkpoint.schema.json",
        "schemas/backup-recovery-policy.schema.json",
        "schemas/backup-envelope-evidence.schema.json",
        "schemas/recovery-evidence.schema.json",
        "schemas/no-backup-evidence.schema.json",
        "schemas/metadata-privacy-registry.schema.json",
        "schemas/metadata-privacy-policy.schema.json",
        "schemas/metadata-delivery-evidence.schema.json",
        "schemas/contact-discovery-registry.schema.json",
        "schemas/contact-discovery-policy.schema.json",
        "schemas/contact-discovery-evidence.schema.json",
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

    crypto_registry_path = root / "registry/cryptographic-algorithms.json"
    crypto_registry_data = load_json(crypto_registry_path) if crypto_registry_path.is_file() else {}
    if crypto_registry_data:
        errors.extend(
            crypto_registry.validate_registry(
                crypto_registry_data,
                "registry/cryptographic-algorithms.json",
            )
        )

    crypto_spec_path = root / "spec/cryptographic-registry.md"
    if crypto_spec_path.is_file():
        crypto_spec = crypto_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 1. Closed-world rule",
            "## 2. No new cryptographic primitives",
            "## 3. Lifecycle status",
            "## 6. Post-quantum scope",
            "## 10. Fail-closed interpretation",
            "ML-KEM",
            "ML-DSA",
        ):
            if required_text not in crypto_spec:
                errors.append(f"cryptographic-registry.md missing required marker: {required_text}")

    negotiation_spec_path = root / "spec/negotiation-downgrade.md"
    if negotiation_spec_path.is_file():
        negotiation_spec = negotiation_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 1. Core invariant",
            "## 2. Explicit version ordering",
            "## 3. Exact suite pinning",
            "## 4. Transcript binding",
            "## 6. No automatic weaker fallback",
            "## 7. Freshness and replay",
            "## 12. Conformance",
            "SP-DOWNGRADE-RESISTANCE",
        ):
            if required_text not in negotiation_spec:
                errors.append(f"negotiation-downgrade.md missing required marker: {required_text}")

    identity_spec_path = root / "spec/identity-device-architecture.md"
    if identity_spec_path.is_file():
        identity_spec = identity_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 1. Core invariant",
            "## 4. Enrollment",
            "## 5. Key rotation",
            "## 6. Revocation",
            "identity-account-root@0.1.0",
            "identity-device-cross-signing@0.1.0",
            "identity-threshold-quorum@0.1.0",
            "## 14. Conformance",
        ):
            if required_text not in identity_spec:
                errors.append(f"identity-device-architecture.md missing required marker: {required_text}")

    pairwise_spec_path = root / "spec/pairwise-e2ee.md"
    if pairwise_spec_path.is_file():
        pairwise_spec = pairwise_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 1. Scope and invariant",
            "## 4. Prekey publication and verification",
            "pairwise-x3dh-double-ratchet@0.1.0",
            "pairwise-pqxdh-double-ratchet@0.1.0",
            "pairwise-pqxdh-spqr@0.1.0",
            "pairwise-pqxdh-triple-ratchet@0.1.0",
            "## 13. Downgrade resistance",
            "## 15. Conformance evidence",
            "SP-PQ-AUTHENTICATION",
        ):
            if required_text not in pairwise_spec:
                errors.append(f"pairwise-e2ee.md missing required marker: {required_text}")

    group_spec_path = root / "spec/group-e2ee.md"
    if group_spec_path.is_file():
        group_spec = group_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 1. Common group invariant",
            "group-mls-rfc9420@0.1.0",
            "group-sender-key-aead@0.1.0",
            "group-pairwise-fanout@0.1.0",
            "## 13. Downgrade resistance",
            "## 15. Conformance evidence",
            "UpdatePath",
        ):
            if required_text not in group_spec:
                errors.append(f"group-e2ee.md missing required marker: {required_text}")

    verification_spec_path = root / "spec/key-verification.md"
    if verification_spec_path.is_file():
        verification_spec = verification_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "## 1. Core invariant",
            "verify-account-root@0.1.0",
            "verify-device-set@0.1.0",
            "## 9. Change handling",
            "## 11. Automatic verification and transparency boundary",
            "## 13. Conformance",
            "real-world identity",
        ):
            if required_text not in verification_spec:
                errors.append(f"key-verification.md missing required marker: {required_text}")

    transparency_spec_path = root / "spec/key-transparency.md"
    if transparency_spec_path.is_file():
        transparency_spec = transparency_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "KEYTRANS-IETF-05",
            "draft-ietf-keytrans-protocol-05",
            "draft-ietf-keytrans-architecture-09",
            "kt-contact-monitoring@0.1.0",
            "kt-third-party-auditing@0.1.0",
            "kt-third-party-management@0.1.0",
            "## 18. Failure behavior",
            "## 19. Conformance evidence",
        ):
            if required_text not in transparency_spec:
                errors.append(f"key-transparency.md missing required marker: {required_text}")

    recovery_spec_path = root / "spec/backup-recovery.md"
    if recovery_spec_path.is_file():
        recovery_spec = recovery_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "backup-none@0.1.0",
            "backup-user-secret@0.1.0",
            "backup-hardware-assisted@0.1.0",
            "ALG-ARGON2ID",
            "## 10. Rollback resistance",
            "## 11. Restore sequence",
            "## 16. Conformance evidence",
            "MUST NOT",
        ):
            if required_text not in recovery_spec:
                errors.append(f"backup-recovery.md missing required marker: {required_text}")

    metadata_spec_path = root / "spec/metadata-privacy.md"
    if metadata_spec_path.is_file():
        metadata_spec = metadata_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "metadata-minimized@0.1.0",
            "metadata-sender-hidden@0.1.0",
            "metadata-relay-partitioned@0.1.0",
            "RFC 9458",
            "## 10. Replay protection",
            "## 12. Traffic-analysis boundary",
            "## 15. Conformance evidence",
            "recipient routing identifier",
        ):
            if required_text not in metadata_spec:
                errors.append(f"metadata-privacy.md missing required marker: {required_text}")

    contact_spec_path = root / "spec/contact-discovery.md"
    if contact_spec_path.is_file():
        contact_spec = contact_spec_path.read_text(encoding="utf-8")
        for required_text in (
            "**Status:** Normative",
            "contact-exact-handle@0.1.0",
            "contact-voprf-directory@0.1.0",
            "contact-attested-private-set@0.1.0",
            "RFC 9497",
            "## 7. Enumeration resistance",
            "## 11. Confidential-compute security boundary",
            "## 15. Conformance evidence",
            "raw address book",
        ):
            if required_text not in contact_spec:
                errors.append(f"contact-discovery.md missing required marker: {required_text}")

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

    pairwise_protocol_registry_path = root / "registry/pairwise-protocols.json"
    pairwise_protocol_registry = (
        load_json(pairwise_protocol_registry_path)
        if pairwise_protocol_registry_path.is_file()
        else {}
    )
    if pairwise_protocol_registry:
        known_pairwise_property_ids = {
            prop.get("id")
            for prop in property_registry.get("properties", [])
            if isinstance(prop, dict) and isinstance(prop.get("id"), str)
        }
        errors.extend(
            pairwise_session_engine.validate_protocol_registry(
                pairwise_protocol_registry,
                known_property_ids=known_pairwise_property_ids,
                source="registry/pairwise-protocols.json",
            )
        )

    group_protocol_registry_path = root / "registry/group-protocols.json"
    group_protocol_registry = (
        load_json(group_protocol_registry_path)
        if group_protocol_registry_path.is_file()
        else {}
    )
    if group_protocol_registry:
        errors.extend(
            group_e2ee_engine.validate_protocol_registry(
                group_protocol_registry,
                source="registry/group-protocols.json",
            )
        )

    transparency_registry_path = root / "registry/key-transparency-protocols.json"
    transparency_registry = (
        load_json(transparency_registry_path)
        if transparency_registry_path.is_file()
        else {}
    )
    if transparency_registry:
        errors.extend(
            key_transparency_engine.validate_protocol_registry(
                transparency_registry,
                source="registry/key-transparency-protocols.json",
            )
        )

    metadata_registry_path = root / "registry/metadata-privacy-mechanisms.json"
    metadata_registry = (
        load_json(metadata_registry_path)
        if metadata_registry_path.is_file()
        else {}
    )
    if metadata_registry:
        errors.extend(
            metadata_privacy_engine.validate_protocol_registry(
                metadata_registry,
                source="registry/metadata-privacy-mechanisms.json",
            )
        )

    contact_registry_path = root / "registry/contact-discovery-mechanisms.json"
    contact_registry = (
        load_json(contact_registry_path)
        if contact_registry_path.is_file()
        else {}
    )
    if contact_registry:
        errors.extend(
            contact_discovery_engine.validate_registry(
                contact_registry,
                source="registry/contact-discovery-mechanisms.json",
            )
        )

    negotiation_policy_path = root / "fixtures/negotiation/policy.json"
    negotiation_policy = load_json(negotiation_policy_path) if negotiation_policy_path.is_file() else {}
    if negotiation_policy and crypto_registry_data and profile_catalog:
        errors.extend(
            negotiation_engine.validate_policy(
                negotiation_policy,
                crypto_registry_data,
                profile_catalog,
                "fixtures/negotiation/policy.json",
            )
        )

        valid_negotiation_dir = root / "fixtures/negotiation/valid"
        for path in sorted(valid_negotiation_dir.glob("*.json")) if valid_negotiation_dir.exists() else []:
            result = negotiation_engine.validate_evidence(
                negotiation_policy,
                load_json(path),
                crypto_registry_data,
                profile_catalog,
                str(path.relative_to(root)),
            )
            if result:
                errors.append(
                    f"{path.relative_to(root)}: valid negotiation evidence failed: "
                    + "; ".join(result)
                )

        invalid_negotiation_dir = root / "fixtures/negotiation/invalid"
        for path in sorted(invalid_negotiation_dir.glob("*.json")) if invalid_negotiation_dir.exists() else []:
            result = negotiation_engine.validate_evidence(
                negotiation_policy,
                load_json(path),
                crypto_registry_data,
                profile_catalog,
                str(path.relative_to(root)),
            )
            if not result:
                errors.append(
                    f"{path.relative_to(root)}: invalid negotiation evidence unexpectedly passed validation"
                )

    identity_cases = [
        ("account-root", "account-root", "valid/account-root-enroll.json", True),
        ("cross-signing", "cross-signing", "valid/cross-sign-enroll.json", True),
        ("cross-signing", "cross-signing", "valid/cross-sign-rotate.json", True),
        ("threshold", "threshold", "valid/threshold-enroll.json", True),
        ("cross-signing", "cross-signing", "invalid/server-only.json", False),
        ("cross-signing", "cross-signing", "invalid/stale-state-hash.json", False),
        ("threshold", "threshold", "invalid/insufficient-threshold.json", False),
        ("cross-signing", "cross-signing", "invalid/key-reuse.json", False),
        ("cross-signing", "cross-signing", "invalid/unknown-authorizer.json", False),
    ]
    if crypto_registry_data and profile_catalog:
        for policy_name, state_name, event_rel, should_pass in identity_cases:
            policy_path = root / "fixtures/identity/policies" / f"{policy_name}.json"
            state_path = root / "fixtures/identity/states" / f"{state_name}.json"
            event_path = root / "fixtures/identity" / event_rel
            if not (policy_path.is_file() and state_path.is_file() and event_path.is_file()):
                errors.append(f"missing identity fixture for {event_rel}")
                continue
            result = identity_device_engine.validate_transition(
                load_json(policy_path),
                load_json(state_path),
                load_json(event_path),
                profile_catalog,
                crypto_registry_data,
            )
            if should_pass and result:
                errors.append(f"fixtures/identity/{event_rel}: valid identity transition failed: " + "; ".join(result))
            if not should_pass and not result:
                errors.append(f"fixtures/identity/{event_rel}: invalid identity transition unexpectedly passed")

    if pairwise_protocol_registry and crypto_registry_data and profile_catalog:
        pairwise_policy_names = ("classical", "pq-init", "spqr", "triple")
        for name in pairwise_policy_names:
            policy_path = root / "fixtures/pairwise/policies" / f"{name}.json"
            handshake_path = root / "fixtures/pairwise/handshakes/valid" / f"{name}.json"
            checkpoint_path = root / "fixtures/pairwise/checkpoints/valid" / f"{name}.json"
            if not (policy_path.is_file() and handshake_path.is_file() and checkpoint_path.is_file()):
                errors.append(f"missing valid pairwise fixture set: {name}")
                continue
            result = pairwise_session_engine.validate_pairwise_case(
                load_json(policy_path),
                load_json(handshake_path),
                load_json(checkpoint_path),
                pairwise_protocol_registry,
                crypto_registry_data,
                profile_catalog,
            )
            if result:
                errors.append(
                    f"valid pairwise fixture set {name} failed: " + "; ".join(result)
                )

        for invalid_policy_name in (
            "invalid-classical-pq-kem",
            "invalid-triple-downgrade",
        ):
            path = root / "fixtures/pairwise/policies" / f"{invalid_policy_name}.json"
            if path.is_file():
                result = pairwise_session_engine.validate_policy(
                    load_json(path),
                    pairwise_protocol_registry,
                    crypto_registry_data,
                    profile_catalog,
                )
                if not result:
                    errors.append(
                        f"fixtures/pairwise/policies/{invalid_policy_name}.json: "
                        "invalid policy unexpectedly passed"
                    )

        invalid_handshake_cases = (
            ("triple", "replay"),
            ("triple", "one-time-not-consumed"),
            ("triple", "pq-prekey-unverified"),
            ("classical", "classical-pq-fields"),
        )
        for policy_name, fixture_name in invalid_handshake_cases:
            path = root / "fixtures/pairwise/handshakes/invalid" / f"{fixture_name}.json"
            if path.is_file():
                result = pairwise_session_engine.validate_handshake_evidence(
                    load_json(root / "fixtures/pairwise/policies" / f"{policy_name}.json"),
                    load_json(path),
                )
                if not result:
                    errors.append(
                        f"fixtures/pairwise/handshakes/invalid/{fixture_name}.json: "
                        "invalid handshake unexpectedly passed"
                    )

        for fixture_name in (
            "message-key-not-deleted",
            "triple-pq-component-off",
            "skipped-bound-exceeded",
            "replay",
        ):
            path = root / "fixtures/pairwise/checkpoints/invalid" / f"{fixture_name}.json"
            if path.is_file():
                result = pairwise_session_engine.validate_message_checkpoint(
                    load_json(root / "fixtures/pairwise/policies/triple.json"),
                    load_json(path),
                )
                if not result:
                    errors.append(
                        f"fixtures/pairwise/checkpoints/invalid/{fixture_name}.json: "
                        "invalid checkpoint unexpectedly passed"
                    )

    if group_protocol_registry and crypto_registry_data and profile_catalog:
        for name in ("mls", "sender", "pairwise"):
            policy_path = root / "fixtures/group/policies" / f"{name}.json"
            membership_path = root / "fixtures/group/membership/valid" / f"{name}.json"
            message_path = root / "fixtures/group/messages/valid" / f"{name}.json"
            if not (policy_path.is_file() and membership_path.is_file() and message_path.is_file()):
                errors.append(f"missing valid group fixture set: {name}")
                continue
            result = group_e2ee_engine.validate_group_case(
                load_json(policy_path),
                load_json(membership_path),
                load_json(message_path),
                group_protocol_registry,
                crypto_registry_data,
                profile_catalog,
            )
            if result:
                errors.append(
                    f"valid group fixture set {name} failed: " + "; ".join(result)
                )

        invalid_membership_cases = (
            ("mls", "server-authorizer"),
            ("mls", "stale-epoch"),
            ("mls", "new-member-history"),
            ("mls", "mls-missing-update-path"),
            ("sender", "sender-not-rotated"),
            ("pairwise", "pairwise-recipient-set-not-updated"),
        )
        for policy_name, fixture_name in invalid_membership_cases:
            path = root / "fixtures/group/membership/invalid" / f"{fixture_name}.json"
            if path.is_file():
                result = group_e2ee_engine.validate_membership_event(
                    load_json(root / "fixtures/group/policies" / f"{policy_name}.json"),
                    load_json(path),
                )
                if not result:
                    errors.append(
                        f"fixtures/group/membership/invalid/{fixture_name}.json: "
                        "invalid membership event unexpectedly passed"
                    )

        invalid_message_cases = (
            ("mls", "replay"),
            ("mls", "nonmember-recipient"),
            ("mls", "server-plaintext"),
            ("sender", "sender-key-not-deleted"),
            ("sender", "sender-skipped-overflow"),
            ("pairwise", "pairwise-count-mismatch"),
            ("pairwise", "pairwise-session-invalid"),
        )
        for policy_name, fixture_name in invalid_message_cases:
            path = root / "fixtures/group/messages/invalid" / f"{fixture_name}.json"
            if path.is_file():
                result = group_e2ee_engine.validate_message_checkpoint(
                    load_json(root / "fixtures/group/policies" / f"{policy_name}.json"),
                    load_json(path),
                )
                if not result:
                    errors.append(
                        f"fixtures/group/messages/invalid/{fixture_name}.json: "
                        "invalid group message unexpectedly passed"
                    )

    if crypto_registry_data and profile_catalog:
        verification_policy_account = root / "fixtures/verification/policies/account.json"
        verification_policy_devices = root / "fixtures/verification/policies/devices.json"
        account_alice = root / "fixtures/verification/snapshots/account/alice.json"
        account_bob = root / "fixtures/verification/snapshots/account/bob.json"
        account_bob_added = root / "fixtures/verification/snapshots/account/bob-device-added.json"
        account_bob_root_changed = root / "fixtures/verification/snapshots/account/bob-root-changed.json"
        devices_alice = root / "fixtures/verification/snapshots/devices/alice.json"
        devices_bob = root / "fixtures/verification/snapshots/devices/bob.json"
        devices_bob_added = root / "fixtures/verification/snapshots/devices/bob-device-added.json"
        devices_bob_rotated = root / "fixtures/verification/snapshots/devices/bob-key-rotated.json"

        verification_paths = (
            verification_policy_account,
            verification_policy_devices,
            account_alice,
            account_bob,
            account_bob_added,
            account_bob_root_changed,
            devices_alice,
            devices_bob,
            devices_bob_added,
            devices_bob_rotated,
        )
        missing_verification = [str(path.relative_to(root)) for path in verification_paths if not path.is_file()]
        if missing_verification:
            errors.append("missing key verification fixtures: " + ", ".join(missing_verification))
        else:
            account_policy = load_json(verification_policy_account)
            devices_policy = load_json(verification_policy_devices)
            account_record = key_verification_engine.create_manual_record(
                record_id="validator-account-record",
                verification_method="qr",
                user_confirmed=True,
                policy=account_policy,
                first_snapshot=load_json(account_alice),
                second_snapshot=load_json(account_bob),
                crypto_registry=crypto_registry_data,
                profile_catalog=profile_catalog,
            )
            if key_verification_engine.verification_status(
                account_record,
                account_policy,
                load_json(account_alice),
                load_json(account_bob_added),
                crypto_registry_data,
                profile_catalog,
            )["status"] != "verified":
                errors.append("account-root verification must survive subordinate device addition")
            if key_verification_engine.verification_status(
                account_record,
                account_policy,
                load_json(account_alice),
                load_json(account_bob_root_changed),
                crypto_registry_data,
                profile_catalog,
            )["status"] != "invalidated":
                errors.append("account-root verification must invalidate after root change")

            devices_record = key_verification_engine.create_manual_record(
                record_id="validator-device-record",
                verification_method="numeric",
                user_confirmed=True,
                policy=devices_policy,
                first_snapshot=load_json(devices_alice),
                second_snapshot=load_json(devices_bob),
                crypto_registry=crypto_registry_data,
                profile_catalog=profile_catalog,
            )
            for changed_path, label in (
                (devices_bob_added, "device addition"),
                (devices_bob_rotated, "device key rotation"),
            ):
                if key_verification_engine.verification_status(
                    devices_record,
                    devices_policy,
                    load_json(devices_alice),
                    load_json(changed_path),
                    crypto_registry_data,
                    profile_catalog,
                )["status"] != "invalidated":
                    errors.append(f"device-set verification must invalidate after {label}")

            if not key_verification_engine.compare_qr(
                devices_record, devices_record["qr_payload"]
            ):
                errors.append("key verification QR self-comparison failed")
            if not key_verification_engine.compare_numeric(
                devices_record, devices_record["numeric_safety_number"]
            ):
                errors.append("key verification numeric self-comparison failed")

    if transparency_registry and profile_catalog:
        transparency_required = (
            root / "fixtures/transparency/policies/contact.json",
            root / "fixtures/transparency/policies/audit.json",
            root / "fixtures/transparency/policies/manager.json",
            root / "fixtures/transparency/contact-first.json",
            root / "fixtures/transparency/audit-first.json",
            root / "fixtures/transparency/manager-first.json",
            root / "fixtures/transparency/contact-next.json",
            root / "fixtures/transparency/base-checkpoint.json",
        )
        missing_transparency = [
            str(path.relative_to(root))
            for path in transparency_required
            if not path.is_file()
        ]
        if missing_transparency:
            errors.append(
                "missing key transparency fixtures: " + ", ".join(missing_transparency)
            )
        else:
            kv_policy = load_json(root / "fixtures/verification/policies/devices.json")
            kv_alice = load_json(root / "fixtures/verification/snapshots/devices/alice.json")
            kv_bob = load_json(root / "fixtures/verification/snapshots/devices/bob.json")
            expected_digest = key_verification_engine.subject_digest(
                kv_policy, kv_alice, kv_bob
            ).hex()

            for policy_name, evidence_name in (
                ("contact", "contact-first"),
                ("audit", "audit-first"),
                ("manager", "manager-first"),
            ):
                result = key_transparency_engine.validate_evidence(
                    load_json(root / "fixtures/transparency/policies" / f"{policy_name}.json"),
                    load_json(root / "fixtures/transparency" / f"{evidence_name}.json"),
                    transparency_registry,
                    profile_catalog,
                    expected_digest,
                )
                if result:
                    errors.append(
                        f"valid transparency fixture {evidence_name} failed: "
                        + "; ".join(result)
                    )

            prior_checkpoint = load_json(
                root / "fixtures/transparency/base-checkpoint.json"
            )
            result = key_transparency_engine.validate_evidence(
                load_json(root / "fixtures/transparency/policies/contact.json"),
                load_json(root / "fixtures/transparency/contact-next.json"),
                transparency_registry,
                profile_catalog,
                expected_digest,
                prior_checkpoint,
            )
            if result:
                errors.append(
                    "valid transparency continuity fixture failed: " + "; ".join(result)
                )

            invalid_transparency_cases = (
                ("contact", "invalid-subject-mismatch", None),
                ("contact", "invalid-contact-monitor-missed", None),
                ("audit", "invalid-auditor-threshold", None),
                ("audit", "invalid-auditor-lag", None),
                ("manager", "invalid-manager-update-signature", None),
                ("contact", "invalid-stale-tree-head", None),
                ("contact", "invalid-same-size-fork", prior_checkpoint),
                ("contact", "invalid-label-rollback", prior_checkpoint),
            )
            for policy_name, evidence_name, previous in invalid_transparency_cases:
                path = root / "fixtures/transparency" / f"{evidence_name}.json"
                result = key_transparency_engine.validate_evidence(
                    load_json(root / "fixtures/transparency/policies" / f"{policy_name}.json"),
                    load_json(path),
                    transparency_registry,
                    profile_catalog,
                    expected_digest,
                    previous,
                )
                if not result:
                    errors.append(
                        f"fixtures/transparency/{evidence_name}.json: "
                        "invalid transparency evidence unexpectedly passed"
                    )

    if crypto_registry_data and profile_catalog:
        recovery_policies = {
            name: load_json(root / "fixtures/recovery/policies" / f"{name}.json")
            for name in ("none", "user", "hardware")
        }
        for name, policy in recovery_policies.items():
            result = backup_recovery_engine.validate_policy(
                policy,
                crypto_registry_data,
                profile_catalog,
                f"fixtures/recovery/policies/{name}.json",
            )
            if result:
                errors.append(
                    f"valid recovery policy {name} failed: " + "; ".join(result)
                )

        no_backup_result = backup_recovery_engine.validate_no_backup_evidence(
            recovery_policies["none"],
            load_json(root / "fixtures/recovery/no-backup.json"),
        )
        if no_backup_result:
            errors.append(
                "valid no-backup evidence failed: " + "; ".join(no_backup_result)
            )

        user_gen1 = load_json(root / "fixtures/recovery/user-envelope-gen1.json")
        user_gen2 = load_json(root / "fixtures/recovery/user-envelope-gen2.json")
        for policy_name, path_name in (
            ("user", "user-envelope-gen1"),
            ("hardware", "hardware-envelope"),
        ):
            result = backup_recovery_engine.validate_envelope(
                recovery_policies[policy_name],
                load_json(root / "fixtures/recovery" / f"{path_name}.json"),
                crypto_registry_data,
                profile_catalog,
            )
            if result:
                errors.append(
                    f"valid recovery envelope {path_name} failed: " + "; ".join(result)
                )

        transition_result = backup_recovery_engine.validate_generation_transition(
            user_gen1, user_gen2
        )
        if transition_result:
            errors.append(
                "valid backup generation transition failed: "
                + "; ".join(transition_result)
            )

        for policy_name, path_name in (
            ("user", "user-recovery"),
            ("hardware", "hardware-recovery"),
        ):
            result = backup_recovery_engine.validate_recovery(
                recovery_policies[policy_name],
                load_json(root / "fixtures/recovery" / f"{path_name}.json"),
                crypto_registry_data,
                profile_catalog,
            )
            if result:
                errors.append(
                    f"valid recovery evidence {path_name} failed: " + "; ".join(result)
                )

        weak_policy = dict(recovery_policies["user"])
        weak_policy["argon2_memory_kib"] = 32768
        if not backup_recovery_engine.validate_policy(
            weak_policy, crypto_registry_data, profile_catalog
        ):
            errors.append("weak Argon2 recovery policy unexpectedly passed")

        unauthorized = load_json(root / "fixtures/recovery/user-recovery.json")
        unauthorized["restoring_device_authorized"] = False
        if not backup_recovery_engine.validate_recovery(
            recovery_policies["user"], unauthorized, crypto_registry_data, profile_catalog
        ):
            errors.append("unauthorized restoring device unexpectedly passed")

        stale = load_json(root / "fixtures/recovery/user-recovery.json")
        stale["backup_generation"] = 1
        stale["latest_known_generation"] = 2
        if not backup_recovery_engine.validate_recovery(
            recovery_policies["user"], stale, crypto_registry_data, profile_catalog
        ):
            errors.append("stale backup generation unexpectedly passed rollback protection")

    if metadata_registry and crypto_registry_data and profile_catalog:
        for name in ("minimized", "sender-hidden", "relay"):
            policy_path = root / "fixtures/metadata/policies" / f"{name}.json"
            evidence_path = root / "fixtures/metadata/evidence" / f"{name}.json"
            result = metadata_privacy_engine.validate_delivery_evidence(
                load_json(policy_path),
                load_json(evidence_path),
                metadata_registry,
                crypto_registry_data,
                profile_catalog,
            )
            if result:
                errors.append(
                    f"valid metadata fixture {name} failed: " + "; ".join(result)
                )

        sender_leak = load_json(root / "fixtures/metadata/evidence/sender-hidden.json")
        sender_leak["sender_identity_visible_to_service"] = True
        if not metadata_privacy_engine.validate_delivery_evidence(
            load_json(root / "fixtures/metadata/policies/sender-hidden.json"),
            sender_leak,
            metadata_registry,
            crypto_registry_data,
            profile_catalog,
        ):
            errors.append("sender-visible metadata evidence unexpectedly passed")

        relay_ip_leak = load_json(root / "fixtures/metadata/evidence/relay.json")
        relay_ip_leak["service_observed_client_network_address"] = True
        if not metadata_privacy_engine.validate_delivery_evidence(
            load_json(root / "fixtures/metadata/policies/relay.json"),
            relay_ip_leak,
            metadata_registry,
            crypto_registry_data,
            profile_catalog,
        ):
            errors.append("relay profile with service-visible client IP unexpectedly passed")

        relay_header_leak = load_json(root / "fixtures/metadata/evidence/relay.json")
        relay_header_leak["relay_added_identifying_headers"] = True
        if not metadata_privacy_engine.validate_delivery_evidence(
            load_json(root / "fixtures/metadata/policies/relay.json"),
            relay_header_leak,
            metadata_registry,
            crypto_registry_data,
            profile_catalog,
        ):
            errors.append("relay profile with identifying forwarding headers unexpectedly passed")

        durable_graph = load_json(root / "fixtures/metadata/evidence/minimized.json")
        durable_graph["durable_sender_recipient_mapping_written"] = True
        if not metadata_privacy_engine.validate_delivery_evidence(
            load_json(root / "fixtures/metadata/policies/minimized.json"),
            durable_graph,
            metadata_registry,
            crypto_registry_data,
            profile_catalog,
        ):
            errors.append("metadata profile with durable social graph unexpectedly passed")

    if contact_registry and profile_catalog:
        for name in ("exact", "voprf", "attested"):
            policy_path = root / "fixtures/contact-discovery/policies" / f"{name}.json"
            evidence_path = root / "fixtures/contact-discovery/evidence" / f"{name}.json"
            result = contact_discovery_engine.validate_evidence(
                load_json(policy_path),
                load_json(evidence_path),
                contact_registry,
                profile_catalog,
            )
            if result:
                errors.append(
                    f"valid contact-discovery fixture {name} failed: "
                    + "; ".join(result)
                )

        raw_upload = load_json(root / "fixtures/contact-discovery/evidence/voprf.json")
        raw_upload["raw_address_book_sent_to_service"] = True
        if not contact_discovery_engine.validate_evidence(
            load_json(root / "fixtures/contact-discovery/policies/voprf.json"),
            raw_upload,
            contact_registry,
            profile_catalog,
        ):
            errors.append("raw address-book contact discovery unexpectedly passed")

        voprf_leak = load_json(root / "fixtures/contact-discovery/evidence/voprf.json")
        voprf_leak["service_observed_query_identifiers"] = True
        if not contact_discovery_engine.validate_evidence(
            load_json(root / "fixtures/contact-discovery/policies/voprf.json"),
            voprf_leak,
            contact_registry,
            profile_catalog,
        ):
            errors.append("VOPRF contact discovery with service-visible identifiers unexpectedly passed")

        bad_attestation = load_json(root / "fixtures/contact-discovery/evidence/attested.json")
        bad_attestation["attestation_verified"] = False
        if not contact_discovery_engine.validate_evidence(
            load_json(root / "fixtures/contact-discovery/policies/attested.json"),
            bad_attestation,
            contact_registry,
            profile_catalog,
        ):
            errors.append("unverified attested contact discovery unexpectedly passed")

        persistent_query = load_json(root / "fixtures/contact-discovery/evidence/attested.json")
        persistent_query["query_persisted_after_completion"] = True
        if not contact_discovery_engine.validate_evidence(
            load_json(root / "fixtures/contact-discovery/policies/attested.json"),
            persistent_query,
            contact_registry,
            profile_catalog,
        ):
            errors.append("contact discovery with persisted query identifiers unexpectedly passed")

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
