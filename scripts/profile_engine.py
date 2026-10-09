#!/usr/bin/env python3
"""Deterministic E2EESA profile and configuration resolver."""

from __future__ import annotations

import profile_dependencies

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILE_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
PROFILE_REF_RE = re.compile(
    r"^(?P<profile_id>[a-z0-9]+(?:-[a-z0-9]+)*)@"
    r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$"
)
PROPERTY_ID_RE = re.compile(r"^SP-[A-Z0-9]+(?:-[A-Z0-9]+)*$")

DEFAULT_ALLOWED_STATUSES = {"recommended", "allowed"}
NONDEFAULT_OPT_IN_STATUSES = {"provisional", "experimental", "legacy", "deprecated"}
ALL_STATUSES = DEFAULT_ALLOWED_STATUSES | NONDEFAULT_OPT_IN_STATUSES | {"prohibited"}
CARDINALITIES = {"exactly-one", "at-most-one", "one-or-more", "many"}
DECISION_CLASSES = {"invariant", "profile-choice", "capability", "experimental"}


@dataclass
class ResolutionResult:
    valid: bool
    configuration_id: str | None
    standard_version: str | None
    requested_profiles: list[str] = field(default_factory=list)
    effective_profiles: list[str] = field(default_factory=list)
    auto_added_profiles: list[str] = field(default_factory=list)
    security_properties: list[str] = field(default_factory=list)
    family_selections: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "configuration_id": self.configuration_id,
            "standard_version": self.standard_version,
            "requested_profiles": self.requested_profiles,
            "effective_profiles": self.effective_profiles,
            "auto_added_profiles": self.auto_added_profiles,
            "security_properties": self.security_properties,
            "family_selections": self.family_selections,
            "warnings": self.warnings,
            "errors": self.errors,
        }


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    return value


def profile_ref(profile: dict[str, Any]) -> str:
    return f"{profile.get('profile_id')}@{profile.get('profile_version')}"


def parse_profile_ref(value: str) -> tuple[str, str] | None:
    match = PROFILE_REF_RE.fullmatch(value)
    if match is None:
        return None
    return match.group("profile_id"), match.group("version")


def _unique_string_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
        and len(value) == len(set(value))
    )


def validate_catalog(
    catalog: dict[str, Any],
    *,
    known_property_ids: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    allowed_top = {"schema_version", "standard_version", "families", "profiles"}
    extra_top = sorted(set(catalog) - allowed_top)
    if extra_top:
        errors.append(f"catalog: unknown fields: {', '.join(extra_top)}")

    if catalog.get("schema_version") != "0.1":
        errors.append("catalog: schema_version must be 0.1")

    standard_version = catalog.get("standard_version")
    if not isinstance(standard_version, str) or not standard_version.strip():
        errors.append("catalog: standard_version must be a non-empty string")

    families = catalog.get("families")
    profiles = catalog.get("profiles")
    if not isinstance(families, list) or not families:
        errors.append("catalog: families must be a non-empty array")
        families = []
    if not isinstance(profiles, list) or not profiles:
        errors.append("catalog: profiles must be a non-empty array")
        profiles = []

    family_ids: set[str] = set()
    family_names: set[str] = set()
    for index, family in enumerate(families):
        prefix = f"catalog: families[{index}]"
        if not isinstance(family, dict):
            errors.append(f"{prefix}: family must be an object")
            continue
        allowed = {"family_id", "name", "cardinality", "description"}
        extra = sorted(set(family) - allowed)
        if extra:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra)}")
        missing = sorted(allowed - family.keys())
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")

        family_id = family.get("family_id")
        if not isinstance(family_id, str) or not PROFILE_ID_RE.fullmatch(family_id):
            errors.append(f"{prefix}: invalid family_id")
        elif family_id in family_ids:
            errors.append(f"{prefix}: duplicate family_id: {family_id}")
        else:
            family_ids.add(family_id)

        name = family.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix}: name must be a non-empty string")
        else:
            folded = name.casefold()
            if folded in family_names:
                errors.append(f"{prefix}: duplicate family name: {name}")
            else:
                family_names.add(folded)

        if family.get("cardinality") not in CARDINALITIES:
            errors.append(f"{prefix}: invalid cardinality")
        if not isinstance(family.get("description"), str) or not family.get("description", "").strip():
            errors.append(f"{prefix}: description must be a non-empty string")

    refs: set[str] = set()
    profile_families_by_id: dict[str, str] = {}
    pending_references: list[tuple[str, str, str]] = []

    for index, profile in enumerate(profiles):
        prefix = f"catalog: profiles[{index}]"
        if not isinstance(profile, dict):
            errors.append(f"{prefix}: profile must be an object")
            continue

        required_fields = {
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
        allowed_fields = required_fields | {"notes", "dependency_rules"}
        extra = sorted(set(profile) - allowed_fields)
        if extra:
            errors.append(f"{prefix}: unknown fields: {', '.join(extra)}")
        missing = sorted(required_fields - profile.keys())
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")

        if profile.get("schema_version") != "0.1":
            errors.append(f"{prefix}: schema_version must be 0.1")

        profile_id = profile.get("profile_id")
        version = profile.get("profile_version")
        if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
            errors.append(f"{prefix}: invalid profile_id")
        if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
            errors.append(f"{prefix}: invalid profile_version")

        ref = profile_ref(profile)
        if parse_profile_ref(ref) is not None:
            if ref in refs:
                errors.append(f"{prefix}: duplicate profile reference: {ref}")
            else:
                refs.add(ref)

        family_id = profile.get("family_id")
        if not isinstance(family_id, str) or family_id not in family_ids:
            errors.append(f"{prefix}: unknown family_id: {family_id}")
        elif isinstance(profile_id, str) and PROFILE_ID_RE.fullmatch(profile_id):
            prior_family = profile_families_by_id.get(profile_id)
            if prior_family is not None and prior_family != family_id:
                errors.append(
                    f"{prefix}: all versions of {profile_id} must remain in family {prior_family}"
                )
            else:
                profile_families_by_id[profile_id] = family_id

        if profile.get("status") not in ALL_STATUSES:
            errors.append(f"{prefix}: invalid status")
        if profile.get("decision_class") not in DECISION_CLASSES:
            errors.append(f"{prefix}: invalid decision_class")

        properties = profile.get("security_properties")
        if not _unique_string_list(properties):
            errors.append(f"{prefix}: security_properties must be a unique string array")
        else:
            for property_id in properties:
                if not PROPERTY_ID_RE.fullmatch(property_id):
                    errors.append(f"{prefix}: invalid security property id: {property_id}")
                elif known_property_ids is not None and property_id not in known_property_ids:
                    errors.append(f"{prefix}: unknown security property id: {property_id}")

        for field_name in ("requires_profile_refs", "incompatible_profile_refs"):
            values = profile.get(field_name)
            if not _unique_string_list(values):
                errors.append(f"{prefix}: {field_name} must be a unique string array")
                continue
            for target in values:
                if parse_profile_ref(target) is None:
                    errors.append(f"{prefix}: malformed profile reference in {field_name}: {target}")
                else:
                    pending_references.append((prefix, field_name, target))

        if isinstance(profile.get("notes"), object) and "notes" in profile and not isinstance(profile["notes"], str):
            errors.append(f"{prefix}: notes must be a string")

    for prefix, field_name, target in pending_references:
        if target not in refs:
            errors.append(f"{prefix}: unknown profile reference in {field_name}: {target}")

    for profile in profiles:
        if isinstance(profile,dict):
            errors.extend(profile_dependencies.validate_rules(profile.get("dependency_rules",[]),family_ids,refs))

    profiles_by_ref = {
        profile_ref(profile): profile
        for profile in profiles
        if isinstance(profile, dict) and profile_ref(profile) in refs
    }
    for ref, profile in profiles_by_ref.items():
        if ref in profile.get("requires_profile_refs", []):
            errors.append(f"catalog: profile {ref} must not require itself")
        if ref in profile.get("incompatible_profile_refs", []):
            errors.append(f"catalog: profile {ref} must not be incompatible with itself")
        direct_requirements = set(profile.get("requires_profile_refs", []))
        direct_incompatibilities = set(profile.get("incompatible_profile_refs", []))
        contradictions = sorted(direct_requirements & direct_incompatibilities)
        if contradictions:
            errors.append(
                f"catalog: profile {ref} both requires and conflicts with: {', '.join(contradictions)}"
            )

    populated_families = {
        profile.get("family_id")
        for profile in profiles
        if isinstance(profile, dict)
    }
    for family_id in sorted(family_ids - populated_families):
        errors.append(f"catalog: family has no profiles: {family_id}")

    return errors


def validate_configuration(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "configuration_id",
        "standard_version",
        "selected_profiles",
        "accepted_nondefault_statuses",
    }
    allowed = required | {"notes"}
    extra = sorted(set(config) - allowed)
    if extra:
        errors.append(f"configuration: unknown fields: {', '.join(extra)}")
    missing = sorted(required - config.keys())
    if missing:
        errors.append(f"configuration: missing fields: {', '.join(missing)}")

    if config.get("schema_version") != "0.1":
        errors.append("configuration: schema_version must be 0.1")

    configuration_id = config.get("configuration_id")
    if not isinstance(configuration_id, str) or not PROFILE_ID_RE.fullmatch(configuration_id):
        errors.append("configuration: invalid configuration_id")

    if not isinstance(config.get("standard_version"), str) or not config.get("standard_version", "").strip():
        errors.append("configuration: standard_version must be a non-empty string")

    selected = config.get("selected_profiles")
    if not _unique_string_list(selected):
        errors.append("configuration: selected_profiles must be a unique string array")
    else:
        for ref in selected:
            if parse_profile_ref(ref) is None:
                errors.append(f"configuration: profile reference must be exact and version-pinned: {ref}")

    accepted = config.get("accepted_nondefault_statuses")
    if not _unique_string_list(accepted):
        errors.append("configuration: accepted_nondefault_statuses must be a unique string array")
    else:
        unknown = sorted(set(accepted) - NONDEFAULT_OPT_IN_STATUSES)
        if unknown:
            errors.append(
                "configuration: invalid accepted_nondefault_statuses: "
                + ", ".join(unknown)
            )

    if "notes" in config and not isinstance(config["notes"], str):
        errors.append("configuration: notes must be a string")

    return errors


def resolve_configuration(
    catalog: dict[str, Any],
    config: dict[str, Any],
    *,
    known_property_ids: set[str] | None = None,
) -> ResolutionResult:
    errors = validate_catalog(catalog, known_property_ids=known_property_ids)
    errors.extend(validate_configuration(config))

    configuration_id = config.get("configuration_id")
    if not isinstance(configuration_id, str):
        configuration_id = None
    standard_version = config.get("standard_version")
    if not isinstance(standard_version, str):
        standard_version = None

    result = ResolutionResult(
        valid=False,
        configuration_id=configuration_id,
        standard_version=standard_version,
    )
    result.errors.extend(errors)
    if errors:
        return result

    if config["standard_version"] != catalog["standard_version"]:
        result.errors.append(
            "configuration standard_version does not match catalog standard_version: "
            f"{config['standard_version']} != {catalog['standard_version']}"
        )
        return result

    profiles_by_ref = {profile_ref(profile): profile for profile in catalog["profiles"]}
    families_by_id = {family["family_id"]: family for family in catalog["families"]}

    requested = sorted(config["selected_profiles"])
    result.requested_profiles = requested

    unknown_requested = sorted(ref for ref in requested if ref not in profiles_by_ref)
    if unknown_requested:
        result.errors.append(
            "configuration references unknown profiles: " + ", ".join(unknown_requested)
        )
        return result

    effective: set[str] = set(requested)
    auto_added: set[str] = set()
    queue = list(requested)

    while queue:
        ref = queue.pop(0)
        profile = profiles_by_ref[ref]
        for required_ref in sorted(profile["requires_profile_refs"]):
            if required_ref not in profiles_by_ref:
                result.errors.append(f"{ref} requires missing profile {required_ref}")
                continue
            if required_ref not in effective:
                effective.add(required_ref)
                auto_added.add(required_ref)
                queue.append(required_ref)

    if result.errors:
        return result

    versions_by_id: dict[str, set[str]] = {}
    for ref in effective:
        parsed = parse_profile_ref(ref)
        assert parsed is not None
        profile_id, version = parsed
        versions_by_id.setdefault(profile_id, set()).add(version)

    for profile_id, versions in sorted(versions_by_id.items()):
        if len(versions) > 1:
            result.errors.append(
                f"multiple versions selected for {profile_id}: {', '.join(sorted(versions))}"
            )

    accepted_statuses = set(config["accepted_nondefault_statuses"])
    for ref in sorted(effective):
        status = profiles_by_ref[ref]["status"]
        if status == "prohibited":
            result.errors.append(f"prohibited profile selected: {ref}")
        elif status in NONDEFAULT_OPT_IN_STATUSES and status not in accepted_statuses:
            result.errors.append(
                f"profile {ref} has nondefault status {status} without explicit opt-in"
            )
        elif status in {"deprecated", "legacy", "provisional", "experimental"}:
            result.warnings.append(f"profile {ref} uses lifecycle status {status}")

    for ref in sorted(effective):
        profile = profiles_by_ref[ref]
        for incompatible_ref in profile["incompatible_profile_refs"]:
            if incompatible_ref in effective:
                pair = sorted([ref, incompatible_ref])
                message = f"incompatible profiles selected: {pair[0]} and {pair[1]}"
                if message not in result.errors:
                    result.errors.append(message)

    family_selections: dict[str, list[str]] = {family_id: [] for family_id in families_by_id}
    for ref in sorted(effective):
        family_id = profiles_by_ref[ref]["family_id"]
        family_selections[family_id].append(ref)

    for family_id, family in sorted(families_by_id.items()):
        count = len(family_selections[family_id])
        cardinality = family["cardinality"]
        valid_count = (
            (cardinality == "exactly-one" and count == 1)
            or (cardinality == "at-most-one" and count <= 1)
            or (cardinality == "one-or-more" and count >= 1)
            or (cardinality == "many")
        )
        if not valid_count:
            result.errors.append(
                f"family {family_id} violates cardinality {cardinality}: selected {count}"
            )

    result.errors.extend(profile_dependencies.configuration_errors(profiles_by_ref,effective))

    properties = sorted(
        {
            property_id
            for ref in effective
            for property_id in profiles_by_ref[ref]["security_properties"]
        }
    )

    result.effective_profiles = sorted(effective)
    result.auto_added_profiles = sorted(auto_added)
    result.security_properties = properties
    result.family_selections = {
        family_id: sorted(refs)
        for family_id, refs in sorted(family_selections.items())
    }
    result.errors = sorted(set(result.errors))
    result.warnings = sorted(set(result.warnings))
    result.valid = not result.errors
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve an E2EESA profile configuration.")
    parser.add_argument("catalog", type=Path)
    parser.add_argument("configuration", type=Path)
    parser.add_argument(
        "--property-registry",
        type=Path,
        help="Optional security-properties registry used to fail closed on property references.",
    )
    args = parser.parse_args()

    try:
        catalog = load_json(args.catalog)
        config = load_json(args.configuration)
        known_property_ids: set[str] | None = None
        if args.property_registry is not None:
            property_registry = load_json(args.property_registry)
            known_property_ids = {
                item["id"]
                for item in property_registry.get("properties", [])
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            }
        result = resolve_configuration(
            catalog,
            config,
            known_property_ids=known_property_ids,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"valid": False, "errors": [str(exc)]}, indent=2, sort_keys=True))
        return 1

    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
