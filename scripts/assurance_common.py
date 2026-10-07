"""Strict data/evidence helpers for the assurance milestones.

This implements only the JSON Schema keywords used by these new schemas, not a
general JSON Schema engine. Unsupported keywords fail closed. It validates
evidence records; it does not authenticate externally supplied reports.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_KEYS = {
    "$schema", "$id", "title", "description", "type", "properties",
    "required", "additionalProperties", "items", "uniqueItems", "minItems",
    "maxItems", "minLength", "maxLength", "pattern", "enum", "const",
    "minimum", "maximum",
}


def load_json(path: Path):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                      parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))


def digest(value) -> str:
    """Repository-local deterministic JSON encoding, not an RFC 8785 claim."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise ValueError("timestamp must be UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def shape(value, schema: dict, source: str = "record") -> list[str]:
    errors = []
    unknown = set(schema) - SCHEMA_KEYS
    if unknown:
        return [f"{source}: unsupported schema keywords: {sorted(unknown)}"]
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: type(v) is int,
        "boolean": lambda v: type(v) is bool,
        "null": lambda v: v is None,
    }
    kinds = schema.get("type", [])
    kinds = [kinds] if isinstance(kinds, str) else kinds
    if kinds and not any(checks.get(k, lambda v: False)(value) for k in kinds):
        return [f"{source}: expected type {kinds}"]
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        errors.append(f"{source}: must equal {schema['const']!r}")
    if "enum" in schema and not any(type(value) is type(v) and value == v for v in schema["enum"]):
        errors.append(f"{source}: unrecognized value")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{source}: missing {key}")
        if schema.get("additionalProperties") is False:
            for key in sorted(set(value) - props.keys()):
                errors.append(f"{source}: unknown field {key}")
        for key in value.keys() & props.keys():
            errors.extend(shape(value[key], props[key], f"{source}.{key}"))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            errors.append(f"{source}: invalid item count")
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errors.append(f"{source}: duplicate items")
        for i, item in enumerate(value):
            errors.extend(shape(item, schema.get("items", {}), f"{source}[{i}]"))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            errors.append(f"{source}: invalid string length")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{source}: invalid string format")
    if type(value) is int:
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            errors.append(f"{source}: out of bounds")
    return errors


def check_schema(root: Path, name: str, value) -> list[str]:
    return shape(value, load_json(root / "schemas" / f"{name}.schema.json"), name)


def profile_errors(ref: str, family: str, catalog: dict) -> list[str]:
    for p in catalog.get("profiles", []):
        if f"{p.get('profile_id')}@{p.get('profile_version')}" == ref:
            if p.get("family_id") != family or p.get("status") not in {"allowed", "recommended"}:
                return [f"{ref}: wrong family or non-production lifecycle status"]
            return []
    return [f"unknown profile: {ref}"]


def binding_errors(policy: dict, evidence: dict) -> list[str]:
    errors = []
    for key in ("policy_id", "profile_ref", "product_id", "product_version", "platform"):
        if policy[key] != evidence[key]:
            errors.append(f"evidence: {key} does not match policy")
    if evidence["policy_digest"] != digest(policy):
        errors.append("evidence: policy_digest does not bind the exact policy")
    return errors


def required_true(record: dict, fields) -> list[str]:
    return [f"{name}: must be true" for name in fields if record.get(name) is not True]


def required_false(record: dict, fields) -> list[str]:
    return [f"{name}: must be false" for name in fields if record.get(name) is not False]


def validate_fixture_set(root: Path, name: str, validator, catalog: dict) -> list[str]:
    """Manifest keeps fixtures required, including negative cases and evidence pins."""
    errors = []
    directory = root / "fixtures" / name
    try:
        manifest = load_json(directory / "cases.json")
        if not isinstance(manifest, list) or not manifest:
            return [f"{name}: fixture manifest must be a non-empty array"]
        seen = set()
        for case in manifest:
            if not isinstance(case, dict) or set(case) != {"name", "policy", "evidence", "valid"}:
                errors.append(f"{name}: malformed fixture case")
                continue
            if type(case["valid"]) is not bool or case["name"] in seen:
                errors.append(f"{name}: invalid/duplicate fixture case")
                continue
            seen.add(case["name"])
            paths = [case["policy"], case["evidence"]]
            if any(not isinstance(p, str) or Path(p).is_absolute() or ".." in Path(p).parts for p in paths):
                errors.append(f"{name}: unsafe fixture path")
                continue
            result = validator(load_json(directory / paths[0]),
                               load_json(directory / paths[1]), catalog, root=root)
            if (not result) != case["valid"]:
                errors.append(f"{name}/{case['name']}: unexpected result: {result}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"{name}: fixture validation failed: {exc}")
    return errors
