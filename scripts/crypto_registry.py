#!/usr/bin/env python3
"""Validation helpers for the E2EESA cryptographic registry."""

from __future__ import annotations

import re
from typing import Any

ALGORITHM_ID_RE = re.compile(r"^ALG-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
SUITE_ID_RE = re.compile(r"^SUITE-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
VALID_CATEGORIES = {"key-agreement", "kem", "signature", "hash", "kdf", "aead"}
VALID_STATUSES = {"recommended", "allowed", "provisional", "experimental", "legacy", "deprecated", "prohibited"}
VALID_PQ_CHARACTERISTICS = {"classical", "post-quantum", "symmetric-or-hash"}
STATUS_RANK = {
    "recommended": 0,
    "allowed": 1,
    "provisional": 2,
    "experimental": 3,
    "legacy": 4,
    "deprecated": 5,
    "prohibited": 6,
}


def _string_list(value: Any, *, min_items: int = 1) -> bool:
    return (
        isinstance(value, list)
        and len(value) >= min_items
        and all(isinstance(item, str) and bool(item.strip()) for item in value)
        and len(value) == len(set(value))
    )


def validate_registry(data: dict, source: str = "<cryptographic-registry>") -> list[str]:
    errors: list[str] = []
    allowed_top = {"schema_version", "registry_version", "standard_version", "algorithms", "suites"}
    extras = sorted(set(data) - allowed_top)
    if extras:
        errors.append(f"{source}: unknown top-level fields: {', '.join(extras)}")

    if data.get("schema_version") != "0.1":
        errors.append(f"{source}: schema_version must be 0.1")
    if not isinstance(data.get("registry_version"), str) or not SEMVER_RE.fullmatch(data["registry_version"]):
        errors.append(f"{source}: registry_version must be exact semantic version")
    if not isinstance(data.get("standard_version"), str) or not data["standard_version"].strip():
        errors.append(f"{source}: standard_version must be non-empty")

    algorithms = data.get("algorithms")
    if not isinstance(algorithms, list) or not algorithms:
        errors.append(f"{source}: algorithms must be a non-empty array")
        return errors

    allowed_algorithm_fields = {
        "id", "name", "category", "status", "status_reason", "specification",
        "reference_uri", "pq_characteristic", "uses", "constraints",
    }
    required_algorithm_fields = allowed_algorithm_fields - {"status_reason"}
    seen_algorithm_ids: set[str] = set()
    seen_algorithm_names: set[str] = set()
    algorithms_by_id: dict[str, dict] = {}

    for index, algorithm in enumerate(algorithms):
        prefix = f"{source}: algorithms[{index}]"
        if not isinstance(algorithm, dict):
            errors.append(f"{prefix}: algorithm entry must be an object")
            continue
        missing = sorted(required_algorithm_fields - algorithm.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields: {', '.join(missing)}")
        extras = sorted(set(algorithm) - allowed_algorithm_fields)
        if extras:
            errors.append(f"{prefix}: unknown fields: {', '.join(extras)}")

        algorithm_id = algorithm.get("id")
        if not isinstance(algorithm_id, str) or not ALGORITHM_ID_RE.fullmatch(algorithm_id):
            errors.append(f"{prefix}: invalid algorithm id")
        elif algorithm_id in seen_algorithm_ids:
            errors.append(f"{prefix}: duplicate algorithm id: {algorithm_id}")
        else:
            seen_algorithm_ids.add(algorithm_id)
            algorithms_by_id[algorithm_id] = algorithm

        name = algorithm.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix}: name must be non-empty")
        elif name.casefold() in seen_algorithm_names:
            errors.append(f"{prefix}: duplicate algorithm name: {name}")
        else:
            seen_algorithm_names.add(name.casefold())

        category = algorithm.get("category")
        if category not in VALID_CATEGORIES:
            errors.append(f"{prefix}: invalid category: {category}")

        status = algorithm.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"{prefix}: invalid status: {status}")
        if status in {"deprecated", "prohibited"} and (
            not isinstance(algorithm.get("status_reason"), str) or not algorithm["status_reason"].strip()
        ):
            errors.append(f"{prefix}: {status} algorithm requires status_reason")

        pq_characteristic = algorithm.get("pq_characteristic")
        if pq_characteristic not in VALID_PQ_CHARACTERISTICS:
            errors.append(f"{prefix}: invalid pq_characteristic: {pq_characteristic}")

        if not isinstance(algorithm.get("specification"), str) or not algorithm["specification"].strip():
            errors.append(f"{prefix}: specification must be non-empty")
        if not isinstance(algorithm.get("reference_uri"), str) or not algorithm["reference_uri"].startswith("https://"):
            errors.append(f"{prefix}: reference_uri must use https")
        if not _string_list(algorithm.get("uses")):
            errors.append(f"{prefix}: uses must be a unique non-empty string array")
        if not _string_list(algorithm.get("constraints")):
            errors.append(f"{prefix}: constraints must be a unique non-empty string array")

    suites = data.get("suites")
    if not isinstance(suites, list):
        errors.append(f"{source}: suites must be an array")
        return errors

    allowed_suite_fields = {
        "id", "name", "status", "protocol", "specification", "reference_uri",
        "algorithm_ids", "constraints", "notes",
    }
    seen_suite_ids: set[str] = set()
    for index, suite in enumerate(suites):
        prefix = f"{source}: suites[{index}]"
        if not isinstance(suite, dict):
            errors.append(f"{prefix}: suite entry must be an object")
            continue
        missing = sorted(allowed_suite_fields - suite.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields: {', '.join(missing)}")
        extras = sorted(set(suite) - allowed_suite_fields)
        if extras:
            errors.append(f"{prefix}: unknown fields: {', '.join(extras)}")

        suite_id = suite.get("id")
        if not isinstance(suite_id, str) or not SUITE_ID_RE.fullmatch(suite_id):
            errors.append(f"{prefix}: invalid suite id")
        elif suite_id in seen_suite_ids:
            errors.append(f"{prefix}: duplicate suite id: {suite_id}")
        else:
            seen_suite_ids.add(suite_id)

        status = suite.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"{prefix}: invalid status: {status}")

        algorithm_ids = suite.get("algorithm_ids")
        if not _string_list(algorithm_ids):
            errors.append(f"{prefix}: algorithm_ids must be a unique non-empty string array")
            continue

        member_statuses: list[str] = []
        for algorithm_id in algorithm_ids:
            if not ALGORITHM_ID_RE.fullmatch(algorithm_id):
                errors.append(f"{prefix}: malformed algorithm reference: {algorithm_id}")
                continue
            algorithm = algorithms_by_id.get(algorithm_id)
            if algorithm is None:
                errors.append(f"{prefix}: unknown algorithm reference: {algorithm_id}")
                continue
            member_status = algorithm.get("status")
            if member_status == "prohibited":
                errors.append(f"{prefix}: suite references prohibited algorithm: {algorithm_id}")
            if member_status in VALID_STATUSES:
                member_statuses.append(member_status)

        if status in STATUS_RANK and member_statuses:
            weakest_rank = max(STATUS_RANK[item] for item in member_statuses)
            if STATUS_RANK[status] < weakest_rank:
                errors.append(f"{prefix}: suite status is stronger than one or more component statuses")

        for field in ("name", "protocol", "specification", "notes"):
            if not isinstance(suite.get(field), str) or not suite[field].strip():
                errors.append(f"{prefix}: {field} must be non-empty")
        if not isinstance(suite.get("reference_uri"), str) or not suite["reference_uri"].startswith("https://"):
            errors.append(f"{prefix}: reference_uri must use https")
        if not _string_list(suite.get("constraints")):
            errors.append(f"{prefix}: constraints must be a unique non-empty string array")

    required_ids = {
        "ALG-X25519", "ALG-ML-KEM-768", "ALG-ED25519", "ALG-ML-DSA-65",
        "ALG-SHA256", "ALG-HKDF-SHA256", "ALG-AES-256-GCM",
        "ALG-CHACHA20-POLY1305", "ALG-MD5", "ALG-SHA1",
    }
    missing_ids = sorted(required_ids - seen_algorithm_ids)
    if missing_ids:
        errors.append(f"{source}: missing baseline algorithm ids: {', '.join(missing_ids)}")

    return errors
