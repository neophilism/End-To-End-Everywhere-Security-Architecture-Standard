#!/usr/bin/env python3
"""Normalized advisory validation and constrained CSAF export for E2EESA PR 33."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import profile_engine
import vulnerability_handling

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,5}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PROHIBITED_SYNTHETIC_SCORE_KEYS = {
    "combined_score",
    "overall_score",
    "synthetic_risk_score",
    "aggregate_risk_score",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _parse_time(value: object, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an RFC3339 UTC timestamp")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        errors.append(f"{field} must use YYYY-MM-DDTHH:MM:SSZ")
        return None


def _profile_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["profile_ref"]: item
        for item in registry.get("profiles", [])
        if isinstance(item, dict) and isinstance(item.get("profile_ref"), str)
    }


def _find_prohibited_score_keys(value: object, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in PROHIBITED_SYNTHETIC_SCORE_KEYS:
                found.append(f"{path}.{key}")
            found.extend(_find_prohibited_score_keys(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_find_prohibited_score_keys(item, f"{path}[{index}]"))
    return found


def validate_registry(registry: dict[str, Any], catalog: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if registry.get("schema_version") != "0.1":
        errors.append("advisory interoperability registry schema_version must be 0.1")
    if registry.get("current_cve_record_format") != "5.2.0":
        errors.append("current CVE Record Format must be 5.2.0 for E2EESA 0.1")
    if registry.get("current_epss_model") != "EPSS-v5":
        errors.append("current EPSS model must be EPSS-v5 for E2EESA 0.1")
    if registry.get("epss_v5_effective_date") != "2026-06-15":
        errors.append("EPSS-v5 effective date must be 2026-06-15")

    profiles = registry.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        return errors + ["advisory interoperability profiles must be non-empty"]

    catalog_map = {
        profile_engine.profile_ref(profile): profile
        for profile in catalog.get("profiles", [])
        if isinstance(profile, dict)
    }
    seen_refs: set[str] = set()
    seen_versions: set[str] = set()

    for index, item in enumerate(profiles):
        prefix = f"advisory interoperability profiles[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        ref = item.get("profile_ref")
        if not isinstance(ref, str) or profile_engine.parse_profile_ref(ref) is None:
            errors.append(f"{prefix} invalid profile_ref")
            continue
        if ref in seen_refs:
            errors.append(f"{prefix} duplicate profile_ref {ref}")
        seen_refs.add(ref)

        profile = catalog_map.get(ref)
        if profile is None:
            errors.append(f"{prefix} profile absent from catalog: {ref}")
        elif profile.get("family_id") != "advisory-interoperability":
            errors.append(f"{prefix} profile is not in advisory-interoperability family")

        version = item.get("csaf_version")
        if version not in {"2.0", "2.1"}:
            errors.append(f"{prefix} invalid csaf_version")
        elif version in seen_versions:
            errors.append(f"{prefix} duplicate CSAF version {version}")
        seen_versions.add(version)

        expected = {
            "2.0": {
                "maturity": "stable",
                "native_cvss_v4": False,
                "native_epss": False,
                "native_ssvc_v2": False,
                "native_first_known_exploitation_dates": False,
            },
            "2.1": {
                "maturity": "provisional",
                "native_cvss_v4": True,
                "native_epss": True,
                "native_ssvc_v2": True,
                "native_first_known_exploitation_dates": True,
            },
        }.get(version, {})
        for field, value in expected.items():
            if item.get(field) != value:
                errors.append(f"{prefix} {field} must be {value!r}")

        if item.get("document_category") != "csaf_security_advisory":
            errors.append(f"{prefix} document_category must be csaf_security_advisory")
        schema_uri = item.get("schema_uri")
        if not isinstance(schema_uri, str) or not schema_uri.startswith("https://"):
            errors.append(f"{prefix} schema_uri must use HTTPS")

    return sorted(set(errors))


def _score_severity(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _validate_revision_history(advisory: dict[str, Any], errors: list[str]) -> None:
    history = advisory.get("revision_history")
    if not isinstance(history, list) or not history:
        errors.append("revision_history must be a non-empty array")
        return
    revisions: list[int] = []
    dates: list[datetime] = []
    for index, item in enumerate(history):
        prefix = f"revision_history[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue
        revision = item.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            errors.append(f"{prefix} revision must be a positive integer")
        else:
            revisions.append(revision)
        date = _parse_time(item.get("date"), f"{prefix}.date", errors)
        if date is not None:
            dates.append(date)
        if not isinstance(item.get("summary"), str) or not item["summary"].strip():
            errors.append(f"{prefix} summary must be non-empty")
    if revisions and revisions != sorted(revisions):
        errors.append("revision_history revisions must be sorted ascending")
    if len(revisions) != len(set(revisions)):
        errors.append("revision_history revisions must be unique")
    if dates and dates != sorted(dates):
        errors.append("revision_history dates must be sorted ascending")
    if revisions and revisions[-1] != advisory.get("revision"):
        errors.append("revision_history latest revision must equal advisory revision")
    if history and history[-1].get("date") != advisory.get("current_release_at"):
        errors.append("revision_history latest date must equal current_release_at")
    if history and history[0].get("date") != advisory.get("initial_release_at"):
        errors.append("revision_history first date must equal initial_release_at")


def validate_advisory(
    advisory: dict[str, Any],
    registry: dict[str, Any],
    catalog: dict[str, Any],
    *,
    handling_case: dict[str, Any] | None = None,
    handling_policy: dict[str, Any] | None = None,
    disclosure_policy: dict[str, Any] | None = None,
    handling_registry: dict[str, Any] | None = None,
    disclosure_registry: dict[str, Any] | None = None,
) -> list[str]:
    errors = validate_registry(registry, catalog)

    if advisory.get("schema_version") != "0.1":
        errors.append("normalized advisory schema_version must be 0.1")

    prohibited = _find_prohibited_score_keys(advisory)
    for path in prohibited:
        errors.append(f"synthetic combined risk score is prohibited: {path}")

    initial = _parse_time(advisory.get("initial_release_at"), "initial_release_at", errors)
    current = _parse_time(advisory.get("current_release_at"), "current_release_at", errors)
    if initial is not None and current is not None and current < initial:
        errors.append("current_release_at must not precede initial_release_at")
    revision = advisory.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        errors.append("revision must be a positive integer")
    _validate_revision_history(advisory, errors)

    products = advisory.get("products")
    if not isinstance(products, list) or not products:
        return sorted(set(errors + ["products must be a non-empty array"]))
    product_map: dict[str, dict[str, Any]] = {}
    for index, product in enumerate(products):
        prefix = f"products[{index}]"
        if not isinstance(product, dict):
            errors.append(f"{prefix} must be an object")
            continue
        product_id = product.get("product_id")
        if not isinstance(product_id, str) or not product_id:
            errors.append(f"{prefix} product_id must be non-empty")
        elif product_id in product_map:
            errors.append(f"{prefix} duplicate product_id {product_id}")
        else:
            product_map[product_id] = product
        for field in ("product_line_id", "vendor", "name", "version"):
            if not isinstance(product.get(field), str) or not product[field].strip():
                errors.append(f"{prefix} {field} must be non-empty")
        purl = product.get("purl")
        if purl is not None and (not isinstance(purl, str) or not purl.startswith("pkg:")):
            errors.append(f"{prefix} purl must be null or canonical pkg: URI")
        cpe = product.get("cpe")
        if cpe is not None and (not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:")):
            errors.append(f"{prefix} cpe must be null or CPE 2.3")

    vulnerabilities = advisory.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return sorted(set(errors + ["vulnerabilities must be a non-empty array"]))

    seen_vuln_ids: set[str] = set()
    seen_cves: set[str] = set()
    epss_v5_date = datetime.strptime(
        registry["epss_v5_effective_date"], "%Y-%m-%d"
    ).replace(tzinfo=timezone.utc)

    for index, vulnerability in enumerate(vulnerabilities):
        prefix = f"vulnerabilities[{index}]"
        if not isinstance(vulnerability, dict):
            errors.append(f"{prefix} must be an object")
            continue
        vuln_id = vulnerability.get("vulnerability_id")
        if not isinstance(vuln_id, str) or not vuln_id:
            errors.append(f"{prefix} vulnerability_id must be non-empty")
        elif vuln_id in seen_vuln_ids:
            errors.append(f"{prefix} duplicate vulnerability_id {vuln_id}")
        else:
            seen_vuln_ids.add(vuln_id)

        cve = vulnerability.get("cve")
        if cve is not None:
            if not isinstance(cve, str) or CVE_RE.fullmatch(cve) is None:
                errors.append(f"{prefix} invalid CVE identifier")
            elif cve in seen_cves:
                errors.append(f"{prefix} duplicate CVE {cve}")
            else:
                seen_cves.add(cve)

        cve_format = vulnerability.get("cve_record_format")
        if cve_format is not None and not re.fullmatch(r"5\.[0-9]+(?:\.[0-9]+)?", str(cve_format)):
            errors.append(f"{prefix} invalid CVE Record Format version")

        cwes = vulnerability.get("cwes")
        if not isinstance(cwes, list):
            errors.append(f"{prefix} cwes must be an array")
        else:
            seen_cwe: set[str] = set()
            for cwe_index, cwe in enumerate(cwes):
                if not isinstance(cwe, dict):
                    errors.append(f"{prefix}.cwes[{cwe_index}] must be an object")
                    continue
                cwe_id = cwe.get("id")
                if not isinstance(cwe_id, str) or CWE_RE.fullmatch(cwe_id) is None:
                    errors.append(f"{prefix}.cwes[{cwe_index}] invalid CWE id")
                elif cwe_id in seen_cwe:
                    errors.append(f"{prefix} duplicate CWE {cwe_id}")
                else:
                    seen_cwe.add(cwe_id)
                for field in ("name", "version"):
                    if not isinstance(cwe.get(field), str) or not cwe[field].strip():
                        errors.append(f"{prefix}.cwes[{cwe_index}] {field} must be non-empty")

        status = vulnerability.get("product_status")
        status_sets: dict[str, set[str]] = {}
        if not isinstance(status, dict):
            errors.append(f"{prefix} product_status must be an object")
        else:
            for field in ("known_affected", "fixed", "known_not_affected", "under_investigation"):
                values = status.get(field)
                if not isinstance(values, list) or len(values) != len(set(values)):
                    errors.append(f"{prefix}.product_status.{field} must be a unique array")
                    status_sets[field] = set()
                else:
                    status_sets[field] = set(values)
                    unknown = sorted(status_sets[field] - set(product_map))
                    if unknown:
                        errors.append(
                            f"{prefix}.product_status.{field} references unknown products: "
                            + ", ".join(unknown)
                        )
            fields = list(status_sets)
            for left_index, left in enumerate(fields):
                for right in fields[left_index + 1:]:
                    overlap = sorted(status_sets[left] & status_sets[right])
                    if overlap:
                        errors.append(
                            f"{prefix} product status conflict {left}/{right}: "
                            + ", ".join(overlap)
                        )
            affected_lines = {
                product_map[pid].get("product_line_id")
                for pid in status_sets.get("known_affected", set())
                if pid in product_map
            }
            for fixed_id in status_sets.get("fixed", set()):
                product = product_map.get(fixed_id)
                if product is not None and product.get("product_line_id") not in affected_lines:
                    errors.append(
                        f"{prefix} fixed product {fixed_id} has no known-affected product lineage"
                    )

        remediations = vulnerability.get("remediations")
        if not isinstance(remediations, list):
            errors.append(f"{prefix} remediations must be an array")
        else:
            for remediation_index, remediation in enumerate(remediations):
                rp = f"{prefix}.remediations[{remediation_index}]"
                if not isinstance(remediation, dict):
                    errors.append(f"{rp} must be an object")
                    continue
                product_ids = remediation.get("product_ids")
                if not isinstance(product_ids, list) or not product_ids:
                    errors.append(f"{rp} product_ids must be non-empty")
                else:
                    unknown = sorted(set(product_ids) - set(product_map))
                    if unknown:
                        errors.append(f"{rp} references unknown products: {', '.join(unknown)}")
                if not isinstance(remediation.get("details"), str) or not remediation["details"].strip():
                    errors.append(f"{rp} details must be non-empty")

        cvss = vulnerability.get("cvss_v4")
        if cvss is not None:
            if not isinstance(cvss, dict):
                errors.append(f"{prefix} cvss_v4 must be null or object")
            else:
                if cvss.get("version") != "4.0":
                    errors.append(f"{prefix} CVSS version must be 4.0")
                vector = cvss.get("vectorString")
                if not isinstance(vector, str) or not vector.startswith("CVSS:4.0/"):
                    errors.append(f"{prefix} invalid CVSS v4 vector")
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity")
                if not isinstance(score, (int, float)) or isinstance(score, bool) or not (0 <= score <= 10):
                    errors.append(f"{prefix} CVSS baseScore must be 0..10")
                elif severity != _score_severity(float(score)):
                    errors.append(f"{prefix} CVSS baseSeverity contradicts baseScore")

        epss = vulnerability.get("epss")
        if epss is not None:
            if not isinstance(epss, dict):
                errors.append(f"{prefix} epss must be null or object")
            else:
                for field in ("probability", "percentile"):
                    value = epss.get(field)
                    if not isinstance(value, (int, float)) or isinstance(value, bool) or not (0 <= value <= 1):
                        errors.append(f"{prefix} EPSS {field} must be 0..1")
                observed = _parse_time(epss.get("observed_at"), f"{prefix}.epss.observed_at", errors)
                if observed is not None and observed >= epss_v5_date and epss.get("model") != registry["current_epss_model"]:
                    errors.append(
                        f"{prefix} EPSS observations on/after 2026-06-15 must identify EPSS-v5"
                    )
                source = epss.get("source_uri")
                if not isinstance(source, str) or not source.startswith("https://"):
                    errors.append(f"{prefix} EPSS source_uri must use HTTPS")

        kev = vulnerability.get("kev")
        if not isinstance(kev, dict):
            errors.append(f"{prefix} kev must be an object")
        else:
            kev_status = kev.get("status")
            if kev_status not in {"listed", "not-listed", "unknown"}:
                errors.append(f"{prefix} invalid KEV status")
            source = kev.get("source_uri")
            if not isinstance(source, str) or not source.startswith("https://"):
                errors.append(f"{prefix} KEV source_uri must use HTTPS")
            _parse_time(kev.get("checked_at"), f"{prefix}.kev.checked_at", errors)
            date_added = kev.get("date_added")
            if kev_status == "listed" and not isinstance(date_added, str):
                errors.append(f"{prefix} listed KEV observation requires date_added")
            if kev_status != "listed" and date_added is not None:
                errors.append(f"{prefix} non-listed KEV observation must not set date_added")

        priority = vulnerability.get("priority")
        if not isinstance(priority, dict):
            errors.append(f"{prefix} priority must be an object")
        else:
            profile_ref = priority.get("profile_ref")
            decision = priority.get("decision")
            decisions = {
                "vulnerability-prioritization-cvss-threat@0.1.0":
                    {"defer", "scheduled", "out-of-band", "emergency"},
                "vulnerability-prioritization-ssvc@0.1.0":
                    {"track", "track-star", "attend", "act"},
            }
            if profile_ref not in decisions:
                errors.append(f"{prefix} unknown priority profile")
            elif decision not in decisions[profile_ref]:
                errors.append(f"{prefix} invalid priority decision for selected profile")
            _parse_time(priority.get("observed_at"), f"{prefix}.priority.observed_at", errors)
            if not isinstance(priority.get("rationale"), str) or not priority["rationale"].strip():
                errors.append(f"{prefix} priority rationale must be non-empty")

        exploitation = vulnerability.get("exploitation")
        if not isinstance(exploitation, dict):
            errors.append(f"{prefix} exploitation must be an object")
        else:
            exploitation_status = exploitation.get("status")
            if exploitation_status not in {"none-known", "proof-of-concept", "active", "unknown"}:
                errors.append(f"{prefix} invalid exploitation status")
            first_known = exploitation.get("first_known_exploitation_at")
            if first_known is not None:
                first_dt = _parse_time(
                    first_known, f"{prefix}.exploitation.first_known_exploitation_at", errors
                )
                if first_dt is not None and current is not None and first_dt > current:
                    errors.append(f"{prefix} first known exploitation is after current release")
            evidence_refs = exploitation.get("evidence_refs")
            if not isinstance(evidence_refs, list) or len(evidence_refs) != len(set(evidence_refs)):
                errors.append(f"{prefix} exploitation evidence_refs must be a unique array")
            elif exploitation_status in {"proof-of-concept", "active"} and not evidence_refs:
                errors.append(f"{prefix} proof-of-concept/active exploitation requires evidence_refs")
            if exploitation_status == "none-known" and first_known is not None:
                errors.append(f"{prefix} none-known exploitation cannot have first-known date")

    if handling_case is not None:
        if advisory.get("handling_case_id") != handling_case.get("case_id"):
            errors.append("advisory handling_case_id does not match source handling case")
        if advisory.get("handling_case_digest") != canonical_digest(handling_case):
            errors.append("advisory handling_case_digest does not match source handling case")
        handling_args = (
            handling_policy,
            disclosure_policy,
            handling_registry,
            disclosure_registry,
        )
        if all(arg is not None for arg in handling_args):
            result = vulnerability_handling.validate_case(
                handling_case,
                handling_policy,
                disclosure_policy,
                handling_registry,
                disclosure_registry,
                catalog,
                as_of=advisory.get("current_release_at"),
            )
            errors.extend("handling case: " + error for error in result.errors)
            if result.state not in {"disclosure-ready", "closed"}:
                errors.append(
                    f"source handling case must be disclosure-ready or closed, got {result.state}"
                )

    return sorted(set(errors))


def _product_helper(product: dict[str, Any], csaf_version: str) -> dict[str, Any] | None:
    helper: dict[str, Any] = {}
    if product.get("cpe"):
        helper["cpe"] = product["cpe"]
    if product.get("purl"):
        if csaf_version == "2.0":
            helper["purl"] = product["purl"]
        else:
            helper["purls"] = [product["purl"]]
    return helper or None


def _risk_note(vulnerability: dict[str, Any]) -> str:
    epss = vulnerability.get("epss")
    kev = vulnerability.get("kev", {})
    priority = vulnerability.get("priority", {})
    exploitation = vulnerability.get("exploitation", {})
    parts = [
        f"Known exploitation: {exploitation.get('status', 'unknown')}.",
        f"CISA KEV: {kev.get('status', 'unknown')}.",
        f"Contextual priority: {priority.get('decision', 'unknown')} "
        f"({priority.get('profile_ref', 'unknown')}).",
    ]
    if isinstance(epss, dict):
        parts.append(
            f"EPSS {epss.get('model')}: probability={epss.get('probability')}, "
            f"percentile={epss.get('percentile')} observed {epss.get('observed_at')}."
        )
    return " ".join(parts)


def export_csaf(
    advisory: dict[str, Any],
    profile_ref: str,
    registry: dict[str, Any],
    catalog: dict[str, Any],
) -> dict[str, Any]:
    errors = validate_advisory(advisory, registry, catalog)
    if errors:
        raise ValueError("invalid normalized advisory: " + "; ".join(errors))

    descriptor = _profile_map(registry).get(profile_ref)
    if descriptor is None:
        raise ValueError(f"unknown advisory profile {profile_ref}")
    version = descriptor["csaf_version"]

    full_product_names: list[dict[str, Any]] = []
    for product in advisory["products"]:
        item: dict[str, Any] = {
            "name": f"{product['vendor']} {product['name']} {product['version']}",
            "product_id": product["product_id"],
        }
        helper = _product_helper(product, version)
        if helper is not None:
            item["product_identification_helper"] = helper
        full_product_names.append(item)

    document = {
        "category": descriptor["document_category"],
        "csaf_version": version,
        "publisher": advisory["publisher"],
        "title": advisory["title"],
        "tracking": {
            "current_release_date": advisory["current_release_at"],
            "id": advisory["advisory_id"],
            "initial_release_date": advisory["initial_release_at"],
            "revision_history": [
                {
                    "date": item["date"],
                    "number": str(item["revision"]),
                    "summary": item["summary"],
                }
                for item in advisory["revision_history"]
            ],
            "status": "final",
            "version": str(advisory["revision"]),
        },
    }

    vulnerabilities: list[dict[str, Any]] = []
    for vulnerability in advisory["vulnerabilities"]:
        item: dict[str, Any] = {
            "notes": [
                {
                    "category": "description",
                    "text": vulnerability["description"],
                    "title": "Description",
                },
                {
                    "category": "other",
                    "text": _risk_note(vulnerability),
                    "title": "E2EESA risk signals",
                },
            ],
            "product_status": {
                key: list(vulnerability["product_status"][key])
                for key in ("known_affected", "fixed", "known_not_affected", "under_investigation")
                if vulnerability["product_status"][key]
            },
            "references": [
                {
                    "category": "external",
                    "summary": reference,
                    "url": reference,
                }
                for reference in vulnerability["references"]
            ],
            "remediations": [
                {
                    **{
                        "category": remediation["category"],
                        "details": remediation["details"],
                        "product_ids": remediation["product_ids"],
                    },
                    **({"url": remediation["url"]} if remediation.get("url") else {}),
                }
                for remediation in vulnerability["remediations"]
            ],
            "title": vulnerability["vulnerability_id"],
        }
        if vulnerability.get("cve"):
            item["cve"] = vulnerability["cve"]
        elif version == "2.0":
            item["id"] = {"system_name": "E2EESA", "text": vulnerability["vulnerability_id"]}
        else:
            item["ids"] = [{"system_name": "E2EESA", "text": vulnerability["vulnerability_id"]}]

        cwes = vulnerability.get("cwes", [])
        if cwes:
            if version == "2.0":
                item["cwe"] = {"id": cwes[0]["id"], "name": cwes[0]["name"]}
                if len(cwes) > 1:
                    item["notes"].append({
                        "category": "other",
                        "title": "Additional CWE classifications",
                        "text": ", ".join(cwe["id"] for cwe in cwes[1:]),
                    })
            else:
                item["cwes"] = [
                    {"id": cwe["id"], "name": cwe["name"], "version": cwe["version"]}
                    for cwe in cwes
                ]

        if version == "2.1":
            metrics: list[dict[str, Any]] = []
            products = vulnerability["product_status"]["known_affected"]
            cvss = vulnerability.get("cvss_v4")
            if isinstance(cvss, dict) and products:
                metrics.append({
                    "content": {
                        "cvss_v4": {
                            "version": cvss["version"],
                            "vectorString": cvss["vectorString"],
                            "baseScore": cvss["baseScore"],
                            "baseSeverity": cvss["baseSeverity"],
                        }
                    },
                    "products": products,
                    "source": cvss["source"],
                })
            epss = vulnerability.get("epss")
            if isinstance(epss, dict) and products:
                metrics.append({
                    "content": {
                        "epss": {
                            "percentile": f"{float(epss['percentile']):.9f}",
                            "probability": f"{float(epss['probability']):.9f}",
                            "timestamp": epss["observed_at"],
                        }
                    },
                    "products": products,
                    "source": epss["source_uri"],
                })
            priority = vulnerability.get("priority")
            if (
                isinstance(priority, dict)
                and priority.get("profile_ref") == "vulnerability-prioritization-ssvc@0.1.0"
                and isinstance(priority.get("ssvc_v2"), dict)
                and products
            ):
                metrics.append({
                    "content": {"ssvc_v2": priority["ssvc_v2"]},
                    "products": products,
                    "source": advisory["publisher"]["namespace"],
                })
            if metrics:
                item["metrics"] = metrics

            exploitation = vulnerability.get("exploitation", {})
            first_known = exploitation.get("first_known_exploitation_at")
            if exploitation.get("status") == "active" and first_known and products:
                item["first_known_exploitation_dates"] = [{
                    "date": advisory["current_release_at"],
                    "exploitation_date": first_known,
                    "product_ids": products,
                }]

        vulnerabilities.append(item)

    return {
        "$schema": descriptor["schema_uri"],
        "document": document,
        "product_tree": {"full_product_names": full_product_names},
        "vulnerabilities": vulnerabilities,
    }


def validate_export_scope(
    document: dict[str, Any],
    advisory: dict[str, Any],
    profile_ref: str,
    registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    descriptor = _profile_map(registry).get(profile_ref)
    if descriptor is None:
        return [f"unknown advisory profile {profile_ref}"]
    if document.get("$schema") != descriptor["schema_uri"]:
        errors.append("CSAF export schema URI does not match selected profile")
    doc = document.get("document")
    if not isinstance(doc, dict):
        return errors + ["CSAF export document must be an object"]
    if doc.get("category") != descriptor["document_category"]:
        errors.append("CSAF document category mismatch")
    if doc.get("csaf_version") != descriptor["csaf_version"]:
        errors.append("CSAF version mismatch")
    tracking = doc.get("tracking", {})
    if tracking.get("id") != advisory.get("advisory_id"):
        errors.append("CSAF advisory ID differs from normalized advisory")
    if tracking.get("current_release_date") != advisory.get("current_release_at"):
        errors.append("CSAF current release date differs from normalized advisory")
    if tracking.get("initial_release_date") != advisory.get("initial_release_at"):
        errors.append("CSAF initial release date differs from normalized advisory")

    exported_products = {
        item.get("product_id")
        for item in document.get("product_tree", {}).get("full_product_names", [])
        if isinstance(item, dict)
    }
    normalized_products = {item["product_id"] for item in advisory.get("products", [])}
    if exported_products != normalized_products:
        errors.append("CSAF product scope differs from normalized advisory")

    exported_vulns = document.get("vulnerabilities")
    if not isinstance(exported_vulns, list) or len(exported_vulns) != len(advisory.get("vulnerabilities", [])):
        errors.append("CSAF vulnerability count differs from normalized advisory")
        return sorted(set(errors))

    for normalized, exported in zip(advisory["vulnerabilities"], exported_vulns):
        if not isinstance(exported, dict):
            errors.append(f"CSAF vulnerability export for {normalized['vulnerability_id']} is malformed")
            continue
        if normalized.get("cve") and exported.get("cve") != normalized["cve"]:
            errors.append(f"CSAF CVE mismatch for {normalized['vulnerability_id']}")
        exported_status = exported.get("product_status", {})
        for field in ("known_affected", "fixed", "known_not_affected", "under_investigation"):
            if set(exported_status.get(field, [])) != set(normalized["product_status"][field]):
                errors.append(
                    f"CSAF product status {field} differs for {normalized['vulnerability_id']}"
                )

        normalized_remediations = {
            (item["category"], item["details"], tuple(sorted(item["product_ids"])))
            for item in normalized["remediations"]
        }
        exported_remediations = {
            (item.get("category"), item.get("details"), tuple(sorted(item.get("product_ids", []))))
            for item in exported.get("remediations", [])
            if isinstance(item, dict)
        }
        if normalized_remediations != exported_remediations:
            errors.append(f"CSAF remediation scope differs for {normalized['vulnerability_id']}")

        if descriptor["csaf_version"] == "2.0":
            if exported.get("scores"):
                errors.append("CSAF 2.0 export must not synthesize CVSS v3 from normalized CVSS v4")
        else:
            metrics = exported.get("metrics", [])
            if normalized.get("cvss_v4") is not None:
                if not any(
                    isinstance(metric, dict)
                    and isinstance(metric.get("content"), dict)
                    and "cvss_v4" in metric["content"]
                    for metric in metrics
                ):
                    errors.append(f"CSAF 2.1 export omitted CVSS v4 for {normalized['vulnerability_id']}")
            if normalized.get("epss") is not None:
                if not any(
                    isinstance(metric, dict)
                    and isinstance(metric.get("content"), dict)
                    and "epss" in metric["content"]
                    for metric in metrics
                ):
                    errors.append(f"CSAF 2.1 export omitted EPSS for {normalized['vulnerability_id']}")

    return sorted(set(errors))


def validate_external_csaf_result(
    document: dict[str, Any],
    profile_ref: str,
    result: dict[str, Any],
    registry: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    descriptor = _profile_map(registry).get(profile_ref)
    if descriptor is None:
        return [f"unknown advisory profile {profile_ref}"]
    if result.get("schema_version") != "0.1":
        errors.append("CSAF validation result schema_version must be 0.1")
    if result.get("profile_ref") != profile_ref:
        errors.append("CSAF validation result profile_ref mismatch")
    if result.get("csaf_version") != descriptor["csaf_version"]:
        errors.append("CSAF validation result version mismatch")
    digest = canonical_digest(document)
    if result.get("document_digest") != digest:
        errors.append("CSAF validation result document_digest mismatch")
    validator = result.get("validator")
    if not isinstance(validator, dict):
        errors.append("CSAF validation result validator must be an object")
    else:
        for field in ("name", "version", "reference"):
            if not isinstance(validator.get(field), str) or not validator[field].strip():
                errors.append(f"CSAF validation result validator.{field} must be non-empty")
    _parse_time(result.get("validated_at"), "CSAF validation result validated_at", errors)
    validation_errors = result.get("errors")
    if not isinstance(validation_errors, list):
        errors.append("CSAF validation result errors must be an array")
    elif validation_errors:
        errors.append("external CSAF validator reported errors")
    warnings = result.get("warnings")
    if not isinstance(warnings, list):
        errors.append("CSAF validation result warnings must be an array")
    return sorted(set(errors))


def csaf_validated(
    document: dict[str, Any],
    profile_ref: str,
    result: dict[str, Any] | None,
    registry: dict[str, Any],
) -> bool:
    return result is not None and not validate_external_csaf_result(
        document, profile_ref, result, registry
    )
