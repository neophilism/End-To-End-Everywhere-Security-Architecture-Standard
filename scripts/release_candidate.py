#!/usr/bin/env python3
"""E2EESA 0.9 release-candidate freeze and completeness validation."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import crypto_registry
import integration_contracts
import profile_engine
import reference_fixtures
import security_rationale
import standards_crosswalk


RC1_ARCHIVE_ANCHOR = {'release_version': '0.9.0-rc.1', 'source_commit': 'dea8f54cab9130da86a71f36de553766a978daf2', 'manifest_path': 'release/0.9.0-rc.1-manifest.json', 'manifest_sha256': '85c3cb9e607c1508ae65baeda5987e4a04d8b89d25ca167d48f85983b3afd278', 'archive_path': 'release/archive/0.9.0-rc.1.tar.gz', 'archive_sha256': 'cf7f3a999ad35676ea732db065303bc2f61ecce655daf1cf0897f6870d4b862e', 'tree_digest': 'sha256:9d546433dde60d3157e2adb3d9c630dbc36fd92c551083f5f5189491370ce2a2'}
REQUIRED_FROZEN_ROOTS = {'reference', 'fixtures', 'schemas', 'profiles', '.github/workflows', 'scripts', 'registry', 'tests', 'spec', 'adr'}

def sha256_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def git_blob_sha(data):
    header = ("blob " + str(len(data)) + chr(0)).encode("utf-8")
    return hashlib.sha1(header + data).hexdigest()


def canonical_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def canonical_digest(value):
    return sha256_bytes(canonical_bytes(value))


def load_json(root, rel):
    value=json.loads((root/rel).read_text(encoding="utf-8"))
    if not isinstance(value,dict):
        raise ValueError(rel+" must contain an object")
    return value


def frozen_paths(root, policy):
    excluded=set(policy["excluded_paths"])
    paths=set()
    for top in policy["frozen_top_level_files"]:
        p=root/top
        if p.is_file() and top not in excluded:
            paths.add(top)
    for relroot in policy["frozen_roots"]:
        base=root/relroot
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            rel=p.relative_to(root).as_posix()
            if rel in excluded or "__pycache__" in p.parts or p.suffix==".pyc":
                continue
            paths.add(rel)
    return sorted(paths)


def build_manifest(root, policy):
    entries=[]
    for rel in frozen_paths(root,policy):
        data=(root/rel).read_bytes()
        entries.append({"path":rel,"size":len(data),"git_blob_sha":git_blob_sha(data)})
    manifest={
        "schema_version":"0.1",
        "release_version":policy["release_version"],
        "basis_standard_version":policy["basis_standard_version"],
        "file_count":len(entries),
        "files":entries,
        "tree_digest":"",
    }
    manifest["tree_digest"]=canonical_digest(entries)
    return manifest


def validate_release(root):
    errors=[]
    policy=load_json(root,"registry/release-candidate.json")
    errors.extend(validate_historical_candidates(root, policy))
    if not REQUIRED_FROZEN_ROOTS.issubset(set(policy.get("frozen_roots",[]))):
        errors.append("release freeze omits a required source root")
    if any(path.startswith(tuple(top+"/" for top in REQUIRED_FROZEN_ROOTS)) and path!="registry/release-candidate.json" for path in policy.get("excluded_paths",[])):
        errors.append("release freeze excludes a source file")
    if policy.get("development_state") not in {"audit-remediation","frozen-candidate"}:
        errors.append("release development state must be explicit")
    if (policy.get("development_state")=="audit-remediation") != policy.get("release_version", "").endswith("-dev"):
        errors.append("development/frozen candidate version identity mismatch")
    version=(root/"VERSION").read_text(encoding="utf-8").strip()
    if version!=policy["release_version"]:
        errors.append("VERSION does not match release candidate version")

    catalog=load_json(root,"profiles/catalog.json")
    crypto=load_json(root,"registry/cryptographic-algorithms.json")
    integration=load_json(root,"registry/integration-contracts.json")
    basis=policy["basis_standard_version"]
    for name,obj in (("profile catalog",catalog),("cryptographic registry",crypto),("integration registry",integration)):
        if obj.get("standard_version")!=basis:
            errors.append(name+" standard_version does not match frozen basis")

    property_registry=load_json(root,"registry/security-properties.json")
    known_props={x.get("id") for x in property_registry.get("properties",[]) if isinstance(x,dict)}
    errors.extend("profile catalog: "+e for e in profile_engine.validate_catalog(catalog,known_property_ids=known_props))
    errors.extend("cryptographic registry: "+e for e in crypto_registry.validate_registry(crypto))
    errors.extend("integration contracts: "+e for e in integration_contracts.validate_registry(integration,root=root))

    fixture_registry=load_json(root,"registry/reference-fixtures.json")
    fixture_manifest=load_json(root,"fixtures/reference-architectures/manifest.json")
    promotion_registry=load_json(root,"registry/research-promotion.json")
    errors.extend("reference fixtures: "+e for e in reference_fixtures.validate_manifest(fixture_manifest,fixture_registry=fixture_registry,catalog=catalog,promotion_registry=promotion_registry))

    catalog_refs={profile_engine.profile_ref(x) for x in catalog.get("profiles",[]) if isinstance(x,dict)}
    fixture_refs={x.get("profile_ref") for x in fixture_manifest.get("entries",[]) if isinstance(x,dict)}
    if catalog_refs!=fixture_refs:
        errors.append("release candidate reference fixture coverage is not catalog-complete")
    production_refs={
        x.get("profile_ref") for x in fixture_manifest.get("entries",[])
        if isinstance(x,dict) and x.get("disposition")=="production-positive"
    }
    expected_pairs=len(production_refs)*(len(production_refs)-1)//2
    if expected_pairs < 1:
        errors.append("release candidate has no production interoperability pair space")

    standards=load_json(root,"registry/external-standards.json")
    crosswalk_rules=load_json(root,"registry/standards-crosswalk-rules.json")
    crosswalk_errors=standards_crosswalk.validate(standards,crosswalk_rules,root)
    errors.extend("standards crosswalk: "+e for e in crosswalk_errors)
    if not crosswalk_errors:
        crosswalk=standards_crosswalk.build_report(root,standards,crosswalk_rules)
        if crosswalk["coverage_percent_basis_points"]!=10000:
            errors.append("release candidate standards crosswalk coverage is not 100 percent")

    rationale_rules=load_json(root,"registry/security-rationale-rules.json")
    threat_registry=load_json(root,"registry/threat-model.json")
    rationale_errors=security_rationale.validate_rules(rationale_rules,root,threat_registry,property_registry)
    errors.extend("security rationale: "+e for e in rationale_errors)
    if not rationale_errors and not crosswalk_errors:
        rationale=security_rationale.build_report(root,rationale_rules,threat_registry,property_registry,standards,crosswalk_rules)
        if rationale["coverage_percent_basis_points"]!=10000:
            errors.append("release candidate security rationale coverage is not 100 percent")

    manifest_path=policy["manifest_path"]
    if not (root/manifest_path).is_file():
        errors.append("release candidate manifest is missing")
    else:
        stored=load_json(root,manifest_path)
        expected=build_manifest(root,policy)
        if stored!=expected:
            errors.append("release candidate frozen-file manifest differs from working tree")

    return sorted(set(errors))


def validate_historical_candidates(root, policy):
    """Verify archived bytes without requiring a Git history or extracting paths."""
    errors = []
    if "release/0.9.0-rc.1-archive.json" not in policy.get("historical_candidates", []):
        errors.append("original rc.1 verification anchor is mandatory")
    for path in policy.get("historical_candidates", []):
        try:
            anchor = load_json(root, path)
            if path == "release/0.9.0-rc.1-archive.json" and anchor != RC1_ARCHIVE_ANCHOR:
                raise ValueError("original rc.1 verification anchor changed")
            manifest_bytes = (root / anchor["manifest_path"]).read_bytes()
            archive_bytes = (root / anchor["archive_path"]).read_bytes()
            if hashlib.sha256(manifest_bytes).hexdigest() != anchor["manifest_sha256"]:
                raise ValueError("historical manifest byte identity changed")
            if hashlib.sha256(archive_bytes).hexdigest() != anchor["archive_sha256"]:
                raise ValueError("historical archive byte identity changed")
            manifest = json.loads(manifest_bytes)
            if canonical_digest(manifest["files"]) != anchor["tree_digest"]:
                raise ValueError("historical tree digest changed")
            with tarfile.open(root / anchor["archive_path"], "r:gz") as archive:
                members = archive.getmembers()
                if [item.name for item in members] != [item["path"] for item in manifest["files"]]:
                    raise ValueError("historical archive path set changed")
                for item, expected in zip(members, manifest["files"]):
                    if not item.isfile():
                        raise ValueError("historical archive contains a non-file")
                    data = archive.extractfile(item).read()
                    if len(data) != expected["size"] or git_blob_sha(data) != expected["git_blob_sha"]:
                        raise ValueError("historical bytes changed: " + item.name)
        except (OSError, ValueError, KeyError, tarfile.TarError) as exc:
            errors.append(path + ": " + str(exc))
    return errors


if __name__=="__main__":
    root=Path(__file__).resolve().parents[1]
    errors=validate_release(root)
    if errors:
        for error in errors: print("ERROR:",error)
        raise SystemExit(1)
    print("E2EESA 0.9 release candidate validation passed.")
