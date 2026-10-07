"""Validate artifact-bound SBOM, signed-provenance and reproduction evidence."""
import base64
import hashlib
from pathlib import Path
import re

from assurance_common import (
    binding_errors, check_schema, digest, load_json, parse_json, profile_errors,
    required_false, required_true, timestamp, validate_fixture_set,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "supply-chain-attested-reproducible@0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


def artifact_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def validate_policy(policy, catalog, *, root=ROOT):
    errors = check_schema(root, "supply-chain-policy", policy)
    if errors:
        return errors
    errors.extend(profile_errors(policy["profile_ref"], "software-supply-chain", catalog))
    if policy["profile_ref"] != PROFILE:
        errors.append("unsupported supply-chain profile")
    if policy["minimum_verified_signatures"] > len(policy["trusted_signer_ids"]):
        errors.append("signature threshold exceeds the trusted signer set")
    errors.extend(required_true(policy, ("require_reproducibility", "require_complete_sbom", "require_immutable_dependencies")))
    return errors


def validate_release(policy, evidence, catalog, *, root=ROOT):
    errors = validate_policy(policy, catalog, root=root)
    errors.extend(check_schema(root, "supply-chain-evidence", evidence))
    if errors:
        return errors
    errors.extend(binding_errors(policy, evidence))
    errors.extend(required_true(evidence, (
        "signature_verified", "artifact_digest_verified", "sbom_format_verified",
        "complete_transitive_inventory", "inventory_projection_verified", "hermetic_build",
        "ephemeral_builder", "signing_keys_isolated", "provenance_authenticated",
    )))
    errors.extend(required_false(evidence, ("unrecorded_network_dependencies", "unreviewed_build_parameters")))
    if evidence["source_commit"] != policy["source_commit"]:
        errors.append("supply chain: source commit differs from policy")
    if evidence["builder_id"] not in policy["trusted_builder_ids"]:
        errors.append("supply chain: untrusted builder identity")
    inventory = evidence["inventory"]
    ids = [c["component_id"] for c in inventory]
    if len(ids) != len(set(ids)):
        errors.append("inventory: duplicate component IDs")
    for component in inventory:
        if not set(component["dependency_ids"]).issubset(ids):
            errors.append("inventory: transitive dependency missing from inventory")
    sbom = evidence["sbom"]
    if sbom["subject_digest"] != evidence["artifact_digest"]:
        errors.append("SBOM subject does not match the release artifact")
    if set(sbom["component_ids"]) != set(ids) or sbom["inventory_digest"] != digest(inventory):
        errors.append("SBOM: inventory projection is incomplete or has a wrong digest")
    envelope = evidence["provenance_envelope"]
    try:
        statement = parse_json(base64.b64decode(envelope["payload"], validate=True).decode("utf-8"))
        errors.extend(check_schema(root, "slsa-build-statement", statement))
        for signature in envelope["signatures"]:
            if not base64.b64decode(signature["sig"], validate=True):
                errors.append("DSSE: empty signature")
    except (ValueError, UnicodeError) as exc:
        return errors + [f"DSSE: invalid payload/signature encoding: {exc}"]
    if errors:
        return errors
    signature_ids = [s["keyid"] for s in envelope["signatures"]]
    if len(signature_ids) != len(set(signature_ids)):
        errors.append("DSSE: duplicate signing identities")
    verified = set(evidence["verified_signer_ids"])
    if not verified.issubset(signature_ids) or not verified.issubset(policy["trusted_signer_ids"]) or len(verified) < policy["minimum_verified_signatures"]:
        errors.append("DSSE: insufficient policy-authorized verified signers")
    subject = statement["subject"]
    if len(subject) != 1 or subject[0]["name"] != evidence["artifact_name"] or "sha256:" + subject[0]["digest"]["sha256"] != evidence["artifact_digest"]:
        errors.append("provenance: wrong artifact subject")
    predicate = statement["predicate"]
    definition = predicate["buildDefinition"]
    expected = {"source_repository": policy["source_repository"], "source_commit": policy["source_commit"]}
    if definition["buildType"] != policy["build_type"] or definition["externalParameters"] != expected:
        errors.append("provenance: build type/source/parameters do not match policy")
    if predicate["runDetails"]["builder"]["id"] != evidence["builder_id"]:
        errors.append("provenance: builder identity mismatch")
    materials = {(c["uri"], c["digest"]["sha256"]) for c in definition["resolvedDependencies"]}
    expected_materials = {(c["source_uri"], c["artifact_digest"].removeprefix("sha256:")) for c in inventory}
    if materials != expected_materials or len(materials) != len(definition["resolvedDependencies"]):
        errors.append("provenance: resolved materials do not exactly cover the dependency inventory")
    try:
        observed = timestamp(evidence["observed_at"])
        meta = predicate["runDetails"]["metadata"]
        started, finished = timestamp(meta["startedOn"]), timestamp(meta["finishedOn"])
        if started > finished or finished > observed:
            errors.append("provenance: invalid build timing")
    except ValueError as exc:
        errors.append(str(exc))
    reproduction = evidence["reproduction"]
    if reproduction["builder_id"] == evidence["builder_id"] or reproduction["operator_id"] == evidence["builder_operator_id"]:
        errors.append("reproducibility: independent builder/operator required")
    if reproduction["artifact_digest"] != evidence["artifact_digest"] or reproduction["source_commit"] != evidence["source_commit"]:
        errors.append("reproducibility: artifact/source mismatch")
    errors.extend(required_true(reproduction, ("byte_identical", "inputs_verified")))
    if evidence["claimed_slsa_build_level"] >= 2:
        errors.extend(required_true(evidence, ("hosted_builder", "platform_generated_provenance")))
    if evidence["claimed_slsa_build_level"] >= 3:
        errors.extend(required_true(evidence, ("isolated_builds", "unforgeable_provenance")))
    if evidence["claimed_slsa_build_level"] < policy["minimum_slsa_build_level"]:
        errors.append("provenance: SLSA build evidence below policy floor")
    return errors


def validate_repository(root, catalog):
    errors = []
    try:
        registry = load_json(root / "registry/software-supply-chain.json")
        errors.extend(check_schema(root, "software-supply-chain-registry", registry))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"supply-chain registry: {exc}")
    workflow = root / ".github/workflows/validate.yml"
    if workflow.is_file():
        for line in workflow.read_text().splitlines():
            if "uses:" in line and not re.search(r"uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s|$)", line):
                errors.append("reference CI: remote actions must be pinned to immutable commit SHAs")
    return errors + validate_fixture_set(root, "supply-chain", validate_release, catalog)
