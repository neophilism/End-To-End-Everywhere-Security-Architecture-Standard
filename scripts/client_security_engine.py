"""Evidence validation for signed-native and hardened/verified web clients.

Signature, transparency and runtime checks are performed by external assessors;
this validator checks their artifact-bound records and policy consistency.
"""
from pathlib import Path
from urllib.parse import urlsplit
import re

from assurance_common import (
    binding_errors, check_schema, digest, load_json, profile_errors,
    required_false, required_true, timestamp, validate_fixture_set,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE_MODES = {
    "client-native-signed@0.1.0": "native",
    "client-web-hardened@0.1.0": "web",
    "client-web-verified-bootstrap@0.1.0": "verified-web",
}


def secure_origin(value: str) -> bool:
    try:
        u = urlsplit(value)
        return (u.scheme == "https" and bool(u.hostname)
                and bool(re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", u.hostname)) and u.username is None
                and u.password is None and u.path in {"", "/"}
                and not u.query and not u.fragment and u.port in {None, 443})
    except ValueError:
        return False


def csp_errors(value: str) -> list[str]:
    directives = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            tokens[0] = tokens[0].lower()
            if tokens[0] in directives:
                return ["CSP: duplicate directive"]
            directives[tokens[0]] = tokens[1:]
    errors = []
    for field in ("default-src", "object-src", "base-uri", "frame-ancestors"):
        if directives.get(field) != ["'none'"]:
            errors.append(f"CSP: {field} must be 'none'")
    scripts = directives.get("script-src", [])
    if not scripts or any(not re.fullmatch(r"'sha256-[A-Za-z0-9+/]{43}='", s) for s in scripts):
        errors.append("CSP: executable scripts must use explicit SHA-256 hashes")
    if "script-src-elem" in directives and directives["script-src-elem"] != scripts:
        errors.append("CSP: script-src-elem must not override the pinned script hashes")
    if directives.get("script-src-attr") != ["'none'"]:
        errors.append("CSP: script-src-attr must be 'none'")
    if directives.get("worker-src") != ["'self'"]:
        errors.append("CSP: worker-src must be restricted to self")
    connects = directives.get("connect-src", [])
    if not connects or any(not secure_origin(s) for s in connects):
        errors.append("CSP: connect-src must contain explicit HTTPS origins")
    return errors


def validate_policy(policy, catalog, *, root=ROOT):
    errors = check_schema(root, "client-security-policy", policy)
    if errors:
        return errors
    errors.extend(profile_errors(policy["profile_ref"], "client-security", catalog))
    mode = PROFILE_MODES.get(policy["profile_ref"])
    if mode is None:
        errors.append("unsupported client profile")
    if mode != "native" and not secure_origin(policy["origin"]):
        errors.append("web policy must pin an exact HTTPS origin")
    if mode == "native" and policy["origin"] is not None:
        errors.append("native policy must not carry a web origin")
    if policy["claims_origin_independent_execution"] != (mode in {"native", "verified-web"}):
        errors.append("client claim must match execution trust boundary")
    if policy["claims_compromised_endpoint_protection"]:
        errors.append("client hardening cannot claim protection from a compromised endpoint")
    return errors


def validate_client(policy, evidence, catalog, *, root=ROOT):
    errors = validate_policy(policy, catalog, root=root)
    errors.extend(check_schema(root, "client-release-evidence", evidence))
    if errors:
        return errors
    errors.extend(binding_errors(policy, evidence))
    mode = PROFILE_MODES[policy["profile_ref"]]
    release = evidence["release"]
    if release["artifact_digest"] != digest(release["manifest"]):
        errors.append("release: artifact_digest must bind the complete release manifest")
    if release["manifest"]["product_id"] != policy["product_id"] or release["manifest"]["version"] != policy["product_version"]:
        errors.append("release manifest: wrong product/version")
    paths = [a["path"] for a in release["manifest"]["artifacts"]]
    if len(set(paths)) != len(paths) or any(Path(p).is_absolute() or ".." in Path(p).parts for p in paths):
        errors.append("release manifest: duplicate or unsafe artifact paths")
    if not set(release["executable_paths"]).issubset(paths):
        errors.append("release: executable content is missing from the manifest")
    if release["signer_id"] not in policy["trusted_release_signers"]:
        errors.append("release: signer is not independently trusted")
    errors.extend(required_true(release, ("signature_verified", "all_executables_covered", "trust_root_rotation_verified", "update_metadata_verified")))
    if release["sequence"] < policy["minimum_release_sequence"] or release["sequence"] < release["previous_sequence"]:
        errors.append("release: rollback below a pinned or previously accepted sequence")
    try:
        observed, expires = timestamp(evidence["observed_at"]), timestamp(release["metadata_expires_at"])
        if expires <= observed:
            errors.append("release: update metadata expired (freeze protection)")
    except ValueError as exc:
        errors.append(str(exc))
    log = evidence["transparency"]
    if (log["operator_id"] == policy["origin_operator_id"]
            or log["operator_id"] in log["witness_ids"]
            or policy["origin_operator_id"] in log["witness_ids"]):
        errors.append("transparency: log/witnesses must be independently operated")
    if len(log["witness_ids"]) < policy["minimum_independent_witnesses"]:
        errors.append("transparency: insufficient independent witnesses")
    if log["entry_digest"] != release["artifact_digest"]:
        errors.append("transparency: entry does not bind this release")
    if log["checkpoint_sequence"] < log["previous_checkpoint_sequence"]:
        errors.append("transparency: checkpoint rollback")
    errors.extend(required_true(log, ("inclusion_verified", "consistency_verified", "equivocation_monitoring")))
    runtime = evidence["runtime"]
    if runtime["mode"] != mode:
        errors.append("runtime: profile/mode mismatch")
    errors.extend(required_true(runtime, ("authenticated_local_secret_storage", "least_privilege", "untrusted_content_isolated", "no_unverified_dynamic_code", "safe_update_failure", "version_visible")))
    if mode == "native":
        errors.extend(required_true(runtime, ("platform_signature_verified", "sandbox_enforced", "debug_interfaces_disabled")))
        if runtime["web"] is not None:
            errors.append("native: web evidence must be absent")
    else:
        web = runtime["web"]
        if web is None:
            return errors + ["web: browser security evidence required"]
        if web["origin"] != policy["origin"]:
            errors.append("web: origin mismatch")
        errors.extend(csp_errors(web["csp"]))
        errors.extend(required_true(web, ("secure_context", "hsts", "sri_checked", "service_workers_manifest_bound", "origin_checks", "csrf_protection", "dom_injection_defense", "secret_storage_encrypted", "extensions_risk_disclosed")))
        errors.extend(required_false(web, ("plaintext_secrets_in_web_storage", "third_party_code_in_secret_context", "mixed_content")))
        if mode == "verified-web":
            if web["bootstrap_trust_source"] != "independently-installed" or web["bootstrap_operator_id"] == policy["origin_operator_id"]:
                errors.append("verified web: bootstrap must be trusted independently of the origin")
            errors.extend(required_true(web, ("verification_before_execution", "fail_closed_on_manifest_mismatch")))
            if not web["claims_malicious_origin_prevention"]:
                errors.append("verified web: the independently enforced execution boundary must be declared")
        elif web["bootstrap_trust_source"] != "origin" or web["claims_malicious_origin_prevention"]:
            errors.append("ordinary web: origin delivery trust must be disclosed without a prevention claim")
    return errors


def validate_repository(root, catalog):
    errors = []
    try:
        registry = load_json(root / "registry/client-security.json")
        errors.extend(check_schema(root, "client-security-registry", registry))
        if set(registry.get("profile_refs", [])) != set(PROFILE_MODES):
            errors.append("client registry: unsupported profile set")
        expected = {"tuf": "1.0.36", "csp3": "2026-09-16", "sri": "2016-06-23"}
        if {r["id"]: r["version"] for r in registry.get("references", [])} != expected:
            errors.append("client registry: external specifications must remain version pinned")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"client registry: {exc}")
    return errors + validate_fixture_set(root, "client-security", validate_client, catalog)
